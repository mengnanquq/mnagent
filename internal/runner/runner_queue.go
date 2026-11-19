package runner

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
)

func isHeavy(job model.Job) bool {
	kind := probe.ProbeKind(job)
	return kind == probe.KindTrace || kind == "miaospeed"
}

// loop 不断领取任务并执行，直到 ctx 结束；启用自动更新时按周期检查新版本。
// heavyWorker 串行处理重任务与远程更新，避免多重任务争抢带宽与端口，
// 并与主长轮询完全解耦，使长轮询与轻任务始终保持秒级响应。
func (a *Agent) heavyWorker(ctx context.Context) {
	defer a.tasksWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-a.heavyQueue:
			if !ok {
				return
			}

			// 检查任务在排队期间是否已被 cancel
			if a.tracker != nil && a.tracker.IsCancelled(j.ID) {
				a.logger.Info("任务在排队期间已被取消，标记为无结果并跳过执行", "job", j.ID, "kind", j.Kind)
				a.dedupStore().complete(j.ID, nil)
				continue
			}

			if j.Kind == "upgrade" || j.Kind == "update" {
				a.handleUpgradeJob(ctx, j)
			} else {
				a.execute(ctx, j)
			}
		}
	}
}

// startHeartbeat 启动独立于任务执行的周期心跳协程，确保长任务执行期间服务端 lastSeen 始终保活。
func (a *Agent) execute(ctx context.Context, job model.Job) {
	start := time.Now()
	a.logger.Info("开始执行任务", "job", job.ID, "kind", probe.ProbeKind(job), "target", job.Target,
		"hops", job.Hops, "port", job.Port, "protocol", job.Protocol, "count", job.Count)

	taskCtx, taskCancel := context.WithCancel(ctx)
	defer taskCancel()
	if a.tracker != nil {
		a.tracker.Register(job.ID, taskCancel)
		defer a.tracker.Unregister(job.ID)
	}

	run := a.runner.Run(taskCtx, job)
	output, errText, exitCode := run.Output, run.ErrText, run.ExitCode

	res := model.Result{ID: job.ID, Kind: probe.ProbeKind(job), Output: output, ExitCode: exitCode, Error: errText, Data: run.Data}
	a.dedupStore().complete(job.ID, &res)
	// 回传不依赖任务上下文：即使任务超时或进程正在退出，也尽量让机器人拿到结果，
	// 否则用户要一直等到超时。
	if err := a.sendResult(res); err != nil {
		a.logger.Warn("回传结果失败", "job", job.ID, "error", err)
		return
	}
	entry := []any{"job", job.ID, "target", job.Target, "exit_code", exitCode,
		"duration", time.Since(start).Round(time.Millisecond).String(), "bytes", len(output)}
	if errText != "" {
		a.logger.Warn("任务结束（有错误）", append(entry, "error", errText)...)
		return
	}
	a.logger.Info("任务完成", entry...)
}

// failPendingHeavy 在退出/重启前把 heavyQueue 中尚未执行的任务逐一回报，
// 避免机器人一直等到任务超时。
func (a *Agent) failPendingHeavy(ctx context.Context, reason string) int {
	if a.heavyQueue == nil {
		return 0
	}
	var jobs []model.Job
	for {
		select {
		case job, ok := <-a.heavyQueue:
			if !ok {
				goto send
			}
			if job.Kind == "cancel" {
				continue
			}
			jobs = append(jobs, job)
		default:
			goto send
		}
	}

send:
	if len(jobs) == 0 {
		return 0
	}
	// 退出时可能积压多个任务：小并发回报，共享同一个退出预算（见 Loop），
	// 既比原来 5s 串行更宽裕，也不会超过 systemd 的停止超时。
	var (
		wg sync.WaitGroup
		n  atomic.Int64
	)
	sem := make(chan struct{}, 4)
	for _, job := range jobs {
		wg.Add(1)
		go func(job model.Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := model.Result{
				ID:       job.ID,
				Kind:     probe.ProbeKind(job),
				ExitCode: -1,
				Error:    reason,
			}
			a.dedupStore().complete(job.ID, &res)
			if a.client != nil {
				if err := a.client.SendResult(ctx, res); err != nil {
					a.logger.Warn("回报未执行重任务失败", "job", job.ID, "error", err)
				}
			}
			n.Add(1)
		}(job)
	}
	wg.Wait()
	return int(n.Load())
}

// sleep 等待指定时长；ctx 结束时返回 false。
func sleep(ctx context.Context, d time.Duration) bool {
	// 加抖动，避免多台主机同时重连打满机器人。
	jitter := time.Duration(rand.Int64N(int64(d/4) + 1))
	timer := time.NewTimer(d + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// evaluateRemoteTarget 检查服务端下发的显式目标版本。
// 默认只允许严格升级：目标等于当前版本视为无操作，低于当前版本一律拒绝，
// 除非 agent 本地用 -allow-remote-downgrade 显式放行（本地 CLI -apply-update 不走这里）。
func (a *Agent) enqueueHeavy(ctx context.Context, job model.Job) bool {
	select {
	case a.heavyQueue <- job:
		return true
	case <-ctx.Done():
		return false
	default:
		a.rejectBusyJob(job, "节点任务队列已满，任务未执行，请稍后重试")
		return false
	}
}

// rejectBusyJob 异步回传“队列已满”的失败结果，并标记任务已完成，避免重复下发再次执行。
func (a *Agent) rejectBusyJob(job model.Job, reason string) {
	res := model.Result{
		ID:       job.ID,
		Kind:     probe.ProbeKind(job),
		ExitCode: -1,
		Error:    reason,
	}
	a.dedupStore().complete(job.ID, &res)
	if a.logger != nil {
		a.logger.Warn("节点任务队列已满，立即回报失败", "job", job.ID, "kind", probe.ProbeKind(job))
	}
	if a.client == nil {
		return
	}
	a.tasksWG.Add(1)
	go func() {
		defer a.tasksWG.Done()
		if err := a.sendResult(res); err != nil {
			a.logger.Warn("回报队列已满失败结果失败", "job", job.ID, "error", err)
		}
	}()
}

// setStopContext 记录退出阶段的共享停止预算，供在途任务回传使用。
