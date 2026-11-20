package runner

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mengnanquq/mnagent/internal/miaospeed"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
)

func isHeavy(job model.Job) bool {
	kind := probe.ProbeKind(job)
	return kind == probe.KindTrace || kind == "miaospeed"
}

// isUpgradeJob 判断是否为远程更新控制任务（Kind 归一化后比较）。
func isUpgradeJob(job model.Job) bool {
	switch job.NormalizedKind() {
	case "upgrade", "update":
		return true
	default:
		return false
	}
}

// loggableTarget 返回可安全写入日志的任务目标。
// miaospeed 的 Target 可能是含 token 的订阅 URL、节点 URI 或整段配置，
// 直接打印会泄露凭据；其他探针目标受 targetPattern 限制，本身不含敏感信息。
func loggableTarget(job model.Job) string {
	if probe.ProbeKind(job) == "miaospeed" {
		return miaospeed.RedactTargetForLog(job.Target)
	}
	return job.Target
}

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

			if isUpgradeJob(j) {
				a.handleUpgradeJob(ctx, j)
			} else {
				a.execute(ctx, j)
			}
		}
	}
}

// execute 在任务上下文中执行一次任务并回传结果；回传不随任务取消而中断。
func (a *Agent) execute(ctx context.Context, job model.Job) {
	start := time.Now()
	a.logger.Info("开始执行任务", "job", job.ID, "kind", probe.ProbeKind(job), "target", loggableTarget(job),
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
	entry := []any{"job", job.ID, "target", loggableTarget(job), "exit_code", exitCode,
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
			if job.NormalizedKind() == "cancel" {
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
	// 先单独判断退出：select 中的 ctx.Done 与 default 同时就绪时是随机选择，
	// 这里是本循环最后一次入队，必须稳定地走「节点正在退出」回报而不是“队列已满”。
	if ctx.Err() != nil {
		a.rejectBusyJob(job, "节点正在退出")
		return false
	}
	select {
	case a.heavyQueue <- job:
		return true
	case <-ctx.Done():
		// 入队与取消同时发生：与其静默丢弃，不如立即回报失败，避免机器人等到超时。
		a.rejectBusyJob(job, "节点正在退出")
		return false
	default:
		a.rejectBusyJob(job, "节点任务队列已满，任务未执行，请稍后重试")
		return false
	}
}

// maxConcurrentRejectSends 限制 rejectBusyJob 并发回传的协程数，
// 避免服务端异常时大量「队列已满」结果同时占满连接与内存。
const maxConcurrentRejectSends = 4

// rejectSendLimiter 懒初始化并发上限，允许测试直接构造 Agent 而不显式初始化。
func (a *Agent) rejectSendLimiter() chan struct{} {
	a.rejectOnce.Do(func() {
		a.rejectSem = make(chan struct{}, maxConcurrentRejectSends)
	})
	return a.rejectSem
}

// rejectBusyJob 异步回传“队列已满/正在退出”的失败结果，并标记任务已完成，避免重复下发再次执行。
// 失败结果会写入去重缓存，即使并发上限已满而丢弃本次回传，服务端重发时仍能拿到结果。
func (a *Agent) rejectBusyJob(job model.Job, reason string) {
	res := model.Result{
		ID:       job.ID,
		Kind:     probe.ProbeKind(job),
		ExitCode: -1,
		Error:    reason,
	}
	a.dedupStore().complete(job.ID, &res)
	if a.logger != nil {
		a.logger.Warn("节点任务队列不可用，立即回报失败", "job", job.ID, "kind", probe.ProbeKind(job), "reason", reason)
	}
	if a.client == nil {
		return
	}
	sem := a.rejectSendLimiter()
	select {
	case sem <- struct{}{}:
		// 已占用一个并发槽位。
	default:
		// 并发已满：这里在入队路径上，同步发送会拖住主长轮询与退出流程，
		// 无界开协程则会在服务端异常时堆集。结果已写入去重缓存，
		// 因此选择丢弃本次回传并告警（服务端重发同一任务时会命中去重缓存）。
		if a.logger != nil {
			a.logger.Warn("失败结果回传并发已达上限，本次回传丢弃待服务端重发",
				"job", job.ID, "limit", maxConcurrentRejectSends)
		}
		return
	}
	a.tasksWG.Add(1)
	go func() {
		defer a.tasksWG.Done()
		defer func() { <-sem }()
		if err := a.sendResult(res); err != nil && a.logger != nil {
			a.logger.Warn("回报失败结果失败", "job", job.ID, "error", err)
		}
	}()
}

// setStopContext 记录退出阶段的共享停止预算，供在途任务回传使用。
