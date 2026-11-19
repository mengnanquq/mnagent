package runner

import (
	"context"
	"time"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
)

func (a *Agent) dedupStore() *jobDedup {
	a.dedupOnce.Do(func() {
		if a.dedup == nil {
			a.dedup = newJobDedup()
		}
	})
	return a.dedup
}

// beginResend 为缓存结果重发登记 in-flight 标记，同一 jobID 同时只允许一个重发。
func (a *Agent) beginResend(id string) bool {
	a.resendMu.Lock()
	defer a.resendMu.Unlock()
	if a.resendInFlight == nil {
		a.resendInFlight = make(map[string]struct{})
	}
	if _, ok := a.resendInFlight[id]; ok {
		return false
	}
	a.resendInFlight[id] = struct{}{}
	return true
}

// finishResend 清除缓存重发 in-flight 标记。
func (a *Agent) finishResend(id string) {
	a.resendMu.Lock()
	delete(a.resendInFlight, id)
	a.resendMu.Unlock()
}

// setStopContext 记录退出阶段的共享停止预算，供在途任务回传使用。
func (a *Agent) setStopContext(ctx context.Context) {
	a.stopMu.Lock()
	a.stopCtx = ctx
	a.stopMu.Unlock()
}

// stopContext 返回退出阶段的共享预算；未进入退出流程时返回 Background。
func (a *Agent) stopContext() context.Context {
	a.stopMu.RLock()
	ctx := a.stopCtx
	a.stopMu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// waitTasks 等待在途任务结束；ctx 到期后放弃等待，避免退出被卡死。
func (a *Agent) waitTasks(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		a.tasksWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if a.logger != nil {
			a.logger.Warn("等待在途任务结束超时，剩余结果可能无法回传", "error", ctx.Err())
		}
	}
}

// resultTimeout 返回结果回传超时，与 client 的 /results 独立超时保持一致。
func (a *Agent) resultTimeout() time.Duration {
	if a.cfg != nil && a.cfg.ResultTimeout > 0 {
		return a.cfg.ResultTimeout
	}
	return config.DefaultResultTimeout
}

// sendResult 在独立于任务上下文的整体预算内回传结果。
// 正常运行时使用 -result-timeout 作为单次回传上限；退出阶段再叠加共享停止预算。
func (a *Agent) sendResult(res model.Result) error {
	return a.sendResultWithin(a.stopContext(), res, a.resultTimeout())
}

// sendResultWithin 在给定整体预算内回传结果；ctx 取消时立即返回。
func (a *Agent) sendResultWithin(ctx context.Context, res model.Result, total time.Duration) error {
	if total <= 0 {
		total = config.DefaultResultTotalTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	return a.client.SendResult(ctx, res)
}

// resendCachedResult 处理重复下发的已完成任务：能拿到缓存就重发，否则只记录跳过，
// 绝不重新执行（尤其是 upgrade/miaospeed/trace）。
// 在独立协程中调用，ctx 随主循环结束而取消，避免退出时被大结果上传拖住。
func (a *Agent) resendCachedResult(ctx context.Context, job model.Job, cached *model.Result, state dedupCacheState) {
	if cached == nil {
		if state == dedupCacheOversized {
			a.logger.Warn("任务已执行过，但结果超出缓存上限，跳过重复执行", "job", job.ID, "kind", probe.ProbeKind(job),
				"cache_limit_bytes", int64(maxCachedResultsTotal))
			return
		}
		a.logger.Info("任务已取消或没有可回传的结果，跳过重复执行", "job", job.ID, "kind", probe.ProbeKind(job))
		return
	}
	// 重发同样尊重 -result-timeout：缓存结果可能有数 MB，不能用无限制预算。
	if err := a.sendResultWithin(ctx, *cached, a.resultTimeout()); err != nil {
		a.logger.Warn("重发缓存结果失败", "job", job.ID, "error", err)
		return
	}
	a.logger.Info("已重发缓存结果（跳过重复执行）", "job", job.ID, "kind", probe.ProbeKind(job))
}
