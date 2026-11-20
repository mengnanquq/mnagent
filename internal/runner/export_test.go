package runner

import (
	"context"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
)

// 以下包装函数仅供包内测试使用，集中放在 export_test.go，
// 避免生产代码里长期保留无调用者的测试专用别名。

func newRunner(binary string, log Logger) *Runner {
	return NewRunnerFull(binary, "miaospeed", "", false, log)
}

func newRunnerWithMiaospeed(binary, miaospeed string, log Logger) *Runner {
	return NewRunnerFull(binary, miaospeed, "", false, log)
}

func newRunnerFull(binary, miaospeed, ghProxy string, allowPrivate bool, log Logger) *Runner {
	return NewRunnerFull(binary, miaospeed, ghProxy, allowPrivate, log)
}

func (r *Runner) run(ctx context.Context, job model.Job) runResult {
	return r.Run(ctx, job)
}

func (r *Runner) setProgressReporter(fn func(model.Progress)) {
	r.SetProgressReporter(fn)
}

func (a *Agent) loop(ctx context.Context) error {
	return a.Loop(ctx)
}

func handleUpdateCLI(cfg *config.Config, log Logger) (handled bool, err error) {
	return HandleUpdateCLI(cfg, log)
}
