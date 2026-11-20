package miaospeed

import (
	"context"
	"encoding/json"

	"github.com/mengnanquq/mnagent/internal/model"
)

// 以下包装函数仅供包内测试使用，集中放在 export_test.go，
// 避免生产代码里长期保留无调用者的测试专用别名。

func filterBlockedNodes(ctx context.Context, nodes []MiaospeedNode, log Logger) ([]MiaospeedNode, int) {
	return filterBlockedNodesWithPolicy(ctx, nodes, nodeFilterPolicy{}, log)
}

func runMiaospeedJob(ctx context.Context, binary, ghProxy string, job model.Job, log Logger, onProgress func(model.Progress), allowPrivate ...bool) (string, json.RawMessage, error) {
	return RunJob(ctx, binary, ghProxy, job, log, onProgress, allowPrivate...)
}
