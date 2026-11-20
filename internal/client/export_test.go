package client

import (
	"context"

	"github.com/mengnanquq/mnagent/internal/model"
)

// 以下包装函数仅供包内测试使用，集中放在 export_test.go，
// 避免生产代码里长期保留无调用者的测试专用别名。

func (c *Client) poll(ctx context.Context) (*model.Job, error) {
	return c.Poll(ctx)
}

func (c *Client) sendResult(ctx context.Context, res model.Result) error {
	return c.SendResult(ctx, res)
}

func (c *Client) sendProgress(ctx context.Context, p model.Progress) (bool, error) {
	return c.SendProgress(ctx, p)
}

func (c *Client) heartbeat(ctx context.Context) error {
	return c.Heartbeat(ctx)
}
