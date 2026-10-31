package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
)

// Version 是当前客户端版本。
var Version = "dev"

// maxResponseBytes 限制解析响应体时读取的字节数（16MB），支持超大代理配置与多节点订阅的整体下发。
const maxResponseBytes = 16 << 20

// maxResultAttempts 是回传结果的最大尝试次数（结果按任务 ID 幂等，重试安全）。
const maxResultAttempts = 3

// Client 负责与机器人的 agent 端点通信。
type Client struct {
	baseURL string
	host    string
	tokens  *config.TokenSource
	http    *http.Client

	isp    atomic.Pointer[string]
	paused atomic.Bool // 更新期间暂停轮询，避免新旧版本交替领取任务。
}

// New 构建通信客户端；轮询超时略大于机器人侧的长轮询保持时间。
func New(cfg *config.Config) *Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Client{
		baseURL: cfg.BotURL,
		tokens:  cfg.Tokens,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.PollTimeout,
		},
	}
}

// SetISP 设置本地探测或指定的运营商/ISP 名称。
func (c *Client) SetISP(isp string) {
	s := strings.TrimSpace(isp)
	c.isp.Store(&s)
}

func (c *Client) setISP(isp string) {
	c.SetISP(isp)
}

// GetISP 获取当前已探测或指定的运营商/ISP 名称。
func (c *Client) GetISP() string {
	if p := c.isp.Load(); p != nil {
		return *p
	}
	return ""
}

func (c *Client) getISP() string {
	return c.GetISP()
}

// SetPaused 设置更新暂停状态。
func (c *Client) SetPaused(paused bool) {
	c.paused.Store(paused)
}

// Poll 领取一个任务；无任务时返回 (nil, nil)。
func (c *Client) Poll(ctx context.Context) (*model.Job, error) {
	if c.paused.Load() {
		return nil, model.ErrUpdating
	}
	resp, err := c.do(ctx, http.MethodPost, "/jobs", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var job model.Job
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&job); err != nil {
			return nil, fmt.Errorf("解析任务失败: %w", err)
		}
		if strings.TrimSpace(job.ID) == "" {
			return nil, errors.New("任务缺少必需字段 ID")
		}
		if job.Kind != "cancel" && strings.TrimSpace(job.Target) == "" {
			return nil, errors.New("任务缺少必需字段 Target")
		}
		return &job, nil
	case http.StatusUnauthorized:
		return nil, model.ErrUnauthorized
	default:
		return nil, fmt.Errorf("领取任务失败：%s %s", resp.Status, readSnippet(resp.Body))
	}
}

func (c *Client) poll(ctx context.Context) (*model.Job, error) {
	return c.Poll(ctx)
}

// SendResult 回传执行结果，失败时按退避重试。
func (c *Client) SendResult(ctx context.Context, res model.Result) error {
	payload, err := json.Marshal(res)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 1; attempt <= maxResultAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		resp, err := c.do(ctx, http.MethodPost, "/results", payload)
		if err != nil {
			lastErr = err
			continue
		}
		status := resp.StatusCode
		snippet := readSnippet(resp.Body)
		resp.Body.Close()
		if status == http.StatusNoContent || status == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("回传结果失败：%s %s", resp.Status, snippet)
		if status == http.StatusUnauthorized || status == http.StatusBadRequest {
			return lastErr // 鉴权/请求本身有问题，重试无意义。
		}
	}
	return lastErr
}

func (c *Client) sendResult(ctx context.Context, res model.Result) error {
	return c.SendResult(ctx, res)
}

// SendProgress 上报实时进度，返回机器人是否要求取消该任务（单次网络错误不阻塞主流程）。
func (c *Client) SendProgress(ctx context.Context, p model.Progress) (bool, error) {
	payload, err := json.Marshal(p)
	if err != nil {
		return false, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/progress", payload)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		var pr model.ProgressResponse
		if err := json.NewDecoder(resp.Body).Decode(&pr); err == nil && pr.Cancel {
			return true, nil
		}
	}
	return false, nil
}

func (c *Client) sendProgress(ctx context.Context, p model.Progress) (bool, error) {
	return c.SendProgress(ctx, p)
}

// Heartbeat 发送轻量保活心跳，更新服务端的 lastSeen 时间戳。
func (c *Client) Heartbeat(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodPost, "/heartbeat", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return model.ErrUnauthorized
	}
	return fmt.Errorf("心跳失败：%s %s", resp.Status, readSnippet(resp.Body))
}

func (c *Client) heartbeat(ctx context.Context) error {
	return c.Heartbeat(ctx)
}

// do 发送一次带鉴权头的请求。
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	token, err := c.tokens.Get()
	if err != nil {
		return nil, err
	}
	endpoint := c.baseURL + path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "mnagent/"+Version)
	req.Header.Set("X-Agent-Version", Version)
	if isp := c.GetISP(); isp != "" {
		req.Header.Set("X-Agent-ISP", isp)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// readSnippet 读取响应片段用于错误提示（不打印可能很长的正文）。
func readSnippet(body io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(body, 512))
	return strings.TrimSpace(string(data))
}
