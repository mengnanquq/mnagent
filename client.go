package main

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
)

// errUnauthorized 表示机器人拒绝了令牌，通常意味着配置错误或令牌已轮换。
var errUnauthorized = errors.New("接入令牌被拒绝（请检查 /host 配置与本机令牌是否一致）")

// errUpdating 表示正在应用自动更新，暂停轮询。
var errUpdating = errors.New("正在应用更新")

// Job 是机器人下发的探测任务，字段与机器人侧 internal/agent 的 Job 保持一致。
//
// Kind 决定执行方式：空/"trace" 走 nexttrace；"miaospeed"/"speed" 走 miaospeed 代理测速；
// "ping"/"tcping"/"http"/"dns" 由本进程内的探针实现（不依赖外部二进制）。
type Job struct {
	ID        string `json:"id"`
	Kind      string `json:"kind,omitempty"`
	Target    string `json:"target"`
	Hops      int    `json:"hops,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Count     int    `json:"count,omitempty"`
	Query     string `json:"query,omitempty"`
	TimeoutMS int64  `json:"timeout_ms"`
}

// 任务超时的夹取区间（测试中可覆盖）。
var (
	jobMinTimeout = 5 * time.Second
	jobMaxTimeout = 10 * time.Minute
)

// Timeout 返回任务执行超时，并夹在合理区间内，避免异常值让进程挂死或秒退。
func (j Job) Timeout() time.Duration {
	timeout := time.Duration(j.TimeoutMS) * time.Millisecond
	if timeout < jobMinTimeout {
		timeout = jobMinTimeout
	}
	if timeout > jobMaxTimeout {
		timeout = jobMaxTimeout
	}
	return timeout
}

// Result 是回传给机器人的执行结果，字段与机器人侧 internal/agent 的 Result 保持一致。
// Data 携带结构化探针结果（ping/tcping/http/dns），由机器人负责排版展示。
type Result struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind,omitempty"`
	Output   string          `json:"output"`
	ExitCode int             `json:"exit_code"`
	Error    string          `json:"error,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// maxResponseBytes 限制解析响应体时读取的字节数。
const maxResponseBytes = 1 << 20

// maxResultAttempts 是回传结果的最大尝试次数（结果按任务 ID 幂等，重试安全）。
const maxResultAttempts = 3

// client 负责与机器人的 agent 端点通信。
type client struct {
	baseURL string
	host    string
	tokens  *tokenSource
	http    *http.Client

	paused atomic.Bool // 更新期间暂停轮询，避免新旧版本交替领取任务。
}

// newClient 构建通信客户端；轮询超时略大于机器人侧的长轮询保持时间。
func newClient(cfg *config) *client {
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
	return &client{
		baseURL: cfg.botURL,
		tokens:  cfg.tokens,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.pollTimeout,
		},
	}
}

// poll 领取一个任务；无任务时返回 (nil, nil)。
func (c *client) poll(ctx context.Context) (*Job, error) {
	if c.paused.Load() {
		return nil, errUpdating
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
		var job Job
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&job); err != nil {
			return nil, fmt.Errorf("解析任务失败: %w", err)
		}
		if strings.TrimSpace(job.ID) == "" || strings.TrimSpace(job.Target) == "" {
			return nil, errors.New("任务缺少必需字段")
		}
		return &job, nil
	case http.StatusUnauthorized:
		return nil, errUnauthorized
	default:
		return nil, fmt.Errorf("领取任务失败：%s %s", resp.Status, readSnippet(resp.Body))
	}
}

// sendResult 回传执行结果，失败时按退避重试。
func (c *client) sendResult(ctx context.Context, res Result) error {
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

// do 发送一次带鉴权头的请求。
func (c *client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	token, err := c.tokens.get()
	if err != nil {
		return nil, err
	}
	// 不再附带 host 参数：机器人按令牌识别是哪台主机。
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
	req.Header.Set("User-Agent", "mnagent/"+version)
	req.Header.Set("X-Agent-Version", version)
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
