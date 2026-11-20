package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
)

// Version 是当前客户端版本。
var Version = "dev"

// maxResponseBytes 限制解析响应体时读取的字节数（16MB），支持超大代理配置与多节点订阅的整体下发。
const maxResponseBytes = 16 << 20

// maxResultAttempts 是回传结果的最大尝试次数（结果按任务 ID 幂等，重试安全）。
const maxResultAttempts = 3

// 长轮询为空时的防热循环退避：服务端若立刻返回 204（长轮询未真正挂起），
// 客户端必须自行退避，否则会形成每秒数百次请求的热循环。
const (
	emptyPollFastThreshold = time.Second
	emptyPollMinBackoff    = 200 * time.Millisecond
	emptyPollMaxBackoff    = 500 * time.Millisecond
)

// Client 负责与机器人的 agent 端点通信。
type Client struct {
	baseURL string
	host    string
	tokens  *config.TokenSource
	http    *http.Client
	// results 使用独立客户端：/results 可能上传 16MB，慢速网络下不能沿用长轮询的短超时。
	resultsHTTP        *http.Client
	resultTimeout      time.Duration // 单次上传超时
	resultTotalTimeout time.Duration // 一次 SendResult（含重试）的整体预算

	paused atomic.Bool // 更新期间暂停轮询，避免新旧版本交替领取任务。

	// WebSocket 长连接（可用时优先使用，否则回退 HTTP）
	wsDisabled bool
	wsHTTP     *http.Client
	wsOnce     sync.Once
	ws         atomic.Pointer[websocket.Conn]
	wsJobs     chan *model.Job
	wsReject   chan model.Result // 队列满时的失败结果，由独立协程回传，避免阻塞读循环
	wsAck      atomic.Bool       // 当前连接的机器人是否会确认结果（hello 声明）

	ackMu sync.Mutex
	acks  map[string]chan struct{} // 等待机器人确认的结果 ID
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
	resultTimeout := cfg.ResultTimeout
	if resultTimeout <= 0 {
		resultTimeout = config.DefaultResultTimeout
	}
	// 整体预算默认 6 分钟；用户显式把单次超时调得更大时，整体预算跟随放大，
	// 避免自定义配置被静默截断。
	resultTotalTimeout := config.DefaultResultTotalTimeout
	if resultTimeout > resultTotalTimeout {
		resultTotalTimeout = resultTimeout
	}
	return &Client{
		baseURL: cfg.BotURL,
		tokens:  cfg.Tokens,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.PollTimeout,
		},
		resultsHTTP: &http.Client{
			Transport: transport,
			Timeout:   resultTimeout,
		},
		resultTimeout:      resultTimeout,
		resultTotalTimeout: resultTotalTimeout,
		wsDisabled:         wsDisabledByEnv(),
		wsHTTP:             newWSHTTPClient(),
		wsJobs:             make(chan *model.Job, 16),
		wsReject:           make(chan model.Result, 64),
	}
}

// SetPaused 设置更新暂停状态；暂停时断开长连接，避免机器人继续推送任务。
func (c *Client) SetPaused(paused bool) {
	c.paused.Store(paused)
	if paused {
		if conn := c.ws.Load(); conn != nil {
			_ = conn.Close(websocket.StatusGoingAway, "agent updating")
		}
	}
}

// Poll 领取一个任务；无任务时返回 (nil, nil)。
func (c *Client) Poll(ctx context.Context) (*model.Job, error) {
	if c.paused.Load() {
		return nil, model.ErrUpdating
	}
	c.startWS(ctx)
	// 先取走长连接已推送的任务（含断线前缓冲的）
	select {
	case job := <-c.wsJobs:
		return job, nil
	default:
	}
	if c.WSConnected() {
		return c.pollWS(ctx)
	}
	pollStart := time.Now()
	resp, err := c.do(ctx, http.MethodPost, "/jobs", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		if err := c.waitEmptyPoll(ctx, time.Since(pollStart)); err != nil {
			return nil, err
		}
		return nil, nil
	case http.StatusOK:
		var job model.Job
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&job); err != nil {
			return nil, fmt.Errorf("解析任务失败: %w", err)
		}
		if err := validateJob(&job); err != nil {
			return nil, err
		}
		return &job, nil
	case http.StatusUnauthorized:
		return nil, model.ErrUnauthorized
	default:
		return nil, fmt.Errorf("领取任务失败：%s %s", resp.Status, readSnippet(resp.Body))
	}
}

// waitEmptyPoll 在服务端“立即返回空任务”时加入 200-500ms 抖动退避，避免热循环。
// 真正的长轮询（请求本身已等待 ≥1s）不需要额外等待。
func (c *Client) waitEmptyPoll(ctx context.Context, elapsed time.Duration) error {
	if elapsed >= emptyPollFastThreshold {
		return nil
	}
	wait := emptyPollMinBackoff + time.Duration(rand.Int64N(int64(emptyPollMaxBackoff-emptyPollMinBackoff)+1))
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// validateJob 校验任务必需字段。
func validateJob(job *model.Job) error {
	if strings.TrimSpace(job.ID) == "" {
		return errors.New("任务缺少必需字段 ID")
	}
	if job.NormalizedKind() != "cancel" && strings.TrimSpace(job.Target) == "" {
		return errors.New("任务缺少必需字段 Target")
	}
	return nil
}

func (c *Client) poll(ctx context.Context) (*model.Job, error) {
	return c.Poll(ctx)
}

// SendResult 回传执行结果，失败时按退避重试。
func (c *Client) SendResult(ctx context.Context, res model.Result) error {
	if c.WSConnected() && c.sendResultWS(ctx, res) {
		return nil
	}
	payload, err := json.Marshal(res)
	if err != nil {
		return err
	}
	// 整体 deadline：最多 maxResultAttempts 次，但总耗时不超过 resultTotalTimeout，
	// 避免“3 次 × 单次 4 分钟”在慢速网络下把任务回传拖到十几分钟。
	totalCtx, cancelTotal := context.WithTimeout(ctx, c.resultTotalTimeout)
	defer cancelTotal()
	var lastErr error
	for attempt := 1; attempt <= maxResultAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-totalCtx.Done():
				return totalCtx.Err()
			case <-time.After(time.Duration(attempt-1) * time.Second):
			}
		}
		// 每次上传单独限时：结果体可达 16MB，慢速网络需要远长于长轮询的时限。
		// 单次超时同时受整体 deadline 约束。
		attemptCtx, cancel := context.WithTimeout(totalCtx, c.resultTimeout)
		resp, err := c.doWith(c.resultsHTTP, attemptCtx, http.MethodPost, "/results", payload)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		status := resp.StatusCode
		snippet := readSnippet(resp.Body)
		resp.Body.Close()
		cancel()
		if status == http.StatusNoContent || status == http.StatusOK {
			return nil
		}
		if status == http.StatusRequestEntityTooLarge {
			// 结果体超过机器人上限：重试只会再被拒一次，直接给出可诊断的明确错误。
			return fmt.Errorf("回传结果被机器人拒绝：结果体积超过上限（413 %s），请减少测速节点数或升级机器人", snippet)
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
// 长连接模式下取消指令由机器人主动推送，这里固定返回 false。
func (c *Client) SendProgress(ctx context.Context, p model.Progress) (bool, error) {
	if c.wsSend(ctx, wsMessage{Type: "progress", Progress: &p}) == nil {
		return false, nil
	}
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
// 长连接在线时无需心跳（连接本身即在线状态），直接返回。
func (c *Client) Heartbeat(ctx context.Context) error {
	if c.WSConnected() {
		return nil
	}
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

// do 发送一次带鉴权头的请求（长轮询等短请求共用默认客户端）。
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	return c.doWith(c.http, ctx, method, path, body)
}

// doWith 使用指定 HTTP 客户端发送一次带鉴权头的请求。
func (c *Client) doWith(cli *http.Client, ctx context.Context, method, path string, body []byte) (*http.Response, error) {
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return cli.Do(req)
}

// readSnippet 读取响应片段用于错误提示（不打印可能很长的正文）。
func readSnippet(body io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(body, 512))
	return strings.TrimSpace(string(data))
}
