package client

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/mengnanquq/mnagent/internal/model"
)

// WebSocket 长连接传输：任务推送、进度、结果、取消走同一条连接，机器人据连接状态实时判定在线。
// 连接不可用（旧版机器人、反代未开启 WebSocket、网络异常）时自动回退到 HTTP 长轮询 + 心跳。

const (
	wsPingInterval     = 20 * time.Second
	wsPingTimeout      = 10 * time.Second
	wsWriteTimeout     = 15 * time.Second
	wsHandshakeTimeout = 15 * time.Second
	wsMaxBackoff       = 30 * time.Second
	wsUnsupportedRetry = 10 * time.Minute // 机器人不支持 WebSocket 时，隔一段时间再探测（适配机器人升级）
	wsIdlePollWait     = 5 * time.Second  // 长连接模式下 Poll 单次等待上限，便于及时感知断线并回退
)

// wsAckTimeout 是等待机器人确认结果的上限，超时改走 HTTP 重发（测试中会缩短）。
var wsAckTimeout = 10 * time.Second

var errNoWS = errors.New("websocket 未连接")

// wsMessage 与机器人侧 internal/agent 的消息信封保持一致。
type wsMessage struct {
	Type     string          `json:"type"`
	ID       string          `json:"id,omitempty"`       // ack：机器人已收到的结果 ID
	Features []string        `json:"features,omitempty"` // hello：机器人支持的协议特性
	Job      *model.Job      `json:"job,omitempty"`
	Result   *model.Result   `json:"result,omitempty"`
	Progress *model.Progress `json:"progress,omitempty"`
}

func wsDisabledByEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("MNAGENT_DISABLE_WS")))
	return v == "1" || v == "true" || v == "yes"
}

func newWSHTTPClient() *http.Client {
	// WebSocket 握手只能走 HTTP/1.1，单独使用不协商 h2 的传输层
	return &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}}
}

// WSConnected 返回当前是否通过 WebSocket 长连接与机器人通信。
func (c *Client) WSConnected() bool {
	return c.ws.Load() != nil
}

// startWS 在首次 Poll 时启动长连接维护协程（生命周期跟随 agent 主循环）。
func (c *Client) startWS(ctx context.Context) {
	if c.wsDisabled {
		return
	}
	c.wsOnce.Do(func() { go c.wsLoop(ctx) })
}

func (c *Client) wsLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if c.paused.Load() {
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		conn, status, err := c.dialWS(ctx)
		if err != nil {
			wait := backoff
			switch status {
			case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusBadRequest, http.StatusUpgradeRequired:
				wait = wsUnsupportedRetry
			case http.StatusUnauthorized:
				wait = time.Minute
			default:
				backoff = min(backoff*2, wsMaxBackoff)
			}
			jitter := time.Duration(rand.Int64N(int64(wait/4) + 1))
			if !sleepCtx(ctx, wait+jitter) {
				return
			}
			continue
		}
		started := time.Now()
		c.serveWS(ctx, conn)
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
	}
}

func (c *Client) dialWS(ctx context.Context) (*websocket.Conn, int, error) {
	token, err := c.tokens.Get()
	if err != nil {
		return nil, 0, err
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	h.Set("User-Agent", "mnagent/"+Version)
	h.Set("X-Agent-Version", Version)
	dctx, cancel := context.WithTimeout(ctx, wsHandshakeTimeout)
	defer cancel()
	conn, resp, err := websocket.Dial(dctx, c.baseURL+"/ws", &websocket.DialOptions{
		HTTPClient:      c.wsHTTP,
		HTTPHeader:      h,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return nil, status, err
	}
	conn.SetReadLimit(maxResponseBytes)
	return conn, http.StatusSwitchingProtocols, nil
}

// serveWS 处理一条已建立的连接，直到断开。
func (c *Client) serveWS(ctx context.Context, conn *websocket.Conn) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.wsAck.Store(false) // 等机器人 hello 声明支持后再启用结果确认
	c.ws.Store(conn)
	defer func() {
		c.ws.CompareAndSwap(conn, nil)
		if ctx.Err() != nil {
			_ = conn.Close(websocket.StatusGoingAway, "agent shutdown")
		} else {
			_ = conn.CloseNow()
		}
	}()

	go func() {
		ticker := time.NewTicker(wsPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-cctx.Done():
				return
			case <-ticker.C:
				if c.paused.Load() {
					cancel() // 更新期间断开，避免机器人继续推送任务
					return
				}
				pctx, pcancel := context.WithTimeout(cctx, wsPingTimeout)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()

	for {
		_, data, err := conn.Read(cctx)
		if err != nil {
			return
		}
		var msg wsMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "hello":
			c.wsAck.Store(slices.Contains(msg.Features, "ack"))
			continue
		case "ack":
			c.resolveAck(msg.ID)
			continue
		case "job":
		default:
			continue
		}
		if msg.Job == nil {
			continue
		}
		if err := validateJob(msg.Job); err != nil {
			continue
		}
		select {
		case c.wsJobs <- msg.Job:
		case <-cctx.Done():
			return
		}
	}
}

// wsSend 通过长连接发送一条消息；未连接时返回 errNoWS。
func (c *Client) wsSend(ctx context.Context, msg wsMessage) error {
	conn := c.ws.Load()
	if conn == nil {
		return errNoWS
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
	defer cancel()
	if err := conn.Write(wctx, websocket.MessageText, data); err != nil {
		_ = conn.CloseNow()
		return err
	}
	return nil
}

// pollWS 在长连接模式下等待推送的任务。
func (c *Client) pollWS(ctx context.Context) (*model.Job, error) {
	timer := time.NewTimer(wsIdlePollWait)
	defer timer.Stop()
	select {
	case job := <-c.wsJobs:
		return job, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, nil
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// sendResultWS 通过长连接回传结果，返回机器人是否已确认收到。
// 机器人支持 ack 时等待确认，超时视为未送达（由调用方改走 HTTP 重发，结果按 ID 幂等）；
// 旧版机器人不支持 ack，写入成功即视为送达。
func (c *Client) sendResultWS(ctx context.Context, res model.Result) bool {
	if !c.wsAck.Load() {
		return c.wsSend(ctx, wsMessage{Type: "result", Result: &res}) == nil
	}
	ch := make(chan struct{})
	c.ackMu.Lock()
	if c.acks == nil {
		c.acks = make(map[string]chan struct{})
	}
	c.acks[res.ID] = ch
	c.ackMu.Unlock()
	defer func() {
		c.ackMu.Lock()
		if c.acks[res.ID] == ch {
			delete(c.acks, res.ID)
		}
		c.ackMu.Unlock()
	}()
	if c.wsSend(ctx, wsMessage{Type: "result", Result: &res}) != nil {
		return false
	}
	timer := time.NewTimer(wsAckTimeout)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (c *Client) resolveAck(id string) {
	c.ackMu.Lock()
	ch, ok := c.acks[id]
	if ok {
		delete(c.acks, id)
	}
	c.ackMu.Unlock()
	if ok {
		close(ch)
	}
}

// FailPending 把长连接已推送、但尚未被主循环领取的任务回报为失败（进程退出/重启前调用），
// 避免机器人一直等到任务超时。返回回报的任务数。
func (c *Client) FailPending(ctx context.Context, reason string) int {
	n := 0
	for {
		select {
		case job := <-c.wsJobs:
			if job == nil || job.Kind == "cancel" {
				continue
			}
			_ = c.SendResult(ctx, model.Result{ID: job.ID, Kind: job.Kind, ExitCode: -1, Error: reason})
			n++
		default:
			return n
		}
	}
}
