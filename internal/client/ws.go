package client

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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

	wsJobsCapacity   = 16  // 普通待执行任务缓冲，与低内存设备的既有预算保持一致
	wsCancelCapacity = 256 // 取消指令独立缓冲，不能被普通任务挤占

	wsCancelOverflowCapacity = 1024 // 取消溢出列表硬上限，超限丢弃最旧条目
	wsCancelDropLogEvery     = 100  // 溢出丢弃告警节流：首次及每丢 100 条打一次
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
				// 机器人/反代不支持 WebSocket：明确提示已降级到 HTTP 长轮询，
				// 否则用户只会看到“在线状态时好时坏”而不知道原因。
				wait = wsUnsupportedRetry
				slog.Warn("机器人不支持 WebSocket，已降级为 HTTP 长轮询", "status", status, "retry_in", wait, "error", err)
			case http.StatusUnauthorized:
				wait = time.Minute
				slog.Warn("WebSocket 握手鉴权失败，降级为 HTTP 长轮询", "status", status, "error", err)
			default:
				backoff = min(backoff*2, wsMaxBackoff)
				slog.Debug("WebSocket 连接失败，稍后重试", "status", status, "retry_in", wait, "error", err)
			}
			jitter := time.Duration(rand.Int64N(int64(wait/4) + 1))
			if !sleepCtx(ctx, wait+jitter) {
				return
			}
			continue
		}
		slog.Debug("WebSocket 长连接已建立", "endpoint", c.baseURL+"/ws")
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
	go c.wsRejectLoop(cctx)
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
		if msg.Job.NormalizedKind() == "cancel" {
			// 取消指令绝不能因普通任务队列满被丢弃，也绝不能阻塞读循环：
			// 一旦阻塞，pong/ack 都无法处理，Ping 与结果确认会一起超时。
			c.enqueueWSCancel(msg.Job)
			continue
		}
		select {
		case c.wsJobs <- msg.Job:
		default:
			// 普通任务队列满时读循环绝不阻塞：runner 的 heavyQueue 满时若同步写入，
			// 会让整条 WebSocket 停止读取（连 ping/ack 都无法处理）。队列满时立即
			// 回报明确的失败结果，由独立协程回传。
			c.rejectJob(msg.Job, "节点队列已满，任务未执行，请稍后重试")
		}
	}
}

// rejectJob 把“队列已满”的失败结果投入独立回传队列；该函数不阻塞 WebSocket 读循环。
func (c *Client) rejectJob(job *model.Job, reason string) {
	if job == nil || job.ID == "" {
		return
	}
	res := model.Result{ID: job.ID, Kind: job.NormalizedKind(), ExitCode: -1, Error: reason}
	select {
	case c.wsReject <- res:
	default:
		// 连失败回报都排满时只能丢弃，避免反向阻塞读循环；
		// 但必须留下 Warn 日志，否则任务会静默丢失、无从排查。
		slog.Warn("WebSocket 失败回传队列已满，丢弃任务结果",
			"job", job.ID, "kind", res.Kind, "reason", reason)
	}
}

// stopWSRejectLoop 通知所有回传协程停止取新条目；多次调用安全。
func (c *Client) stopWSRejectLoop() {
	c.wsRejectMu.Lock()
	defer c.wsRejectMu.Unlock()
	c.wsRejectHalt = true
	if c.wsRejectStop != nil {
		close(c.wsRejectStop)
		c.wsRejectStop = nil
	}
}

// waitWSRejectLoops 等待在途回传结束；ctx 到期时返回 false。
// 注意：ctx 到期后这个等待协程会一直留到 WaitGroup 归零才退出（协程里无法中断
// WaitGroup.Wait）。这是有意接受的：回传协程本身受 ctx 约束，会很快结束，
// 因此这里只可能短暂滞留一个协程，不值得为此引入额外的完成信号通道。
func (c *Client) waitWSRejectLoops(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		c.wsRejectWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// wsRejectLoop 串行回传队列满的失败结果，避免大量并发写同一条连接。
// stop 关闭后不再取新条目，但会完成当前在途 SendResult 再退出。
func (c *Client) wsRejectLoop(ctx context.Context) {
	c.wsRejectMu.Lock()
	if c.wsRejectHalt {
		c.wsRejectMu.Unlock()
		return
	}
	stop := c.wsRejectStop
	if stop == nil {
		stop = make(chan struct{})
		c.wsRejectStop = stop
	}
	c.wsRejectWG.Add(1)
	c.wsRejectMu.Unlock()
	defer c.wsRejectWG.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case res := <-c.wsReject:
			c.wsRejectBusy.Add(1)
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			_ = c.SendResult(sctx, res)
			cancel()
			c.wsRejectBusy.Add(-1)
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

// enqueueWSCancel 把取消指令写入独立队列；该函数绝不阻塞 WebSocket 读循环。
// 独立队列满时进入受锁保护的溢出列表；溢出列表达到硬上限后丢弃最旧条目，
// 避免取消指令无界占用内存。普通任务队列不再为取消腾位置，排队任务由
// runner 的 tracker 取消标记在执行前拦截。
func (c *Client) enqueueWSCancel(job *model.Job) {
	if job == nil {
		return
	}
	select {
	case c.wsCancel <- job:
		return
	default:
	}
	c.wsCancelMu.Lock()
	c.wsCancelOverflow = append(c.wsCancelOverflow, job)
	droppedTotal := 0
	droppedID := ""
	if excess := len(c.wsCancelOverflow) - wsCancelOverflowCapacity; excess > 0 {
		if oldest := c.wsCancelOverflow[0]; oldest != nil {
			droppedID = oldest.ID
		}
		for i := 0; i < excess; i++ {
			c.wsCancelOverflow[i] = nil
		}
		c.wsCancelOverflow = c.wsCancelOverflow[excess:]
		c.wsCancelDropped += excess
		droppedTotal = c.wsCancelDropped
	}
	c.wsCancelMu.Unlock()
	if droppedTotal > 0 && (droppedTotal == 1 || droppedTotal%wsCancelDropLogEvery == 0) {
		slog.Warn("取消指令溢出列表达到上限，丢弃最旧条目",
			"job", droppedID, "dropped_total", droppedTotal, "limit", wsCancelOverflowCapacity)
	}
	select {
	case c.wsCancelNotify <- struct{}{}:
	default:
	}
}

// takeWSCancel 非阻塞地取出一条待处理取消指令；没有时返回 nil。
func (c *Client) takeWSCancel() *model.Job {
	select {
	case job := <-c.wsCancel:
		return job
	default:
	}
	c.wsCancelMu.Lock()
	defer c.wsCancelMu.Unlock()
	if len(c.wsCancelOverflow) == 0 {
		return nil
	}
	job := c.wsCancelOverflow[0]
	c.wsCancelOverflow[0] = nil
	c.wsCancelOverflow = c.wsCancelOverflow[1:]
	return job
}

// pollWS 在长连接模式下等待推送的任务。
func (c *Client) pollWS(ctx context.Context) (*model.Job, error) {
	for {
		if job := c.takeWSCancel(); job != nil {
			return job, nil
		}
		timer := time.NewTimer(wsIdlePollWait)
		select {
		case job := <-c.wsCancel:
			timer.Stop()
			return job, nil
		case job := <-c.wsJobs:
			timer.Stop()
			return job, nil
		case <-c.wsCancelNotify:
			// 溢出队列有新取消：立即回头检查，避免等待最多 wsIdlePollWait。
			timer.Stop()
			continue
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
			return nil, nil
		}
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
		c.acks = make(map[string][]chan struct{})
	}
	// 同一 jobID 可能因重试/重发出现多个并发等待者：追加而不是覆盖，
	// 覆盖会让先登记的协程永远等不到 ack（白等到超时）。
	c.acks[res.ID] = append(c.acks[res.ID], ch)
	c.ackMu.Unlock()
	defer c.removeAckWaiter(res.ID, ch)
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

// removeAckWaiter 注销一个 ack 等待者；没有等待者时删除键，避免 map 无限增长。
func (c *Client) removeAckWaiter(id string, ch chan struct{}) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	waiters := c.acks[id]
	for i, w := range waiters {
		if w == ch {
			waiters = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(waiters) == 0 {
		delete(c.acks, id)
		return
	}
	c.acks[id] = waiters
}

func (c *Client) resolveAck(id string) {
	c.ackMu.Lock()
	waiters := c.acks[id]
	delete(c.acks, id)
	c.ackMu.Unlock()
	// 唤醒全部等待者：ack 是针对结果 ID 的，不是针对某一次发送。
	for _, ch := range waiters {
		close(ch)
	}
}

// FailPending 把长连接已推送、但尚未被主循环领取的任务，以及残留在失败回传队列中的
// 结果回报给机器人（进程退出/重启前调用），避免机器人一直等到任务超时。
// 返回成功经 SendResult 回传的条数；ctx 结束后立即停止，并告警剩余未回报条数。
func (c *Client) FailPending(ctx context.Context, reason string) int {
	n := 0
	remaining := len(c.wsJobs) + len(c.wsReject) + int(c.wsRejectBusy.Load())
	warned := false
	warnRemaining := func() {
		if warned {
			return
		}
		warned = true
		// 退出期间可能仍有新任务入队：以“已跟踪数量”和“当前队列实际数量”
		// 的较大值告警，避免漏计。
		if pending := len(c.wsJobs) + len(c.wsReject) + int(c.wsRejectBusy.Load()); pending > remaining {
			remaining = pending
		}
		slog.Warn("退出回报超时，仍有剩余任务未回报", "remaining", remaining)
	}
	decrement := func() {
		if remaining > 0 {
			remaining--
		}
	}
	send := func(res model.Result) {
		if err := c.SendResult(ctx, res); err == nil {
			n++
			decrement()
		}
	}

	// 先让失败回传协程停止取新条目，并等待其在途 SendResult 结束，
	// 否则进程退出会截断它手里最后一条结果。
	c.stopWSRejectLoop()
	if !c.waitWSRejectLoops(ctx) {
		warnRemaining()
		return n
	}
	// 在途结果已处理完，按队列实际内容重新计数。
	remaining = len(c.wsJobs) + len(c.wsReject)

	for {
		if ctx.Err() != nil {
			warnRemaining()
			return n
		}
		// 取消指令无需回传，但必须从独立队列中取走，避免退出前残留。
		if job := c.takeWSCancel(); job != nil {
			continue
		}
		select {
		case job := <-c.wsJobs:
			if job == nil {
				decrement()
				continue
			}
			if job.NormalizedKind() == "cancel" {
				decrement()
				continue
			}
			send(model.Result{ID: job.ID, Kind: job.NormalizedKind(), ExitCode: -1, Error: reason})
		default:
			// wsJobs 已清空，再补发断线后残留在 wsReject 中的失败结果，
			// 避免单连接生命周期结束后这些结果静默丢失。
			for {
				if ctx.Err() != nil {
					warnRemaining()
					return n
				}
				select {
				case res := <-c.wsReject:
					send(res)
				default:
					return n
				}
			}
		}
	}
}
