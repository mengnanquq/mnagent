package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/mengnanquq/mnagent/internal/model"
)

// 既有 HTTP 用例默认关闭 WebSocket，避免测试服务器收到 /ws 握手。
func TestMain(m *testing.M) {
	os.Setenv("MNAGENT_DISABLE_WS", "1")
	os.Exit(m.Run())
}

func newWSClient(url string) *Client {
	cli := New(testConfig(url, nil))
	cli.wsDisabled = false
	return cli
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// TestRejectJobFullQueueLogsWarning 验证 wsReject 队列满时丢弃结果会留下 Warn 日志，
// 而不是静默丢任务。
func TestRejectJobFullQueueLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	c := &Client{wsReject: make(chan model.Result, 1)}
	c.rejectJob(&model.Job{ID: "j1", Kind: "trace"}, "队列已满")
	c.rejectJob(&model.Job{ID: "j2", Kind: "trace"}, "队列已满")

	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "j2") {
		t.Fatalf("队列满丢弃时应打印包含任务 ID 的 Warn 日志，实际：%q", logged)
	}
}

// TestClientWSRoundTrip 覆盖：建立长连接 → 接收推送任务 → 进度/结果走长连接 → 心跳免发。
func TestClientWSRoundTrip(t *testing.T) {
	got := make(chan wsMessage, 8)
	var httpHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			httpHits.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := r.Context()
		job, _ := json.Marshal(wsMessage{Type: "job", Job: &model.Job{ID: "j1", Target: "1.1.1.1"}})
		_ = conn.Write(ctx, websocket.MessageText, job)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var msg wsMessage
			_ = json.Unmarshal(data, &msg)
			got <- msg
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)

	var job *model.Job
	waitFor(t, "收到推送任务", func() bool {
		j, err := cli.Poll(ctx)
		if err != nil {
			t.Fatalf("Poll 失败: %v", err)
		}
		job = j
		return j != nil
	})
	if job.ID != "j1" {
		t.Fatalf("任务异常: %+v", job)
	}
	if !cli.WSConnected() {
		t.Fatal("应处于长连接模式")
	}

	if cancelled, err := cli.SendProgress(ctx, model.Progress{ID: "j1", Current: 1, Total: 2}); err != nil || cancelled {
		t.Fatalf("SendProgress 异常: %v %v", cancelled, err)
	}
	if err := cli.SendResult(ctx, model.Result{ID: "j1", Output: "out"}); err != nil {
		t.Fatalf("SendResult 失败: %v", err)
	}
	before := httpHits.Load()
	if err := cli.Heartbeat(ctx); err != nil {
		t.Fatalf("Heartbeat 失败: %v", err)
	}
	if httpHits.Load() != before {
		t.Fatal("长连接模式下心跳不应发 HTTP 请求")
	}

	var types []string
	for len(types) < 2 {
		select {
		case m := <-got:
			if m.Type == "meta" {
				continue
			}
			types = append(types, m.Type)
			if m.Type == "result" && (m.Result == nil || m.Result.Output != "out") {
				t.Fatalf("结果异常: %+v", m)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("服务端未收到消息，已收到: %v", types)
		}
	}
	if types[0] != "progress" || types[1] != "result" {
		t.Fatalf("消息顺序异常: %v", types)
	}

	cli.SetPaused(true)
	waitFor(t, "暂停后断开长连接", func() bool { return !cli.WSConnected() })
}

// TestClientWSFallbackToHTTP 验证机器人不支持 /ws 时回退 HTTP 长轮询。
func TestClientWSFallbackToHTTP(t *testing.T) {
	var jobsHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			jobsHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.Job{ID: "h1", Target: "8.8.8.8"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	job, err := cli.Poll(ctx)
	if err != nil || job == nil || job.ID != "h1" {
		t.Fatalf("HTTP 回退失败: job=%+v err=%v", job, err)
	}
	if cli.WSConnected() {
		t.Fatal("不支持 /ws 时不应处于长连接模式")
	}
	if jobsHits.Load() == 0 {
		t.Fatal("应通过 /jobs 领取任务")
	}
}

// TestClientWSResultAck 验证：机器人确认的结果不走 HTTP；未确认的结果超时后改走 HTTP 重发；
// 退出前未领取的推送任务会被回报为失败。
func TestClientWSResultAck(t *testing.T) {
	// 等待 ack 的超时是功能本身的一部分，不能去掉；但传 200ms 时一次调度抖动就会把
	// “已确认”误判为“未确认”。这里放宽到 2s，ack 是进程内回包，正常远小于 1s。
	old := wsAckTimeout
	wsAckTimeout = 2 * time.Second
	defer func() { wsAckTimeout = old }()

	var httpResults atomic.Int32
	wsResults := make(chan model.Result, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/results" {
			httpResults.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/ws" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := r.Context()
		send := func(m wsMessage) {
			b, _ := json.Marshal(m)
			_ = conn.Write(ctx, websocket.MessageText, b)
		}
		send(wsMessage{Type: "hello", Features: []string{"ack"}})
		send(wsMessage{Type: "job", Job: &model.Job{ID: "p1", Target: "1.1.1.1"}})
		send(wsMessage{Type: "job", Job: &model.Job{ID: "c1", Kind: "cancel"}})
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m wsMessage
			_ = json.Unmarshal(data, &m)
			if m.Type != "result" || m.Result == nil {
				continue
			}
			wsResults <- *m.Result
			if m.Result.ID != "lost" {
				send(wsMessage{Type: "ack", ID: m.Result.ID})
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	cli.startWS(ctx)
	waitFor(t, "建立长连接并收到 hello", func() bool { return cli.WSConnected() && cli.wsAck.Load() })
	waitFor(t, "推送任务进入缓冲", func() bool { return len(cli.wsJobs) == 2 })

	if err := cli.SendResult(ctx, model.Result{ID: "ok"}); err != nil {
		t.Fatalf("SendResult 失败: %v", err)
	}
	if httpResults.Load() != 0 {
		t.Fatal("已确认的结果不应再走 HTTP")
	}
	if err := cli.SendResult(ctx, model.Result{ID: "lost"}); err != nil {
		t.Fatalf("SendResult 失败: %v", err)
	}
	if httpResults.Load() != 1 {
		t.Fatalf("未确认的结果应改走 HTTP 重发，实际 %d 次", httpResults.Load())
	}

	if n := cli.FailPending(ctx, "restarting"); n != 1 {
		t.Fatalf("应回报 1 个未执行任务（取消指令除外），实际 %d", n)
	}
	for {
		select {
		case r := <-wsResults:
			if r.ID == "p1" {
				if r.ExitCode != -1 || r.Error != "restarting" {
					t.Fatalf("未执行任务回报异常: %+v", r)
				}
				return
			}
		case <-time.After(2 * time.Second):
			t.Fatal("机器人未收到未执行任务的失败回报")
		}
	}
}

// TestClientWSQueueFullRejectsWithoutBlockingReadLoop 验证 wsJobs 满时读循环不会卡住，
// 而是立即经独立协程回报“节点队列已满”的失败结果。
func TestClientWSQueueFullRejectsWithoutBlockingReadLoop(t *testing.T) {
	results := make(chan model.Result, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := r.Context()
		for i := 1; i <= 3; i++ {
			b, _ := json.Marshal(wsMessage{Type: "job", Job: &model.Job{ID: fmt.Sprintf("q%d", i), Target: "1.1.1.1"}})
			if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
				return
			}
		}
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m wsMessage
			_ = json.Unmarshal(data, &m)
			if m.Type == "result" && m.Result != nil {
				results <- *m.Result
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	cli.wsJobs = make(chan *model.Job, 1) // 只容纳 1 个，后续立即触发背压

	cli.startWS(ctx)
	want := map[string]bool{"q2": true, "q3": true}
	deadline := time.After(3 * time.Second)
	for len(want) > 0 {
		select {
		case res := <-results:
			if !want[res.ID] {
				t.Fatalf("不应为任务 %s 回报失败: %+v", res.ID, res)
			}
			delete(want, res.ID)
			if res.ExitCode != -1 || !strings.Contains(res.Error, "节点队列已满") {
				t.Fatalf("队列满的失败结果异常: %+v", res)
			}
		case <-deadline:
			t.Fatalf("读循环被阻塞，未及时回报队列满: 剩余 %v", want)
		}
	}
	if got := len(cli.wsJobs); got != 1 {
		t.Fatalf("wsJobs 应只保留 1 个任务，实际 %d", got)
	}
}

// syncBuffer 是并发安全的日志缓冲，供后台协程写、测试轮询读。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestWSFallbackLogsWarn 验证机器人不支持 WebSocket 时会输出降级告警日志，
// 方便用户排查“为什么一直在走 HTTP 长轮询”。
// 用轮询日志代替固定 200ms ctx：只要降级告警出现就取消，慢机器上不会误判。
func TestWSFallbackLogsWarn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := newWSClient(srv.URL)
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cli.wsLoop(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "降级") {
		if time.Now().After(deadline) {
			t.Fatalf("WS 降级应输出 Warn 日志，实际日志：%s", buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消上下文后 wsLoop 未及时退出")
	}

	out := buf.String()
	if !strings.Contains(out, "WebSocket") {
		t.Fatalf("WS 降级日志应包含 WebSocket，实际日志：%s", out)
	}
}
