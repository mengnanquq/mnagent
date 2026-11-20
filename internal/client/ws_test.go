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

// TestRejectJobNormalizesKind 验证失败结果中的 Kind 使用归一化后的任务类型。
func TestRejectJobNormalizesKind(t *testing.T) {
	c := &Client{wsReject: make(chan model.Result, 2)}
	c.rejectJob(&model.Job{ID: "j1", Kind: "  MiaoSpeed  "}, "队列已满")
	c.rejectJob(&model.Job{ID: "j2"}, "队列已满")

	want := []struct {
		id   string
		kind string
	}{{"j1", "miaospeed"}, {"j2", "trace"}}
	for _, w := range want {
		select {
		case res := <-c.wsReject:
			if res.ID != w.id || res.Kind != w.kind {
				t.Fatalf("失败结果 Kind 未归一化，期望 %s/%s，实际: %+v", w.id, w.kind, res)
			}
		default:
			t.Fatalf("缺少任务 %s 的失败结果", w.id)
		}
	}
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
	waitFor(t, "推送任务与取消分别进入缓冲", func() bool { return len(cli.wsJobs) == 1 && len(cli.wsCancel) == 1 })

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

// TestFailPendingDrainsRejectAndCountsSuccessfulSends 验证退出前会补发残留在 wsReject
// 中的失败结果、归一化排队任务的 Kind，并且只统计 SendResult 成功的条数。
func TestFailPendingDrainsRejectAndCountsSuccessfulSends(t *testing.T) {
	var mu sync.Mutex
	received := make(map[string]model.Result)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var res model.Result
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			t.Errorf("解析结果失败: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if res.ID == "reject-bad" {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received[res.ID] = res
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cli := New(testConfig(srv.URL, nil))
	cli.wsJobs = make(chan *model.Job, 2)
	cli.wsJobs <- &model.Job{ID: "queued", Kind: "  PING  "}
	cli.wsReject = make(chan model.Result, 2)
	cli.wsReject <- model.Result{ID: "reject-ok", Kind: "miaospeed"}
	cli.wsReject <- model.Result{ID: "reject-bad", Kind: "trace"}

	if n := cli.FailPending(context.Background(), "restarting"); n != 2 {
		t.Fatalf("应成功回报排队任务与可回传的残留结果共 2 条，实际 %d", n)
	}
	if len(cli.wsJobs) != 0 || len(cli.wsReject) != 0 {
		t.Fatalf("FailPending 应清空两个队列，剩余 jobs=%d reject=%d", len(cli.wsJobs), len(cli.wsReject))
	}
	mu.Lock()
	queued, ok := received["queued"]
	_, rejectOK := received["reject-ok"]
	mu.Unlock()
	if !ok || queued.Kind != "ping" || queued.ExitCode != -1 || queued.Error != "restarting" {
		t.Fatalf("排队任务的回报异常: %+v", queued)
	}
	if !rejectOK {
		t.Fatal("wsReject 中成功的残留结果未被补发")
	}

	cli.wsJobs <- &model.Job{ID: "still-queued", Kind: "trace"}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n := cli.FailPending(cctx, "restarting"); n != 0 {
		t.Fatalf("ctx 已结束时应立即停止回报，实际 %d", n)
	}
	if len(cli.wsJobs) != 1 {
		t.Fatalf("ctx 结束后不应继续清空队列，剩余 %d", len(cli.wsJobs))
	}
}

// TestFailPendingWaitsForInFlightRejectLoop 验证 FailPending 会先让 wsRejectLoop
// 停止取新条目并等待其在途 SendResult 结束，避免进程退出截断最后一条结果。
// 与 -race 一起运行时覆盖两个协程并发访问回传队列/停止信号的场景。
func TestFailPendingWaitsForInFlightRejectLoop(t *testing.T) {
	var mu sync.Mutex
	received := make(map[string]bool)
	started := make(chan string, 4)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var res model.Result
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			t.Errorf("解析结果失败: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		received[res.ID] = true
		mu.Unlock()
		started <- res.ID
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cli := New(testConfig(srv.URL, nil))
	cli.wsReject = make(chan model.Result, 4)
	cli.wsReject <- model.Result{ID: "inflight", Kind: "trace"}
	cli.wsReject <- model.Result{ID: "queued", Kind: "trace"}
	loopCtx, loopCancel := context.WithCancel(context.Background())
	defer loopCancel()
	go cli.wsRejectLoop(loopCtx)

	select {
	case id := <-started:
		if id != "inflight" {
			t.Fatalf("回传顺序异常，首个结果应为 inflight，实际 %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("wsRejectLoop 未开始回传")
	}

	failDone := make(chan int, 1)
	go func() { failDone <- cli.FailPending(context.Background(), "exit") }()

	// 等 FailPending 已发出停止信号，确保后续由它而不是 reject loop 取走剩余条目。
	waitFor(t, "FailPending 通知回传协程停止", func() bool {
		cli.wsRejectMu.Lock()
		defer cli.wsRejectMu.Unlock()
		return cli.wsRejectStop == nil
	})
	select {
	case n := <-failDone:
		t.Fatalf("FailPending 在在途回传结束前返回（n=%d）", n)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case n := <-failDone:
		if n != 1 {
			t.Fatalf("在途结果结束后应补发剩余 1 条，实际 %d", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FailPending 未在在途回传结束后返回")
	}

	mu.Lock()
	inflightOK, queuedOK := received["inflight"], received["queued"]
	mu.Unlock()
	if !inflightOK || !queuedOK {
		t.Fatalf("结果被截断：inflight=%v queued=%v", inflightOK, queuedOK)
	}
}

// TestFailPendingWarnsRemainingOnContextExpiry 验证退出预算耗尽时只告警一次，
// 并带上仍未回报的条数。
func TestFailPendingWarnsRemainingOnContextExpiry(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	c := &Client{
		wsJobs:   make(chan *model.Job, 2),
		wsReject: make(chan model.Result, 2),
	}
	c.wsJobs <- &model.Job{ID: "job-1", Kind: "trace", Target: "1.1.1.1"}
	c.wsReject <- model.Result{ID: "res-1", Kind: "trace"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n := c.FailPending(ctx, "exit"); n != 0 {
		t.Fatalf("ctx 已结束时应停止回报，实际成功 %d 条", n)
	}

	logged := buf.String()
	if got := strings.Count(logged, "退出回报超时"); got != 1 {
		t.Fatalf("ctx 到期应只告警一次，实际 %d 次：%s", got, logged)
	}
	if !strings.Contains(logged, "remaining=2") {
		t.Fatalf("告警应包含剩余未回报条数 2，实际：%s", logged)
	}
}

// TestClientWSCancelKindNormalized 验证 " Cancel " 这类带空白/大小写的 Kind
// 也能通过校验并进入取消队列，而不是普通任务队列。
func TestClientWSCancelKindNormalized(t *testing.T) {
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
		b, _ := json.Marshal(wsMessage{Type: "job", Job: &model.Job{ID: "c1", Kind: "  Cancel  "}})
		if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
			return
		}
		<-ctx.Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	cli.startWS(ctx)
	waitFor(t, "归一化后的取消指令进入独立队列", func() bool {
		return len(cli.wsCancel) == 1 && len(cli.wsJobs) == 0
	})
	if job := cli.takeWSCancel(); job == nil || job.ID != "c1" {
		t.Fatalf("取消指令未正确入队: %+v", job)
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

// TestClientWSCancelNeverDroppedWhenQueueFull 验证取消指令不会因普通任务队列已满
// 被丢弃或阻塞：它进入独立队列，并由 Poll 优先领取。
func TestClientWSCancelNeverDroppedWhenQueueFull(t *testing.T) {
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
		for _, job := range []*model.Job{
			{ID: "busy", Target: "1.1.1.1"},
			{ID: "cancel-me", Kind: "cancel"},
			{ID: "cancel-me-too", Kind: "cancel"},
		} {
			b, _ := json.Marshal(wsMessage{Type: "job", Job: job})
			if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
				return
			}
		}
		<-ctx.Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	cli.wsJobs = make(chan *model.Job, 1)
	cli.startWS(ctx)

	waitFor(t, "普通任务填满队列且两条取消进入独立队列", func() bool {
		return len(cli.wsJobs) == 1 && len(cli.wsCancel) == 2
	})
	for _, want := range []string{"cancel-me", "cancel-me-too"} {
		got, err := cli.Poll(ctx)
		if err != nil {
			t.Fatalf("Poll 取消指令失败: %v", err)
		}
		if got == nil || got.Kind != "cancel" || got.ID != want {
			t.Fatalf("队列满时应优先领取取消指令 %s，实际: %+v", want, got)
		}
	}
	got, err := cli.Poll(ctx)
	if err != nil {
		t.Fatalf("Poll 普通任务失败: %v", err)
	}
	if got == nil || got.ID != "busy" {
		t.Fatalf("取消指令处理后应领取保留的普通任务，实际: %+v", got)
	}
}

// TestClientWSReadLoopContinuesAfterQueueFullCancel 验证普通任务队列与取消队列都
// 经历满/溢出后，读循环仍能继续处理后续的 cancel 与 result ack，而不是卡在投递上。
func TestClientWSReadLoopContinuesAfterQueueFullCancel(t *testing.T) {
	var httpResults atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/results":
			httpResults.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		case "/ws":
		default:
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
		for i := 1; i <= 3; i++ {
			send(wsMessage{Type: "job", Job: &model.Job{ID: fmt.Sprintf("q%d", i), Target: "1.1.1.1"}})
		}
		send(wsMessage{Type: "job", Job: &model.Job{ID: "c1", Kind: "cancel"}})
		send(wsMessage{Type: "job", Job: &model.Job{ID: "c2", Kind: "cancel"}})
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m wsMessage
			_ = json.Unmarshal(data, &m)
			if m.Type != "result" || m.Result == nil || m.Result.ID != "probe" {
				continue
			}
			// 在 ack 前后各塞一条取消，确保读循环没有被前面的满队列/取消卡住。
			send(wsMessage{Type: "job", Job: &model.Job{ID: "c3", Kind: "cancel"}})
			send(wsMessage{Type: "ack", ID: "probe"})
			send(wsMessage{Type: "job", Job: &model.Job{ID: "c4", Kind: "cancel"}})
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cli := newWSClient(srv.URL)
	cli.wsJobs = make(chan *model.Job, 1)
	cli.startWS(ctx)
	waitFor(t, "取消指令进入独立队列", func() bool { return len(cli.wsCancel) == 2 })

	if err := cli.SendResult(ctx, model.Result{ID: "probe"}); err != nil {
		t.Fatalf("读循环阻塞导致 result 未送达: %v", err)
	}
	if httpResults.Load() != 0 {
		t.Fatal("机器人已 ack 的结果不应回退 HTTP 重发")
	}
	waitFor(t, "ack 后的后续取消仍被读循环处理", func() bool { return len(cli.wsCancel) >= 4 })
}

// TestClientWSCancelOverflowKeepsQueuedJobs 验证取消通道满时进入溢出队列，
// 但不再为取消指令淘汰无关的普通排队任务。
func TestClientWSCancelOverflowKeepsQueuedJobs(t *testing.T) {
	c := &Client{
		wsJobs:         make(chan *model.Job, 1),
		wsCancel:       make(chan *model.Job, 1),
		wsCancelNotify: make(chan struct{}, 1),
		wsReject:       make(chan model.Result, 4),
	}
	c.wsCancel <- &model.Job{ID: "cancel-1", Kind: "cancel"}
	c.wsJobs <- &model.Job{ID: "busy", Kind: "trace", Target: "1.1.1.1"}
	c.enqueueWSCancel(&model.Job{ID: "cancel-2", Kind: "cancel"})
	c.enqueueWSCancel(&model.Job{ID: "cancel-3", Kind: "cancel"})

	select {
	case res := <-c.wsReject:
		t.Fatalf("取消指令溢出不应淘汰普通任务，实际回报: %+v", res)
	default:
	}
	select {
	case job := <-c.wsJobs:
		if job == nil || job.ID != "busy" {
			t.Fatalf("普通排队任务不应被淘汰，实际: %+v", job)
		}
	default:
		t.Fatal("普通排队任务不应被淘汰")
	}
	for _, want := range []string{"cancel-1", "cancel-2", "cancel-3"} {
		got := c.takeWSCancel()
		if got == nil || got.ID != want {
			t.Fatalf("取消指令丢失或顺序异常，期望 %s，实际: %+v", want, got)
		}
	}
	if got := c.takeWSCancel(); got != nil {
		t.Fatalf("不应残留取消指令，实际: %+v", got)
	}
}

// TestWSCancelOverflowBounded 验证取消溢出列表有硬上限，超限丢弃最旧条目，
// 并只在首次及每丢 100 条时打印告警。
func TestWSCancelOverflowBounded(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	c := &Client{
		wsJobs:         make(chan *model.Job, 1),
		wsCancel:       make(chan *model.Job, 1),
		wsCancelNotify: make(chan struct{}, 1),
		wsReject:       make(chan model.Result, 4),
	}
	c.wsCancel <- &model.Job{ID: "channel", Kind: "cancel"}
	c.wsJobs <- &model.Job{ID: "busy", Kind: "trace"}
	for i := 0; i < wsCancelOverflowCapacity; i++ {
		c.wsCancelOverflow = append(c.wsCancelOverflow, &model.Job{ID: fmt.Sprintf("initial-%d", i), Kind: "cancel"})
	}
	for i := 0; i < wsCancelDropLogEvery*2; i++ {
		c.enqueueWSCancel(&model.Job{ID: fmt.Sprintf("new-%d", i), Kind: "cancel"})
	}

	c.wsCancelMu.Lock()
	gotLen := len(c.wsCancelOverflow)
	first := c.wsCancelOverflow[0].ID
	dropped := c.wsCancelDropped
	c.wsCancelMu.Unlock()
	if gotLen != wsCancelOverflowCapacity {
		t.Fatalf("溢出列表长度 = %d，期望硬上限 %d", gotLen, wsCancelOverflowCapacity)
	}
	if first != fmt.Sprintf("initial-%d", wsCancelDropLogEvery*2) {
		t.Fatalf("应丢弃最旧条目，实际队首为 %s", first)
	}
	if dropped != wsCancelDropLogEvery*2 {
		t.Fatalf("累计丢弃数 = %d，期望 %d", dropped, wsCancelDropLogEvery*2)
	}
	if got := strings.Count(buf.String(), "取消指令溢出列表达到上限"); got != 3 {
		t.Fatalf("首次及每丢 %d 条应各打一次告警（共 3 次），实际 %d：%s", wsCancelDropLogEvery, got, buf.String())
	}
	select {
	case job := <-c.wsJobs:
		if job == nil || job.ID != "busy" {
			t.Fatalf("普通排队任务不应被淘汰，实际: %+v", job)
		}
	default:
		t.Fatal("普通排队任务不应被淘汰")
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
