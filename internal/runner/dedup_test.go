package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
)

func TestJobDedupSkipsRunningAndReplaysCompleted(t *testing.T) {
	d := newJobDedup()
	if action, cached := d.start("j1"); action != dedupRun || cached != nil {
		t.Fatalf("首次任务应执行: action=%v cached=%v", action, cached)
	}
	if action, _ := d.start("j1"); action != dedupRunning {
		t.Fatalf("执行中的重复任务应跳过，实际 action=%v", action)
	}

	res := &model.Result{ID: "j1", Kind: "trace", Output: "cached-output", ExitCode: 0}
	d.complete("j1", res)
	action, cached := d.start("j1")
	if action != dedupCompleted {
		t.Fatalf("已完成任务的重复下发应走缓存，实际 action=%v", action)
	}
	if cached == nil || cached.ID != "j1" || cached.Output != "cached-output" {
		t.Fatalf("缓存结果异常: %+v", cached)
	}
}

func TestJobDedupExpiresAndEvictsLRU(t *testing.T) {
	now := time.Unix(1000, 0)
	d := newJobDedup()
	d.ttl = time.Minute
	d.capacity = 2
	d.now = func() time.Time { return now }

	if action, _ := d.start("a"); action != dedupRun {
		t.Fatalf("a 首次应执行")
	}
	d.complete("a", &model.Result{ID: "a", Output: "a"})
	if action, _ := d.start("b"); action != dedupRun {
		t.Fatalf("b 首次应执行")
	}
	d.complete("b", &model.Result{ID: "b", Output: "b"})
	// b 最近使用过，插入 c 应淘汰最久未使用的 a。
	if action, _ := d.start("c"); action != dedupRun {
		t.Fatalf("c 首次应执行")
	}
	if action, cached := d.start("b"); action != dedupCompleted || cached == nil {
		t.Fatalf("b 应仍在缓存中，实际 action=%v cached=%v", action, cached)
	}
	if action, _ := d.start("a"); action != dedupRun {
		t.Fatalf("a 应已被 LRU 淘汰，实际 action=%v", action)
	}

	// TTL 到期后同一 jobID 可重新执行。
	now = now.Add(2 * time.Minute)
	if action, _ := d.start("b"); action != dedupRun {
		t.Fatalf("TTL 到期后应重新执行，实际 action=%v", action)
	}
}

func TestJobDedupExpiresEntryNotAtLRUTail(t *testing.T) {
	now := time.Unix(2000, 0)
	d := newJobDedup()
	d.ttl = time.Minute
	d.now = func() time.Time { return now }

	d.start("old")
	d.complete("old", &model.Result{ID: "old"})
	now = now.Add(30 * time.Second)
	d.start("new")
	d.complete("new", &model.Result{ID: "new"})
	d.start("old") // 把未过期的 old 移到 LRU 前端，使其不再位于尾部
	// 推进到 old 过期、new 未过期：过期清理只看尾部会漏掉 old。
	now = now.Add(40 * time.Second)
	if action, _ := d.start("new"); action != dedupCompleted {
		t.Fatalf("未过期的 new 应命中缓存，实际 action=%v", action)
	}
	if action, _ := d.start("old"); action != dedupRun {
		t.Fatalf("不在 LRU 尾部的过期条目也必须失效并重新执行，实际 action=%v", action)
	}
}

func TestJobDedupOversizedResultStillSkipsExecution(t *testing.T) {
	d := newJobDedup()
	d.start("big")
	huge := &model.Result{ID: "big", Output: strings.Repeat("x", maxCachedResultBytes+1)}
	d.complete("big", huge)
	action, cached := d.start("big")
	if action != dedupCompleted || cached != nil {
		t.Fatalf("超大结果应标记完成但不缓存，实际 action=%v cached=%v", action, cached)
	}
}

// TestAgentLoopDeduplicatesCompletedJob 验证同一 jobID 只执行一次，重复下发时重发缓存结果。
func TestAgentLoopDeduplicatesCompletedJob(t *testing.T) {
	var jobsServed atomic.Int32
	var duplicateServed atomic.Bool
	var resultCount atomic.Int32
	var resultMu sync.Mutex
	var results []model.Result

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			switch jobsServed.Add(1) {
			case 1:
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"dup-1","kind":"trace","target":"1.1.1.1","hops":5,"timeout_ms":5000}`))
			default:
				// 第一次执行完成后再重复下发同一任务，验证走缓存而不重跑。
				if resultCount.Load() >= 1 && duplicateServed.CompareAndSwap(false, true) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":"dup-1","kind":"trace","target":"1.1.1.1","hops":5,"timeout_ms":5000}`))
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}
		case "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			resultMu.Lock()
			results = append(results, res)
			resultMu.Unlock()
			resultCount.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	marker := filepath.Join(t.TempDir(), "runs")
	script := writeScript(t, "printf x >> "+marker+`; echo "trace ok"`)
	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		Binary:      script,
		MinBackoff:  5 * time.Millisecond,
		MaxBackoff:  20 * time.Millisecond,
		PollTimeout: time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg), runner: newRunner(cfg.Binary, nil)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for resultCount.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	_ = <-done

	runs, _ := os.ReadFile(marker)
	if got := len(runs); got != 1 {
		t.Fatalf("同一 jobID 应只执行一次，实际执行 %d 次", got)
	}
	resultMu.Lock()
	defer resultMu.Unlock()
	if len(results) != 2 {
		t.Fatalf("应回传两次（首次 + 缓存重发），实际 %d 次: %+v", len(results), results)
	}
	if results[0].ID != "dup-1" || results[1].ID != "dup-1" || results[1].Output != results[0].Output {
		t.Fatalf("缓存重发结果不一致: %+v", results)
	}
}

// TestFailPendingHeavyReportsQueuedJobs 验证退出时 heavyQueue 中未执行的任务会逐一回报。
func TestFailPendingHeavyReportsQueuedJobs(t *testing.T) {
	var mu sync.Mutex
	var got []model.Result
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/results" {
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			mu.Lock()
			got = append(got, res)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &config.Config{BotURL: srv.URL, Tokens: &config.TokenSource{Value: "tok"}, PollTimeout: time.Second}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}
	a.heavyQueue = make(chan model.Job, 4)
	a.heavyQueue <- model.Job{ID: "h1", Kind: "trace", Target: "1.1.1.1"}
	a.heavyQueue <- model.Job{ID: "h2", Kind: "miaospeed", Target: "sub"}
	a.heavyQueue <- model.Job{ID: "h1", Kind: "cancel"} // 取消控制包不应回报

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if n := a.failPendingHeavy(ctx, "节点停止，未执行"); n != 2 {
		t.Fatalf("应回报 2 个未执行重任务，实际 %d", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("结果数量 = %d，期望 2: %+v", len(got), got)
	}
	ids := map[string]bool{}
	for _, res := range got {
		ids[res.ID] = true
		if res.ExitCode != -1 || res.Error != "节点停止，未执行" {
			t.Fatalf("未执行任务回报异常: %+v", res)
		}
	}
	if !ids["h1"] || !ids["h2"] {
		t.Fatalf("回报的任务 ID 异常: %+v", ids)
	}
}
