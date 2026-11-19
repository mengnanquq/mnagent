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
