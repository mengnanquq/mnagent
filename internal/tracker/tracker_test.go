package tracker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJobTracker(t *testing.T) {
	trk := New()

	var cancelled sync.Map

	// 1. 注册两个任务
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	trk.Register("j1", func() {
		cancelled.Store("j1", true)
		cancel1()
	})
	trk.Register("j2", func() {
		cancelled.Store("j2", true)
		cancel2()
	})

	// 2. 取消 j1
	if !trk.Cancel("j1") {
		t.Fatal("Cancel(j1) 应该返回 true")
	}
	if ctx1.Err() == nil {
		t.Fatal("ctx1 应该已被取消")
	}
	if _, ok := cancelled.Load("j1"); !ok {
		t.Fatal("j1 取消回调未执行")
	}

	// 重复取消 j1 应返回 false
	if trk.Cancel("j1") {
		t.Fatal("第二次 Cancel(j1) 应该返回 false")
	}

	// 3. j2 正常结束并注销
	trk.Unregister("j2")
	if trk.Cancel("j2") {
		t.Fatal("注销后的 j2 取消应该返回 false")
	}
	if ctx2.Err() != nil {
		t.Fatal("ctx2 不应该被取消")
	}
	cancel2()

	// 4. 提前取消尚未 Register 的任务 j3
	trk.Cancel("j3")
	if !trk.IsCancelled("j3") {
		t.Fatal("j3 应该已被标记为取消")
	}
	ctx3, cancel3 := context.WithCancel(context.Background())
	trk.Register("j3", cancel3)
	if ctx3.Err() == nil {
		t.Fatal("已标记取消的任务在 Register 时应立即触发取消")
	}
}

// TestTrackerCancelledMapBounded 验证取消标记有容量上限，超限时淘汰最早的条目。
func TestTrackerCancelledMapBounded(t *testing.T) {
	trk := New()
	base := time.Now().Add(time.Hour)
	trk.mu.Lock()
	for i := 0; i < maxCancelledEntries; i++ {
		trk.cancelled[fmt.Sprintf("old-%d", i)] = base.Add(time.Duration(i) * time.Second)
	}
	trk.mu.Unlock()

	trk.Cancel("new-job")
	trk.mu.Lock()
	defer trk.mu.Unlock()
	if got := len(trk.cancelled); got != maxCancelledEntries {
		t.Fatalf("取消标记数量 = %d，期望上限 %d", got, maxCancelledEntries)
	}
	if _, ok := trk.cancelled["old-0"]; ok {
		t.Fatal("超限时应淘汰最早过期的条目 old-0")
	}
	if _, ok := trk.cancelled["old-1"]; !ok {
		t.Fatal("只应淘汰最旧条目，old-1 不应被淘汰")
	}
	if _, ok := trk.cancelled["new-job"]; !ok {
		t.Fatal("新取消标记应保留")
	}
}

// TestTrackerEvictionLogsWarning 验证取消标记达到容量上限而淘汰仍在有效期内的条目时，
// 会打出可排查的 Warn 日志（否则任务取消突然“失效”将无从定位）。
func TestTrackerEvictionLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(old)

	trk := New()
	base := time.Now().Add(time.Hour)
	trk.mu.Lock()
	for i := 0; i < maxCancelledEntries; i++ {
		trk.cancelled[fmt.Sprintf("old-%d", i)] = base.Add(time.Duration(i) * time.Second)
	}
	trk.mu.Unlock()

	trk.Cancel("new-job")
	logged := buf.String()
	if !strings.Contains(logged, "level=WARN") || !strings.Contains(logged, "old-0") {
		t.Fatalf("淘汰有效期内的取消标记时应打印包含被淘汰 ID 的 Warn 日志，实际：%q", logged)
	}
}

func TestJobTrackerCancelAll(t *testing.T) {
	trk := New()
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	trk.Register("job-1", cancel1)
	trk.Register("job-2", cancel2)

	n := trk.CancelAll()
	if n != 2 {
		t.Fatalf("CancelAll 期望取消 2 个任务，实际: %d", n)
	}

	if ctx1.Err() == nil || ctx2.Err() == nil {
		t.Fatal("CancelAll 后所有在途任务 context 必须已被取消")
	}

	// 再次调用应返回 0
	if n2 := trk.CancelAll(); n2 != 0 {
		t.Fatalf("空集合 CancelAll 期望 0，实际: %d", n2)
	}
}
