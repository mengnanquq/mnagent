package main

import (
	"context"
	"sync"
	"testing"
)

func TestJobTracker(t *testing.T) {
	tracker := newJobTracker()

	var cancelled sync.Map

	// 1. 注册两个任务
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	tracker.Register("j1", func() {
		cancelled.Store("j1", true)
		cancel1()
	})
	tracker.Register("j2", func() {
		cancelled.Store("j2", true)
		cancel2()
	})

	// 2. 取消 j1
	if !tracker.Cancel("j1") {
		t.Fatal("Cancel(j1) 应该返回 true")
	}
	if ctx1.Err() == nil {
		t.Fatal("ctx1 应该已被取消")
	}
	if _, ok := cancelled.Load("j1"); !ok {
		t.Fatal("j1 取消回调未执行")
	}

	// 重复取消 j1 应返回 false
	if tracker.Cancel("j1") {
		t.Fatal("第二次 Cancel(j1) 应该返回 false")
	}

	// 3. j2 正常结束并注销
	tracker.Unregister("j2")
	if tracker.Cancel("j2") {
		t.Fatal("注销后的 j2 取消应该返回 false")
	}
	if ctx2.Err() != nil {
		t.Fatal("ctx2 不应该被取消")
	}
	cancel2()

	// 4. 提前取消尚未 Register 的任务 j3
	tracker.Cancel("j3")
	if !tracker.IsCancelled("j3") {
		t.Fatal("j3 应该已被标记为取消")
	}
	ctx3, cancel3 := context.WithCancel(context.Background())
	tracker.Register("j3", cancel3)
	if ctx3.Err() == nil {
		t.Fatal("已标记取消的任务在 Register 时应立即触发取消")
	}
}

func TestConcurrentLightExecutionDuringHeavyJob(t *testing.T) {
	heavyJob := Job{ID: "heavy-1", Kind: "trace", Target: "1.1.1.1"}
	if !isHeavy(heavyJob) {
		t.Fatal("heavyJob 应该是重任务")
	}

	lightJob := Job{ID: "light-1", Kind: "ping", Target: "1.1.1.1"}
	if isHeavy(lightJob) {
		t.Fatal("lightJob 应该是轻任务")
	}
}

func TestJobTrackerCancelAll(t *testing.T) {
	tracker := newJobTracker()
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())

	tracker.Register("job-1", cancel1)
	tracker.Register("job-2", cancel2)

	n := tracker.CancelAll()
	if n != 2 {
		t.Fatalf("CancelAll 期望取消 2 个任务，实际: %d", n)
	}

	if ctx1.Err() == nil || ctx2.Err() == nil {
		t.Fatal("CancelAll 后所有在途任务 context 必须已被取消")
	}

	// 再次调用应返回 0
	if n2 := tracker.CancelAll(); n2 != 0 {
		t.Fatalf("空集合 CancelAll 期望 0，实际: %d", n2)
	}
}
