package main

import (
	"context"
	"sync"
	"testing"
	"time"
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
}

func TestConcurrentLightExecutionDuringHeavyJob(t *testing.T) {
	tracker := newJobTracker()
	a := &agent{
		tracker: tracker,
	}

	// 模拟重任务开始执行
	a.heavyActive.Store(true)
	doneCh := make(chan struct{})
	a.heavyDone = doneCh

	heavyJob := Job{ID: "heavy-1", Kind: "trace", Target: "1.1.1.1"}
	if !isHeavy(heavyJob) {
		t.Fatal("heavyJob 应该是重任务")
	}

	lightJob := Job{ID: "light-1", Kind: "ping", Target: "1.1.1.1"}
	if isHeavy(lightJob) {
		t.Fatal("lightJob 应该是轻任务")
	}

	// 验证重任务激活状态下，isHeavy 判定有效
	if !a.heavyActive.Load() {
		t.Fatal("heavyActive 应该为 true")
	}

	// 模拟重任务结束
	a.heavyActive.Store(false)
	close(doneCh)

	select {
	case <-a.heavyDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("heavyDone 超时未就绪")
	}
}
