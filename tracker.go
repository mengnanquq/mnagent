package main

import (
	"context"
	"sync"
)

// jobTracker 并发安全地维护当前主机上正在运行的任务及其取消函数。
type jobTracker struct {
	mu   sync.Mutex
	jobs map[string]context.CancelFunc
}

func newJobTracker() *jobTracker {
	return &jobTracker{
		jobs: make(map[string]context.CancelFunc),
	}
}

// Register 登记一个正在执行的任务及其取消函数。
func (t *jobTracker) Register(id string, cancel context.CancelFunc) {
	if t == nil || id == "" || cancel == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.jobs[id] = cancel
}

// Unregister 任务完成后注销该任务。
func (t *jobTracker) Unregister(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, id)
}

// Cancel 依据任务 ID 触发取消；返回是否存在并已取消。
func (t *jobTracker) Cancel(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	cancel, ok := t.jobs[id]
	if ok {
		delete(t.jobs, id)
	}
	t.mu.Unlock()
	if ok && cancel != nil {
		cancel()
		return true
	}
	return false
}
