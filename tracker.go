package main

import (
	"context"
	"sync"
	"time"
)

// jobTracker 并发安全地维护当前主机上正在运行的任务及其取消函数。
type jobTracker struct {
	mu        sync.Mutex
	jobs      map[string]context.CancelFunc
	cancelled map[string]time.Time
}

func newJobTracker() *jobTracker {
	return &jobTracker{
		jobs:      make(map[string]context.CancelFunc),
		cancelled: make(map[string]time.Time),
	}
}

// cleanExpiredCancelled 清理超时的已取消任务记录（需在锁内调用）。
func (t *jobTracker) cleanExpiredCancelled() {
	now := time.Now()
	for id, exp := range t.cancelled {
		if now.After(exp) {
			delete(t.cancelled, id)
		}
	}
}

// Register 登记一个正在执行的任务及其取消函数。
// 若该任务之前已被标记取消，则立即触发 cancel 并返回。
func (t *jobTracker) Register(id string, cancel context.CancelFunc) {
	if t == nil || id == "" || cancel == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if exp, ok := t.cancelled[id]; ok && time.Now().Before(exp) {
		cancel()
		return
	}
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

// Cancel 依据任务 ID 触发取消；记录取消标记并在任务运行时触发取消回调。
// 若当前有正在运行的任务被立即取消，返回 true；若任务未在运行列表中则仅记录取消标记并返回 false。
func (t *jobTracker) Cancel(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanExpiredCancelled()
	t.cancelled[id] = time.Now().Add(10 * time.Minute)
	cancel, ok := t.jobs[id]
	if ok {
		delete(t.jobs, id)
		if cancel != nil {
			cancel()
		}
		return true
	}
	return false
}

// IsCancelled 查询指定任务是否已被标记取消。
func (t *jobTracker) IsCancelled(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.cancelled[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(t.cancelled, id)
		return false
	}
	return true
}

// CancelAll 取消所有当前正在运行的任务，并返回取消的任务数量。
func (t *jobTracker) CancelAll() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for id, cancel := range t.jobs {
		if cancel != nil {
			cancel()
			count++
		}
		delete(t.jobs, id)
	}
	return count
}
