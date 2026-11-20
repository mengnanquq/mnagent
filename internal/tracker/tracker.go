package tracker

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// maxCancelledEntries 限制已取消任务标记的数量，防止长期运行或恶意任务 ID
// 让 cancelled map 无界增长；达到上限时淘汰最早过期的条目。
const maxCancelledEntries = 4096

// Tracker 并发安全地维护当前主机上正在运行的任务及其取消函数。
type Tracker struct {
	mu        sync.Mutex
	jobs      map[string]context.CancelFunc
	cancelled map[string]time.Time
}

// New 创建一个新的任务生命周期跟踪器。
func New() *Tracker {
	return &Tracker{
		jobs:      make(map[string]context.CancelFunc),
		cancelled: make(map[string]time.Time),
	}
}

// cleanExpiredCancelled 清理超时的已取消任务记录（需在锁内调用）。
func (t *Tracker) cleanExpiredCancelled() {
	now := time.Now()
	for id, exp := range t.cancelled {
		if now.After(exp) {
			delete(t.cancelled, id)
		}
	}
}

// Register 登记一个正在执行的任务及其取消函数。
// 若该任务之前已被标记取消，则立即触发 cancel 并返回。
func (t *Tracker) Register(id string, cancel context.CancelFunc) {
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
func (t *Tracker) Unregister(id string) {
	if t == nil || id == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, id)
}

// Cancel 依据任务 ID 触发取消；记录取消标记并在任务运行时触发取消回调。
// 若当前有正在运行的任务被立即取消，返回 true；若任务未在运行列表中则仅记录取消标记并返回 false。
func (t *Tracker) Cancel(id string) bool {
	if t == nil || id == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cleanExpiredCancelled()
	if _, exists := t.cancelled[id]; !exists && len(t.cancelled) >= maxCancelledEntries {
		if evicted := t.evictOldestCancelled(); evicted != "" {
			slog.Warn("已取消任务标记达到上限，淘汰最旧条目", "evicted", evicted, "limit", maxCancelledEntries)
		}
	}
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

// evictOldestCancelled 淘汰取消标记中最早过期的一项（需在锁内调用），返回被淘汰的任务 ID。
func (t *Tracker) evictOldestCancelled() string {
	var oldestID string
	var oldestExp time.Time
	for id, exp := range t.cancelled {
		if oldestID == "" || exp.Before(oldestExp) {
			oldestID = id
			oldestExp = exp
		}
	}
	if oldestID != "" {
		delete(t.cancelled, oldestID)
	}
	return oldestID
}

// IsCancelled 查询指定任务是否已被标记取消。
func (t *Tracker) IsCancelled(id string) bool {
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
func (t *Tracker) CancelAll() int {
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
