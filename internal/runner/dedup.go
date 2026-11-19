package runner

import (
	"container/list"
	"sync"
	"time"

	"github.com/mengnanquq/mnagent/internal/model"
)

// 任务去重：机器人可能在长轮询/重连/重试时重复下发同一个 jobID。
// 重复执行 trace、miaospeed、upgrade 代价很高（甚至会被连续升级），因此节点侧维护
// 一个有界的 LRU + TTL 记录：执行中的任务直接跳过，已完成的任务重发缓存结果。
// TTL 必须不小于最长任务超时，否则任务还没结束记录就过期了。
var defaultDedupTTL = model.JobMiaospeedMaxTimeout + 10*time.Minute

const (
	defaultDedupCapacity  = 2048
	maxCachedResultBytes  = 16 << 20 // 单个结果最多缓存 16MB（与结果体上限一致）
	maxCachedResultsTotal = 64 << 20 // 所有缓存结果的总内存上限
)

type dedupAction int

const (
	dedupRun       dedupAction = iota // 首次收到，正常执行
	dedupRunning                      // 同一任务正在执行，跳过重复下发
	dedupCompleted                    // 任务已完成，有缓存则重发缓存结果
)

type dedupEntry struct {
	id      string
	state   dedupAction
	result  *model.Result
	size    int64
	expires time.Time
	elem    *list.Element
}

type jobDedup struct {
	mu       sync.Mutex
	entries  map[string]*dedupEntry
	order    *list.List // 前端最新、后端最旧
	capacity int
	ttl      time.Duration
	now      func() time.Time

	cachedBytes int64
}

func newJobDedup() *jobDedup {
	return &jobDedup{
		entries:  make(map[string]*dedupEntry),
		order:    list.New(),
		capacity: defaultDedupCapacity,
		ttl:      defaultDedupTTL,
		now:      time.Now,
	}
}

// start 登记任务并返回处理动作；已完成时同时返回缓存结果（可能为 nil，例如结果过大）。
func (d *jobDedup) start(id string) (dedupAction, *model.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)

	if e, ok := d.entries[id]; ok {
		d.order.MoveToFront(e.elem)
		switch e.state {
		case dedupRunning:
			return dedupRunning, nil
		default:
			if e.result != nil {
				cached := *e.result
				return dedupCompleted, &cached
			}
			return dedupCompleted, nil
		}
	}

	e := &dedupEntry{id: id, state: dedupRunning, expires: now.Add(d.ttl)}
	e.elem = d.order.PushFront(e)
	d.entries[id] = e
	d.evictLocked()
	return dedupRun, nil
}

// complete 把任务标记为已完成，并在体积允许时缓存结果供重复下发时重发。
func (d *jobDedup) complete(id string, res *model.Result) {
	if id == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)

	e, ok := d.entries[id]
	if !ok {
		e = &dedupEntry{id: id}
		e.elem = d.order.PushFront(e)
		d.entries[id] = e
	}
	e.state = dedupCompleted
	e.expires = now.Add(d.ttl)
	d.order.MoveToFront(e.elem)

	d.dropResultLocked(e)
	if res != nil {
		size := int64(len(res.Output) + len(res.Data) + len(res.Error))
		if size <= maxCachedResultBytes {
			cached := *res
			e.result = &cached
			e.size = size
			d.cachedBytes += size
			d.trimResultsLocked()
		}
	}
	d.evictLocked()
}

// forget 删除记录（例如任务被取消，不应把取消状态当作“已完成”）。
func (d *jobDedup) forget(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e, ok := d.entries[id]; ok {
		d.removeLocked(e)
	}
}

func (d *jobDedup) expireLocked(now time.Time) {
	for {
		back := d.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*dedupEntry)
		if e.expires.After(now) {
			return
		}
		d.removeLocked(e)
	}
}

func (d *jobDedup) evictLocked() {
	for len(d.entries) > d.capacity {
		back := d.order.Back()
		if back == nil {
			return
		}
		d.removeLocked(back.Value.(*dedupEntry))
	}
}

func (d *jobDedup) trimResultsLocked() {
	if d.cachedBytes <= maxCachedResultsTotal {
		return
	}
	for el := d.order.Back(); el != nil && d.cachedBytes > maxCachedResultsTotal; el = el.Prev() {
		d.dropResultLocked(el.Value.(*dedupEntry))
	}
}

func (d *jobDedup) dropResultLocked(e *dedupEntry) {
	if e.result != nil {
		d.cachedBytes -= e.size
		e.result = nil
		e.size = 0
	}
}

func (d *jobDedup) removeLocked(e *dedupEntry) {
	d.dropResultLocked(e)
	delete(d.entries, e.id)
	if e.elem != nil {
		d.order.Remove(e.elem)
	}
}
