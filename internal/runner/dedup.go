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
	maxCachedResultsTotal = 16 << 20 // 所有缓存结果的总内存上限（常驻内存，不宜过大）
)

type dedupAction int

const (
	dedupRun       dedupAction = iota // 首次收到，正常执行
	dedupRunning                      // 同一任务正在执行，跳过重复下发
	dedupCompleted                    // 任务已完成，有缓存则重发缓存结果
)

// dedupCacheState 说明已完成任务为什么有/没有可重发的缓存结果。
type dedupCacheState int

const (
	dedupCacheNone      dedupCacheState = iota // 没有结果（任务被取消或未产生结果）
	dedupCacheHit                              // 命中缓存，可重发
	dedupCacheOversized                        // 结果超出单个结果缓存上限，未缓存
)

type dedupEntry struct {
	id      string
	state   dedupAction
	cache   dedupCacheState
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

// start 登记任务并返回处理动作；已完成时同时返回缓存结果与缓存状态
// （结果可能为 nil：任务已取消，或结果超过缓存上限）。
func (d *jobDedup) start(id string) (dedupAction, *model.Result, dedupCacheState) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.expireLocked(now)

	if e, ok := d.entries[id]; ok {
		// 该条目可能不在 LRU 尾部但仍已过期（例如被重复访问提前移到前面），
		// 必须按自己的 expires 判断，不能只看尾部。
		if !e.expires.After(now) {
			d.removeLocked(e)
		} else {
			d.order.MoveToFront(e.elem)
			switch e.state {
			case dedupRunning:
				return dedupRunning, nil, dedupCacheNone
			default:
				if e.cache == dedupCacheHit && e.result != nil {
					cached := *e.result
					return dedupCompleted, &cached, dedupCacheHit
				}
				if e.cache == dedupCacheOversized {
					return dedupCompleted, nil, dedupCacheOversized
				}
				return dedupCompleted, nil, dedupCacheNone
			}
		}
	}

	e := &dedupEntry{id: id, state: dedupRunning, expires: now.Add(d.ttl)}
	e.elem = d.order.PushFront(e)
	d.entries[id] = e
	d.evictLocked()
	return dedupRun, nil, dedupCacheNone
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
	e.cache = dedupCacheNone
	e.expires = now.Add(d.ttl)
	d.order.MoveToFront(e.elem)

	d.dropResultLocked(e)
	if res != nil {
		size := int64(len(res.Output) + len(res.Data) + len(res.Error))
		if size <= maxCachedResultBytes {
			cached := *res
			e.result = &cached
			e.size = size
			e.cache = dedupCacheHit
			d.cachedBytes += size
			d.trimResultsLocked()
		} else {
			e.cache = dedupCacheOversized
		}
	}
	d.evictLocked()
}

// expireLocked 清理所有过期项。不能只从 LRU 尾部扫：被重复访问过的条目会
// 提前移到前面，即使已经过期也不会落在尾部，只扫尾部会长期占用内存。
func (d *jobDedup) expireLocked(now time.Time) {
	for el := d.order.Front(); el != nil; {
		next := el.Next()
		e := el.Value.(*dedupEntry)
		if !e.expires.After(now) {
			d.removeLocked(e)
		}
		el = next
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
		e := el.Value.(*dedupEntry)
		d.dropResultLocked(e)
		// 因总缓存上限被挤出：重复下发时应说明“超出缓存上限”，而不是“已取消/无结果”。
		e.cache = dedupCacheOversized
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
