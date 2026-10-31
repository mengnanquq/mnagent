package process

import (
	"bytes"
	"sync"
)

// CappedBuffer 收集命令输出，超过上限后丢弃多余内容。
// stdout 与 stderr 会被并发写入，因此需要加锁。
type CappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

// NewCappedBuffer 创建一个带上限的并发安全缓冲区。
func NewCappedBuffer(max int) *CappedBuffer {
	return &CappedBuffer{max: max}
}

// Write 追加输出；始终返回完整长度，避免进程因写入错误而中断。
func (w *CappedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if remaining := w.max - w.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// String 返回已收集的输出。
func (w *CappedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}
