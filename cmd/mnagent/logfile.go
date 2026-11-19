package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	// 当前日志 + 2 个历史文件 = 5MB × 3，避免 Windows 服务长期运行写满磁盘。
	defaultLogMaxBytes int64 = 5 << 20
	defaultLogBackups        = 2
)

// rotatingLogWriter 是一个按大小轮转的简单日志写入器。
// Windows 服务没有终端可看 stderr，因此需要把日志落到文件；
// 轮转只保留有限的几份，避免长期运行占满磁盘。
type rotatingLogWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	backups  int
	file     *os.File
	size     int64
}

func newRotatingLogWriter(path string, maxBytes int64, backups int) (*rotatingLogWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("日志文件路径为空")
	}
	if maxBytes <= 0 {
		maxBytes = defaultLogMaxBytes
	}
	if backups < 0 {
		backups = defaultLogBackups
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	return &rotatingLogWriter{path: path, maxBytes: maxBytes, backups: backups, file: f, size: size}, nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotateLocked 关闭当前文件，把历史文件依次后移，再创建新的当前日志。
func (w *rotatingLogWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	for i := w.backups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		_ = os.Remove(dst)
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// Windows 的 Rename 不会覆盖已存在的目标，先清理 .1。
	_ = os.Remove(w.path + ".1")
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
