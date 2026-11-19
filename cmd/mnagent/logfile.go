package main

import (
	"fmt"
	"io"
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

	// warnWriter 是轮转失败时的告警输出，默认 stderr；测试可替换。
	warnWriter io.Writer
	// warned 避免本轮轮转失败在每次写入时反复刷告警。
	warned bool
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
	return &rotatingLogWriter{path: path, maxBytes: maxBytes, backups: backups, file: f, size: size, warnWriter: os.Stderr}, nil
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
			// 轮转失败不能把日志丢掉：rotateLocked 会尽量保持旧文件可写，
			// 这里只告警一次，随后照常写入当前文件。
			w.warnRotateLocked(err)
		} else {
			w.warned = false
		}
	}
	if w.file == nil {
		return 0, os.ErrClosed
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// warnRotateLocked 在轮转失败时向 stderr 输出一次提示，避免运维误以为日志已丢失。
func (w *rotatingLogWriter) warnRotateLocked(cause error) {
	if w.warned {
		return
	}
	w.warned = true
	out := w.warnWriter
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "mnagent: 日志轮转失败，将继续写入当前文件 %s（请检查磁盘空间与目录权限）：%v\n", w.path, cause)
}

// rotateLocked 关闭当前文件，把历史文件依次后移，再创建新的当前日志。
// 轮转失败时尽量不让日志静默丢失：只要旧文件还能重新打开就继续追加写入，
// 并返回首个错误供调用方告警（典型原因：目录只读、磁盘满、目标被目录占用）。
func (w *rotatingLogWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		// 关闭失败时保留原句柄继续写，文件可能已不可用。
		return err
	}
	w.file = nil
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for i := w.backups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			record(err)
		}
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			record(err)
		}
	}
	// Windows 的 Rename 不会覆盖已存在的目标，先清理 .1。
	if err := os.Remove(w.path + ".1"); err != nil && !os.IsNotExist(err) {
		record(err)
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		record(err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		if firstErr != nil {
			return fmt.Errorf("%w（重新打开 %s 失败：%v）", firstErr, w.path, err)
		}
		return err
	}
	w.file = f
	// 重命名失败时 w.path 仍是旧文件：按实际大小继续累加，避免误判为已轮转。
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	w.size = size
	return firstErr
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
