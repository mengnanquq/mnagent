package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// 当前日志 + 2 个历史文件 = 5MB × 3，避免 Windows 服务长期运行写满磁盘。
	defaultLogMaxBytes int64 = 5 << 20
	defaultLogBackups        = 2
	// defaultLogReopenInterval 限制日志文件不可用时的重试频率：每次写日志都尝试
	// 打开会反复刷失败告警并浪费 IO，30 秒一次足以在磁盘/权限恢复后继续落盘。
	defaultLogReopenInterval = 30 * time.Second
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
	// openFile 默认 openLogFile；测试可注入“轮转后重开失败”的场景。
	openFile func(string) (*os.File, error)

	// warnWriter 是轮转/重开失败时的告警输出，默认 stderr；测试可替换。
	warnWriter io.Writer
	// warned 避免同一轮故障在每次写入时反复刷告警。
	warned bool
	// reopenInterval 是文件不可用时的重试间隔（测试可缩短）。
	reopenInterval time.Duration
	// nextOpenAttempt 是下一次允许尝试重新打开文件的时间。
	nextOpenAttempt time.Time
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
	f, err := openLogFile(path)
	if err != nil {
		return nil, err
	}
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	return &rotatingLogWriter{
		path: path, maxBytes: maxBytes, backups: backups, file: f, size: size,
		openFile: openLogFile, warnWriter: os.Stderr, reopenInterval: defaultLogReopenInterval,
	}, nil
}

// openLogFile 以追加方式打开日志文件，并拒绝符号链接（Linux/Unix 上通过
// O_NOFOLLOW）：日志路径来自配置/服务参数，若被替换成指向任意文件的符号链接，
// 以 root 运行时会向目标文件追加内容。Windows 没有等价标志，由 logOpenNoFollow
// 的平台实现退化为普通 OpenFile。
func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|logOpenNoFollow, 0o640)
	if err != nil {
		return nil, logOpenError(err)
	}
	return f, nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return w.writeUnavailableLocked(p)
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
		return w.writeUnavailableLocked(p)
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
	if w.file == nil {
		w.warnReopenLocked(cause)
		return
	}
	out := w.warnWriter
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "mnagent: 日志轮转失败，将继续写入当前文件 %s（请检查磁盘空间与目录权限）：%v\n", w.path, cause)
}

// warnReopenLocked 在日志文件不可写时输出一次告警。调用方保证 w.warned 已置位。
func (w *rotatingLogWriter) warnReopenLocked(cause error) {
	out := w.warnWriter
	if out == nil {
		out = os.Stderr
	}
	interval := w.reopenInterval
	if interval <= 0 {
		interval = defaultLogReopenInterval
	}
	fmt.Fprintf(out, "mnagent: 日志文件 %s 重新打开失败，将每 %s 重试一次（请检查磁盘空间与目录权限）：%v\n",
		w.path, interval, cause)
}

// writeUnavailableLocked 在日志文件不可用时按 reopenInterval 节流重试 openLogFile。
// 不在失败时回退 stderr：main 已用 MultiWriter 把同一行写到 stderr，再回退会导致
// 每行日志重复输出。重试失败期间只丢弃文件镜像，返回成功避免影响调用方。
func (w *rotatingLogWriter) writeUnavailableLocked(p []byte) (int, error) {
	now := time.Now()
	interval := w.reopenInterval
	if interval <= 0 {
		interval = defaultLogReopenInterval
	}
	if w.nextOpenAttempt.IsZero() || !now.Before(w.nextOpenAttempt) {
		openFile := w.openFile
		if openFile == nil {
			openFile = openLogFile
		}
		f, err := openFile(w.path)
		if err == nil {
			w.file = f
			w.nextOpenAttempt = time.Time{}
			w.warned = false
			var size int64
			if fi, statErr := f.Stat(); statErr == nil {
				size = fi.Size()
			}
			w.size = size
			out := w.warnWriter
			if out == nil {
				out = os.Stderr
			}
			fmt.Fprintf(out, "mnagent: 日志文件 %s 已恢复写入\n", w.path)
			n, writeErr := f.Write(p)
			w.size += int64(n)
			return n, writeErr
		}
		w.nextOpenAttempt = now.Add(interval)
		if !w.warned {
			w.warned = true
			w.warnReopenLocked(err)
		}
	}
	return len(p), nil
}

// rotateLocked 关闭当前文件，把历史文件依次后移，再创建新的当前日志。
// 轮转失败时尽量不让日志静默丢失：旧文件仍可写就继续追加；重新打开失败则
// 记录下次重试时间，并返回错误供调用方告警一次（典型原因：目录只读、磁盘满）。
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
	openFile := w.openFile
	if openFile == nil {
		openFile = openLogFile
	}
	f, err := openFile(w.path)
	if err != nil {
		// 重开失败：记录重试时间，由 writeUnavailableLocked 节流重试。
		interval := w.reopenInterval
		if interval <= 0 {
			interval = defaultLogReopenInterval
		}
		w.nextOpenAttempt = time.Now().Add(interval)
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
