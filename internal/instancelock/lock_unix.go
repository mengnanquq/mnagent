//go:build !windows

package instancelock

import (
	"errors"
	"os"
	"syscall"
)

// tryLock 用 flock 做非阻塞排他锁；加锁状态跟随打开的文件描述符，
// 进程退出（包括崩溃/被 SIGKILL）时由内核自动释放，不会留下“僵尸锁”。
func tryLock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errLocked
	}
	return err
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
