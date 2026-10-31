//go:build !windows

package process

import (
	"os/exec"
	"syscall"
)

// SetupCmdProcessGroup 为外部进程设置独立的进程组（PGID），并在上下文取消时杀死整个进程组，
// 避免因仅杀死父进程而产生孤儿孙进程残留。
func SetupCmdProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
}

// KillProcessGroup 杀死外部进程所属的整个进程组。
func KillProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
