//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
)

// setupCmdProcessGroup 在 Windows 平台设置进程取消钩子，彻底终止整棵进程树（防孤儿进程），
// 并隐去控制台窗口，避免桌面交互环境下弹出闪烁黑框。
func setupCmdProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.Cancel = func() error {
		return killProcessTree(cmd)
	}
}

// killProcessGroup 杀死进程及其派生的整个进程树。
func killProcessGroup(cmd *exec.Cmd) {
	_ = killProcessTree(cmd)
}

// killProcessTree 尝试通过 taskkill.exe /F /T 杀死整棵进程树；若失败则回退到 Process.Kill()。
func killProcessTree(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return nil
	}
	pidStr := strconv.Itoa(cmd.Process.Pid)
	killCmd := exec.Command("taskkill.exe", "/F", "/T", "/PID", pidStr)
	killCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := killCmd.Run(); err == nil {
		return nil
	}
	return cmd.Process.Kill()
}
