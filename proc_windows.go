//go:build windows

package main

import "os/exec"

// setupCmdProcessGroup 在 Windows 平台设置进程取消钩子。
func setupCmdProcessGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}

// killProcessGroup 杀死进程。
func killProcessGroup(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
