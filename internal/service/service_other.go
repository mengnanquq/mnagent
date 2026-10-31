//go:build !windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Run 在非 Windows 平台上直接返回 false（不以 Windows 服务模式运行）。
func Run(_ []string, _ func(context.Context, []string) error) (bool, error) {
	return false, nil
}

// RestartWindowsService 在非 Windows 平台上不支持。
func RestartWindowsService() error {
	return errors.New("非 Windows 平台")
}

// RestartService 重启 mnagent 服务（systemd 或 OpenWrt procd）。
func RestartService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "restart", "mnagent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart mnagent 失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if _, err := os.Stat("/etc/init.d/mnagent"); err == nil {
		out, err := exec.Command("/etc/init.d/mnagent", "restart").CombinedOutput()
		if err != nil {
			return fmt.Errorf("/etc/init.d/mnagent restart 失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return errors.New("未找到 systemd 或 /etc/init.d/mnagent，无法自动重启（请手动重启服务）")
}
