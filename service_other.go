//go:build !windows

package main

// runService 在非 Windows 平台上直接返回 false（不以 Windows 服务模式运行）。
func runService(_ []string) (bool, error) {
	return false, nil
}
