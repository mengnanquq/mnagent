//go:build !linux

package miaospeed

// verifyMiaospeedListener 在非 Linux 平台保留原有行为（不做 socket 归属校验）。
//
// 原因：/proc/net/tcp 与 /proc/<pid>/fd 是 Linux 专有接口；macOS/Windows 没有
// 等价且无需额外权限的“端口 -> 持有进程”查询方式（Windows 需要 iphlpapi 的
// GetExtendedTcpTable 并处理 PID 复用，实现复杂且收益有限）。因此这些平台
// 仍存在先探测端口、再交给子进程绑定的 TOCTOU 窗口。
func verifyMiaospeedListener(pid, port int) error {
	return nil
}
