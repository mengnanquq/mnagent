//go:build windows

package main

// Windows 的 CreateFile 没有与 O_NOFOLLOW 等价的原子标志；
// 保持原有打开语义，符号链接防护仅由 Unix 平台的 O_NOFOLLOW 提供。
const logOpenNoFollow = 0

// logOpenError 在 Windows 上原样返回（没有 O_NOFOLLOW 等价的 ELOOP 场景）。
func logOpenError(err error) error { return err }
