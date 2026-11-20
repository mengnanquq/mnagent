//go:build !windows

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// logOpenNoFollow 让 OpenFile 在最终路径是符号链接时直接失败（ELOOP），
// 避免日志路径被替换成指向任意文件的链接后以 root 追加写入。
const logOpenNoFollow = unix.O_NOFOLLOW

// logOpenError 把 ELOOP 转换成明确的中文提示：日志路径是符号链接时，
// O_NOFOLLOW 会返回 ELOOP，运维需要知道拒绝原因而不是只看 errno。
func logOpenError(err error) error {
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("日志路径是符号链接，已被拒绝：%w", err)
	}
	return err
}
