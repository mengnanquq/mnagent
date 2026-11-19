//go:build !windows

package statedir

import (
	"fmt"
	"os"
	"syscall"
)

// checkDirOwner 要求状态目录属主为 root 或当前运行用户。
// 若目录属于其他普通用户，即使权限位看似安全，对方仍可替换目录内容
// （跳过版本记录、降级依赖等），因此必须拒绝。
func checkDirOwner(dir string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	owner := int(st.Uid)
	current := os.Geteuid()
	if owner != 0 && owner != current {
		return fmt.Errorf("%s 属主 uid=%d 既不是 root 也不是当前用户 uid=%d，拒绝使用", dir, owner, current)
	}
	return nil
}
