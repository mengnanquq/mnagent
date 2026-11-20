//go:build !windows

package statedir

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// otherOwnerFileInfo 把真实 FileInfo 的属主替换为指定 uid，用于模拟非当前用户目录。
type otherOwnerFileInfo struct {
	os.FileInfo
	uid uint32
}

func (f otherOwnerFileInfo) Sys() any {
	return &syscall.Stat_t{Uid: f.uid}
}

// TestTightenDirPermOnlyCurrentOwner 验证只有属主为当前用户时才收紧权限。
func TestTightenDirPermOnlyCurrentOwner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 属主不是当前用户（例如 root 拥有、非 root 运行）时不得尝试修改。
	tightenDirPerm(dir, otherOwnerFileInfo{FileInfo: fi, uid: uint32(os.Geteuid() + 1)})
	if got, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if perm := got.Mode().Perm(); perm != 0o755 {
		t.Fatalf("非当前用户拥有的目录不应被修改，权限 = %04o", perm)
	}

	// 属主是当前用户且权限更宽时收紧到 0700。
	tightenDirPerm(dir, fi)
	if got, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if perm := got.Mode().Perm(); perm != 0o700 {
		t.Fatalf("当前用户拥有的宽权限目录应收紧到 0700，实际 %04o", perm)
	}
}
