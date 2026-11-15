package statedir

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsurePrivateRejectsUnsafeDirs(t *testing.T) {
	base := t.TempDir()

	ok := filepath.Join(base, "ok")
	if err := ensurePrivate(ok); err != nil {
		t.Fatalf("新建私有目录应成功：%v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	fi, _ := os.Stat(ok)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("新建目录权限应为 0700，实际 %o", fi.Mode().Perm())
	}

	shared := filepath.Join(base, "shared")
	_ = os.Mkdir(shared, 0o777)
	_ = os.Chmod(shared, 0o777)
	if err := ensurePrivate(shared); err == nil {
		t.Fatal("其他用户可写的目录应被拒绝")
	}

	link := filepath.Join(base, "link")
	_ = os.Symlink(ok, link)
	if err := ensurePrivate(link); err == nil {
		t.Fatal("符号链接应被拒绝")
	}
}
