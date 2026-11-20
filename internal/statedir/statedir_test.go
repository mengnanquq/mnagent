package statedir

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestWarnfWritesToWarnWriter 验证属主校验等告警能被运维看见（默认输出到 stderr）。
func TestWarnfWritesToWarnWriter(t *testing.T) {
	var buf bytes.Buffer
	old := warnWriter
	warnWriter = &buf
	defer func() { warnWriter = old }()

	warnf("状态目录属主校验失败：%s", "bad owner")
	got := buf.String()
	if !strings.Contains(got, "WARN [statedir] 状态目录属主校验失败：bad owner") {
		t.Fatalf("告警内容异常：%q", got)
	}
}

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

// TestEnsurePrivateChecksOwner 验证 Unix 上拒绝属于其他普通用户的目录。
// 非 root 测试环境无法 chown，跳过该分支。
func TestEnsurePrivateChecksOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 的属主检查由 owner_windows.go 实现，普通测试目录属主为当前用户，应通过。
		if err := ensurePrivate(filepath.Join(t.TempDir(), "win-ok")); err != nil {
			t.Fatalf("当前用户拥有的目录应被接受：%v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("非 root 环境无法把目录 chown 给其他用户")
	}
	dir := filepath.Join(t.TempDir(), "other-owner")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skipf("chown 失败，跳过：%v", err)
	}
	if err := ensurePrivate(dir); err == nil || !strings.Contains(err.Error(), "属主") {
		t.Fatalf("其他用户拥有的目录应被拒绝，实际 err=%v", err)
	}
}

// TestEnsurePrivateTightensWidePermissions 验证已存在且属主为当前用户的宽权限目录
// 会收紧到 0700（MkdirAll 不会修改已存在目录的权限）。
func TestEnsurePrivateTightensWidePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不适用 POSIX 权限")
	}
	dir := filepath.Join(t.TempDir(), "wide")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivate(dir); err != nil {
		t.Fatalf("当前用户拥有的宽权限目录应可用（仅告警并收紧）：%v", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("状态目录权限 = %04o，期望收紧到 0700", perm)
	}
}
