package instancelock

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcquireExclusiveAndRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir, "instance-test", 0)
	if err != nil {
		t.Fatalf("首次获取锁失败: %v", err)
	}
	if _, err := Acquire(dir, "instance-test", 0); err == nil {
		t.Fatal("锁已被占用时第二次获取应失败")
	} else if !strings.Contains(err.Error(), "已有另一个 mnagent 实例") {
		t.Fatalf("错误提示应说明已有实例在运行: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("释放锁失败: %v", err)
	}
	second, err := Acquire(dir, "instance-test", 0)
	if err != nil {
		t.Fatalf("释放后应能重新获取锁: %v", err)
	}
	_ = second.Close()
}

func TestAcquireWaitsForRelease(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir, "instance-wait", 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = first.Close()
	}()
	start := time.Now()
	second, err := Acquire(dir, "instance-wait", 2*time.Second)
	if err != nil {
		t.Fatalf("等待旧实例退出后应能获取锁: %v", err)
	}
	_ = second.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("等待时间异常: %s", elapsed)
	}
}

func TestNameStablePerToken(t *testing.T) {
	a := Name("https://bot.example/agent", "token-a")
	b := Name("https://bot.example/agent", "token-a")
	c := Name("https://bot.example/agent", "token-b")
	d := Name("https://other.example/agent", "token-a")
	if a != b {
		t.Fatalf("同一 bot+令牌应得到相同锁名: %s != %s", a, b)
	}
	if a == c || a == d {
		t.Fatal("不同令牌或不同机器人地址应得到不同锁名，避免误踢其他部署")
	}
	if !strings.HasPrefix(a, "instance-") {
		t.Fatalf("锁名格式异常: %s", a)
	}
}

// TestInstanceLockChild 是 TestLockReleasedWhenProcessExits 的子进程入口：
// 获取锁后直接 os.Exit，不执行 Close，模拟崩溃/被强杀。
func TestInstanceLockChild(t *testing.T) {
	if os.Getenv("MNAGENT_LOCK_CHILD") != "1" {
		return
	}
	dir := os.Getenv("MNAGENT_LOCK_CHILD_DIR")
	lock, err := Acquire(dir, "child", 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = lock // 故意不 Close
	fmt.Println("locked")
	os.Exit(0)
}

// TestLockReleasedWhenProcessExits 验证进程退出（而非正常 Close）后锁会自动释放，
// 这直接对应自更新流程：updater 走 systemd/procd 重启，旧进程退出即释放锁，
// 新进程可以正常获取；不会因为残留锁文件而启动失败。
func TestLockReleasedWhenProcessExits(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestInstanceLockChild")
	cmd.Env = append(os.Environ(),
		"MNAGENT_LOCK_CHILD=1",
		"MNAGENT_LOCK_CHILD_DIR="+dir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("子进程获取锁失败: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "locked") {
		t.Fatalf("子进程未确认已加锁: %s", out)
	}
	lock, err := Acquire(dir, "child", 0)
	if err != nil {
		t.Fatalf("子进程退出后锁应自动释放: %v", err)
	}
	_ = lock.Close()
	if _, err := os.Stat(filepath.Join(dir, "child.lock")); err != nil {
		t.Fatalf("锁文件应保留（内容仅供诊断），实际: %v", err)
	}
}

// TestAcquireWarnsAndContinuesOnNonLockError 验证非“锁被占用”的错误（如目录不可用）
// 只告警并继续运行，不会阻止 agent 启动。
func TestAcquireWarnsAndContinuesOnNonLockError(t *testing.T) {
	// 把父路径做成普通文件，打开 <file>/instance.lock 会得到 ENOTDIR。
	blockedParent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warned error
	lock, err := AcquireWithWarn(blockedParent, "instance", 0, func(cause error) { warned = cause })
	if err != nil {
		t.Fatalf("非锁占用错误不应阻止启动，实际错误: %v", err)
	}
	if lock != nil {
		t.Fatal("无法加锁时应返回 nil lock")
	}
	if warned == nil {
		t.Fatal("非锁占用错误应通过 warn 回调告警")
	}
	if lock, err := Acquire(blockedParent, "instance", 0); err != nil || lock != nil {
		t.Fatalf("Acquire 在非锁占用错误时应继续运行，实际 lock=%v err=%v", lock, err)
	}
}
