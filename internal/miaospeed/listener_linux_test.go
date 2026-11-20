//go:build linux

package miaospeed

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TestVerifyMiaospeedListenerAcceptsOwnSocket 验证能识别当前进程自己持有的监听套接字。
func TestVerifyMiaospeedListenerAcceptsOwnSocket(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	inodes, err := listeningSocketInodes(port)
	if err != nil {
		t.Fatalf("枚举监听套接字失败: %v", err)
	}
	if len(inodes) == 0 {
		t.Fatalf("未在 /proc/net/tcp{,6} 找到 127.0.0.1:%d 的 LISTEN 套接字", port)
	}
	if err := verifyMiaospeedListener(os.Getpid(), port); err != nil {
		t.Fatalf("当前进程持有的监听套接字应通过归属校验: %v", err)
	}
}

// TestVerifyMiaospeedListenerRejectsForeignProcess 验证窗口期抢占端口的其他进程会被识别并拒绝。
func TestVerifyMiaospeedListenerRejectsForeignProcess(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("系统缺少 sleep，跳过外来进程测试")
	}
	cmd := exec.Command(sleepPath, "30")
	// 与真实调用方一致：子进程使用独立进程组，否则它会和测试进程同组，
	// 按进程组归属校验会误把测试进程自己的套接字算作 sleep 的。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	if err := verifyMiaospeedListener(cmd.Process.Pid, port); err == nil {
		t.Fatal("监听套接字不属于 sleep 子进程，应拒绝")
	}
}

// TestListeningSocketInodesIgnoresWildcardBind 验证 0.0.0.0 上的同端口监听不会被当作
// 我们的 127.0.0.1 监听（否则攻击者绑定通配地址即可绕过归属校验）。
func TestListeningSocketInodesIgnoresWildcardBind(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("无法绑定 0.0.0.0: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	inodes, err := listeningSocketInodes(port)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 0 {
		t.Fatalf("通配地址监听不应匹配回环地址校验，实际 inode=%v", inodes)
	}
}

// TestLoopbackProcAddrEndianness 覆盖 procfs 按主机字节序打印地址的两种形式：
// 小端主机（amd64/arm64）与大端主机（s390x 等）都必须识别回环监听。
func TestLoopbackProcAddrEndianness(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"0100007F", true},                          // 127.0.0.1（小端主机）
		{"7F000001", true},                          // 127.0.0.1（大端主机）
		{"00000000000000000000000001000000", true},  // ::1（小端主机）
		{"00000000000000000000000000000001", true},  // ::1（大端主机）
		{"0000000000000000FFFF00000100007F", true},  // ::ffff:127.0.0.1（小端主机）
		{"00000000000000000000FFFF7F000001", true},  // ::ffff:127.0.0.1（大端主机）
		{"0000000000000000FFFF000001000001", false}, // ::ffff:127.0.0.2
		{"00000000000000000000FFFF7F000002", false}, // ::ffff:127.0.0.2
		{"0200007F", false},                         // 127.0.0.2
		{"7F000002", false},                         // 127.0.0.2（大端主机）
		{"", false},
		{"0100007", false},  // 长度非法
		{"XYZ", false},      // 非十六进制
		{"0A00007F", false}, // 10.0.0.127，非回环
	}
	for _, tc := range cases {
		if got := isLoopbackProcAddr(tc.addr); got != tc.want {
			t.Errorf("isLoopbackProcAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// fakeProc 在临时目录中构造最小 procfs 结构，避免依赖真实 /proc 的进程与权限。
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	p := &fakeProc{t: t, root: t.TempDir()}
	old := procRoot
	procRoot = p.root
	oldWarn := listenerWarnf
	t.Cleanup(func() {
		procRoot = old
		listenerWarnf = oldWarn
	})
	return p
}

func (p *fakeProc) writeFile(rel, content string) {
	p.t.Helper()
	path := filepath.Join(p.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

// tcpLine 生成 /proc/net/tcp 的一行 LISTEN 记录（10 列，inode 位于第 10 列）。
func tcpLine(localAddr string, port int, inode string) string {
	return fmt.Sprintf("  0: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %s 1 0 0 10 0\n",
		localAddr, port, inode)
}

func (p *fakeProc) addProc(pid, pgid int) {
	p.t.Helper()
	p.writeFile(filepath.Join(strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (miaospeed) S 1 %d %d 0 -1 4194560 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, pgid, pgid))
	if err := os.MkdirAll(filepath.Join(p.root, strconv.Itoa(pid), "fd"), 0o755); err != nil {
		p.t.Fatal(err)
	}
}

func (p *fakeProc) addSocketFD(pid int, fd, inode string) {
	p.t.Helper()
	dir := filepath.Join(p.root, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, fd)); err != nil {
		p.t.Fatal(err)
	}
}

// TestVerifyMiaospeedListenerFakeProc 覆盖大端主机、进程组孙进程、外来进程组与
// procfs 不可读四类结果（使用伪造 procRoot，不依赖真实内核状态）。
func TestVerifyMiaospeedListenerFakeProc(t *testing.T) {
	const port = 18080
	const inode = "4242"

	t.Run("大端主机的监听套接字属于子进程", func(t *testing.T) {
		p := newFakeProc(t)
		p.writeFile("net/tcp", "header\n"+tcpLine("7F000001", port, inode))
		p.addProc(100, 100)
		p.addSocketFD(100, "3", inode)
		if err := verifyMiaospeedListener(100, port); err != nil {
			t.Fatalf("大端形式 7F000001 应被识别为回环且归属匹配: %v", err)
		}
	})

	t.Run("监听套接字由同进程组的孙进程持有", func(t *testing.T) {
		p := newFakeProc(t)
		p.writeFile("net/tcp", "header\n"+tcpLine("0100007F", port, inode))
		p.addProc(100, 100) // 子进程本身
		p.addProc(101, 100) // 同组的孙进程
		p.addSocketFD(101, "5", inode)
		if err := verifyMiaospeedListener(100, port); err != nil {
			t.Fatalf("同进程组内任意进程持有监听套接字都应通过: %v", err)
		}
	})

	t.Run("监听套接字属于其他进程组判为抢占", func(t *testing.T) {
		p := newFakeProc(t)
		p.writeFile("net/tcp", "header\n"+tcpLine("0100007F", port, inode))
		p.addProc(100, 100)
		p.addProc(200, 999)
		p.addSocketFD(200, "3", inode)
		err := verifyMiaospeedListener(100, port)
		if err == nil || !strings.Contains(err.Error(), "抢占") {
			t.Fatalf("其他进程组持有监听套接字应判定抢占，实际 err=%v", err)
		}
	})

	t.Run("procfs 不可读时降级放行且只告警一次", func(t *testing.T) {
		p := newFakeProc(t)
		// 把 net/tcp 做成目录：open 成功但读取会返回 EISDIR，模拟 /proc 受限。
		if err := os.MkdirAll(filepath.Join(p.root, "net", "tcp"), 0o755); err != nil {
			t.Fatal(err)
		}
		var warns int
		listenerWarnf = func(string, ...any) { warns++ }
		listenerWarnOnce = sync.Once{}
		for i := 0; i < 2; i++ {
			if err := verifyMiaospeedListener(100, port); err != nil {
				t.Fatalf("procfs 不可读时应降级放行，实际 err=%v", err)
			}
		}
		if warns != 1 {
			t.Fatalf("“无法校验”告警在进程内应只输出一次，实际 %d 次", warns)
		}
	})
}
