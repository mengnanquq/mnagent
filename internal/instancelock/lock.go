// Package instancelock 提供按令牌派生的单实例文件锁。
//
// 服务端对每台主机最多保留 2 条 WebSocket 连接，超出时会踢掉最旧的。若同一令牌
// 意外启动多个 mnagent（例如重复 systemd 单元、手工再跑一次），这些进程会互相
// 踢线，表现为任务反复重连、结果时有时无。启动时先抢锁可以尽早失败并给出明确提示。
package instancelock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// errLocked 表示锁已被其他进程持有（由平台实现返回）。
var errLocked = errors.New("锁已被占用")

// Lock 是一个已持有的排他文件锁。进程退出时操作系统会自动释放，
// 因此无需依赖正常 Close（但仍应 defer Close 以便及时释放）。
type Lock struct {
	f    *os.File
	path string
}

// Path 返回锁文件路径（便于日志与错误提示）。
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close 释放锁并关闭文件；重复调用安全。
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlockErr := unlockFile(l.f)
	closeErr := l.f.Close()
	l.f = nil
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

// Acquire 在 dir 下获取名为 name 的排他锁。
//
// wait > 0 时会在锁被占用时重试一段时间（自更新/服务重启时旧进程退出与新进程
// 启动可能短暂重叠），超时后返回明确错误；wait == 0 表示只尝试一次。
func Acquire(dir, name string, wait time.Duration) (*Lock, error) {
	return AcquireWithWarn(dir, name, wait, nil)
}

// AcquireWithWarn 与 Acquire 相同，但只在锁确实被另一个实例占用时返回错误。
// 文件系统不支持 flock（ENOTSUP）、目录不可写（EACCES）等平台/权限问题只通过
// warn 回调告警并返回 (nil, nil) 继续运行：单实例是防重复启停的优化，不应成为
// 设备上唯一阻止 agent 工作的原因。
func AcquireWithWarn(dir, name string, wait time.Duration, warn func(error)) (*Lock, error) {
	if dir == "" {
		return nil, errors.New("单实例锁目录为空")
	}
	if name == "" {
		name = "instance"
	}
	path := filepath.Join(dir, name+".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		if warn != nil {
			warn(fmt.Errorf("打开锁文件失败：%w", err))
		}
		return nil, nil
	}
	deadline := time.Now().Add(wait)
	for {
		err := tryLock(f)
		if err == nil {
			// 记录持有者 PID，方便排查遗留锁（内容仅供诊断，不参与加锁语义）。
			_ = f.Truncate(0)
			_, _ = f.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0)
			return &Lock{f: f, path: path}, nil
		}
		if !errors.Is(err, errLocked) {
			_ = f.Close()
			if warn != nil {
				warn(fmt.Errorf("获取单实例锁失败（%s）：%w", path, err))
			}
			return nil, nil
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("已有另一个 mnagent 实例在运行（锁文件 %s 被占用）", path)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Name 按机器人地址与令牌派生稳定的锁名：同一令牌的多个进程会互相冲突，
// 不同令牌（例如同一台机器上的多套部署）互不影响。
func Name(botURL, token string) string {
	h := sha256.New()
	h.Write([]byte(botURL))
	h.Write([]byte{0})
	h.Write([]byte(token))
	return "instance-" + hex.EncodeToString(h.Sum(nil))[:16]
}
