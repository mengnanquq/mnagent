//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
)

type mnagentWindowsService struct {
	args []string
}

func (s *mnagentWindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	errCh := make(chan error, 1)
	go func() {
		// 优先使用服务启动传入的参数，若为空则退回进程初始启动参数
		svcArgs := s.args
		if len(args) > 1 {
			svcArgs = args[1:]
		}
		errCh <- runWithContext(ctx, svcArgs)
	}()

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-errCh:
				case <-time.After(10 * time.Second):
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case err := <-errCh:
			changes <- svc.Status{State: svc.Stopped}
			if err != nil && !errors.Is(err, context.Canceled) {
				return false, 1 // 非预期异常退出：返回非零退出码，触发 Windows SCM 失败恢复重启
			}
			return false, 0
		}
	}
}

// runService 检测当前进程是否由 Windows 服务控制管理器 (SCM) 启动；若是则以服务模式运行。
func runService(args []string) (bool, error) {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false, err
	}
	if !isSvc {
		return false, nil
	}
	s := &mnagentWindowsService{args: args}
	return true, svc.Run("mnagent", s)
}

// restartWindowsService 重启 Windows 下的 mnagent 服务。
// 为避免当前服务进程同步等待 net stop 导致与 SCM 死锁，启动独立的后台分离进程执行平滑停止并拉起。
func restartWindowsService() error {
	if _, err := exec.LookPath("sc.exe"); err != nil {
		return errors.New("未找到 sc.exe，无法管理 Windows 服务")
	}
	out, err := exec.Command("sc.exe", "query", "mnagent").CombinedOutput()
	if err != nil || (!strings.Contains(string(out), "RUNNING") && !strings.Contains(string(out), "STOPPED")) {
		return errors.New("Windows 环境下未检测到运行中的 mnagent 服务，请手动重启程序")
	}

	// 延迟 1 秒后依次停止与启动服务，给予当前服务进程充分的处理并退出时间
	cmd := exec.Command("cmd.exe", "/c", "ping 127.0.0.1 -n 2 >nul & net stop mnagent & net start mnagent")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 Windows 服务重启任务失败: %w", err)
	}
	return nil
}
