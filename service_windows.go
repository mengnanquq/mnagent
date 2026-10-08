//go:build windows

package main

import (
	"context"

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
				<-errCh
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-errCh:
			changes <- svc.Status{State: svc.Stopped}
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
