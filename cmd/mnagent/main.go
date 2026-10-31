// Package main 实现 mnagent：运行在追踪主机上的轻量 agent。
//
// 它主动向机器人长轮询领取任务、在本机执行 nexttrace、再回传结果，
// 因此主机不需要公网地址、不需要开放任何入站端口，也不需要 SSH。
// 机器人下发的只有已校验的追踪参数，执行哪个程序由本机启动参数决定。
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/isp"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
	"github.com/mengnanquq/mnagent/internal/runner"
	"github.com/mengnanquq/mnagent/internal/service"
	"github.com/mengnanquq/mnagent/internal/tracker"
	"github.com/mengnanquq/mnagent/internal/updater"
)

// version 由构建时注入（-ldflags "-X main.version=..."），默认 dev。
var version = "dev"

func main() {
	if isService, err := service.Run(os.Args[1:], runWithContext); isService {
		if err != nil {
			fmt.Fprintln(os.Stderr, "mnagent service:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mnagent:", err)
		os.Exit(1)
	}
}

// run 解析参数并进入主循环，直到收到退出信号或发生不可恢复的错误。
func run(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, args)
}

// runWithContext 解析参数并在给定的 context 下运行 agent 主体。
func runWithContext(ctx context.Context, args []string) error {
	client.Version = version
	runner.Version = version
	updater.Version = version
	probe.Version = version

	if exe, err := os.Executable(); err == nil {
		updater.CleanupOldExecutables(exe)
	}

	cfg, err := config.ParseConfig(args, version)
	if err != nil {
		return err
	}
	if cfg.Binary != "" {
		if p, ok := dep.ResolveBinaryPath(cfg.Binary); ok {
			updater.CleanupOldExecutables(p)
		}
	}
	if cfg.MiaospeedBinary != "" {
		if p, ok := dep.ResolveBinaryPath(cfg.MiaospeedBinary); ok {
			updater.CleanupOldExecutables(p)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))

	// CLI 模式：检查/应用/跳过更新（不进入常驻循环）。
	if handled, err := runner.HandleUpdateCLI(cfg, log); handled {
		return err
	}

	if cfg.RunDiag {
		return handleDiagCLI(cfg, log)
	}

	if cfg.ProbeTarget != "" {
		return handleProbeCLI(ctx, cfg, log)
	}

	if cfg.DiagJob != "" {
		rnr := runner.NewRunnerFull(cfg.Binary, cfg.MiaospeedBinary, cfg.GHProxy, cfg.AllowPrivateProbes, log)
		res := rnr.Run(ctx, model.Job{
			ID:        "diag",
			Kind:      "miaospeed",
			Target:    cfg.DiagJob,
			Query:     "full",
			TimeoutMS: 180000,
		})
		fmt.Println("================================================================")
		fmt.Println("  ⚡ mnagent 本地测速诊断结果 (Diagnostic Report)")
		fmt.Println("================================================================")
		fmt.Printf("  • 退出代码: %d\n", res.ExitCode)
		if res.ErrText != "" {
			fmt.Printf("  • 错误信息: %s\n", res.ErrText)
		} else {
			fmt.Printf("  • 执行状态: 成功 (OK)\n")
		}
		fmt.Println("----------------------------------------------------------------")
		fmt.Println("  输出详情:")
		if res.Output != "" {
			fmt.Println(res.Output)
		} else {
			fmt.Println("  (无标准输出)")
		}
		fmt.Println("================================================================")
		return nil
	}

	cli := client.New(cfg)
	if cfg.ISP != "" {
		cli.SetISP(cfg.ISP)
		log.Info("已指定探针运营商", "isp", cfg.ISP)
	} else {
		go func() {
			ispProbeClient := &http.Client{Timeout: 4 * time.Second}
			detected := isp.DetectOutboundISP(ctx, ispProbeClient)
			if detected != "" {
				cli.SetISP(detected)
				log.Info("成功探测出站运营商", "isp", detected)
			}
		}()
	}
	trk := tracker.New()
	rnr := runner.NewRunnerFull(cfg.Binary, cfg.MiaospeedBinary, cfg.GHProxy, cfg.AllowPrivateProbes, log)
	rnr.SetProgressReporter(func(p model.Progress) {
		pCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if cancelled, _ := cli.SendProgress(pCtx, p); cancelled {
			trk.Cancel(p.ID)
		}
	})

	upd := runner.NewUpdater(cfg, log)
	agent := runner.NewAgent(cfg, log, cli, rnr, upd, trk)

	if _, ok := dep.ResolveBinaryPath(cfg.Binary); !ok {
		log.Warn("未检测到 nexttrace 可执行文件，路由追踪任务将暂不可用（其它探针与测速正常）", "nexttrace", cfg.Binary)
	}
	if _, ok := dep.ResolveBinaryPath(cfg.MiaospeedBinary); !ok {
		log.Debug("未检测到 miaospeed 可执行文件（仅测速任务需要）", "miaospeed", cfg.MiaospeedBinary)
	}
	tokenFrom := ""
	if cfg.Tokens != nil {
		tokenFrom = cfg.Tokens.From
	}
	log.Info("mnagent 已启动",
		"version", version, "bot", cfg.BotURL,
		"nexttrace", cfg.Binary, "miaospeed", cfg.MiaospeedBinary,
		"token_from", tokenFrom,
		"poll_timeout", cfg.PollTimeout, "auto_update", cfg.AutoUpdate)
	return agent.Loop(ctx)
}
