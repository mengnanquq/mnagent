package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/runner"
	"github.com/mengnanquq/mnagent/internal/updater"
)

// handleDiagCLI 运行本地系统、依赖与网络连通性自检，输出规整的高对比度终端看板。
func handleDiagCLI(cfg *config.Config, log *slog.Logger) error {
	fmt.Println("================================================================")
	fmt.Printf("  ⚡ mnagent %s 本地环境与系统依赖健康自检 (System Diagnostics)\n", version)
	fmt.Println("================================================================")

	// 1. 系统与架构
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	fmt.Printf("  • 主机名称: %s\n", hostname)
	fmt.Printf("  • 操作系统: %s (%s, %d CPUs)\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	fmt.Printf("  • Go 版本:  %s\n", runtime.Version())

	// 2. 依赖二进制检查：NextTrace
	fmt.Println("----------------------------------------------------------------")
	ntPath, ntOk := dep.ResolveBinaryPath(cfg.Binary)
	if ntOk {
		out, _ := exec.Command(ntPath, "-V").CombinedOutput()
		vStr := dep.StripANSI(strings.TrimSpace(string(out)))
		if idx := strings.Index(vStr, "\n"); idx != -1 {
			vStr = vStr[:idx]
		}
		if vStr == "" {
			vStr = "可用 (未返回版本)"
		}
		fmt.Printf("  • NextTrace: 🟢 正常 -> %s (%s)\n", ntPath, vStr)
	} else {
		fmt.Printf("  • NextTrace: 🟡 未就绪 (未在 PATH 中检测到 %s)\n", cfg.Binary)
	}

	// 3. 依赖二进制检查：MiaoSpeed
	miaoPath, miaoOk := dep.ResolveBinaryPath(cfg.MiaospeedBinary)
	if miaoOk {
		out, _ := exec.Command(miaoPath, "-v").CombinedOutput()
		vStr := dep.StripANSI(strings.TrimSpace(string(out)))
		if idx := strings.Index(vStr, "\n"); idx != -1 {
			vStr = vStr[:idx]
		}
		if vStr == "" {
			vStr = "可用 (未返回版本)"
		}
		fmt.Printf("  • MiaoSpeed: 🟢 正常 -> %s (%s)\n", miaoPath, vStr)
	} else {
		fmt.Printf("  • MiaoSpeed: ⚪️ 未检测到 (仅测速任务需要: %s)\n", cfg.MiaospeedBinary)
	}

	// 4. 网络特权 / Raw Socket 检测
	fmt.Println("----------------------------------------------------------------")
	conn, rawErr := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if rawErr == nil {
		conn.Close()
		fmt.Println("  • ICMP 套接字: 🟢 原生套接字权限正常 (CAP_NET_RAW / root 具备)")
	} else {
		uconn, uerr := net.ListenPacket("udp4", "0.0.0.0:0")
		if uerr == nil {
			uconn.Close()
			fmt.Printf("  • ICMP 套接字: 🟡 Raw Socket 受限 (%v)，回退非特权探针模式\n", rawErr)
		} else {
			fmt.Printf("  • ICMP 套接字: 🔴 套接字创建失败: %v\n", rawErr)
		}
	}

	// 5. IPv6 双栈与系统 DNS 解析
	fmt.Println("----------------------------------------------------------------")
	dnsStart := time.Now()
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 2*time.Second)
	addrs, dnsErr := net.DefaultResolver.LookupIP(dnsCtx, "ip", "one.one.one.one")
	dnsCancel()
	if dnsErr == nil && len(addrs) > 0 {
		fmt.Printf("  • 系统 DNS:    🟢 解析正常 (耗时 %v, 目标 one.one.one.one -> %s)\n",
			time.Since(dnsStart).Round(time.Millisecond), addrs[0].String())
	} else {
		fmt.Printf("  • 系统 DNS:    🟡 域名解析异常 (%v)\n", dnsErr)
	}

	v6Conn, v6Err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 1500*time.Millisecond)
	if v6Err == nil {
		v6Conn.Close()
		fmt.Println("  • IPv6 双栈:   🟢 原生 IPv6 出站连通正常 (具备全局单播路由)")
	} else {
		fmt.Println("  • IPv6 双栈:   ⚪️ 仅 IPv4 单栈（无全局 IPv6 出站路由）")
	}

	// 6. 自动更新与 GitHub 下载源连通性
	fmt.Println("----------------------------------------------------------------")
	if cfg.GHProxy != "" {
		fmt.Printf("  • 更新加速源: 🟢 已启用加速代理 -> %s\n", cfg.GHProxy)
	} else {
		fmt.Println("  • 更新加速源: ⚪️ 直连模式 (未配置 --gh-proxy 代理)")
	}
	testGHURL := "https://github.com/mengnanquq/mnagent/releases/latest"
	if cfg.GHProxy != "" {
		testGHURL = updater.ApplyGHProxy(testGHURL, cfg.GHProxy)
	}
	ghStart := time.Now()
	ghClient := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ghResp, ghErr := ghClient.Head(testGHURL)
	ghDur := time.Since(ghStart)
	if ghErr == nil {
		ghResp.Body.Close()
		fmt.Printf("  • Release 源: 🟢 访问正常 (耗时 %v, HTTP %s)\n", ghDur.Round(time.Millisecond), ghResp.Status)
	} else {
		fmt.Printf("  • Release 源: 🟡 访问受限 (%v，建议配置 --gh-proxy 加速)\n", ghErr)
	}

	// 7. 接入凭据状态
	fmt.Println("----------------------------------------------------------------")
	if cfg.Tokens != nil {
		if tok, err := cfg.Tokens.Get(); err == nil && tok != "" {
			masked := tok
			if len(masked) > 8 {
				masked = masked[:4] + "...." + masked[len(masked)-4:]
			}
			fmt.Printf("  • 接入凭据:   🟢 已加载 (来自 %s: %s)\n", cfg.Tokens.From, masked)
		} else {
			fmt.Printf("  • 接入凭据:   🟡 令牌读取失败 (来源 %s: %v)\n", cfg.Tokens.From, err)
		}
	} else {
		fmt.Println("  • 接入凭据:   ⚪️ 未配置令牌 (非守护进程运行模式)")
	}

	// 8. 机器人端点连通性测试
	if cfg.BotURL != "" {
		fmt.Println("----------------------------------------------------------------")
		fmt.Printf("  • 机器人连接: 正在测试出站握手 -> %s\n", cfg.BotURL)
		start := time.Now()
		c := &http.Client{Timeout: 5 * time.Second}
		resp, err := c.Get(cfg.BotURL + "/heartbeat")
		dur := time.Since(start)
		if err == nil {
			resp.Body.Close()
			fmt.Printf("  • 连通结果:   🟢 握手成功 (耗时 %v, HTTP %s)\n", dur.Round(time.Millisecond), resp.Status)
		} else {
			fmt.Printf("  • 连通结果:   🔴 访问失败 (%v)\n", err)
		}
	}
	fmt.Println("================================================================")
	return nil
}

// handleProbeCLI 本地执行探针任务，直接在终端打印结构化诊断结果。
func handleProbeCLI(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	rnr := runner.NewRunnerFull(cfg.Binary, cfg.MiaospeedBinary, cfg.GHProxy, cfg.AllowPrivateProbes, log)
	kind := cfg.ProbeKind
	if kind == "" {
		kind = "ping"
	}

	fmt.Println("================================================================")
	fmt.Printf("  ⚡ mnagent 本地网络探针执行: [%s] -> %s\n", strings.ToUpper(kind), cfg.ProbeTarget)
	fmt.Println("================================================================")

	res := rnr.Run(ctx, model.Job{
		ID:        "cli-probe",
		Kind:      kind,
		Target:    cfg.ProbeTarget,
		Query:     "full",
		TimeoutMS: 30000,
	})

	if res.ExitCode != 0 {
		fmt.Printf("  ❌ 执行失败 (Exit Code %d)\n", res.ExitCode)
		if res.ErrText != "" {
			fmt.Printf("  • 错误信息: %s\n", res.ErrText)
		}
		if res.Output != "" {
			fmt.Printf("  • 详细输出: %s\n", res.Output)
		}
		fmt.Println("================================================================")
		return nil
	}

	fmt.Println("  ✅ 执行成功 (OK)")
	fmt.Println("----------------------------------------------------------------")
	if res.Output != "" {
		fmt.Println(res.Output)
	} else {
		fmt.Println("  (探测完成，无标准输出)")
	}
	fmt.Println("================================================================")
	return nil
}
