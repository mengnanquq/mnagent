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
		out := runDiagCommand(ntPath, "-V")
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
		out := runDiagCommand(miaoPath, "-v")
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
			fmt.Printf("  • 接入凭据:   🟢 %s\n", tokenDiagSummary(cfg.Tokens.From, tok))
		} else {
			fmt.Printf("  • 接入凭据:   🟡 令牌读取失败 (来源 %s: %v)\n", cfg.Tokens.From, err)
		}
	} else {
		fmt.Println("  • 接入凭据:   ⚪️ 未配置令牌 (非守护进程运行模式)")
	}

	// 8. 机器人端点连通性测试
	if cfg.BotURL != "" {
		fmt.Println("----------------------------------------------------------------")
		// 诊断输出常被贴进工单/聊天记录：只打印 scheme://host，不泄露路径（路径里可能带凭据）。
		fmt.Printf("  • 机器人连接: 正在测试出站握手 -> %s\n", config.RedactEndpoint(cfg.BotURL))
		start := time.Now()
		c := &http.Client{Timeout: 5 * time.Second}
		resp, err := c.Get(cfg.BotURL + "/heartbeat")
		dur := time.Since(start)
		if err == nil {
			resp.Body.Close()
			fmt.Printf("  • 连通结果:   🟢 握手成功 (耗时 %v, HTTP %s)\n", dur.Round(time.Millisecond), resp.Status)
		} else {
			fmt.Printf("  • 连通结果:   🔴 访问失败 (%s)\n", redactEndpointInError(cfg.BotURL, err))
		}
	}
	fmt.Println("================================================================")
	return nil
}

// runDiagCommand 带超时执行依赖的版本命令：-diag 是给人现场排障用的，
// 不能让损坏/卡死的二进制把整个自检挂住（以前是无超时的 exec.Command）。
func runDiagCommand(path string, args ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	// 子进程若派生了孙进程并占用输出管道，Wait 会一直等：超时后再多等 2 秒就放弃。
	cmd.WaitDelay = 2 * time.Second
	out, _ := cmd.CombinedOutput()
	return out
}

// redactEndpointInError 把错误文本中的端点替换为脱敏形式（只保留 scheme://host）：
// net/http 的错误会带上完整 URL（含路径），而 -diag 输出常被贴进工单与聊天记录。
func redactEndpointInError(endpoint string, err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if endpoint != "" {
		msg = strings.ReplaceAll(msg, endpoint, config.RedactEndpoint(endpoint))
	}
	return msg
}

// tokenDiagSummary 生成令牌诊断摘要：只暴露来源与长度，绝不打印令牌的任何片段。
// -diag 的输出常被贴进工单/聊天记录，即使首尾各 4 位也可能泄露过多信息。
func tokenDiagSummary(from, token string) string {
	if from == "" {
		from = "未知"
	}
	return fmt.Sprintf("已加载 (来源 %s，长度 %d)", from, len(token))
}

// normalizeLocalProbeKind 归一化本地 -probe-kind，空值默认 ping。
func normalizeLocalProbeKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		return "ping"
	}
	return kind
}

// validateLocalProbeKind 校验本地探针类型，避免把拼写错误静默当成 trace 执行。
func validateLocalProbeKind(kind string) error {
	switch kind {
	case "ping", "tcping", "trace", "http", "dns":
		return nil
	default:
		return fmt.Errorf("不支持的 -probe-kind：%q（可选：ping / tcping / trace / http / dns）", kind)
	}
}

// normalizeProbeTarget 对 http 探针自动补全 https://：用户本地手敲 example.com 时
// 不应该只因为缺少 scheme 就报错。
func normalizeProbeTarget(kind, target string) string {
	target = strings.TrimSpace(target)
	if kind == "http" && target != "" && !strings.Contains(target, "://") {
		return "https://" + target
	}
	return target
}

// localProbeQuery 返回探针默认查询参数；DNS 探针必须使用合法的记录类型。
func localProbeQuery(kind string) string {
	if kind == "dns" {
		return "A"
	}
	return "full"
}

// buildLocalProbeJob 根据 CLI 参数构造本地探针任务。
func buildLocalProbeJob(cfg *config.Config) (model.Job, error) {
	kind := normalizeLocalProbeKind(cfg.ProbeKind)
	if err := validateLocalProbeKind(kind); err != nil {
		return model.Job{}, err
	}
	return model.Job{
		ID:        "cli-probe",
		Kind:      kind,
		Target:    normalizeProbeTarget(kind, cfg.ProbeTarget),
		Query:     localProbeQuery(kind),
		TimeoutMS: 30000,
	}, nil
}

// handleProbeCLI 本地执行探针任务，直接在终端打印结构化诊断结果。
func handleProbeCLI(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	rnr := runner.NewRunnerFull(cfg.Binary, cfg.MiaospeedBinary, cfg.GHProxy, cfg.AllowPrivateProbes, log)
	rnr.SetAllowAutoInstallDeps(cfg.AllowAutoInstallDeps)
	job, err := buildLocalProbeJob(cfg)
	if err != nil {
		return err
	}

	fmt.Println("================================================================")
	fmt.Printf("  ⚡ mnagent 本地网络探针执行: [%s] -> %s\n", strings.ToUpper(job.Kind), job.Target)
	fmt.Println("================================================================")

	res := rnr.Run(ctx, job)

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
