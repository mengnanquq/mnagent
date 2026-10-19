// Package main 实现 mnagent：运行在追踪主机上的轻量 agent。
//
// 它主动向机器人长轮询领取任务、在本机执行 nexttrace、再回传结果，
// 因此主机不需要公网地址、不需要开放任何入站端口，也不需要 SSH。
// 机器人下发的只有已校验的追踪参数，执行哪个程序由本机启动参数决定。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// version 由构建时注入（-ldflags "-X main.version=..."），默认 dev。
var version = "dev"

// defaultTokenFile 根据操作系统平台返回默认的令牌文件路径。
func defaultTokenFile() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd != "" {
			return filepath.Join(pd, "mnagent", "token")
		}
		return "token"
	}
	return "/etc/mnagent/token"
}

// 默认参数。
const (
	defaultMinBackoff = time.Second
	defaultMaxBackoff = time.Minute
	defaultPollWait   = 40 * time.Second // 机器人侧长轮询最多保持 20 秒。
)

// config 是进程启动参数解析后的运行配置。
type config struct {
	botURL          string
	tokens          *tokenSource
	binary          string
	miaospeedBinary string
	minBackoff      time.Duration
	maxBackoff      time.Duration
	pollTimeout     time.Duration
	logLevel        slog.Level

	autoUpdate         bool
	updateInterval     time.Duration
	checkUpdateOnce    bool
	applyUpdate        string
	skipUpdate         string
	ghProxy            string
	diagJob            string
	runDiag            bool
	probeTarget        string
	probeKind          string
	allowPrivateProbes bool
}

func main() {
	if isService, err := runService(os.Args[1:]); isService {
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
	if exe, err := os.Executable(); err == nil {
		cleanupOldExecutables(exe)
	}

	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.logLevel}))

	// CLI 模式：检查/应用/跳过更新（不进入常驻循环）。
	if handled, err := handleUpdateCLI(cfg, log); handled {
		return err
	}

	if cfg.runDiag {
		return handleDiagCLI(cfg, log)
	}

	if cfg.probeTarget != "" {
		return handleProbeCLI(ctx, cfg, log)
	}

	if cfg.diagJob != "" {
		runner := newRunnerFull(cfg.binary, cfg.miaospeedBinary, cfg.ghProxy, cfg.allowPrivateProbes, log)
		res := runner.run(ctx, Job{
			ID:        "diag",
			Kind:      "miaospeed",
			Target:    cfg.diagJob,
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

	cli := newClient(cfg)
	tracker := newJobTracker()
	rnr := newRunnerFull(cfg.binary, cfg.miaospeedBinary, cfg.ghProxy, cfg.allowPrivateProbes, log)
	rnr.setProgressReporter(func(p Progress) {
		pCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if cancelled, _ := cli.sendProgress(pCtx, p); cancelled {
			tracker.Cancel(p.ID)
		}
	})

	agent := &agent{
		cfg:     cfg,
		logger:  log,
		client:  cli,
		runner:  rnr,
		update:  newUpdater(cfg, log),
		tracker: tracker,
	}
	log.Info("mnagent 已启动",
		"version", version, "bot", cfg.botURL,
		"nexttrace", cfg.binary, "miaospeed", cfg.miaospeedBinary,
		"token_from", cfg.tokens.from,
		"poll_timeout", cfg.pollTimeout, "auto_update", cfg.autoUpdate)
	return agent.loop(ctx)
}

// parseConfig 解析命令行参数并校验必填项。
func parseConfig(args []string) (*config, error) {
	fs := flag.NewFlagSet("mnagent", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "⚡ mnagent %s (%s/%s) - 猛男 Bot 拨测探针客户端\n\n", version, runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(fs.Output(), "用法：\n")
		fmt.Fprintf(fs.Output(), "  mnagent -bot <URL> -token-file <路径> [选项...]\n\n")
		fmt.Fprintf(fs.Output(), "参数选项：\n")
		fs.PrintDefaults()
	}
	var (
		botURL       = fs.String("bot", "", "机器人 agent 端点基地址，例如 https://mnbot.example.org/agent")
		tokenValue   = fs.String("token", "", "接入令牌（不推荐：优先用 -token-file 或 MNAGENT_TOKEN）")
		tokenFile    = fs.String("token-file", "", "存放接入令牌的文件路径（默认 "+defaultTokenFile()+"）")
		binary       = fs.String("nexttrace", "nexttrace", "nexttrace 可执行文件路径或在 PATH 中的名称")
		miaospeed    = fs.String("miaospeed", "miaospeed", "miaospeed 可执行文件路径或在 PATH 中的名称")
		minBackoff   = fs.Duration("min-backoff", defaultMinBackoff, "轮询失败后的最小重试间隔")
		maxBackoff   = fs.Duration("max-backoff", defaultMaxBackoff, "轮询失败后的最大重试间隔")
		pollWait     = fs.Duration("poll-timeout", defaultPollWait, "单次长轮询的客户端超时")
		autoUpdate   = fs.Bool("auto-update", false, "自动更新：定期检查 GitHub Releases，有新版本时下载并重启服务")
		updateIntv   = fs.Duration("update-interval", autoUpdateDefaultInterval, "自动更新检查间隔")
		checkUpd     = fs.Bool("check-update", false, "检查一次更新后退出（不下载）")
		applyUpd     = fs.String("apply-update", "", "下载并安装指定版本后退出（如 v0.1.7）；latest 表示最新版")
		skipUpd      = fs.String("skip-update", "", "跳过指定版本一段时间（如 v0.1.7，默认 24 小时）")
		ghProxy      = fs.String("gh-proxy", "", "GitHub 代理加速前缀，例如 https://gh-proxy.com/")
		logLevel     = fs.String("log-level", "info", "日志级别：debug / info / warn / error")
		showVer      = fs.Bool("version", false, "输出版本后退出")
			diagJob      = fs.String("diag-job", "", "本地直接执行一次测速任务并输出调试信息后退出")
			runDiag      = fs.Bool("diag", false, "执行本地环境与系统依赖健康自检并输出诊断看板后退出")
			probeTarget  = fs.String("probe-target", "", "本地直接执行一次探针网络测试的目标（域名或 IP）")
			probeKind    = fs.String("probe-kind", "ping", "本地探针类型：ping / tcping / trace / http / dns")
			allowPrivate = fs.Bool("allow-private-probes", false, "允许探测内网私有地址与链路本地地址（默认禁止，防范 SSRF/云元数据盗取）")
		)
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if *showVer {
			fmt.Printf("mnagent %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			os.Exit(0)
		}

		isUpdateCLI := *checkUpd || strings.TrimSpace(*applyUpd) != "" || strings.TrimSpace(*skipUpd) != "" || strings.TrimSpace(*diagJob) != "" || *runDiag || strings.TrimSpace(*probeTarget) != ""

	endpoint := strings.TrimRight(strings.TrimSpace(*botURL), "/")
	if endpoint == "" && !isUpdateCLI {
		return nil, errors.New("必须指定 -bot（例如 https://mnbot.example.org/agent）")
	}
	if endpoint != "" {
		parsed, err := url.Parse(endpoint)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("-bot 必须是完整的 http(s) 地址，收到 %q", *botURL)
		}
	}
	if *minBackoff <= 0 || *maxBackoff < *minBackoff {
		return nil, errors.New("-min-backoff / -max-backoff 不合法")
	}
	if *pollWait <= time.Second {
		return nil, errors.New("-poll-timeout 应大于 1 秒")
	}

	var tokens *tokenSource
	if !isUpdateCLI {
		var err error
		tokens, err = newTokenSource(*tokenValue, *tokenFile)
		if err != nil {
			return nil, err
		}
	} else if *runDiag {
		// 诊断模式下如果存在令牌文件，尝试读取以供诊断看板展示状态
		tokens, _ = newTokenSource(*tokenValue, *tokenFile)
	}
	var path string
	if !isUpdateCLI {
		if p, ok := resolveBinaryPath(*binary); ok {
			path = p
		} else {
			var err error
			path, err = exec.LookPath(*binary)
			if err != nil {
				return nil, fmt.Errorf("找不到 nexttrace 可执行文件 %q：%w", *binary, err)
			}
		}
	} else {
		path = *binary
	}

	var miaoPath string
	if p, ok := resolveBinaryPath(*miaospeed); ok {
		miaoPath = p
	} else {
		miaoPath = *miaospeed
	}

	if *updateIntv <= 0 {
		*updateIntv = autoUpdateDefaultInterval
	}
	proxyVal := strings.TrimSpace(*ghProxy)
	if proxyVal == "" {
		proxyVal = strings.TrimSpace(os.Getenv("GH_PROXY"))
	}
	if proxyVal == "" {
		proxyVal = strings.TrimSpace(os.Getenv("MNAGENT_GH_PROXY"))
	}
	return &config{
		botURL:          endpoint,
		tokens:          tokens,
		binary:          path,
		miaospeedBinary: miaoPath,
		minBackoff:      *minBackoff,
		maxBackoff:      *maxBackoff,
		pollTimeout:     *pollWait,
		logLevel:        parseLogLevel(*logLevel),

		autoUpdate:         *autoUpdate,
		updateInterval:     *updateIntv,
		checkUpdateOnce:    *checkUpd,
		applyUpdate:        strings.TrimSpace(*applyUpd),
		skipUpdate:         strings.TrimSpace(*skipUpd),
		ghProxy:            proxyVal,
		diagJob:            strings.TrimSpace(*diagJob),
		runDiag:            *runDiag,
		probeTarget:        strings.TrimSpace(*probeTarget),
		probeKind:          strings.ToLower(strings.TrimSpace(*probeKind)),
		allowPrivateProbes: *allowPrivate,
	}, nil
}

// parseLogLevel 把字符串日志级别映射为 slog 级别。
func parseLogLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// tokenSource 提供接入令牌：来自文件时每次读取，因此轮换令牌无需重启 agent。
type tokenSource struct {
	value string // 直接给出的令牌（-token 或环境变量）。
	path  string // 令牌文件路径；非空时优先。
	from  string // 令牌来源描述，仅用于日志。
}

// newTokenSource 按 -token > MNAGENT_TOKEN > -token-file（含默认路径）的顺序确定令牌来源。
func newTokenSource(value, file string) (*tokenSource, error) {
	if v := strings.TrimSpace(value); v != "" {
		return &tokenSource{value: v, from: "-token"}, nil
	}
	if v := strings.TrimSpace(os.Getenv("MNAGENT_TOKEN")); v != "" {
		return &tokenSource{value: v, from: "MNAGENT_TOKEN"}, nil
	}
	path := strings.TrimSpace(file)
	if path == "" {
		path = defaultTokenFile()
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(path); err != nil {
				if _, err2 := os.Stat("token"); err2 == nil {
					path = "token"
				}
			}
		}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("读取令牌失败：%w（请确认服务用户对 %s 及其所在目录有访问权限——目录需要执行/进入权限；也可用 -token-file 或 MNAGENT_TOKEN 指定）",
			err, path)
	}
	return &tokenSource{path: path, from: path}, nil
}

// get 返回当前令牌；文件来源会重新读取以支持在线轮换。
func (t *tokenSource) get() (string, error) {
	if t.path == "" {
		return t.value, nil
	}
	data, err := os.ReadFile(t.path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("令牌文件 %s 内容为空", t.path)
	}
	return token, nil
}

// handleDiagCLI 运行本地系统、依赖与网络连通性自检，输出规整的高对比度终端看板。
func handleDiagCLI(cfg *config, log *slog.Logger) error {
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
	ntPath, ntOk := resolveBinaryPath(cfg.binary)
	if ntOk {
		out, _ := exec.Command(ntPath, "-V").CombinedOutput()
		vStr := stripANSI(strings.TrimSpace(string(out)))
		if idx := strings.Index(vStr, "\n"); idx != -1 {
			vStr = vStr[:idx]
		}
		if vStr == "" {
			vStr = "可用 (未返回版本)"
		}
		fmt.Printf("  • NextTrace: 🟢 正常 -> %s (%s)\n", ntPath, vStr)
	} else {
		fmt.Printf("  • NextTrace: 🟡 未就绪 (未在 PATH 中检测到 %s)\n", cfg.binary)
	}

	// 3. 依赖二进制检查：MiaoSpeed
	miaoPath, miaoOk := resolveBinaryPath(cfg.miaospeedBinary)
	if miaoOk {
		out, _ := exec.Command(miaoPath, "-v").CombinedOutput()
		vStr := stripANSI(strings.TrimSpace(string(out)))
		if idx := strings.Index(vStr, "\n"); idx != -1 {
			vStr = vStr[:idx]
		}
		if vStr == "" {
			vStr = "可用 (未返回版本)"
		}
		fmt.Printf("  • MiaoSpeed: 🟢 正常 -> %s (%s)\n", miaoPath, vStr)
	} else {
		fmt.Printf("  • MiaoSpeed: ⚪️ 未检测到 (仅测速任务需要: %s)\n", cfg.miaospeedBinary)
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

	// 5. 接入凭据状态
	if cfg.tokens != nil {
		if tok, err := cfg.tokens.get(); err == nil && tok != "" {
			masked := tok
			if len(masked) > 8 {
				masked = masked[:4] + "...." + masked[len(masked)-4:]
			}
			fmt.Printf("  • 接入凭据: 🟢 已加载 (来自 %s: %s)\n", cfg.tokens.from, masked)
		} else {
			fmt.Printf("  • 接入凭据: 🟡 令牌读取失败 (来源 %s: %v)\n", cfg.tokens.from, err)
		}
	} else {
		fmt.Println("  • 接入凭据: ⚪️ 未配置令牌 (非守护进程运行模式)")
	}

	// 6. 机器人端点连通性测试
	if cfg.botURL != "" {
		fmt.Println("----------------------------------------------------------------")
		fmt.Printf("  • 机器人连接: 正在测试出站握手 -> %s\n", cfg.botURL)
		start := time.Now()
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(cfg.botURL + "/heartbeat")
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
func handleProbeCLI(ctx context.Context, cfg *config, log *slog.Logger) error {
	runner := newRunnerFull(cfg.binary, cfg.miaospeedBinary, cfg.ghProxy, cfg.allowPrivateProbes, log)
	kind := cfg.probeKind
	if kind == "" {
		kind = "ping"
	}

	fmt.Println("================================================================")
	fmt.Printf("  ⚡ mnagent 本地网络探针执行: [%s] -> %s\n", strings.ToUpper(kind), cfg.probeTarget)
	fmt.Println("================================================================")

	res := runner.run(ctx, Job{
		ID:        "cli-probe",
		Kind:      kind,
		Target:    cfg.probeTarget,
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
