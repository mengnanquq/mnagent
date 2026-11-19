package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/updater"
)

// 默认参数。
const (
	DefaultMinBackoff = time.Second
	DefaultMaxBackoff = time.Minute
	DefaultPollWait   = 40 * time.Second // 机器人侧长轮询最多保持 20 秒。
	// 单次 /results 上传超时：必须小于服务端 5 分钟的结果等待，避免服务端先超时。
	DefaultResultTimeout = 4 * time.Minute
	// 一次结果回传（含重试）的整体预算：3 次 × 单次超时不再无限累加。
	DefaultResultTotalTimeout = 6 * time.Minute
	// 退出/重启时的回报预算：必须明显小于 systemd 的 TimeoutStopSec=90s，
	// 否则服务会在等待旧进程回报时被 SIGKILL，反而丢结果。
	DefaultExitResultTimeout = 60 * time.Second
)

// Config 是进程启动参数解析后的运行配置。
type Config struct {
	BotURL          string
	Tokens          *TokenSource
	Binary          string
	MiaospeedBinary string
	MinBackoff      time.Duration
	MaxBackoff      time.Duration
	PollTimeout     time.Duration
	ResultTimeout   time.Duration
	LogLevel        slog.Level

	AutoUpdate         bool
	UpdateInterval     time.Duration
	CheckUpdateOnce    bool
	ApplyUpdate        string
	SkipUpdate         string
	GHProxy            string
	DiagJob            string
	RunDiag            bool
	ProbeTarget        string
	ProbeKind          string
	AllowPrivateProbes bool

	// AllowRemoteDowngrade 允许服务端下发的升级指令把 agent 降级到旧版本。
	// 默认只接受严格高于当前版本的目标；本地 -apply-update 不受此限制。
	AllowRemoteDowngrade bool

	// AllowInsecureHTTP 允许 -bot 使用明文 HTTP 连接公网地址（默认仅允许回环/内网）。
	AllowInsecureHTTP bool
}

// DefaultTokenFile 根据操作系统平台返回默认的令牌文件路径。
func DefaultTokenFile() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd != "" {
			return filepath.Join(pd, "mnagent", "token")
		}
		return "token"
	}
	return "/etc/mnagent/token"
}

// TokenSource 提供接入令牌：来自文件时每次读取，因此轮换令牌无需重启 agent。
type TokenSource struct {
	Value string // 直接给出的令牌（-token 或环境变量）。
	Path  string // 令牌文件路径；非空时优先。
	From  string // 令牌来源描述，仅用于日志。
}

// NewTokenSource 按 -token > MNAGENT_TOKEN > -token-file（含默认路径）的顺序确定令牌来源。
func NewTokenSource(value, file string) (*TokenSource, error) {
	if v := strings.TrimSpace(value); v != "" {
		return &TokenSource{Value: v, From: "-token"}, nil
	}
	if v := strings.TrimSpace(os.Getenv("MNAGENT_TOKEN")); v != "" {
		return &TokenSource{Value: v, From: "MNAGENT_TOKEN"}, nil
	}
	path := strings.TrimSpace(file)
	if path == "" {
		path = DefaultTokenFile()
		if runtime.GOOS == "windows" {
			if _, err := os.Stat(path); err != nil {
				// 优先检查当前可执行文件同目录下的 token（解决 Windows 服务工作目录默认为 C:\Windows\System32 的问题）
				if exe, errExe := os.Executable(); errExe == nil {
					exeToken := filepath.Join(filepath.Dir(exe), "token")
					if _, errToken := os.Stat(exeToken); errToken == nil {
						path = exeToken
					}
				}
				if _, err2 := os.Stat("token"); err2 == nil && path == DefaultTokenFile() {
					path = "token"
				}
			}
		}
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("读取令牌失败：%w（请确认服务用户对 %s 及其所在目录有访问权限——目录需要执行/进入权限；也可用 -token-file 或 MNAGENT_TOKEN 指定）",
			err, path)
	}
	return &TokenSource{Path: path, From: path}, nil
}

// Get 返回当前令牌；文件来源会重新读取以支持在线轮换。
func (t *TokenSource) Get() (string, error) {
	if t == nil {
		return "", errors.New("tokenSource 为空")
	}
	if t.Path == "" {
		return t.Value, nil
	}
	data, err := os.ReadFile(t.Path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	token = strings.TrimPrefix(token, "\ufeff") // 清除 Windows 记事本/PowerShell 等工具保存时附带的 UTF-8 BOM
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("令牌文件 %s 内容为空", t.Path)
	}
	return token, nil
}

// ParseLogLevel 把字符串日志级别映射为 slog 级别。
func ParseLogLevel(raw string) slog.Level {
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

// ParseConfig 解析命令行参数并校验必填项。
func ParseConfig(args []string, version string) (*Config, error) {
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
		tokenFile    = fs.String("token-file", "", "存放接入令牌的文件路径（默认 "+DefaultTokenFile()+"）")
		binary       = fs.String("nexttrace", "nexttrace", "nexttrace 可执行文件路径或在 PATH 中的名称")
		miaospeed    = fs.String("miaospeed", "miaospeed", "miaospeed 可执行文件路径或在 PATH 中的名称")
		minBackoff   = fs.Duration("min-backoff", DefaultMinBackoff, "轮询失败后的最小重试间隔")
		maxBackoff   = fs.Duration("max-backoff", DefaultMaxBackoff, "轮询失败后的最大重试间隔")
		pollWait     = fs.Duration("poll-timeout", DefaultPollWait, "单次长轮询的客户端超时")
		resultWait   = fs.Duration("result-timeout", DefaultResultTimeout, "单次结果回传（含大体积 /results 上传）的客户端超时")
		autoUpdate   = fs.Bool("auto-update", false, "自动更新：定期检查 GitHub Releases，有新版本时下载并重启服务")
		updateIntv   = fs.Duration("update-interval", updater.DefaultInterval, "自动更新检查间隔")
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
		allowDown    = fs.Bool("allow-remote-downgrade", false, "允许服务端远程下发降级到旧版本（默认只接受更高版本；本地 -apply-update 不受限）")
		allowHTTP    = fs.Bool("allow-insecure-http", false, "允许 -bot 使用明文 HTTP 连接公网地址（默认仅允许回环/内网，明文传输令牌有被窃听风险）")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *showVer {
		fmt.Printf("mnagent %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		os.Exit(0)
	}

	isUpdateCLI := *checkUpd || strings.TrimSpace(*applyUpd) != "" || strings.TrimSpace(*skipUpd) != "" || strings.TrimSpace(*diagJob) != "" || *runDiag || strings.TrimSpace(*probeTarget) != ""

	endpoint := strings.TrimRight(*botURL, "/")
	if endpoint == "" && !isUpdateCLI {
		return nil, errors.New("必须指定 -bot（例如 https://mnbot.example.org/agent）")
	}
	if endpoint != "" {
		if err := validateBotEndpoint(endpoint, *allowHTTP); err != nil {
			return nil, err
		}
	}
	if *minBackoff <= 0 || *maxBackoff < *minBackoff {
		return nil, errors.New("-min-backoff / -max-backoff 不合法")
	}
	if *pollWait <= time.Second {
		return nil, errors.New("-poll-timeout 应大于 1 秒")
	}
	if *resultWait <= time.Second {
		return nil, errors.New("-result-timeout 应大于 1 秒")
	}
	if strings.TrimSpace(*probeTarget) != "" {
		switch strings.ToLower(strings.TrimSpace(*probeKind)) {
		case "", "ping", "tcping", "trace", "http", "dns":
		default:
			return nil, fmt.Errorf("-probe-kind 取值非法：%q（可选：ping / tcping / trace / http / dns）", *probeKind)
		}
	}

	var tokens *TokenSource
	if !isUpdateCLI {
		var err error
		tokens, err = NewTokenSource(*tokenValue, *tokenFile)
		if err != nil {
			return nil, err
		}
	} else if *runDiag {
		// 诊断模式下如果存在令牌文件，尝试读取以供诊断看板展示状态
		tokens, _ = NewTokenSource(*tokenValue, *tokenFile)
	}
	var path string
	if !isUpdateCLI {
		if p, ok := dep.ResolveBinaryPath(*binary); ok {
			path = p
		} else if filepath.IsAbs(*binary) || strings.Contains(*binary, string(filepath.Separator)) {
			return nil, fmt.Errorf("找不到指定的 nexttrace 可执行文件 %q", *binary)
		} else {
			path = *binary
		}
	} else {
		path = *binary
	}

	var miaoPath string
	if p, ok := dep.ResolveBinaryPath(*miaospeed); ok {
		miaoPath = p
	} else {
		miaoPath = *miaospeed
	}

	if *updateIntv <= 0 {
		*updateIntv = updater.DefaultInterval
	}
	proxyVal := strings.TrimSpace(*ghProxy)
	if proxyVal == "" {
		proxyVal = strings.TrimSpace(os.Getenv("GH_PROXY"))
	}
	if proxyVal == "" {
		proxyVal = strings.TrimSpace(os.Getenv("MNAGENT_GH_PROXY"))
	}
	return &Config{
		BotURL:               endpoint,
		Tokens:               tokens,
		Binary:               path,
		MiaospeedBinary:      miaoPath,
		MinBackoff:           *minBackoff,
		MaxBackoff:           *maxBackoff,
		PollTimeout:          *pollWait,
		ResultTimeout:        *resultWait,
		LogLevel:             ParseLogLevel(*logLevel),
		AutoUpdate:           *autoUpdate,
		UpdateInterval:       *updateIntv,
		CheckUpdateOnce:      *checkUpd,
		ApplyUpdate:          strings.TrimSpace(*applyUpd),
		SkipUpdate:           strings.TrimSpace(*skipUpd),
		GHProxy:              proxyVal,
		DiagJob:              strings.TrimSpace(*diagJob),
		RunDiag:              *runDiag,
		ProbeTarget:          strings.TrimSpace(*probeTarget),
		ProbeKind:            strings.ToLower(strings.TrimSpace(*probeKind)),
		AllowPrivateProbes:   *allowPrivate,
		AllowRemoteDowngrade: *allowDown,
		AllowInsecureHTTP:    *allowHTTP,
	}, nil
}

// validateBotEndpoint 严格校验 -bot：禁止空白、换行、引号、反斜杠与控制字符，
// 避免这些字符被原样写进服务单元/命令行；同时默认拒绝用明文 HTTP 连接公网地址
// （令牌与探测结果会明文暴露），仅回环/内网 IP 与 localhost 例外。
func validateBotEndpoint(raw string, allowInsecureHTTP bool) error {
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\\' || r == '"' || r == '\'' || r == '`' {
			return fmt.Errorf("-bot 含有非法字符 %q：地址中不允许空白、换行、引号、反斜杠或控制字符", r)
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("-bot 必须是完整的 http(s) 地址，收到 %q", raw)
	}
	if parsed.Scheme == "http" && !isLocalHTTPHost(parsed.Hostname()) {
		if !allowInsecureHTTP {
			return fmt.Errorf("-bot 使用明文 HTTP 连接非回环/内网地址 %q 会被拒绝（令牌与任务内容可能被窃听）；确需使用请显式加 -allow-insecure-http", parsed.Host)
		}
		fmt.Fprintf(os.Stderr, "警告：-bot 使用明文 HTTP 连接 %s，令牌与任务内容可能被窃听，请仅在可信网络使用\n", parsed.Host)
	}
	return nil
}

// isLocalHTTPHost 判断明文 HTTP 的目标是否为回环/内网地址（含 localhost）。
func isLocalHTTPHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}
