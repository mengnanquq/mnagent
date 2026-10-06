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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// version 由构建时注入（-ldflags "-X main.version=..."），默认 dev。
var version = "dev"

// hostNameForbidden 是不能出现在主机名里的字符：空白、shell/systemd 元字符，
// 以及会破坏 URL 与路径的字符。主机名会被写进服务单元与命令行，必须挡住它们。
const hostNameForbidden = " \t\n\r/\\'\"`$;&|<>()[]{}*?!~#%,:"

// maxHostNameRunes 限制主机名长度（按字符数计，中文名同样适用）。
const maxHostNameRunes = 32

// validHostName 校验主机名：允许中英文等可见字符（/nexthost add 里可以直接写
// “香港节点”这类名字），但不允许空白、控制字符与上表中的特殊字符。
func validHostName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > maxHostNameRunes {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r == 0x7f || strings.ContainsRune(hostNameForbidden, r) {
			return false
		}
	}
	return true
}

// 默认参数。
const (
	defaultTokenFile  = "/etc/mnagent/token"
	defaultMinBackoff = time.Second
	defaultMaxBackoff = time.Minute
	defaultPollWait   = 40 * time.Second // 机器人侧长轮询最多保持 20 秒。
)

// config 是进程启动参数解析后的运行配置。
type config struct {
	botURL      string
	host        string
	tokens      *tokenSource
	binary      string
	minBackoff  time.Duration
	maxBackoff  time.Duration
	pollTimeout time.Duration
	logLevel    slog.Level

	autoUpdate      bool
	updateInterval  time.Duration
	checkUpdateOnce bool
	applyUpdate     string
	skipUpdate      string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mnagent:", err)
		os.Exit(1)
	}
}

// run 解析参数并进入主循环，直到收到退出信号或发生不可恢复的错误。
func run(args []string) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.logLevel}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// CLI 模式：检查/应用/跳过更新（不进入常驻循环）。
	if handled, err := handleUpdateCLI(cfg, log); handled {
		return err
	}

	agent := &agent{
		cfg:    cfg,
		logger: log,
		client: newClient(cfg),
		runner: newRunner(cfg.binary, log),
		update: newUpdater(cfg, log),
	}
	log.Info("mnagent 已启动",
		"version", version, "bot", cfg.botURL, "host", cfg.host,
		"nexttrace", cfg.binary, "token_from", cfg.tokens.from,
		"poll_timeout", cfg.pollTimeout, "auto_update", cfg.autoUpdate)
	return agent.loop(ctx)
}

// parseConfig 解析命令行参数并校验必填项。
func parseConfig(args []string) (*config, error) {
	fs := flag.NewFlagSet("mnagent", flag.ContinueOnError)
	var (
		botURL     = fs.String("bot", "", "机器人 agent 端点基地址，例如 https://mnbot.example.org/agent")
		hostName   = fs.String("host", "", "本机名称（可选）：令牌已能识别主机，名称仅用于展示；与机器人 /nexthost 里的名称一致时更直观")
		tokenValue = fs.String("token", "", "接入令牌（不推荐：优先用 -token-file 或 MNAGENT_TOKEN）")
		tokenFile  = fs.String("token-file", "", "存放接入令牌的文件路径（默认 "+defaultTokenFile+"）")
		binary     = fs.String("nexttrace", "nexttrace", "nexttrace 可执行文件路径或在 PATH 中的名称")
		minBackoff = fs.Duration("min-backoff", defaultMinBackoff, "轮询失败后的最小重试间隔")
		maxBackoff = fs.Duration("max-backoff", defaultMaxBackoff, "轮询失败后的最大重试间隔")
		pollWait   = fs.Duration("poll-timeout", defaultPollWait, "单次长轮询的客户端超时")
		autoUpdate = fs.Bool("auto-update", false, "自动更新：定期检查 GitHub Releases，有新版本时下载并重启服务")
		updateIntv = fs.Duration("update-interval", autoUpdateDefaultInterval, "自动更新检查间隔")
		checkUpd   = fs.Bool("check-update", false, "检查一次更新后退出（不下载）")
		applyUpd   = fs.String("apply-update", "", "下载并安装指定版本后退出（如 v0.1.7）；latest 表示最新版")
		skipUpd    = fs.String("skip-update", "", "跳过指定版本一段时间（如 v0.1.7，默认 24 小时）")
		logLevel   = fs.String("log-level", "info", "日志级别：debug / info / warn / error")
		showVer    = fs.Bool("version", false, "输出版本后退出")
	)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *showVer {
		fmt.Println("mnagent", version)
		os.Exit(0)
	}

	isUpdateCLI := *checkUpd || strings.TrimSpace(*applyUpd) != "" || strings.TrimSpace(*skipUpd) != ""

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
	// -host 可选：令牌即身份，名称只是给机器人做展示；提供时仍做校验。
	if name := strings.TrimSpace(*hostName); !isUpdateCLI && name != "" && !validHostName(name) {
		return nil, fmt.Errorf("-host 不能超过 %d 个字符，也不能包含空白或特殊字符（如斜杠、引号、美元符号、分号、反引号等）", maxHostNameRunes)
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
	}
	var path string
	if !isUpdateCLI {
		var err error
		path, err = exec.LookPath(*binary)
		if err != nil {
			return nil, fmt.Errorf("找不到 nexttrace 可执行文件 %q：%w", *binary, err)
		}
	} else {
		path = *binary
	}

	if *updateIntv <= 0 {
		*updateIntv = autoUpdateDefaultInterval
	}
	return &config{
		botURL:      endpoint,
		host:        strings.TrimSpace(*hostName),
		tokens:      tokens,
		binary:      path,
		minBackoff:  *minBackoff,
		maxBackoff:  *maxBackoff,
		pollTimeout: *pollWait,
		logLevel:    parseLogLevel(*logLevel),

		autoUpdate:      *autoUpdate,
		updateInterval:  *updateIntv,
		checkUpdateOnce: *checkUpd,
		applyUpdate:     strings.TrimSpace(*applyUpd),
		skipUpdate:      strings.TrimSpace(*skipUpd),
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
		path = defaultTokenFile
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
