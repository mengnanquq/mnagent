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
	"regexp"
	"strings"
	"syscall"
	"time"
)

// version 由构建时注入（-ldflags "-X main.version=..."），默认 dev。
var version = "dev"

// hostNameRe 限制主机名可用字符：它会出现在请求参数里，也可能被用于日志。
var hostNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

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

	agent := &agent{
		cfg:    cfg,
		logger: log,
		client: newClient(cfg),
		runner: newRunner(cfg.binary, log),
	}
	log.Info("mnagent 已启动",
		"version", version, "bot", cfg.botURL, "host", cfg.host,
		"nexttrace", cfg.binary, "token_from", cfg.tokens.from, "poll_timeout", cfg.pollTimeout)
	return agent.loop(ctx)
}

// parseConfig 解析命令行参数并校验必填项。
func parseConfig(args []string) (*config, error) {
	fs := flag.NewFlagSet("mnagent", flag.ContinueOnError)
	var (
		botURL     = fs.String("bot", "", "机器人 agent 端点基地址，例如 https://mnbot.example.org/agent")
		hostName   = fs.String("host", "", "本机名称，需与机器人 nexttrace_hosts.json 中的 name 一致")
		tokenValue = fs.String("token", "", "接入令牌（不推荐：优先用 -token-file 或 MNAGENT_TOKEN）")
		tokenFile  = fs.String("token-file", "", "存放接入令牌的文件路径（默认 "+defaultTokenFile+"）")
		binary     = fs.String("nexttrace", "nexttrace", "nexttrace 可执行文件路径或在 PATH 中的名称")
		minBackoff = fs.Duration("min-backoff", defaultMinBackoff, "轮询失败后的最小重试间隔")
		maxBackoff = fs.Duration("max-backoff", defaultMaxBackoff, "轮询失败后的最大重试间隔")
		pollWait   = fs.Duration("poll-timeout", defaultPollWait, "单次长轮询的客户端超时")
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

	endpoint := strings.TrimRight(strings.TrimSpace(*botURL), "/")
	if endpoint == "" {
		return nil, errors.New("必须指定 -bot（例如 https://mnbot.example.org/agent）")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("-bot 必须是完整的 http(s) 地址，收到 %q", *botURL)
	}
	if !hostNameRe.MatchString(strings.TrimSpace(*hostName)) {
		return nil, errors.New("-host 只能包含字母、数字、点、下划线与连字符，且不能为空")
	}
	if *minBackoff <= 0 || *maxBackoff < *minBackoff {
		return nil, errors.New("-min-backoff / -max-backoff 不合法")
	}
	if *pollWait <= time.Second {
		return nil, errors.New("-poll-timeout 应大于 1 秒")
	}

	tokens, err := newTokenSource(*tokenValue, *tokenFile)
	if err != nil {
		return nil, err
	}
	path, err := exec.LookPath(*binary)
	if err != nil {
		return nil, fmt.Errorf("找不到 nexttrace 可执行文件 %q：%w", *binary, err)
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
