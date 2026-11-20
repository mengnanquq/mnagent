package updater

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mengnanquq/mnagent/internal/statedir"
)

// 自动更新默认配置。
const (
	DefaultInterval        = 6 * time.Hour
	DefaultJitter          = 10 * time.Minute
	DefaultCheckTimeout    = 10 * time.Second
	DefaultDownloadTimeout = 5 * time.Minute
	// DefaultChecksumTimeout 是获取 .sha256 校验文件的独立短超时：
	// 校验文件很小，不应沿用 5 分钟的二进制下载超时，避免离线/被墙时长时间挂起。
	DefaultChecksumTimeout = 30 * time.Second
	// DefaultVersionQueryTimeout 是版本查询（含 GitHub API 兜底）的独立短超时：
	// 版本查询只决定“是否有新版本”，卡住时不应让更新流程（乃至调用方）长时间等待。
	DefaultVersionQueryTimeout = 20 * time.Second
	minBinaryBytes             = 1024 // 校验下载内容不是 404 HTML 或空文件。
)

// maxBinaryBytes 限制单次更新下载的二进制体积（128MB）。
// 变量而非常量，便于测试缩短；生产环境保持 128MB。
var maxBinaryBytes int64 = 128 << 20

// Version 是默认版本号（未指定时使用）。
var Version = "dev"

// VersionInfo 保存语义化版本信息。
type VersionInfo struct {
	Major    int
	Minor    int
	Patch    int
	Pre      string
	Raw      string
	IsSemver bool
}

var releaseTagPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// ValidReleaseTag 判断字符串是否为可安全拼入下载地址的发布版本号（如 v1.2.3、v1.2.3-rc.1）。
func ValidReleaseTag(s string) bool {
	return releaseTagPattern.MatchString(s)
}

// ParseVersion 解析版本字符串。
func ParseVersion(s string) (VersionInfo, bool) {
	raw := strings.TrimSpace(s)
	v := strings.TrimPrefix(raw, "v")
	parts := strings.SplitN(v, "-", 2)
	pre := ""
	if len(parts) == 2 {
		pre = parts[1]
	}
	nums := strings.Split(parts[0], ".")
	if len(nums) != 3 {
		return VersionInfo{Raw: raw}, false
	}
	major, err1 := strconv.Atoi(nums[0])
	minor, err2 := strconv.Atoi(nums[1])
	patch, err3 := strconv.Atoi(nums[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return VersionInfo{Raw: raw}, false
	}
	return VersionInfo{
		Major:    major,
		Minor:    minor,
		Patch:    patch,
		Pre:      pre,
		Raw:      raw,
		IsSemver: true,
	}, true
}

// NewerThan 比较两个版本，当 v 晚于 other 时返回 true。
func (v VersionInfo) NewerThan(other VersionInfo) bool {
	if !v.IsSemver || !other.IsSemver {
		return false
	}
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	if v.Patch != other.Patch {
		return v.Patch > other.Patch
	}
	if v.Pre == "" && other.Pre != "" {
		return true // 正式版晚于同编号的预发布
	}
	if v.Pre != "" && other.Pre == "" {
		return false
	}
	return comparePrerelease(v.Pre, other.Pre) > 0
}

// comparePrerelease 按 semver 2.0 比较预发布段：
// 以 . 拆分逐段比较；纯数字段按数值比较且低于字母段；前缀相同时段数少者小。
// 返回 -1、0、1 表示 a 小于、等于、大于 b。
func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		aNum := isNumericPrerelease(as[i])
		bNum := isNumericPrerelease(bs[i])
		switch {
		case aNum && bNum:
			return compareNumericPrerelease(as[i], bs[i])
		case aNum:
			return -1 // 数字段低于字母段
		case bNum:
			return 1
		case as[i] < bs[i]:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	default:
		return 0
	}
}

// isNumericPrerelease 判断预发布段是否为纯数字。
func isNumericPrerelease(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumericPrerelease 按任意长度数值比较两个纯数字预发布段，
// 避免 strconv.Atoi 在超长数字上溢出后退化为字符串比较。
func compareNumericPrerelease(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Logger 是更新器用到的最小日志接口；未注入时退化为 slog 默认 logger。
type Logger interface {
	Warn(msg string, args ...any)
}

// Config 是构建 Updater 所需的参数。
type Config struct {
	CurrentVersion string
	Repo           string
	Platform       string
	Arch           string
	Executable     string
	SkipFile       string
	GHProxy        string
	Restart        func() error
	Client         *http.Client
	DownloadClient *http.Client

	// Logger 用于输出来源信任相关的安全告警；未设置时使用 slog 默认 logger。
	Logger Logger

	// BotDigest 是服务端代取校验值的客户端；为 nil 时只使用直连来源。
	BotDigest *BotDigestClient
}

// Updater 负责检查并应用自身的新版本。
type Updater struct {
	CurrentVersion string
	Repo           string
	Platform       string
	Arch           string
	Client         *http.Client
	DownloadClient *http.Client
	Executable     string
	SkipFile       string
	GHProxy        string
	RestartFunc    func() error

	LatestURLFunc      func() string
	URLForFunc         func(version string) string
	ChecksumURLFunc    func(version string) string
	ChecksumAPIURLFunc func(version string) string
	APIURLFunc         func() string

	// verifyBinary 在替换前执行下载的临时文件，确认其可运行且版本匹配。
	// 测试可注入空实现；生产环境使用 verifyDownloadedBinary。
	verifyBinary func(ctx context.Context, path, version string) error

	logger Logger

	// botDigest 是服务端代取校验值的客户端；nil 表示不启用（只走直连来源）。
	botDigest *BotDigestClient

	// checksumTimeout 仅用于测试缩短校验文件请求超时；0 表示 DefaultChecksumTimeout。
	checksumTimeout time.Duration

	// applyMu 串行化 DownloadAndReplace/Apply，避免后台自动更新与远程升级
	// 同时替换二进制或互相覆盖临时文件。
	applyMu sync.Mutex
}

// New 创建一个新的 Updater 实例。
func New(cfg Config) *Updater {
	repo := cfg.Repo
	if repo == "" {
		repo = "mengnanquq/mnagent"
	}
	platform, arch := cfg.Platform, cfg.Arch
	if platform == "" || arch == "" {
		p, a := DetectPlatformArch()
		if platform == "" {
			platform = p
		}
		if arch == "" {
			arch = a
		}
	}
	cli := cfg.Client
	if cli == nil {
		cli = &http.Client{
			Timeout: DefaultCheckTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	dlCli := cfg.DownloadClient
	if dlCli == nil {
		dlCli = &http.Client{
			Timeout: DefaultDownloadTimeout,
		}
	}
	skipFile := cfg.SkipFile
	if skipFile == "" {
		// 跳过记录决定是否自动安装新版本，必须放在私有状态目录，不能放在所有用户可写的 /tmp；
		// 状态目录不可用时为空串，即不记录跳过（宁可重复尝试更新）。
		skipFile = statedir.Path("skip-versions")
	}
	curVer := cfg.CurrentVersion
	if curVer == "" {
		curVer = Version
	}
	return &Updater{
		CurrentVersion: curVer,
		Repo:           repo,
		Platform:       platform,
		Arch:           arch,
		Client:         cli,
		DownloadClient: dlCli,
		Executable:     cfg.Executable,
		SkipFile:       skipFile,
		GHProxy:        cfg.GHProxy,
		RestartFunc:    cfg.Restart,
		verifyBinary:   verifyDownloadedBinary,
		logger:         cfg.Logger,
		botDigest:      cfg.BotDigest,
	}
}

// AssetName 返回当前平台的 Release 资产名（与安装脚本的命名一致）。
func (u *Updater) AssetName() string {
	name := "mnagent_" + u.Platform + "_" + u.Arch
	if u.Platform == "windows" {
		name += ".exe"
	}
	return name
}

// ProxyURL 将 GitHub 目标地址应用 GHProxy 代理前缀（如果已配置）。
func (u *Updater) ProxyURL(rawURL string) string {
	proxy := strings.TrimSpace(u.GHProxy)
	if proxy == "" {
		return rawURL
	}
	prefix := strings.TrimRight(proxy, "/") + "/"
	if strings.HasPrefix(rawURL, prefix) {
		return rawURL
	}
	return prefix + rawURL
}

func (u *Updater) latestURLOrFallback() string {
	if u.LatestURLFunc != nil {
		return u.LatestURLFunc()
	}
	raw := "https://github.com/" + u.Repo + "/releases/latest/download/" + u.AssetName()
	return u.ProxyURL(raw)
}

func (u *Updater) urlForOrFallback(version string) string {
	if u.URLForFunc != nil {
		return u.URLForFunc(version)
	}
	if version == "" || version == "latest" {
		return u.latestURLOrFallback()
	}
	raw := "https://github.com/" + u.Repo + "/releases/download/" + version + "/" + u.AssetName()
	return u.ProxyURL(raw)
}

func (u *Updater) latestVersionByAPI(ctx context.Context) (string, error) {
	apiTarget := "https://api.github.com/repos/" + u.Repo + "/releases/latest"
	if u.APIURLFunc != nil {
		apiTarget = u.APIURLFunc()
	}

	// 版本查询用独立短超时：DownloadClient 的 5 分钟下载超时对一个小 JSON 响应毫无意义。
	ctx, cancel := context.WithTimeout(ctx, DefaultVersionQueryTimeout)
	defer cancel()

	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultCheckTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiTarget, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent-updater")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API 返回状态码 %d", resp.StatusCode)
	}

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("解析 GitHub API 响应失败: %w", err)
	}
	tag := strings.TrimSpace(data.TagName)
	if tag == "" {
		return "", errors.New("GitHub API 未返回有效 tag_name")
	}
	return tag, nil
}

func (u *Updater) latestVersion(ctx context.Context) (string, string, error) {
	// 版本查询（重定向探测 + API 兜底）整体受一个 20s 预算约束，
	// 避免上游不可达时代理/下载客户端的超时把调用方拖住。
	ctx, cancel := context.WithTimeout(ctx, DefaultVersionQueryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.urlForOrFallback("latest"), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "mnagent-updater")

	resp, err := u.Client.Do(req)
	if err != nil {
		if v, apiErr := u.latestVersionByAPI(ctx); apiErr == nil {
			return v, u.urlForOrFallback(v), nil
		}
		return "", "", fmt.Errorf("检查最新版本失败：%w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc != "" {
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) >= 2 {
			version := parts[len(parts)-2]
			if _, ok := ParseVersion(version); ok {
				return version, loc, nil
			}
		}
	}

	if v, apiErr := u.latestVersionByAPI(ctx); apiErr == nil {
		return v, u.urlForOrFallback(v), nil
	}

	if loc == "" {
		return "", "", errors.New("检查更新失败：响应缺少重定向地址且 API 回退不可用")
	}
	return "", "", fmt.Errorf("解析版本号失败：%q", loc)
}

// Check 返回是否有可应用的新版本。
func (u *Updater) Check(ctx context.Context) (string, bool, error) {
	// 版本号经代理获取可以接受：它只决定“是否有新版本”，最终能否更新仍由
	// 直连获取的 .sha256 与下载后二进制的 -version 自检兜底。
	latest, _, err := u.latestVersion(ctx)
	if err != nil {
		return "", false, err
	}
	current := u.CurrentVersion
	if current == "" {
		current = Version
	}
	if _, ok := ParseVersion(current); !ok || current == "dev" {
		return "", false, nil // 非版本构建（dev）不参与自动更新。
	}
	latestV, ok := ParseVersion(latest)
	if !ok {
		return "", false, fmt.Errorf("解析最新版本失败：%q", latest)
	}
	curV, _ := ParseVersion(current)
	if !latestV.NewerThan(curV) {
		return "", false, nil
	}
	if u.Skipped(latest) {
		return "", false, nil
	}
	return latest, true, nil
}

func (u *Updater) checksumURLFor(version string) string {
	if u.ChecksumURLFunc != nil {
		return u.ChecksumURLFunc(version)
	}
	// Release 工作流为每个资产生成同名的 "<资产>.sha256"（内容为 "<hash>  <文件名>"）。
	raw := "https://github.com/" + u.Repo + "/releases/download/" + version + "/" + u.AssetName() + ".sha256"
	// 配置 GHProxy 时，代理可以同时替换二进制与同源 .sha256，
	// 因此校验文件必须不经 gh-proxy 镜像获取（仍遵循系统 HTTPS_PROXY 环境变量）；
	// 二进制仍可经代理下载。
	if u.usesDirectChecksum() {
		return raw
	}
	return u.ProxyURL(raw)
}

// usesDirectChecksum 表示校验文件必须绕过 GHProxy（不经 gh-proxy 镜像）：
// 只要配置了 GHProxy，二进制与校验文件就可能来自同一代理，必须直连校验文件。
// 注意这只跳过 gh-proxy 前缀，请求仍由 http.DefaultTransport 发出，
// 因此继续遵循 HTTPS_PROXY/HTTP_PROXY 等宿主环境变量（受 TLS 校验保护）。
func (u *Updater) usesDirectChecksum() bool {
	return strings.TrimSpace(u.GHProxy) != ""
}

// directChecksumHint 为直连校验文件失败补充原因，避免用户误以为是普通网络抖动。
func (u *Updater) directChecksumHint(err error) error {
	if err == nil || !u.usesDirectChecksum() {
		return err
	}
	return fmt.Errorf("校验文件不经 gh-proxy 镜像（HTTPS_PROXY 仍生效），但请求失败：%w（已中止更新）", err)
}

var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// 校验值获取的重试参数：国内直连 github.com / api.github.com 时常出现连接重置
// 或短时 5xx，重试与来源兜底必须足够健壮。每次请求使用独立短超时，退避受 ctx 控制。
const checksumFetchAttempts = 3

var (
	checksumRetryBaseDelay = 200 * time.Millisecond
	checksumRetryMaxDelay  = 2 * time.Second
	// checksumResolutionDeadline 是一次更新中获取校验值的整体预算：
	// 服务端代取、交叉校验、直连 .sha256 与 API 兜底共用，避免弱网下
	// 各来源的超时与重试叠加，把升级任务拖过服务端 120s 的预算。
	// 变量而非常量，便于测试缩短。
	checksumResolutionDeadline = 75 * time.Second
)

// nonRetryableHTTPError 标记确定性的 4xx 响应（429 限流除外）：
// 这类响应重试只会空耗更新预算，应立即放弃并回退到另一个来源。
type nonRetryableHTTPError struct{ err error }

func (e *nonRetryableHTTPError) Error() string { return e.err.Error() }
func (e *nonRetryableHTTPError) Unwrap() error { return e.err }

func markNonRetryableHTTPStatus(status int, err error) error {
	if status >= 400 && status < 500 && status != http.StatusTooManyRequests {
		return &nonRetryableHTTPError{err: err}
	}
	return err
}

func isNonRetryableHTTPError(err error) bool {
	var target *nonRetryableHTTPError
	return errors.As(err, &target)
}

// summaryErrorLimit 是单个来源错误在最终提示中的字节上限。
// 保留首尾（HTTP 状态/关键字常在末尾），避免多层包装把关键原因挤出 clampText(300)。
const summaryErrorLimit = 80

func compactErrorText(err error, maxBytes int) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	if len(text) <= maxBytes {
		return text
	}
	if maxBytes < 8 {
		return text[:maxBytes]
	}
	// 多保留尾部：HTTP 状态码和“已中止更新”等关键结论通常在错误链末尾。
	// 头部预算留 55/80 左右，确保“格式非法”“不经 gh-proxy”等关键短语不被截掉。
	head := maxBytes - 23
	if head < 4 {
		head = maxBytes / 2
	}
	for head > 0 && !utf8.RuneStart(text[head]) {
		head--
	}
	tail := len(text) - (maxBytes - head - 3)
	for tail < len(text) && !utf8.RuneStart(text[tail]) {
		tail++
	}
	return text[:head] + "…" + text[tail:]
}

func checksumSourceError(source string, attempts int, err error) string {
	return fmt.Sprintf("%s失败（%d次：%s）", source, attempts, compactErrorText(err, summaryErrorLimit))
}

// retryChecksumSource 对单个直连来源做指数退避 + 抖动重试。
// 错误里带上来源、尝试次数与压缩后的最后错误，方便线上定位；确定性 4xx
// （429 除外）不再重试。
func retryChecksumSource(ctx context.Context, source string, timeout time.Duration, fn func(context.Context) (string, error)) (string, error) {
	var lastErr error
	delay := checksumRetryBaseDelay
	attempts := 0
	for attempt := 1; attempt <= checksumFetchAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return "", fmt.Errorf("%s；%s", checksumSourceError(source, attempts, lastErr), compactErrorText(err, summaryErrorLimit))
			}
			return "", fmt.Errorf("%s失败（0次，%s）", source, compactErrorText(err, summaryErrorLimit))
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		sum, err := fn(attemptCtx)
		cancel()
		if err == nil && sum != "" {
			return sum, nil
		}
		if err == nil {
			err = errors.New("返回空校验值")
		}
		lastErr = err
		attempts = attempt
		if isNonRetryableHTTPError(err) || attempt == checksumFetchAttempts {
			break
		}
		wait := delay + time.Duration(rand.Int64N(int64(delay)+1))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("%s；%s", checksumSourceError(source, attempts, lastErr), compactErrorText(ctx.Err(), summaryErrorLimit))
		case <-timer.C:
		}
		delay = min(delay*2, checksumRetryMaxDelay)
	}
	return "", errors.New(checksumSourceError(source, attempts, lastErr))
}

func (u *Updater) checksumRequestTimeout() time.Duration {
	if u.checksumTimeout > 0 {
		return u.checksumTimeout
	}
	return DefaultChecksumTimeout
}

// fetchChecksumFile 直连下载目标资产的 "<资产>.sha256" 并解析出 SHA-256。
func (u *Updater) fetchChecksumFile(ctx context.Context, version string) (string, error) {
	return retryChecksumSource(ctx, "直连 .sha256", u.checksumRequestTimeout(), func(ctx context.Context) (string, error) {
		return u.fetchChecksumFileOnce(ctx, version)
	})
}

// fetchChecksumFileOnce 只做一次直连 .sha256 请求（不重试），
// 供重试链与服务端代取后的交叉校验共用。
func (u *Updater) fetchChecksumFileOnce(ctx context.Context, version string) (string, error) {
	targetURL := u.checksumURLFor(version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent-updater")

	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultDownloadTimeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return "", u.directChecksumHint(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", u.directChecksumHint(markNonRetryableHTTPStatus(resp.StatusCode, fmt.Errorf("该版本未发布校验文件 %s.sha256（HTTP 404）", u.AssetName())))
	}
	if resp.StatusCode != http.StatusOK {
		return "", u.directChecksumHint(markNonRetryableHTTPStatus(resp.StatusCode, fmt.Errorf("获取校验文件返回 HTTP %d", resp.StatusCode)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<18)) // 256 KiB
	if err != nil {
		return "", u.directChecksumHint(err)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return "", u.directChecksumHint(fmt.Errorf("校验文件 %s.sha256 为空", u.AssetName()))
	}
	sum, err := u.parseChecksum(body)
	if err != nil {
		return "", u.directChecksumHint(err)
	}
	return sum, nil
}

// fetchChecksumFromAPI 通过直连 api.github.com 的 Release 附件 digest 字段获取校验值。
// 这是 .sha256 获取失败时的兜底来源，同样不经过 gh-proxy。
func (u *Updater) fetchChecksumFromAPI(ctx context.Context, version string) (string, error) {
	targetURL := ""
	if u.ChecksumAPIURLFunc != nil {
		targetURL = u.ChecksumAPIURLFunc(version)
	} else {
		targetURL = "https://api.github.com/repos/" + u.Repo + "/releases/tags/" + version
	}
	return retryChecksumSource(ctx, "直连 GitHub API digest", u.checksumRequestTimeout(), func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "mnagent-updater")
		req.Header.Set("Accept", "application/vnd.github+json")

		cli := u.DownloadClient
		if cli == nil {
			cli = &http.Client{Timeout: DefaultDownloadTimeout}
		}
		resp, err := cli.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", markNonRetryableHTTPStatus(resp.StatusCode, fmt.Errorf("GitHub API 返回 HTTP %s", resp.Status))
		}
		var data struct {
			Assets []struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&data); err != nil {
			return "", fmt.Errorf("解析 Release JSON 失败：%w", err)
		}
		for _, asset := range data.Assets {
			if asset.Name != u.AssetName() {
				continue
			}
			digest := strings.ToLower(strings.TrimPrefix(strings.ToLower(asset.Digest), "sha256:"))
			if !sha256HexPattern.MatchString(digest) {
				return "", fmt.Errorf("Release %s 的附件 %s 未提供合法 SHA-256 digest", version, u.AssetName())
			}
			return digest, nil
		}
		return "", fmt.Errorf("Release %s 中不存在附件 %s", version, u.AssetName())
	})
}

// fetchChecksumFromBot 通过服务端代取 SHA-256，并用一次直连 .sha256 做交叉校验。
// 直连失败不阻断（服务端本就用于直连不可靠的场景），只有两侧都拿到值且不一致时
// 才返回 errChecksumMismatch；这种情况下调用方必须中止，不能继续走兜底来源。
func (u *Updater) fetchChecksumFromBot(ctx context.Context, version string) (string, error) {
	if u.botDigest == nil {
		return "", errors.New("未启用服务端代取")
	}
	sum, err := u.botDigest.Fetch(ctx, u.Repo, version, u.AssetName())
	if err != nil {
		return "", err
	}
	return u.crossCheckDirectChecksum(ctx, version, sum)
}

// crossCheckDirectChecksum 在服务端代取成功后，用 5s 窗口单次直连 .sha256 交叉校验：
// 一致时返回服务端的值；直连失败、超时或格式非法时放行（仍用服务端的值）；
// 两侧都有合法值但不一致时 fail-closed。
func (u *Updater) crossCheckDirectChecksum(ctx context.Context, version, botSum string) (string, error) {
	checkCtx, cancel := context.WithTimeout(ctx, crossCheckTimeout)
	defer cancel()
	directSum, err := u.fetchChecksumFileOnce(checkCtx, version)
	if err != nil || directSum == "" {
		u.info("交叉校验未完成（直连不可用），已采用服务端代取值", "version", version, "error", err)
		return botSum, nil
	}
	if !strings.EqualFold(directSum, botSum) {
		u.warn("服务端代取校验值与直连 .sha256 不一致，已中止更新", "version", version, "bot", botSum, "direct", directSum)
		return "", fmt.Errorf("%w（服务端 %s / 直连 %s），已中止更新（疑似篡改或上游重新上传了资产）；若服务端刚更新/重传资产，可稍后重试；确认无误可临时用 -no-bot-checksum 重试",
			errChecksumMismatch, botSum, directSum)
	}
	return botSum, nil
}

// fetchExpectedChecksum 依次尝试服务端代取（含交叉校验）、直连 .sha256 与直连 API digest；
// 三个来源都失败时错误里列出尝试过的来源与次数。
// 服务端代取除交叉校验不一致外都静默回退（只打 Debug 日志）；不一致必须立即中止。
func (u *Updater) fetchExpectedChecksum(ctx context.Context, version string) (string, error) {
	// 所有来源共用同一个整体预算：单个来源的超时与重试不能层层叠加。
	// 预算耗尽后后续来源会立即返回，总耗时不会超过该 deadline（留少量调度开销）。
	parentCtx := ctx
	if checksumResolutionDeadline > 0 {
		deadlineCtx, cancel := context.WithTimeout(ctx, checksumResolutionDeadline)
		defer cancel()
		ctx = deadlineCtx
	}
	var attempted []string
	if u.botDigest != nil {
		sum, err := u.fetchChecksumFromBot(ctx, version)
		if err == nil {
			return sum, nil
		}
		if errors.Is(err, errChecksumMismatch) {
			return "", err
		}
		u.debug("服务端代取校验值失败，回退到直连来源", "version", version, "error", err)
		attempted = append(attempted, fmt.Sprintf("服务端代取（1次：%s）", compactErrorText(err, summaryErrorLimit)))
	}

	sum, err := u.fetchChecksumFile(ctx, version)
	if err == nil {
		return sum, nil
	}
	attempted = append(attempted, err.Error())

	sum, err = u.fetchChecksumFromAPI(ctx, version)
	if err == nil {
		return sum, nil
	}
	attempted = append(attempted, err.Error())
	budgetHint := ""
	if checksumResolutionDeadline > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) && parentCtx.Err() == nil {
		budgetHint = fmt.Sprintf("；整体校验值获取预算（%s）已用尽，后续来源已跳过", formatBudgetDuration(checksumResolutionDeadline))
	}
	return "", fmt.Errorf("无法从任何可信来源获取 SHA-256 校验值%s：%s", budgetHint, strings.Join(attempted, "；"))
}

// formatBudgetDuration 把预算格式化成易读文本：整秒预算显示为 "75s"，
// 其余保留 time.Duration 的默认格式（便于测试使用毫秒级预算）。
func formatBudgetDuration(d time.Duration) string {
	if d >= time.Second && d%time.Second == 0 {
		return fmt.Sprintf("%ds", int64(d/time.Second))
	}
	return d.String()
}

// debug 输出调试日志：优先使用注入 logger 的 Debug 能力，
// 未实现该能力（只注入 Warn）时退化到 slog 默认 logger。
func (u *Updater) debug(msg string, args ...any) {
	if l, ok := u.logger.(interface{ Debug(msg string, args ...any) }); ok {
		l.Debug(msg, args...)
		return
	}
	slog.Debug(msg, args...)
}

// info 输出普通信息：优先使用注入 logger 的 Info 能力，
// 未实现该能力时退化到 slog 默认 logger。
func (u *Updater) info(msg string, args ...any) {
	if l, ok := u.logger.(interface{ Info(msg string, args ...any) }); ok {
		l.Info(msg, args...)
		return
	}
	slog.Info(msg, args...)
}

// warn 输出安全告警：优先使用注入的 logger，未注入时退化到 slog 默认 logger。
func (u *Updater) warn(msg string, args ...any) {
	if u.logger != nil {
		u.logger.Warn(msg, args...)
		return
	}
	slog.Warn(msg, args...)
}

// parseChecksum 从校验文件内容中提取当前资产的 SHA-256。
func (u *Updater) parseChecksum(body []byte) (string, error) {
	assetName := u.AssetName()
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		hash := strings.ToLower(fields[0])
		// 允许两种格式：只含一个哈希，或 "<hash>  <文件名>"。
		if len(fields) == 1 {
			if !sha256HexPattern.MatchString(hash) {
				return "", fmt.Errorf("校验文件格式非法：%q 不是合法的 SHA-256", line)
			}
			return hash, nil
		}
		fileName := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(fileName) != assetName {
			continue
		}
		if !sha256HexPattern.MatchString(hash) {
			return "", fmt.Errorf("校验文件中 %s 的哈希格式非法：%q", assetName, fields[0])
		}
		return hash, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("校验文件 %s.sha256 中未找到当前资产的哈希", assetName)
}

// DownloadAndReplace 下载并原子替换二进制文件，支持 SHA-256 完整性校验，返回目标版本号，但不触发重启。
// 同一 Updater 上的替换操作由 applyMu 串行化，防止自动更新与远程升级并发替换。
func (u *Updater) DownloadAndReplace(ctx context.Context, version string) (string, error) {
	u.applyMu.Lock()
	defer u.applyMu.Unlock()
	return u.downloadAndReplace(ctx, version)
}

func (u *Updater) downloadAndReplace(ctx context.Context, version string) (string, error) {
	if !ValidReleaseTag(version) {
		return "", fmt.Errorf("非法的目标版本号：%q", version)
	}
	// 必须拿到有效校验值：缺失、为空或格式非法都中止更新，避免校验被静默跳过。
	expectedHash, err := u.fetchExpectedChecksum(ctx, version)
	if err != nil {
		return "", fmt.Errorf("获取 SHA-256 校验值失败，已中止更新：%w", err)
	}
	if !u.usesDirectChecksum() {
		u.warn("仅校验 SHA-256；校验文件与二进制同源，无法防御来源同时篡改两者的攻击")
	}

	downloadURL := u.urlForOrFallback(version)
	// 临时文件必须与目标同目录：跨文件系统 rename 会失败（EXDEV），而此前回退到 /tmp
	// 正是踩了这个坑。目录不可写时直接报清晰错误，不悄悄换到不安全的位置。
	updDir := filepath.Dir(u.Executable)
	tmpPattern := "mnagent-upd-*"
	if runtime.GOOS == "windows" {
		// Windows 的 exec 需要 .exe 后缀才能运行自检。
		tmpPattern = "mnagent-upd-*.exe"
	}
	tmpFile, err := os.CreateTemp(updDir, tmpPattern)
	if err != nil {
		return "", fmt.Errorf("在 %s 创建临时更新文件失败（目录不可写，无法同目录替换）：%w", updDir, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, hasher)

	if err := u.downloadTo(ctx, downloadURL, multiWriter); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("下载新版本失败：%w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("同步新版本文件失败：%w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("关闭新版本文件失败：%w", err)
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(actualHash)), []byte(strings.ToLower(expectedHash))) != 1 {
		return "", fmt.Errorf("SHA-256 完整性校验失败：期望 %s，实际 %s (防篡改拦截)", expectedHash, actualHash)
	}

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", fmt.Errorf("设置执行权限失败：%w", err)
	}

	// 替换前先跑一次 -version：能挡住架构不匹配、截断、损坏的二进制，
	// 避免坏版本落盘后让 systemd/procd 进入无限重启。
	if u.verifyBinary != nil {
		if err := u.verifyBinary(ctx, tmpPath, version); err != nil {
			return "", fmt.Errorf("新版本二进制自检失败，已中止替换：%w", err)
		}
	}

	// 取消发生在下载/自检之后时，绝不能继续替换：远程取消升级后不应
	// 悄悄换掉正在运行的二进制。
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("更新已取消，未替换二进制：%w", err)
	}

	if err := ReplaceExecutable(tmpPath, u.Executable); err != nil {
		return "", fmt.Errorf("替换当前二进制失败：%w", err)
	}
	return version, nil
}

// Restart 执行应用新版本后的重启逻辑。
func (u *Updater) Restart() error {
	if u.RestartFunc == nil {
		return errors.New("未配置重启回调")
	}
	return u.RestartFunc()
}

// Apply 依次执行“下载 → 原子替换 → 重启服务”。
// 整个流程（包括重启）持有 applyMu，避免另一轮更新在重启前替换文件。
func (u *Updater) Apply(ctx context.Context, version string) error {
	u.applyMu.Lock()
	defer u.applyMu.Unlock()
	if _, err := u.downloadAndReplace(ctx, version); err != nil {
		return err
	}
	// 替换完成后若任务已被取消，不再重启：避免取消后仍切换到新版本。
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("更新已取消，未重启服务：%w", err)
	}
	if u.RestartFunc != nil {
		if err := u.RestartFunc(); err != nil {
			return fmt.Errorf("更新已写入但重启服务失败：%w", err)
		}
	}
	return nil
}

func (u *Updater) downloadTo(ctx context.Context, targetURL string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mnagent-updater")

	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultDownloadTimeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	n, err := io.Copy(w, io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		return err
	}
	if n > maxBinaryBytes {
		return fmt.Errorf("下载的文件超过体积上限（%d MB），已中止更新", maxBinaryBytes>>20)
	}
	if n < minBinaryBytes {
		return fmt.Errorf("下载的文件过小（%d 字节），可能非有效二进制", n)
	}
	return nil
}

// Skipped 查询指定版本是否已被标记为跳过。
func (u *Updater) Skipped(version string) bool {
	if u.SkipFile == "" {
		return false
	}
	data, err := os.ReadFile(u.SkipFile)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != version {
			continue
		}
		exp, err := time.Parse(time.RFC3339, fields[1])
		if err != nil {
			continue
		}
		if time.Now().Before(exp) {
			return true
		}
	}
	return false
}

// Skip 标记跳过某个版本一段时间。
func (u *Updater) Skip(version string, forDur time.Duration) error {
	if u.SkipFile == "" {
		return nil
	}
	if forDur <= 0 {
		forDur = 24 * time.Hour
	}
	exp := time.Now().Add(forDur).Format(time.RFC3339)
	line := fmt.Sprintf("%s %s\n", version, exp)

	if err := os.MkdirAll(filepath.Dir(u.SkipFile), 0o700); err != nil {
		return err
	}
	u.tightenStateDirPerm(filepath.Dir(u.SkipFile))
	f, err := os.OpenFile(u.SkipFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// tightenStateDirPerm 把已存在的状态目录收紧到 0700。
// MkdirAll 不会修改已存在目录的权限，旧版本或手工创建可能留下 0755；
// 只有在当前进程是属主时 chmod 才会成功（非属主失败时保留原状，由 statedir 的启动校验拒绝）。
func (u *Updater) tightenStateDirPerm(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		u.warn("状态目录权限过宽且无法收紧到 0700，请手动执行 chmod 0700", "dir", dir, "error", err)
	}
}

// DetectPlatformArch 探测当前系统与架构对应的 Release 命名。
func DetectPlatformArch() (platform, arch string) {
	return runtime.GOOS, ReleaseArch(runtime.GOARCH)
}

// ReleaseArch 把 Go 的 GOARCH 映射为 Release 资产名中的架构段。
// Release 工作流直接使用 GOARCH 生成 mnagent_<os>_<goarch>，因此 32 位 ARM
// 的产物是 mnagent_linux_arm，而不是 armv7。
func ReleaseArch(goarch string) string {
	return goarch
}

// ReplaceExecutable 将 newFile 原子替换到 targetPath。
// 非 Windows 平台先把旧版本保留为 <路径>.prev 便于手工回滚；Windows 由于文件锁
// 只能先改名再替换（.old 机制），并在启动时由 CleanupOldExecutables 清理。
func ReplaceExecutable(newFile, targetPath string) error {
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(targetPath); err == nil {
			prevPath := targetPath + ".prev"
			_ = os.Remove(prevPath)
			// 优先硬链接：旧 inode 继续保留为 .prev，主路径在 rename 完成前始终有效。
			if err := os.Link(targetPath, prevPath); err != nil {
				if err := copyFile(targetPath, prevPath); err != nil {
					return fmt.Errorf("保留上一版本失败: %w", err)
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("检查当前可执行文件失败: %w", err)
		}
		if err := os.Rename(newFile, targetPath); err != nil {
			return err
		}
		return syncDir(filepath.Dir(targetPath))
	}

	if _, err := os.Stat(targetPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(newFile, targetPath); err != nil {
			return err
		}
		return syncDir(filepath.Dir(targetPath))
	}

	oldPath := targetPath + ".old"
	_ = os.Remove(oldPath)

	if err := os.Rename(targetPath, oldPath); err != nil {
		oldPath = fmt.Sprintf("%s.old.%d", targetPath, time.Now().UnixNano())
		if err := os.Rename(targetPath, oldPath); err != nil {
			return fmt.Errorf("重命名原可执行文件失败: %w", err)
		}
	}

	if err := os.Rename(newFile, targetPath); err != nil {
		_ = os.Rename(oldPath, targetPath)
		return fmt.Errorf("移动新可执行文件失败: %w", err)
	}

	_ = os.Remove(oldPath)
	return syncDir(filepath.Dir(targetPath))
}

// copyFile 复制文件内容（用于文件系统不支持硬链接时保留上一版本）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// syncDir 对目录执行 fsync，确保 rename 结果在掉电后仍可见。
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

var binaryVersionPattern = regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)

// verifyDownloadedBinary 执行临时二进制的 -version，确认能运行且版本号为目标版本。
// 可拦截架构不匹配（exec format error）、下载截断与内容错误。
func verifyDownloadedBinary(ctx context.Context, path, version string) error {
	want, ok := ParseVersion(version)
	if !ok {
		return fmt.Errorf("目标版本号非法：%q", version)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("执行 %s -version 超时", path)
	}
	if err != nil {
		return fmt.Errorf("执行 %s -version 失败：%w（输出：%s）", path, err, truncateForLog(string(out), 200))
	}
	m := binaryVersionPattern.FindStringSubmatch(string(out))
	if len(m) < 2 {
		return fmt.Errorf("无法从 -version 输出解析版本号：%s", truncateForLog(string(out), 200))
	}
	got, ok := ParseVersion(m[1])
	if !ok || got.Major != want.Major || got.Minor != want.Minor || got.Patch != want.Patch || got.Pre != want.Pre {
		return fmt.Errorf("版本不匹配：期望 %s，实际 %s", version, m[1])
	}
	return nil
}

func truncateForLog(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// staleUpdateFileAge 是清理残留更新临时文件的最小年龄：进程内已用 applyMu 串行化，
// 这个阈值只用于避免误删另一个仍在运行的旧进程刚创建的临时文件。
const staleUpdateFileAge = time.Hour

// cleanupStaleUpdateFiles 删除 dir 下超过 staleUpdateFileAge 的 mnagent-upd-* 普通文件，
// 不跟随符号链接、不递归、不删除目录。
func cleanupStaleUpdateFiles(dir string) {
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "mnagent-upd-") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if time.Since(info.ModTime()) < staleUpdateFileAge {
			continue
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
}

// CleanupOldExecutables 清理可执行文件周边的 .old 遗留备份文件（主要针对 Windows），
// 以及程序目录/系统临时目录中残留的 mnagent-upd-* 更新临时文件。
func CleanupOldExecutables(targetPath string) {
	if targetPath != "" {
		cleanupStaleUpdateFiles(filepath.Dir(targetPath))
	}
	// 旧版本或异常退出可能在系统临时目录留下更新文件；只清匹配前缀且超过阈值的普通文件。
	cleanupStaleUpdateFiles(os.TempDir())
	if runtime.GOOS != "windows" || targetPath == "" {
		return
	}
	dir := filepath.Dir(targetPath)
	base := filepath.Base(targetPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := base + ".old"
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

// ApplyGHProxy 给原始 URL 增加代理前缀。
func ApplyGHProxy(rawURL, ghProxy string) string {
	ghProxy = strings.TrimSpace(ghProxy)
	if ghProxy == "" {
		return rawURL
	}
	prefix := strings.TrimRight(ghProxy, "/") + "/"
	if strings.HasPrefix(rawURL, prefix) {
		return rawURL
	}
	return prefix + rawURL
}

// LatestVersion 返回最新版本号及下载地址。
func (u *Updater) LatestVersion(ctx context.Context) (string, string, error) {
	return u.latestVersion(ctx)
}
