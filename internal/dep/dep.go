package dep

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mengnanquq/mnagent/internal/statedir"
	"github.com/mengnanquq/mnagent/internal/updater"
)

var (
	AnsiEscapePattern   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	NexttraceVerPattern = regexp.MustCompile(`(?i)NextTrace\s+v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	MiaospeedVerPattern = regexp.MustCompile(`(?i)version:\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	GenericVerPattern   = regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	// sha256HexPattern 用于校验上游 .sha256 文件里的哈希格式。
	sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// 查不到最新版本时只允许在“尚未安装”的场景安装这些固定版本；
// 已安装时必须保持现有版本不动，绝不因为 API 临时不可用而悄悄降级。
const (
	fallbackNexttraceVersion = "v1.7.3"
	fallbackMiaospeedVersion = "4.7.8"
)

// selfCheckTimeout 是替换前执行依赖 -version/-V 自检的独立超时。
// 依赖卡死或挂起时不能把整个更新流程一起拖住；测试会缩短该值。
var selfCheckTimeout = 10 * time.Second

// maxExtractBytes 限制从依赖归档中解压出的单个可执行文件大小（防 zip bomb 占满磁盘）。
// 变量而非常量，便于测试缩短；生产环境为 256MB。
var maxExtractBytes int64 = 256 << 20

// 依赖下载体积上限：归档 64MB、裸二进制 128MB。
// 变量而非常量，便于测试缩短；生产环境保持上述值。
var (
	maxDependencyArchiveBytes int64 = 64 << 20
	maxDependencyBinaryBytes  int64 = 128 << 20
)

// dependencyDownloadLimit 按资产名选择下载体积上限：压缩包用归档上限，其余用二进制上限。
func dependencyDownloadLimit(assetName string) int64 {
	lower := strings.ToLower(assetName)
	for _, ext := range []string{".zip", ".tar.gz", ".tgz", ".tar", ".gz"} {
		if strings.HasSuffix(lower, ext) {
			return maxDependencyArchiveBytes
		}
	}
	return maxDependencyBinaryBytes
}

// cmdWaitDelay 是 exec.Cmd.WaitDelay：取消后子进程若仍持有输出管道，
// 最多再等这么久就强制结束等待。变量便于测试缩短。
var cmdWaitDelay = 3 * time.Second

// errExtractTooLarge 表示解压内容超过 maxExtractBytes。
var errExtractTooLarge = errors.New("解压内容超过体积上限")

// binaryPresent 判断目标路径上是否已有文件（用于区分“升级”与“首次安装”）。
func binaryPresent(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func StripANSI(s string) string {
	return AnsiEscapePattern.ReplaceAllString(s, "")
}

// DependencyStatus 表示一个依赖组件（如 nexttrace、miaospeed）的版本状态。
type DependencyStatus struct {
	Name           string // 依赖名称，如 "nexttrace"、"miaospeed"
	BinaryPath     string // 探测到的本地可执行文件路径
	Installed      bool   // 本地是否已安装
	CurrentVersion string // 本地当前版本（如 "v1.7.3" 或 "4.7.7"）
	LatestVersion  string // 远端最新版本
	HasUpdate      bool   // 远端版本是否高于当前版本
	Error          error  // 检查过程中的错误
}

// Summary 返回该依赖状态的单行说明。
func (s DependencyStatus) Summary() string {
	if s.Error != nil {
		return fmt.Sprintf("%s: 检查失败 (%v)", s.Name, s.Error)
	}
	if !s.Installed {
		if s.LatestVersion != "" {
			return fmt.Sprintf("%s: 未安装（最新版本 %s）", s.Name, s.LatestVersion)
		}
		return fmt.Sprintf("%s: 未安装", s.Name)
	}
	if s.HasUpdate {
		return fmt.Sprintf("%s: 发现新版本 %s（当前 %s）", s.Name, s.LatestVersion, s.CurrentVersion)
	}
	return fmt.Sprintf("%s: 已是最新版本（%s）", s.Name, s.CurrentVersion)
}

// depUpdateLocks 按依赖名串行化替换（进程级）：runner 的自动更新循环与远程 upgrade
// 各自 newDependencyManager，互斥锁必须跨实例共享，才能避免两个流程同时下载/替换
// 同一个依赖而互相覆盖，或让自检读到正在被替换的文件。
var (
	depUpdateLocksMu sync.Mutex
	depUpdateLocks   = make(map[string]*sync.Mutex)
)

// DependencyManager 负责检测与更新外部依赖工具。
type DependencyManager struct {
	ghProxy       string
	httpClient    *http.Client
	apiBaseURL    string // 默认 "https://api.github.com"
	githubBaseURL string // 默认 "https://github.com"
	cmdRunner     func(ctx context.Context, name string, args ...string) ([]byte, error)
	goos          string
	goarch        string
}

// newDependencyManager 创建依赖管理器实例。
func newDependencyManager(ghProxy string) *DependencyManager {
	return NewDependencyManager(ghProxy)
}

func NewDependencyManager(ghProxy string) *DependencyManager {
	return &DependencyManager{
		ghProxy: ghProxy,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		apiBaseURL:    "https://api.github.com",
		githubBaseURL: "https://github.com",
		cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			// 子进程被取消后若孙进程仍持有 stdout/stderr 管道，Wait 会无限等待；
			// WaitDelay 在超时后强制结束等待，保证自检不会永久阻塞。
			cmd.WaitDelay = cmdWaitDelay
			return cmd.CombinedOutput()
		},
		goos:   runtime.GOOS,
		goarch: runtime.GOARCH,
	}
}

// SetGitHubEndpoints 覆盖 GitHub API 与站点地址（仅供测试使用）。
func (dm *DependencyManager) SetGitHubEndpoints(apiBaseURL, githubBaseURL string) {
	dm.apiBaseURL = apiBaseURL
	dm.githubBaseURL = githubBaseURL
}

// resolveBinaryPath 解析可执行文件的具体绝对/环境路径。
func ResolveBinaryPath(bin string) (string, bool) {
	trimmed := strings.TrimSpace(bin)
	if trimmed == "" {
		return "", false
	}
	if filepath.IsAbs(trimmed) || strings.Contains(trimmed, string(filepath.Separator)) {
		if _, err := os.Stat(trimmed); err == nil {
			return trimmed, true
		}
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(trimmed), ".exe") {
			if _, err := os.Stat(trimmed + ".exe"); err == nil {
				return trimmed + ".exe", true
			}
		}
		return trimmed, false
	}
	if p, err := exec.LookPath(trimmed); err == nil {
		return p, true
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(trimmed), ".exe") {
		if p, err := exec.LookPath(trimmed + ".exe"); err == nil {
			return p, true
		}
	}
	// 备选常用路径回退（兼容 OpenWrt 等 PATH 缺少 /usr/local/bin 或相对当前二进制路径的环境）
	var fallbackDirs []string
	if exe, err := os.Executable(); err == nil {
		fallbackDirs = append(fallbackDirs, filepath.Dir(exe))
	}
	if runtime.GOOS != "windows" {
		fallbackDirs = append(fallbackDirs, "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin")
	}
	for _, dir := range fallbackDirs {
		candidate := filepath.Join(dir, trimmed)
		if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(candidate), ".exe") {
			candidate += ".exe"
		}
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			return candidate, true
		}
	}
	return trimmed, false
}

// lockDependency 返回按依赖名串行化的解锁函数。
func (dm *DependencyManager) lockDependency(name string) func() {
	key := strings.ToLower(strings.TrimSpace(name))
	depUpdateLocksMu.Lock()
	mu := depUpdateLocks[key]
	if mu == nil {
		mu = &sync.Mutex{}
		depUpdateLocks[key] = mu
	}
	depUpdateLocksMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// detectLocalNextTrace 探测本地已安装的 nexttrace 版本。
// 内部再套一层独立超时：调用方（主循环 / heavyWorker）可能没有 deadline，
// 绝不能因为依赖的 -V 卡死而永久阻塞。
func (dm *DependencyManager) detectLocalNextTrace(ctx context.Context, binPath string) (installed bool, realPath string, ver string, err error) {
	realPath, installed = ResolveBinaryPath(binPath)
	if !installed {
		return false, realPath, "", nil
	}

	runCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()

	out, cmdErr := dm.cmdRunner(runCtx, realPath, "-V")
	if cmdErr != nil {
		// 备选尝试 --version
		if out2, cmdErr2 := dm.cmdRunner(runCtx, realPath, "--version"); cmdErr2 == nil {
			out = out2
			cmdErr = nil
		}
	}
	cleaned := StripANSI(string(out))
	if m := NexttraceVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
		if !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		return true, realPath, ver, nil
	}
	if m := GenericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
		if !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		return true, realPath, ver, nil
	}
	if cmdErr != nil {
		return true, realPath, "", fmt.Errorf("执行 %s -V 失败：%w", realPath, cmdErr)
	}
	return true, realPath, "", errors.New("无法解析 nexttrace 版本输出")
}

// detectLocalMiaospeed 探测本地已安装的 miaospeed 版本。
// 与 detectLocalNextTrace 一样内部套独立超时，避免无 deadline 的调用方被卡死。
func (dm *DependencyManager) detectLocalMiaospeed(ctx context.Context, binPath string) (installed bool, realPath string, ver string, err error) {
	realPath, installed = ResolveBinaryPath(binPath)
	if !installed {
		return false, realPath, "", nil
	}

	runCtx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()

	out, cmdErr := dm.cmdRunner(runCtx, realPath, "-version")
	if cmdErr != nil {
		if out2, cmdErr2 := dm.cmdRunner(runCtx, realPath, "version"); cmdErr2 == nil {
			out = out2
			cmdErr = nil
		}
	}
	cleaned := StripANSI(string(out))
	if m := MiaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = strings.TrimPrefix(m[1], "v")
		return true, realPath, ver, nil
	}
	if m := GenericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = strings.TrimPrefix(m[1], "v")
		return true, realPath, ver, nil
	}
	if cmdErr != nil {
		return true, realPath, "", fmt.Errorf("执行 %s -version 失败：%w", realPath, cmdErr)
	}
	return true, realPath, "", errors.New("无法解析 miaospeed 版本输出")
}

// fetchLatestTag 查询 GitHub 仓库的最新 Release tag。
// 优先使用免 API 配额的 HEAD 重定向方式（Location: /tag/<version>），
// 若失败或在自定义 apiBaseURL 环境下，则平滑回退至通过 API 获取（支持代理）。
func (dm *DependencyManager) fetchLatestTag(ctx context.Context, repo string) (string, error) {
	if dm.apiBaseURL != "" && dm.apiBaseURL != "https://api.github.com" {
		return dm.fetchLatestTagByAPI(ctx, repo)
	}

	tag, headErr := dm.fetchLatestTagByRedirect(ctx, repo)
	if headErr == nil && tag != "" {
		return tag, nil
	}

	return dm.fetchLatestTagByAPI(ctx, repo)
}

// fetchLatestTagByRedirect 通过 HEAD 请求 releases/latest 读取 302 重定向里的 tag，完全免除 API 配额。
func (dm *DependencyManager) fetchLatestTagByRedirect(ctx context.Context, repo string) (string, error) {
	// 直连 GitHub releases/latest 探测 302 重定向，避免将普通网页请求发送给仅支持资产下载的反向代理
	baseURL := dm.githubBaseURL
	if baseURL == "" {
		baseURL = "https://github.com"
	}
	targetURL := fmt.Sprintf("%s/%s/releases/latest", strings.TrimRight(baseURL, "/"), repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if loc != "" {
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		if len(parts) > 0 {
			tag := parts[len(parts)-1]
			if _, ok := updater.ParseVersion(tag); ok {
				return tag, nil
			}
		}
	}
	return "", errors.New("无法从重定向获取版本 tag")
}

// fetchLatestTagByAPI 通过 GitHub API 获取最新发布 tag（注意：api.github.com 必须直连，绝不能走 gh-proxy）。
func (dm *DependencyManager) fetchLatestTagByAPI(ctx context.Context, repo string) (string, error) {
	targetURL := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(dm.apiBaseURL, "/"), repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := dm.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API 返回 HTTP %s", resp.Status)
	}

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("解析 Release JSON 失败：%w", err)
	}
	if data.TagName == "" {
		return "", errors.New("GitHub API 未返回 tag_name")
	}
	return data.TagName, nil
}

// CheckNextTrace 检查 nexttrace 的本地与远端版本。
func (dm *DependencyManager) CheckNextTrace(ctx context.Context, binPath string) DependencyStatus {
	st := DependencyStatus{
		Name: "nexttrace",
	}
	installed, realPath, curVer, err := dm.detectLocalNextTrace(ctx, binPath)
	st.BinaryPath = realPath
	st.Installed = installed
	st.CurrentVersion = curVer
	if err != nil && installed {
		st.Error = err
		return st
	}

	latest, err := dm.fetchLatestTag(ctx, "nxtrace/NTrace-core")
	if err != nil {
		st.Error = fmt.Errorf("获取远端版本失败：%w", err)
		return st
	}
	st.LatestVersion = latest

	if installed && curVer != "" {
		cur, ok1 := updater.ParseVersion(curVer)
		lat, ok2 := updater.ParseVersion(latest)
		if ok1 && ok2 && lat.NewerThan(cur) {
			st.HasUpdate = true
		}
	} else if !installed {
		st.HasUpdate = true
	}
	return st
}

// CheckMiaospeed 检查 miaospeed 的本地与远端版本。
func (dm *DependencyManager) CheckMiaospeed(ctx context.Context, binPath string) DependencyStatus {
	st := DependencyStatus{
		Name: "miaospeed",
	}
	installed, realPath, curVer, err := dm.detectLocalMiaospeed(ctx, binPath)
	st.BinaryPath = realPath
	st.Installed = installed
	st.CurrentVersion = curVer
	if err != nil && installed {
		st.Error = err
		return st
	}

	latest, err := dm.fetchLatestTag(ctx, "AirportR/miaospeed")
	if err != nil {
		st.Error = fmt.Errorf("获取远端版本失败：%w", err)
		return st
	}
	st.LatestVersion = strings.TrimPrefix(latest, "v")

	if installed && curVer != "" {
		cur, ok1 := updater.ParseVersion(curVer)
		lat, ok2 := updater.ParseVersion(st.LatestVersion)
		if ok1 && ok2 && lat.NewerThan(cur) {
			st.HasUpdate = true
		}
	} else if !installed {
		st.HasUpdate = true
	}
	return st
}

// CheckAll 检查所有依赖组件的版本状态。
func (dm *DependencyManager) CheckAll(ctx context.Context, nexttraceBin, miaospeedBin string) []DependencyStatus {
	if nexttraceBin == "" {
		nexttraceBin = "nexttrace"
	}
	if miaospeedBin == "" {
		miaospeedBin = "miaospeed"
	}
	return []DependencyStatus{
		dm.CheckNextTrace(ctx, nexttraceBin),
		dm.CheckMiaospeed(ctx, miaospeedBin),
	}
}

// nexttraceAsset 返回指定平台与架构对应的 nexttrace 发布资产名称。
func NexttraceAsset(goos, goarch string) (string, error) {
	osName := strings.ToLower(goos)
	var archName string
	switch goarch {
	case "amd64":
		archName = "amd64"
	case "arm64":
		archName = "arm64"
	case "arm":
		archName = "armv7"
	case "386":
		archName = "386"
	case "mips":
		archName = "mips"
	case "mipsle":
		archName = "mipsle"
	case "mips64":
		archName = "mips64"
	case "mips64le":
		archName = "mips64le"
	case "riscv64":
		archName = "riscv64"
	default:
		return "", fmt.Errorf("nexttrace 不支持的架构：%s/%s", goos, goarch)
	}

	if osName == "windows" && archName == "arm64" {
		return "nexttrace-tiny_windows_arm64.exe", nil
	}
	name := fmt.Sprintf("nexttrace_%s_%s", osName, archName)
	if osName == "windows" {
		name += ".exe"
	}
	return name, nil
}

// ResolveInstallTarget 确定依赖落地文件的路径。目标目录不可写时降级到 mnagent 的私有状态目录
// （bin 子目录），绝不降级到 /tmp 这类所有用户都可写的目录——agent 通常以 root 运行并会执行这些文件。
func ResolveInstallTarget(configuredPath, defaultName string) string {
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(defaultName), ".exe") {
		defaultName += ".exe"
	}
	dest := configuredPath
	if runtime.GOOS == "windows" && dest != "" && !strings.HasSuffix(strings.ToLower(dest), ".exe") {
		dest += ".exe"
	}
	if dest == "" || dest == defaultName || !filepath.IsAbs(dest) {
		if p, ok := ResolveBinaryPath(defaultName); ok && filepath.IsAbs(p) {
			dest = p
		} else if exe, err := os.Executable(); err == nil {
			dest = filepath.Join(filepath.Dir(exe), defaultName)
		} else if runtime.GOOS == "windows" {
			dest = privateBinPath(defaultName, dest)
		} else {
			dest = filepath.Join("/usr/local/bin", defaultName)
		}
	}

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return privateBinPath(defaultName, dest)
	}
	// 用 os.CreateTemp 而不是可预测的文件名：可预测名 + O_TRUNC 会被本地攻击者
	// 预先放置软链接，把写入重定向到任意文件。
	testFile, err := os.CreateTemp(dir, ".mnagent-write-test-*")
	if err != nil {
		return privateBinPath(defaultName, dest)
	}
	testPath := testFile.Name()
	_, writeErr := testFile.WriteString("ok")
	_ = testFile.Close()
	_ = os.Remove(testPath)
	if writeErr != nil {
		return privateBinPath(defaultName, dest)
	}
	return dest
}

// privateBinPath 返回私有状态目录下的 bin/<name>；状态目录不可用时原样返回 fallback，
// 让后续写入以明确的权限错误失败，而不是悄悄落到不安全的位置。
func privateBinPath(name, fallback string) string {
	d, err := statedir.Dir()
	if err != nil {
		return fallback
	}
	bin := filepath.Join(d, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		return fallback
	}
	return filepath.Join(bin, name)
}

// 依赖摘要获取的重试参数。国内直连 api.github.com / github.com 经常出现
// 连接重置或短时 5xx，单次失败就放弃会让“缺失依赖自动安装”在弱网下几乎不可用。
// 每次请求有独立短超时，重试次数与退避受父 ctx 控制。
const digestFetchAttempts = 3

var (
	digestRetryBaseDelay = 200 * time.Millisecond
	digestRetryMaxDelay  = 2 * time.Second
	digestRequestTimeout = 10 * time.Second
)

// nonRetryableHTTPError 标记确定性的 4xx 响应（429 限流除外）：
// 这类错误重试只会浪费任务预算，应立即放弃并回退到另一个来源。
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

func digestSourceError(source string, attempts int, err error) string {
	return fmt.Sprintf("%s失败（%d次：%s）", source, attempts, compactErrorText(err, summaryErrorLimit))
}

// retryDigest 对单个摘要来源做指数退避 + 抖动重试，错误里带上来源、尝试次数与
// 压缩后的最后错误；确定性 4xx（429 除外）不再重试。
func retryDigest(ctx context.Context, source string, fn func(context.Context) (string, error)) (string, error) {
	var lastErr error
	delay := digestRetryBaseDelay
	attempts := 0
	for attempt := 1; attempt <= digestFetchAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return "", fmt.Errorf("%s；%s", digestSourceError(source, attempts, lastErr), compactErrorText(err, summaryErrorLimit))
			}
			return "", fmt.Errorf("%s失败（0次，%s）", source, compactErrorText(err, summaryErrorLimit))
		}
		attemptCtx, cancel := context.WithTimeout(ctx, digestRequestTimeout)
		sum, err := fn(attemptCtx)
		cancel()
		if err == nil && sum != "" {
			return sum, nil
		}
		if err == nil {
			err = errors.New("返回空摘要")
		}
		lastErr = err
		attempts = attempt
		if isNonRetryableHTTPError(err) || attempt == digestFetchAttempts {
			break
		}
		wait := delay + time.Duration(rand.Int64N(int64(delay)+1))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", fmt.Errorf("%s；%s", digestSourceError(source, attempts, lastErr), compactErrorText(ctx.Err(), summaryErrorLimit))
		case <-timer.C:
		}
		delay = min(delay*2, digestRetryMaxDelay)
	}
	return "", errors.New(digestSourceError(source, attempts, lastErr))
}

// fetchAssetDigest 获取指定 Release 附件的 SHA-256 摘要。
//
// 两个来源都只会直连 GitHub（githubBaseURL / apiBaseURL，均不拼接 gh-proxy），
// 先尝试 "<资产>.sha256"，失败后回退到 api.github.com 的 assets[].digest；
// 每个来源独立重试，互为兜底。
// 拿不到有效摘要（上游未发布 .sha256、API 不可达、限流、附件不存在或未提供 digest）
// 一律返回错误：这些依赖以 root 运行，宁可拒绝安装也不能跳过完整性校验。
func (dm *DependencyManager) fetchAssetDigest(ctx context.Context, repo, tag, assetName string) (string, error) {
	var attempted []string
	sum, err := retryDigest(ctx, "同源 .sha256", func(ctx context.Context) (string, error) {
		return dm.fetchAssetDigestFile(ctx, repo, tag, assetName)
	})
	if err == nil {
		return sum, nil
	}
	attempted = append(attempted, err.Error())

	sum, err = retryDigest(ctx, "GitHub API", func(ctx context.Context) (string, error) {
		return dm.fetchAssetDigestAPI(ctx, repo, tag, assetName)
	})
	if err == nil {
		return sum, nil
	}
	attempted = append(attempted, err.Error())
	return "", digestAPIHint(fmt.Errorf("无法获取 %s 的 SHA-256 摘要：%s", assetName, strings.Join(attempted, "；")))
}

// fetchAssetDigestAPI 通过直连 api.github.com 的 Release 附件 digest 字段获取摘要。
func (dm *DependencyManager) fetchAssetDigestAPI(ctx context.Context, repo, tag, assetName string) (string, error) {
	targetURL := fmt.Sprintf("%s/repos/%s/releases/tags/%s", strings.TrimRight(dm.apiBaseURL, "/"), repo, url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent")
	req.Header.Set("Accept", "application/vnd.github+json")
	client := dm.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
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
	for _, a := range data.Assets {
		if a.Name != assetName {
			continue
		}
		if d, ok := strings.CutPrefix(strings.ToLower(a.Digest), "sha256:"); ok && sha256HexPattern.MatchString(d) {
			return d, nil
		}
		return "", fmt.Errorf("Release %s 的附件 %s 未提供 SHA-256 digest", tag, assetName)
	}
	return "", fmt.Errorf("Release %s 中不存在附件 %s", tag, assetName)
}

// digestAPIHint 给“拿不到摘要”的错误补上可操作说明：依赖校验必须能访问 api.github.com。
// 上游（nexttrace / miaospeed）目前并不发布 <资产>.sha256，因此 API 是唯一来源。
func digestAPIHint(err error) error {
	return fmt.Errorf("%w；获取依赖的上游 SHA-256 需要 api.github.com 连通性（或手动预装依赖）", err)
}

// fetchAssetDigestFile 直连读取 Release 附件的同源 "<资产>.sha256" 文件。
// URL 使用 githubBaseURL（默认直连 github.com，绝不拼接 gh-proxy），因此即使
// 配置了 gh-proxy，校验文件仍来自直连来源，不会被代理同时替换。
// 失败返回具体原因，由 fetchAssetDigest 决定是否回退到 API。
func (dm *DependencyManager) fetchAssetDigestFile(ctx context.Context, repo, tag, assetName string) (string, error) {
	sumURL := fmt.Sprintf("%s/%s/releases/download/%s/%s.sha256", strings.TrimRight(dm.githubBaseURL, "/"), repo, tag, assetName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent")
	client := dm.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", markNonRetryableHTTPStatus(resp.StatusCode, fmt.Errorf("该版本未发布 %s.sha256（HTTP 404）", assetName))
	}
	if resp.StatusCode != http.StatusOK {
		return "", markNonRetryableHTTPStatus(resp.StatusCode, fmt.Errorf("获取 %s.sha256 返回 HTTP %s", assetName, resp.Status))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s.sha256 为空", assetName)
	}
	sum := strings.ToLower(fields[0])
	if !sha256HexPattern.MatchString(sum) {
		return "", fmt.Errorf("%s.sha256 不是合法的 SHA-256", assetName)
	}
	// 带文件名的格式（"<hash>  <file>"）必须指向同一个资产，避免错误配对。
	if len(fields) > 1 {
		name := strings.TrimPrefix(fields[1], "*")
		if filepath.Base(name) != assetName {
			return "", fmt.Errorf("%s.sha256 指向了其他资产 %s", assetName, filepath.Base(name))
		}
	}
	return sum, nil
}

// downloadVerified 下载附件到调用方专用的临时路径 tmpPath，并强制校验上游 SHA-256 摘要；
// 摘要拿不到或不一致即报错。
//
// tmpPath 必须只是本次下载的临时文件（调用方应始终 defer os.Remove(tmpPath)）：
// 函数在写入失败或体积超限时会主动删除半成品，其余路径（含校验失败）由调用方统一清理。
func (dm *DependencyManager) downloadVerified(ctx context.Context, repo, tag, assetName, downloadURL, tmpPath string, log Logger) (int64, error) {
	digest, digestErr := dm.fetchAssetDigest(ctx, repo, tag, assetName)
	if digest == "" {
		if digestErr == nil {
			digestErr = errors.New("上游未提供摘要")
		}
		return 0, fmt.Errorf("无法获取 %s 的上游 SHA-256 摘要，已中止安装：%w", assetName, digestErr)
	}
	if log != nil {
		log.Debug("已获取依赖的上游 SHA-256 摘要", "asset", assetName, "digest", digest)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "mnagent")
	client := dm.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("下载 %s 失败：%w", assetName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("下载 %s HTTP 响应状态 %s", assetName, resp.Status)
	}

	// O_EXCL：临时路径名虽然带 UnixNano，仍可能在创建前被预先放置（软链接/旧残留）。
	// 用独占创建拒绝这类已存在文件，避免把下载内容写进别处。
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return 0, fmt.Errorf("创建临时文件失败：%w", err)
	}
	limit := dependencyDownloadLimit(assetName)
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(resp.Body, limit+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("写入 %s 失败：%w", assetName, err)
	}
	if written > limit {
		_ = os.Remove(tmpPath)
		return 0, fmt.Errorf("%s 下载体积超过上限（%d MB），已中止安装", assetName, limit>>20)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(digest)) != 1 {
		return 0, fmt.Errorf("%s SHA-256 完整性校验失败：期望 %s，实际 %s (防篡改拦截)", assetName, digest, actual)
	}
	return written, nil
}

// selfCheckDependency 在替换前运行一次下载的依赖二进制，确认可执行且版本与目标一致。
// 与 updater 的自检一致：宁可中止更新，也不把架构不匹配或损坏的二进制落盘。
func (dm *DependencyManager) selfCheckDependency(ctx context.Context, name, path, want string) error {
	// 自检独立限时：即使调用方没有 deadline，也不会因为依赖的 -version 卡住而挂死。
	ctx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	var (
		installed bool
		got       string
		err       error
	)
	switch name {
	case "nexttrace":
		installed, _, got, err = dm.detectLocalNextTrace(ctx, path)
	case "miaospeed":
		installed, _, got, err = dm.detectLocalMiaospeed(ctx, path)
	default:
		return fmt.Errorf("未知依赖：%s", name)
	}
	if !installed {
		return fmt.Errorf("自检失败：找不到刚下载的 %s（%s）", name, path)
	}
	if err != nil {
		return fmt.Errorf("%s 版本自检失败：%w", name, err)
	}
	if got == "" {
		return fmt.Errorf("%s 版本自检失败：无法解析版本输出", name)
	}
	wantV, wantOK := updater.ParseVersion(strings.TrimPrefix(want, "v"))
	gotV, gotOK := updater.ParseVersion(strings.TrimPrefix(got, "v"))
	if wantOK && gotOK {
		// 只要求主/次/补丁号一致：上游 tag 与二进制 -version 输出的预发布后缀
		// （-rc.1、+build 等）经常不一致，严格比较会把正常二进制误判为损坏。
		if gotV.Major != wantV.Major || gotV.Minor != wantV.Minor || gotV.Patch != wantV.Patch {
			return fmt.Errorf("%s 版本不匹配：期望 %s，实际 %s", name, want, got)
		}
	} else if strings.TrimPrefix(got, "v") != strings.TrimPrefix(want, "v") {
		return fmt.Errorf("%s 版本不匹配：期望 %s，实际 %s", name, want, got)
	}
	return nil
}

// UpdateNextTrace 下载并安装/更新 nexttrace 到目标路径。
func (dm *DependencyManager) UpdateNextTrace(ctx context.Context, targetPath, version string, log Logger) (string, error) {
	defer dm.lockDependency("nexttrace")()
	destPath := ResolveInstallTarget(targetPath, "nexttrace")
	assetName, err := NexttraceAsset(dm.goos, dm.goarch)
	if err != nil {
		return "", err
	}

	tag := version
	if tag == "" || tag == "latest" {
		latest, err := dm.fetchLatestTag(ctx, "nxtrace/NTrace-core")
		if err != nil {
			if binaryPresent(destPath) {
				return "", fmt.Errorf("获取 nexttrace 最新版本失败，已保留现有版本：%w", err)
			}
			tag = fallbackNexttraceVersion
			if log != nil {
				log.Warn("获取 nexttrace 最新版本失败，尝试安装兜底版本", "version", tag, "error", err)
			}
		} else {
			tag = latest
		}
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	if !updater.ValidReleaseTag(tag) {
		return "", fmt.Errorf("nexttrace 版本号格式非法：%q", tag)
	}

	rawURL := fmt.Sprintf("https://github.com/nxtrace/NTrace-core/releases/download/%s/%s", tag, assetName)
	downloadURL := updater.ApplyGHProxy(rawURL, dm.ghProxy)

	if log != nil {
		log.Info("开始下载 nexttrace", "version", tag, "url", downloadURL, "target", destPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("创建目录失败：%w", err)
	}

	tmpFile := filepath.Join(filepath.Dir(destPath), fmt.Sprintf(".nexttrace-update-%d", time.Now().UnixNano()))
	defer os.Remove(tmpFile)

	written, err := dm.downloadVerified(ctx, "nxtrace/NTrace-core", tag, assetName, downloadURL, tmpFile, log)
	if err != nil {
		return "", err
	}
	if written < 100*1024 { // nexttrace 二进制至少几百 KB 以上
		return "", fmt.Errorf("下载的 nexttrace 二进制体积异常 (%d bytes)", written)
	}
	if err := dm.selfCheckDependency(ctx, "nexttrace", tmpFile, tag); err != nil {
		return "", fmt.Errorf("nexttrace 自检失败，已中止替换：%w", err)
	}

	if err := updater.ReplaceExecutable(tmpFile, destPath); err != nil {
		return "", fmt.Errorf("替换 nexttrace 失败：%w", err)
	}
	if log != nil {
		log.Info("nexttrace 更新成功", "version", tag, "path", destPath)
	}
	return destPath, nil
}

// UpdateMiaospeed 下载并安装/更新 miaospeed 到目标路径。
func (dm *DependencyManager) UpdateMiaospeed(ctx context.Context, targetPath, version string, log Logger) (string, error) {
	defer dm.lockDependency("miaospeed")()
	destPath := ResolveInstallTarget(targetPath, "miaospeed")
	tag := strings.TrimPrefix(version, "v")
	if tag == "" || tag == "latest" {
		latest, err := dm.fetchLatestTag(ctx, "AirportR/miaospeed")
		if err != nil {
			if binaryPresent(destPath) {
				return "", fmt.Errorf("获取 miaospeed 最新版本失败，已保留现有版本：%w", err)
			}
			tag = fallbackMiaospeedVersion
			if log != nil {
				log.Warn("获取 miaospeed 最新版本失败，尝试安装兜底版本", "version", tag, "error", err)
			}
		} else {
			tag = strings.TrimPrefix(latest, "v")
		}
	}

	if !updater.ValidReleaseTag(tag) {
		return "", fmt.Errorf("miaospeed 版本号格式非法：%q", tag)
	}

	archMapped := MapMiaospeedArch(dm.goarch)
	var archiveName string
	if dm.goos == "windows" {
		archiveName = fmt.Sprintf("miaospeed-%s-%s-%s.zip", dm.goos, archMapped, tag)
	} else {
		archiveName = fmt.Sprintf("miaospeed-%s-%s-%s.tar.gz", dm.goos, archMapped, tag)
	}
	rawURL := fmt.Sprintf("https://github.com/AirportR/miaospeed/releases/download/%s/%s", tag, archiveName)
	downloadURL := updater.ApplyGHProxy(rawURL, dm.ghProxy)

	if log != nil {
		log.Info("开始下载 miaospeed", "version", tag, "url", downloadURL, "target", destPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("创建目录失败：%w", err)
	}

	tmpFile, err := createSecureTempPath(filepath.Dir(destPath), ".miaospeed-update-*")
	if err != nil {
		return "", fmt.Errorf("创建 miaospeed 解压临时文件失败：%w", err)
	}
	defer os.Remove(tmpFile)

	dlPath, err := createSecureTempPath(filepath.Dir(destPath), ".miaospeed-dl-*")
	if err != nil {
		return "", fmt.Errorf("创建 miaospeed 下载临时文件失败：%w", err)
	}
	defer os.Remove(dlPath)
	if _, err := dm.downloadVerified(ctx, "AirportR/miaospeed", tag, archiveName, downloadURL, dlPath, log); err != nil {
		return "", err
	}

	if strings.HasSuffix(archiveName, ".zip") {
		if err := ExtractZipFile(dlPath, tmpFile); err != nil {
			return "", fmt.Errorf("解压 miaospeed zip 失败：%w", err)
		}
	} else {
		archive, err := os.Open(dlPath)
		if err != nil {
			return "", fmt.Errorf("打开 miaospeed 压缩包失败：%w", err)
		}
		err = ExtractTarGzFile(archive, tmpFile)
		_ = archive.Close()
		if err != nil {
			return "", fmt.Errorf("解压 miaospeed 失败：%w", err)
		}
	}

	if err := os.Chmod(tmpFile, 0755); err != nil {
		return "", fmt.Errorf("设置权限失败：%w", err)
	}
	if err := dm.selfCheckDependency(ctx, "miaospeed", tmpFile, tag); err != nil {
		return "", fmt.Errorf("miaospeed 自检失败，已中止替换：%w", err)
	}

	if err := updater.ReplaceExecutable(tmpFile, destPath); err != nil {
		return "", fmt.Errorf("替换 miaospeed 失败：%w", err)
	}
	if log != nil {
		log.Info("miaospeed 更新成功", "version", tag, "path", destPath)
	}
	return destPath, nil
}

// createSecureTempPath 在目标同目录用 os.CreateTemp 生成随机临时路径并立即释放。
// 调用方随后用 O_EXCL 创建（downloadVerified/解压函数），与直接使用可预测文件名相比
// 不会被预先放置的软链接接管家；立即删除是为了让 O_EXCL 能重新创建。
func createSecureTempPath(dir, pattern string) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

// extractZipFile 从 zip 压缩包中解压出可执行文件并写入 destFile。
func ExtractZipFile(zipPath, destFile string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		name := filepath.Base(f.Name)
		if f.FileInfo().IsDir() {
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".zip") || strings.EqualFold(name, "license") || strings.HasPrefix(lower, "readme") {
			continue
		}
		if strings.HasSuffix(lower, ".exe") || strings.Contains(lower, "miaospeed") {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			// O_EXCL：目标路径由调用方用 os.CreateTemp 生成并保证不存在，
			// 与 downloadVerified 一致，拒绝被预先放置的软链接/旧文件。
			out, err := os.OpenFile(destFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
			if err != nil {
				_ = rc.Close()
				return err
			}
			_, cpErr := io.Copy(out, io.LimitReader(rc, maxExtractBytes+1))
			closeErr := out.Close()
			_ = rc.Close()
			if cpErr != nil {
				_ = os.Remove(destFile)
				return cpErr
			}
			if closeErr != nil {
				_ = os.Remove(destFile)
				return closeErr
			}
			// 不能只信 zip 头里的 UncompressedSize64（可伪造/为 0），按实际解压字节数检查。
			if fi, statErr := os.Stat(destFile); statErr != nil || fi.Size() > maxExtractBytes {
				_ = os.Remove(destFile)
				if statErr != nil {
					return statErr
				}
				return fmt.Errorf("%w：%s 超过 %d 字节", errExtractTooLarge, name, maxExtractBytes)
			}
			return nil
		}
	}
	return errors.New("zip 压缩包内未找到可执行文件")
}

// extractTarGzFile 从 gzip 压缩的 tar 流中解压出 miaospeed 可执行文件并保存到 destFile。
func ExtractTarGzFile(r io.Reader, destFile string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.FileInfo().IsDir() || hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(hdr.Name)
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") || strings.EqualFold(name, "license") || strings.HasPrefix(lower, "readme") {
			continue
		}
		if strings.HasSuffix(lower, ".exe") || strings.Contains(lower, "miaospeed") ||
			hdr.Name == "runner/runner" { // 4.7.11 起部分 miaospeed 归档把二进制放在 runner/runner
			// O_EXCL：目标路径由调用方用 os.CreateTemp 生成并保证不存在，
			// 与 downloadVerified 一致，拒绝被预先放置的软链接/旧文件。
			f, err := os.OpenFile(destFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
			if err != nil {
				return err
			}
			_, cpErr := io.Copy(f, io.LimitReader(tr, maxExtractBytes+1))
			closeErr := f.Close()
			if cpErr != nil {
				_ = os.Remove(destFile)
				return cpErr
			}
			if closeErr != nil {
				_ = os.Remove(destFile)
				return closeErr
			}
			if fi, statErr := os.Stat(destFile); statErr != nil || fi.Size() > maxExtractBytes {
				_ = os.Remove(destFile)
				if statErr != nil {
					return statErr
				}
				return fmt.Errorf("%w：%s 超过 %d 字节", errExtractTooLarge, name, maxExtractBytes)
			}
			return nil
		}
	}
	return errors.New("压缩包内未找到可执行文件")
}

// UpdateDependency 根据名称更新指定依赖。
func (dm *DependencyManager) UpdateDependency(ctx context.Context, name, targetPath, version string, log Logger) (string, error) {
	switch strings.ToLower(name) {
	case "nexttrace":
		return dm.UpdateNextTrace(ctx, targetPath, version, log)
	case "miaospeed":
		return dm.UpdateMiaospeed(ctx, targetPath, version, log)
	default:
		return "", fmt.Errorf("未知的依赖：%q", name)
	}
}

// Logger 是本包用到的最小日志接口。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// MapMiaospeedArch 映射系统架构为 miaospeed Release 命名格式。
func MapMiaospeedArch(arch string) string {
	switch arch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7"
	case "386":
		return "386"
	case "mips":
		return "mips-softfloat"
	case "mipsle":
		return "mipsle-softfloat"
	case "riscv64":
		return "riscv64"
	default:
		return arch
	}
}
