package updater

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mengnanquq/mnagent/internal/statedir"
)

// 自动更新默认配置。
const (
	DefaultInterval        = 6 * time.Hour
	DefaultJitter          = 10 * time.Minute
	DefaultCheckTimeout    = 10 * time.Second
	DefaultDownloadTimeout = 5 * time.Minute
	minBinaryBytes         = 1024 // 校验下载内容不是 404 HTML 或空文件。
)

// Version 是默认版本号（未指定时使用）。
var Version = "dev"

// SigningPublicKeyBase64 是可选的 Ed25519 更新签名公钥（base64，32 字节）。
// 发布构建通过 -ldflags "-X github.com/mengnanquq/mnagent/internal/updater.SigningPublicKeyBase64=<key>"
// 内置公钥；内置后更新会强制验证 <资产>.sha256 对应的 .sig 签名，未内置则保持旧的 SHA-256 校验行为。
var SigningPublicKeyBase64 = ""

var releaseVersionPattern = regexp.MustCompile(`/releases/download/([^/]+)/`)

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
	return v.Pre > other.Pre
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

	// SigningPublicKey 可直接注入 Ed25519 公钥（测试或自定义构建）；
	// 未设置时使用包级 SigningPublicKeyBase64。
	SigningPublicKey ed25519.PublicKey
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

	LatestURLFunc   func() string
	URLForFunc      func(version string) string
	ChecksumURLFunc func(version string) string
	APIURLFunc      func() string

	// verifyBinary 在替换前执行下载的临时文件，确认其可运行且版本匹配。
	// 测试可注入空实现；生产环境使用 verifyDownloadedBinary。
	verifyBinary func(path, version string) error

	// signingKey 非空时强制验证校验清单签名；signingKeyErr 记录内置公钥配置错误。
	signingKey    ed25519.PublicKey
	signingKeyErr error
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
	signingKey := cfg.SigningPublicKey
	var signingKeyErr error
	if len(signingKey) == 0 {
		signingKey, signingKeyErr = parseSigningPublicKey(SigningPublicKeyBase64)
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
		signingKey:     signingKey,
		signingKeyErr:  signingKeyErr,
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
	if u.GHProxy == "" {
		return rawURL
	}
	prefix := strings.TrimRight(strings.TrimSpace(u.GHProxy), "/") + "/"
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

func (u *Updater) latestVersionByAPI() (string, error) {
	apiTarget := "https://api.github.com/repos/" + u.Repo + "/releases/latest"
	if u.APIURLFunc != nil {
		apiTarget = u.APIURLFunc()
	}

	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultCheckTimeout}
	}
	req, err := http.NewRequest(http.MethodGet, apiTarget, nil)
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

func (u *Updater) latestVersion() (string, string, error) {
	req, err := http.NewRequest(http.MethodHead, u.urlForOrFallback("latest"), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "mnagent-updater")

	resp, err := u.Client.Do(req)
	if err != nil {
		if v, apiErr := u.latestVersionByAPI(); apiErr == nil {
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

	if v, apiErr := u.latestVersionByAPI(); apiErr == nil {
		return v, u.urlForOrFallback(v), nil
	}

	if loc == "" {
		return "", "", errors.New("检查更新失败：响应缺少重定向地址且 API 回退不可用")
	}
	return "", "", fmt.Errorf("解析版本号失败：%q", loc)
}

// Check 返回是否有可应用的新版本。
func (u *Updater) Check() (string, bool, error) {
	latest, _, err := u.latestVersion()
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
	return u.ProxyURL(raw)
}

var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// parseSigningPublicKey 解析 base64 公钥；空值表示未内置（保持旧行为）。
func parseSigningPublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("内置更新签名公钥不是合法 base64：%w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("内置更新签名公钥长度非法：期望 %d 字节，实际 %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// fetchChecksumBody 下载目标资产的 sha256 校验文件原始内容（签名验证必须针对原始字节）。
func (u *Updater) fetchChecksumBody(version string) ([]byte, error) {
	targetURL := u.checksumURLFor(version)
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mnagent-updater")

	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultDownloadTimeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("该版本未发布校验文件 %s.sha256（HTTP 404）", u.AssetName())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取校验文件返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<18)) // 256 KiB
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("校验文件 %s.sha256 为空", u.AssetName())
	}
	return body, nil
}

// signatureURLFor 返回校验清单对应签名文件的地址（默认与 .sha256 同目录的 .sha256.sig）。
func (u *Updater) signatureURLFor(version string) string {
	return u.checksumURLFor(version) + ".sig"
}

// fetchChecksumSignature 下载并解析 .sha256.sig；支持 base64 文本或 64 字节原始签名。
func (u *Updater) fetchChecksumSignature(version string) ([]byte, error) {
	targetURL := u.signatureURLFor(version)
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mnagent-updater")
	cli := u.DownloadClient
	if cli == nil {
		cli = &http.Client{Timeout: DefaultDownloadTimeout}
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("该版本未发布更新签名 %s.sha256.sig（HTTP 404）", u.AssetName())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取更新签名返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == ed25519.SignatureSize {
		return trimmed, nil
	}
	sig, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return nil, fmt.Errorf("更新签名格式非法（应为 base64 或 %d 字节原始签名）：%w", ed25519.SignatureSize, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("更新签名长度非法：期望 %d 字节，实际 %d", ed25519.SignatureSize, len(sig))
	}
	return sig, nil
}

// verifyChecksumSignature 在内置公钥时强制验证校验清单签名；未内置时保持旧行为并打印警告。
func (u *Updater) verifyChecksumSignature(version string, body []byte) error {
	if u.signingKeyErr != nil {
		return fmt.Errorf("内置更新签名公钥无效，已中止更新：%w", u.signingKeyErr)
	}
	if len(u.signingKey) == 0 {
		fmt.Fprintln(os.Stderr, "警告：当前二进制未内置更新签名公钥，仅校验 SHA-256；无法防御同时篡改二进制与校验文件的攻击")
		return nil
	}
	sig, err := u.fetchChecksumSignature(version)
	if err != nil {
		return fmt.Errorf("获取更新签名失败，已中止更新：%w", err)
	}
	if !ed25519.Verify(u.signingKey, body, sig) {
		return errors.New("更新校验清单 Ed25519 签名验证失败（可能被篡改或发布密钥不匹配），已中止更新")
	}
	return nil
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

// fetchExpectedChecksum 获取目标资产的 sha256 校验文件并提取 Hash。
func (u *Updater) fetchExpectedChecksum(version string) (string, error) {
	body, err := u.fetchChecksumBody(version)
	if err != nil {
		return "", err
	}
	return u.parseChecksum(body)
}

// DownloadAndReplace 下载并原子替换二进制文件，支持 SHA-256 完整性校验，返回目标版本号，但不触发重启。
func (u *Updater) DownloadAndReplace(version string) (string, error) {
	if !ValidReleaseTag(version) {
		return "", fmt.Errorf("非法的目标版本号：%q", version)
	}
	// 必须拿到有效校验值：缺失、为空或格式非法都中止更新，避免校验被静默跳过。
	checksumBody, err := u.fetchChecksumBody(version)
	if err != nil {
		return "", fmt.Errorf("获取 SHA-256 校验值失败，已中止更新：%w", err)
	}
	// 内置签名公钥时，先验证校验清单本身的签名，再信任其中的 SHA-256。
	if err := u.verifyChecksumSignature(version, checksumBody); err != nil {
		return "", err
	}
	expectedHash, err := u.parseChecksum(checksumBody)
	if err != nil {
		return "", fmt.Errorf("解析 SHA-256 校验值失败，已中止更新：%w", err)
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

	if err := u.downloadTo(downloadURL, multiWriter); err != nil {
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
		if err := u.verifyBinary(tmpPath, version); err != nil {
			return "", fmt.Errorf("新版本二进制自检失败，已中止替换：%w", err)
		}
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
func (u *Updater) Apply(version string) error {
	if _, err := u.DownloadAndReplace(version); err != nil {
		return err
	}
	if u.RestartFunc != nil {
		if err := u.RestartFunc(); err != nil {
			return fmt.Errorf("更新已写入但重启服务失败：%w", err)
		}
	}
	return nil
}

func (u *Updater) downloadTo(targetURL string, w io.Writer) error {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
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

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return err
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

	if err := os.MkdirAll(filepath.Dir(u.SkipFile), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(u.SkipFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// DetectPlatformArch 探测当前系统与架构对应的 Release 命名。
func DetectPlatformArch() (platform, arch string) {
	platform = runtime.GOOS
	switch runtime.GOARCH {
	case "arm":
		arch = "armv7"
	case "mipsle":
		arch = "mipsle"
	case "mips":
		arch = "mips"
	case "mips64le":
		arch = "mips64le"
	case "mips64":
		arch = "mips64"
	case "riscv64":
		arch = "riscv64"
	default:
		arch = runtime.GOARCH
	}
	return platform, arch
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
func verifyDownloadedBinary(path, version string) error {
	want, ok := ParseVersion(version)
	if !ok {
		return fmt.Errorf("目标版本号非法：%q", version)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

// CleanupOldExecutables 清理可执行文件周边的 .old 遗留备份文件（主要针对 Windows）。
func CleanupOldExecutables(targetPath string) {
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
func (u *Updater) LatestVersion() (string, string, error) {
	return u.latestVersion()
}
