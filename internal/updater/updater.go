package updater

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
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

	LatestURLFunc func() string
	URLForFunc    func(version string) string
	APIURLFunc    func() string
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
		skipFile = filepath.Join(os.TempDir(), "mnagent-skip-versions")
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

// DownloadAndReplace 下载并原子替换二进制文件，返回目标版本号，但不触发重启。
func (u *Updater) DownloadAndReplace(version string) (string, error) {
	downloadURL := u.urlForOrFallback(version)
	tmpFile, err := os.CreateTemp(filepath.Dir(u.Executable), "mnagent-upd-*")
	if err != nil {
		tmpFile, err = os.CreateTemp("", "mnagent-upd-*")
		if err != nil {
			return "", fmt.Errorf("创建临时更新文件失败：%w", err)
		}
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := u.downloadTo(downloadURL, tmpFile); err != nil {
		_ = tmpFile.Close()
		return "", fmt.Errorf("下载新版本失败：%w", err)
	}
	_ = tmpFile.Close()

	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", fmt.Errorf("设置执行权限失败：%w", err)
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

func (u *Updater) downloadTo(targetURL string, f *os.File) error {
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

	n, err := io.Copy(f, resp.Body)
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

// ReplaceExecutable 将 newFile 原子替换（或 Windows 兼容替换）到 targetPath。
func ReplaceExecutable(newFile, targetPath string) error {
	if runtime.GOOS != "windows" {
		return os.Rename(newFile, targetPath)
	}

	if _, err := os.Stat(targetPath); errors.Is(err, os.ErrNotExist) {
		return os.Rename(newFile, targetPath)
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
	return nil
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
