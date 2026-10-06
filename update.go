package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// 自动更新默认参数。
const (
	autoUpdateDefaultInterval = 6 * time.Hour
	autoUpdateDefaultJitter   = time.Hour // 检查时间点加抖动，避免大量主机同时打 GitHub。
	updateCheckTimeout        = 20 * time.Second
	updateDownloadTimeout     = 2 * time.Minute
)

// semverRe 匹配 v1.2.3 或 1.2.3（可带 -pre 等预发布后缀）。
var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$`)

// versionInfo 解析出的版本号（去 v 前缀）。
type versionInfo struct {
	parts [3]int
	pre   string
	raw   string
}

// parseVersion 解析版本字符串；不合法返回 ok=false。
func parseVersion(s string) (versionInfo, bool) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return versionInfo{}, false
	}
	var v versionInfo
	for i := range v.parts {
		if _, err := fmt.Sscanf(m[i+1], "%d", &v.parts[i]); err != nil {
			return versionInfo{}, false
		}
	}
	v.pre = m[4]
	v.raw = m[0]
	return v, true
}

// newerThan 判断 v 是否严格晚于 other（按 semver 比较，预发布 < 正式版）。
func (v versionInfo) newerThan(other versionInfo) bool {
	for i := range v.parts {
		if v.parts[i] != other.parts[i] {
			return v.parts[i] > other.parts[i]
		}
	}
	if v.pre == other.pre {
		return false
	}
	// 相同主版本号：无预发布后缀 > 有预发布后缀。
	if v.pre == "" {
		return true
	}
	if other.pre == "" {
		return false
	}
	return v.pre > other.pre
}

// skipState 记录要跳过的版本（写入 skip 文件，跨重启保留）。
type skipState struct {
	version string
	until   time.Time
}

// updater 负责检查并应用 mnagent 自身的新版本。
// 通过“latest 下载地址会 302 到带版本号的资产地址”来获取最新版本：
// 零 API 配额、无需认证，也适用于受限网络。
type updater struct {
	repo           string // owner/repo
	platform       string // linux|darwin（资产命名用）
	arch           string // amd64|arm64|arm|mipsle…（资产命名用）
	client         *http.Client
	downloadClient *http.Client
	executable     string       // 当前二进制路径（os.Executable 解析后）
	skipFile       string       // 跳过版本记录文件
	restart        func() error // 应用更新后重启服务（由主程序注入：systemd restart / procd restart）

	// latestURL 生成 latest 下载地址（默认指向 GitHub；测试可覆盖为假服务器）。
	latestURL func() string
	// urlFor 生成指定版本（或 latest）的下载地址；测试可覆盖为假服务器。
	urlFor func(version string) string
}

// assetName 返回当前平台的 Release 资产名（与安装脚本的命名一致）。
func (u *updater) assetName() string {
	return "mnagent_" + u.platform + "_" + u.arch
}

// latestURLOrFallback 返回 latest 下载地址；测试可覆盖为假服务器地址。
func (u *updater) latestURLOrFallback() string {
	if u.latestURL != nil {
		return u.latestURL()
	}
	return "https://github.com/" + u.repo + "/releases/latest/download/" + u.assetName()
}

// urlForOrFallback 返回指定版本（或 latest）的下载地址；测试可覆盖。
func (u *updater) urlForOrFallback(version string) string {
	if u.urlFor != nil {
		return u.urlFor(version)
	}
	if version == "" || version == "latest" {
		return u.latestURLOrFallback()
	}
	return "https://github.com/" + u.repo + "/releases/download/" + version + "/" + u.assetName()
}

// latestVersion 返回最新发布版本号（v 前缀，如 v0.1.7），以及真实资产地址。
// HEAD 请求统一走 urlForOrFallback("latest")：默认是 GitHub 的 latest 地址，
// 测试可覆盖为假服务器。
func (u *updater) latestVersion() (string, string, error) {
	req, err := http.NewRequest(http.MethodHead, u.urlForOrFallback("latest"), nil)
	if err != nil {
		return "", "", err
	}
	// 不跟随重定向：我们要读 Location 头。
	resp, err := u.client.Do(req)
	if err != nil {
		return "", "", err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound &&
		resp.StatusCode != http.StatusMovedPermanently {
		return "", "", fmt.Errorf("检查更新失败：HTTP %s", resp.Status)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", "", errors.New("检查更新失败：响应缺少重定向地址")
	}
	// Location 形如 https://github.com/<repo>/releases/download/v0.1.7/<asset>：
	// 版本号在倒数第二段，资产名在最后一段。
	parts := strings.Split(strings.TrimRight(loc, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("解析版本号失败：%q", loc)
	}
	version := parts[len(parts)-2]
	if _, ok := parseVersion(version); !ok {
		return "", "", fmt.Errorf("解析版本号失败：%q", version)
	}
	return version, loc, nil
}

// Check 返回是否有可应用的新版本。
// 返回 (newVersion, true) 表示有更新且未被跳过；被跳过或已是最新返回 (_, false, nil)。
func (u *updater) Check() (string, bool, error) {
	latest, _, err := u.latestVersion()
	if err != nil {
		return "", false, err
	}
	current := version
	if _, ok := parseVersion(current); !ok || current == "dev" {
		return "", false, nil // 非版本构建（dev）不参与自动更新。
	}
	latestV, ok := parseVersion(latest)
	if !ok {
		return "", false, fmt.Errorf("解析最新版本失败：%q", latest)
	}
	curV, _ := parseVersion(current)
	if !latestV.newerThan(curV) {
		return "", false, nil
	}
	if u.skipped(latest) {
		return "", false, nil
	}
	return latest, true, nil
}

// Apply 下载并安装指定版本，然后重启服务。
// 安装是原子的：先下载到同目录临时文件并校验长度/可执行性，再改名覆盖。
// version 可以是具体版本（v0.1.8）或 latest（自动解析成最新版本号）。
func (u *updater) Apply(version string) error {
	if version == "" || version == "latest" {
		l, _, err := u.latestVersion()
		if err != nil {
			return err
		}
		version = l
	}
	if _, ok := parseVersion(version); !ok {
		return fmt.Errorf("版本号格式非法：%q", version)
	}
	url := u.urlForOrFallback(version)
	tmp, err := os.CreateTemp(filepath.Dir(u.executable), ".mnagent-update-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := u.downloadTo(url, tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		return err
	}
	// 覆盖正在运行的二进制：Linux 下进程持有的是已打开的文件描述符，
	// 覆盖路径本身是安全的（旧文件描述符继续指向旧 inode）。
	if err := os.Rename(tmpName, u.executable); err != nil {
		return err
	}
	// 校验新二进制能启动（-version 由 systemd/procd 重启后的新进程打印）。
	if u.restart != nil {
		if err := u.restart(); err != nil {
			return fmt.Errorf("二进制已更新，但重启服务失败：%w", err)
		}
	}
	return nil
}

// downloadTo 下载到目标文件，并做基本校验（非空、至少为合法大小）。
func (u *updater) downloadTo(url string, f *os.File) error {
	client := u.downloadClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载更新失败：HTTP %s", resp.Status)
	}
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	if n < 1024 {
		return fmt.Errorf("下载内容异常（仅 %d 字节）", n)
	}
	return nil
}

// skipped 判断指定版本是否在跳过列表中且未过期。
func (u *updater) skipped(version string) bool {
	data, err := os.ReadFile(u.skipFile)
	if err != nil {
		return false
	}
	until := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, version+" ") {
			until = strings.TrimSpace(strings.TrimPrefix(line, version))
			break
		}
	}
	if until == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return false
	}
	return time.Now().Before(t)
}

// Skip 把指定版本加入跳过列表（默认 24 小时）。
func (u *updater) Skip(version string, forDur time.Duration) error {
	if forDur <= 0 {
		forDur = 24 * time.Hour
	}
	data, err := os.ReadFile(u.skipFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	until := time.Now().Add(forDur).Format(time.RFC3339)
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, version+" ") {
			continue // 移除该版本的旧记录
		}
		lines = append(lines, line)
	}
	lines = append(lines, version+" "+until)
	return os.WriteFile(u.skipFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// sha256Of 计算文件校验和（供诊断/校验使用）。
func sha256Of(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sortVersions 把版本字符串按 semver 从新到旧排序（供日志/展示用）。
func sortVersions(versions []string) []string {
	parsed := make([]versionInfo, 0, len(versions))
	index := map[string]string{}
	for _, v := range versions {
		if p, ok := parseVersion(v); ok {
			parsed = append(parsed, p)
			index[p.raw] = v
		}
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].newerThan(parsed[j]) })
	out := make([]string, 0, len(parsed))
	for _, p := range parsed {
		out = append(out, index[p.raw])
	}
	return out
}

// detectPlatformArch 返回资产命名用的平台/架构（与安装脚本一致）。
func detectPlatformArch() (platform, arch string) {
	platform = strings.ToLower(runtime.GOOS)
	switch runtime.GOARCH {
	case "amd64":
		arch = "amd64"
	case "arm64":
		arch = "arm64"
	case "arm":
		arch = "arm"
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
