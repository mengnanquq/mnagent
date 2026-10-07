package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
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
	"strings"
	"time"
)

var (
	ansiEscapePattern   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	nexttraceVerPattern = regexp.MustCompile(`(?i)NextTrace\s+v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	miaospeedVerPattern = regexp.MustCompile(`(?i)version:\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	genericVerPattern   = regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
)

func stripANSI(s string) string {
	return ansiEscapePattern.ReplaceAllString(s, "")
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

// DependencyManager 负责检测与更新外部依赖工具。
type DependencyManager struct {
	ghProxy    string
	httpClient *http.Client
	apiBaseURL string // 默认 "https://api.github.com"
	cmdRunner  func(ctx context.Context, name string, args ...string) ([]byte, error)
	goos       string
	goarch     string
}

// newDependencyManager 创建依赖管理器实例。
func newDependencyManager(ghProxy string) *DependencyManager {
	return &DependencyManager{
		ghProxy: ghProxy,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		apiBaseURL: "https://api.github.com",
		cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			return cmd.CombinedOutput()
		},
		goos:   runtime.GOOS,
		goarch: runtime.GOARCH,
	}
}

// resolveBinaryPath 解析可执行文件的具体绝对/环境路径。
func resolveBinaryPath(bin string) (string, bool) {
	trimmed := strings.TrimSpace(bin)
	if trimmed == "" {
		return "", false
	}
	if filepath.IsAbs(trimmed) || strings.Contains(trimmed, string(filepath.Separator)) {
		if _, err := os.Stat(trimmed); err == nil {
			return trimmed, true
		}
		return trimmed, false
	}
	if p, err := exec.LookPath(trimmed); err == nil {
		return p, true
	}
	return trimmed, false
}

// detectLocalNextTrace 探测本地已安装的 nexttrace 版本。
func (dm *DependencyManager) detectLocalNextTrace(ctx context.Context, binPath string) (installed bool, realPath string, ver string, err error) {
	realPath, installed = resolveBinaryPath(binPath)
	if !installed {
		return false, realPath, "", nil
	}

	out, cmdErr := dm.cmdRunner(ctx, realPath, "-V")
	if cmdErr != nil {
		// 备选尝试 --version
		if out2, cmdErr2 := dm.cmdRunner(ctx, realPath, "--version"); cmdErr2 == nil {
			out = out2
			cmdErr = nil
		}
	}
	cleaned := stripANSI(string(out))
	if m := nexttraceVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
		if !strings.HasPrefix(ver, "v") {
			ver = "v" + ver
		}
		return true, realPath, ver, nil
	}
	if m := genericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
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
func (dm *DependencyManager) detectLocalMiaospeed(ctx context.Context, binPath string) (installed bool, realPath string, ver string, err error) {
	realPath, installed = resolveBinaryPath(binPath)
	if !installed {
		return false, realPath, "", nil
	}

	out, cmdErr := dm.cmdRunner(ctx, realPath, "-version")
	if cmdErr != nil {
		if out2, cmdErr2 := dm.cmdRunner(ctx, realPath, "version"); cmdErr2 == nil {
			out = out2
			cmdErr = nil
		}
	}
	cleaned := stripANSI(string(out))
	if m := miaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = strings.TrimPrefix(m[1], "v")
		return true, realPath, ver, nil
	}
	if m := genericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = strings.TrimPrefix(m[1], "v")
		return true, realPath, ver, nil
	}
	if cmdErr != nil {
		return true, realPath, "", fmt.Errorf("执行 %s -version 失败：%w", realPath, cmdErr)
	}
	return true, realPath, "", errors.New("无法解析 miaospeed 版本输出")
}

// fetchLatestTag 查询 GitHub 仓库的最新 Release tag。
// 注意：api.github.com 直连，不拼接 ghProxy。
func (dm *DependencyManager) fetchLatestTag(ctx context.Context, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", strings.TrimRight(dm.apiBaseURL, "/"), repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		cur, ok1 := parseVersion(curVer)
		lat, ok2 := parseVersion(latest)
		if ok1 && ok2 && lat.newerThan(cur) {
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
		cur, ok1 := parseVersion(curVer)
		lat, ok2 := parseVersion(st.LatestVersion)
		if ok1 && ok2 && lat.newerThan(cur) {
			st.HasUpdate = true
		}
	} else if !installed {
		st.HasUpdate = true
	}
	return st
}

// CheckAll 检查所有依赖组件的版本状态。
func (dm *DependencyManager) CheckAll(ctx context.Context, cfg *config) []DependencyStatus {
	nexttraceBin := "nexttrace"
	miaospeedBin := "miaospeed"
	if cfg != nil {
		if cfg.binary != "" {
			nexttraceBin = cfg.binary
		}
		if cfg.miaospeedBinary != "" {
			miaospeedBin = cfg.miaospeedBinary
		}
	}
	return []DependencyStatus{
		dm.CheckNextTrace(ctx, nexttraceBin),
		dm.CheckMiaospeed(ctx, miaospeedBin),
	}
}

// nexttraceAsset 返回指定平台与架构对应的 nexttrace 发布资产名称。
func nexttraceAsset(goos, goarch string) (string, error) {
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

	name := fmt.Sprintf("nexttrace_%s_%s", osName, archName)
	if osName == "windows" {
		name += ".exe"
	}
	return name, nil
}

// resolveInstallTarget 确定依赖落地文件的路径，并在无写权限时降级到 TempDir。
func resolveInstallTarget(configuredPath, defaultName string) string {
	dest := configuredPath
	if dest == "" || dest == defaultName || !filepath.IsAbs(dest) {
		if p, err := exec.LookPath(defaultName); err == nil && filepath.IsAbs(p) {
			dest = p
		} else {
			exe, err := os.Executable()
			if err == nil {
				dest = filepath.Join(filepath.Dir(exe), defaultName)
			} else {
				dest = filepath.Join("/usr/local/bin", defaultName)
			}
		}
	}

	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return filepath.Join(os.TempDir(), defaultName)
	}
	testFile := filepath.Join(dir, fmt.Sprintf(".test_write_%d_%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
		return filepath.Join(os.TempDir(), defaultName)
	}
	_ = os.Remove(testFile)
	return dest
}

// UpdateNextTrace 下载并安装/更新 nexttrace 到目标路径。
func (dm *DependencyManager) UpdateNextTrace(ctx context.Context, targetPath, version string, log logger) (string, error) {
	destPath := resolveInstallTarget(targetPath, "nexttrace")
	assetName, err := nexttraceAsset(dm.goos, dm.goarch)
	if err != nil {
		return "", err
	}

	tag := version
	if tag == "" || tag == "latest" {
		latest, err := dm.fetchLatestTag(ctx, "nxtrace/NTrace-core")
		if err != nil {
			tag = "v1.7.3"
		} else {
			tag = latest
		}
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	rawURL := fmt.Sprintf("https://github.com/nxtrace/NTrace-core/releases/download/%s/%s", tag, assetName)
	downloadURL := applyGHProxy(rawURL, dm.ghProxy)

	if log != nil {
		log.Info("开始下载 nexttrace", "version", tag, "url", downloadURL, "target", destPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("创建目录失败：%w", err)
	}

	tmpFile := filepath.Join(filepath.Dir(destPath), fmt.Sprintf(".nexttrace-update-%d", time.Now().UnixNano()))
	defer os.Remove(tmpFile)

	f, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败：%w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		_ = f.Close()
		return "", err
	}
	req.Header.Set("User-Agent", "mnagent")

	client := dm.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		_ = f.Close()
		return "", fmt.Errorf("下载 nexttrace 失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = f.Close()
		return "", fmt.Errorf("下载 nexttrace HTTP 响应状态 %s", resp.Status)
	}

	written, err := io.Copy(f, resp.Body)
	_ = f.Close()
	if err != nil {
		return "", fmt.Errorf("写入 nexttrace 失败：%w", err)
	}
	if written < 100*1024 { // nexttrace 二进制至少几百 KB 以上
		return "", fmt.Errorf("下载的 nexttrace 二进制体积异常 (%d bytes)", written)
	}

	if err := os.Rename(tmpFile, destPath); err != nil {
		return "", fmt.Errorf("替换 nexttrace 失败：%w", err)
	}
	if log != nil {
		log.Info("nexttrace 更新成功", "version", tag, "path", destPath)
	}
	return destPath, nil
}

// UpdateMiaospeed 下载并安装/更新 miaospeed 到目标路径。
func (dm *DependencyManager) UpdateMiaospeed(ctx context.Context, targetPath, version string, log logger) (string, error) {
	destPath := resolveInstallTarget(targetPath, "miaospeed")
	tag := strings.TrimPrefix(version, "v")
	if tag == "" || tag == "latest" {
		latest, err := dm.fetchLatestTag(ctx, "AirportR/miaospeed")
		if err != nil {
			tag = "4.7.7" // 兜底
		} else {
			tag = strings.TrimPrefix(latest, "v")
		}
	}

	archMapped := mapMiaospeedArch(dm.goarch)
	archiveName := fmt.Sprintf("miaospeed-%s-%s-%s.tar.gz", dm.goos, archMapped, tag)
	rawURL := fmt.Sprintf("https://github.com/AirportR/miaospeed/releases/download/%s/%s", tag, archiveName)
	downloadURL := applyGHProxy(rawURL, dm.ghProxy)

	if log != nil {
		log.Info("开始下载 miaospeed", "version", tag, "url", downloadURL, "target", destPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return "", fmt.Errorf("创建目录失败：%w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
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
		return "", fmt.Errorf("下载 miaospeed 失败：%w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载 miaospeed HTTP 响应状态 %s", resp.Status)
	}

	tmpFile := filepath.Join(filepath.Dir(destPath), fmt.Sprintf(".miaospeed-update-%d", time.Now().UnixNano()))
	defer os.Remove(tmpFile)

	if err := extractTarGzFile(resp.Body, tmpFile); err != nil {
		return "", fmt.Errorf("解压 miaospeed 失败：%w", err)
	}

	if err := os.Chmod(tmpFile, 0755); err != nil {
		return "", fmt.Errorf("设置权限失败：%w", err)
	}

	if err := os.Rename(tmpFile, destPath); err != nil {
		return "", fmt.Errorf("替换 miaospeed 失败：%w", err)
	}
	if log != nil {
		log.Info("miaospeed 更新成功", "version", tag, "path", destPath)
	}
	return destPath, nil
}

// extractTarGzFile 从 gzip 压缩的 tar 流中解压出 miaospeed 可执行文件并保存到 destFile。
func extractTarGzFile(r io.Reader, destFile string) error {
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
		name := filepath.Base(hdr.Name)
		if !hdr.FileInfo().IsDir() && !strings.HasSuffix(name, ".tar.gz") && hdr.Typeflag == tar.TypeReg {
			f, err := os.OpenFile(destFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			_, cpErr := io.Copy(f, tr)
			_ = f.Close()
			return cpErr
		}
	}
	return errors.New("压缩包内未找到可执行文件")
}

// UpdateDependency 根据名称更新指定依赖。
func (dm *DependencyManager) UpdateDependency(ctx context.Context, name, targetPath, version string, log logger) (string, error) {
	switch strings.ToLower(name) {
	case "nexttrace":
		return dm.UpdateNextTrace(ctx, targetPath, version, log)
	case "miaospeed":
		return dm.UpdateMiaospeed(ctx, targetPath, version, log)
	default:
		return "", fmt.Errorf("未知的依赖：%q", name)
	}
}
