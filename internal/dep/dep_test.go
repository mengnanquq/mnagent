package dep

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengnanquq/mnagent/internal/updater"
)

// mockDependencyVersion 让下载后的依赖自检返回指定版本（测试无需真实可执行二进制）。
func mockDependencyVersion(dm *DependencyManager, nexttraceVer, miaospeedVer string) {
	dm.cmdRunner = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if strings.Contains(strings.ToLower(name), "miaospeed") {
			return []byte("version: " + miaospeedVer + "\n"), nil
		}
		return []byte("NextTrace  " + nexttraceVer + "\n"), nil
	}
}

// TestStripANSI 验证 ANSI 控制字符的清理。
func TestStripANSI(t *testing.T) {
	raw := "\x1b[37;1mNextTrace\x1b[0;22m  \x1b[90;1mv1.7.3\x1b[0;22m  \x1b[90;1m2026-08-27T04:36:24Z\x1b[0;22m"
	got := StripANSI(raw)
	want := "NextTrace  v1.7.3  2026-08-27T04:36:24Z"
	if got != want {
		t.Fatalf("stripANSI 结果不符合预期: got=%q, want=%q", got, want)
	}
}

// TestDetectLocalNextTrace 验证 nexttrace 本地版本探测及 ANSI 解析。
func TestDetectLocalNextTrace(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-nexttrace")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	dm := newDependencyManager("")
	dm.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out := "\x1b[37;1mNextTrace\x1b[0;22m  \x1b[90;1mv1.7.3\x1b[0;22m  \x1b[90;1m2026-08-27T04:36:24Z\x1b[0;22m  \x1b[90;1m40ac803\x1b[0;22m\n"
		return []byte(out), nil
	}

	installed, realPath, ver, err := dm.detectLocalNextTrace(context.Background(), fakeBin)
	if err != nil {
		t.Fatalf("detectLocalNextTrace 报错: %v", err)
	}
	if !installed {
		t.Fatal("期望 installed 为 true")
	}
	if realPath != fakeBin {
		t.Fatalf("realPath 不匹配: got=%s want=%s", realPath, fakeBin)
	}
	if ver != "v1.7.3" {
		t.Fatalf("版本解析不匹配: got=%s want=v1.7.3", ver)
	}

	// 测试未安装
	installed, _, _, _ = dm.detectLocalNextTrace(context.Background(), filepath.Join(tmpDir, "not-exist-bin"))
	if installed {
		t.Fatal("不存在的二进制期望 installed 为 false")
	}
}

// TestDetectLocalMiaospeed 验证 miaospeed 本地版本输出探测。
func TestDetectLocalMiaospeed(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-miaospeed")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	dm := newDependencyManager("")
	dm.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out := " __  __ _\n|  \\/  (_)\nversion: 4.7.7\ncommit: 6d086e9\n"
		return []byte(out), nil
	}

	installed, realPath, ver, err := dm.detectLocalMiaospeed(context.Background(), fakeBin)
	if err != nil {
		t.Fatalf("detectLocalMiaospeed 报错: %v", err)
	}
	if !installed {
		t.Fatal("期望 installed 为 true")
	}
	if realPath != fakeBin {
		t.Fatalf("realPath 不匹配: got=%s want=%s", realPath, fakeBin)
	}
	if ver != "4.7.7" {
		t.Fatalf("版本解析不匹配: got=%s want=4.7.7", ver)
	}
}

// TestCheckDependencies 验证依赖状态判断与版本对比。
func TestCheckDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	ntBin := filepath.Join(tmpDir, "nexttrace")
	miaoBin := filepath.Join(tmpDir, "miaospeed")
	_ = os.WriteFile(ntBin, []byte("#!/bin/sh\n"), 0755)
	_ = os.WriteFile(miaoBin, []byte("#!/bin/sh\n"), 0755)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "NTrace-core") {
			w.Write([]byte(`{"tag_name":"v1.7.4"}`))
			return
		}
		if strings.Contains(r.URL.Path, "miaospeed") {
			w.Write([]byte(`{"tag_name":"4.7.7"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.cmdRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(name, "nexttrace") {
			return []byte("NextTrace  v1.7.3\n"), nil
		}
		return []byte("version: 4.7.7\n"), nil
	}

	statuses := dm.CheckAll(context.Background(), ntBin, miaoBin)
	if len(statuses) != 2 {
		t.Fatalf("期望检查 2 个依赖，实际: %d", len(statuses))
	}

	// 1. nexttrace 应有更新 (v1.7.3 -> v1.7.4)
	ntSt := statuses[0]
	if ntSt.Name != "nexttrace" || !ntSt.Installed || !ntSt.HasUpdate {
		t.Fatalf("nexttrace 状态不符合预期: %+v", ntSt)
	}
	if !strings.Contains(ntSt.Summary(), "发现新版本") {
		t.Fatalf("nexttrace summary 不符合预期: %s", ntSt.Summary())
	}

	// 2. miaospeed 应已是最新 (4.7.7 == 4.7.7)
	miaoSt := statuses[1]
	if miaoSt.Name != "miaospeed" || !miaoSt.Installed || miaoSt.HasUpdate {
		t.Fatalf("miaospeed 状态不符合预期: %+v", miaoSt)
	}
	if !strings.Contains(miaoSt.Summary(), "已是最新版本") {
		t.Fatalf("miaospeed summary 不符合预期: %s", miaoSt.Summary())
	}
}

// TestNexttraceAsset 验证各架构下的资产命名解析。
func TestNexttraceAsset(t *testing.T) {
	cases := []struct {
		goos   string
		goarch string
		want   string
	}{
		{"linux", "amd64", "nexttrace_linux_amd64"},
		{"linux", "arm64", "nexttrace_linux_arm64"},
		{"linux", "arm", "nexttrace_linux_armv7"},
		{"darwin", "arm64", "nexttrace_darwin_arm64"},
		{"windows", "amd64", "nexttrace_windows_amd64.exe"},
		{"windows", "arm64", "nexttrace-tiny_windows_arm64.exe"},
	}

	for _, c := range cases {
		got, err := NexttraceAsset(c.goos, c.goarch)
		if err != nil {
			t.Fatalf("NexttraceAsset(%s, %s) 失败: %v", c.goos, c.goarch, err)
		}
		if got != c.want {
			t.Fatalf("NexttraceAsset(%s, %s) = %s, want %s", c.goos, c.goarch, got, c.want)
		}
	}
}

// TestUpdateNextTrace 验证 nexttrace 下载与更新逻辑。
func TestUpdateNextTrace(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "bin", "nexttrace")

	content := bytes.Repeat([]byte("F"), 150*1024) // 150KB
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/nxtrace/NTrace-core/releases/tags/v1.7.4") {
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%s"}]}`, digest)
			return
		}
		if strings.Contains(r.URL.Path, "releases/download") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(content)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "v1.7.4", "4.7.7")

	dest, err := dm.UpdateNextTrace(context.Background(), targetPath, "v1.7.4", nil)
	if err != nil {
		t.Fatalf("UpdateNextTrace 失败: %v", err)
	}
	if dest != targetPath {
		t.Fatalf("dest 不匹配: got=%s want=%s", dest, targetPath)
	}

	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("目标文件不存在: %v", err)
	}
	if (fi.Mode() & 0111) == 0 {
		t.Fatalf("目标文件未设置执行权限: %v", fi.Mode())
	}
	if fi.Size() != int64(len(content)) {
		t.Fatalf("文件大小不符合预期: got=%d want=%d", fi.Size(), len(content))
	}
}

// TestUpdateMiaospeed 验证 miaospeed 下载与解压更新逻辑。
func TestUpdateMiaospeed(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "bin", "miaospeed")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	miaoContent := []byte("#!/bin/sh\necho miaospeed\n")
	hdr := &tar.Header{
		Name:     "miaospeed-linux-amd64",
		Mode:     0755,
		Size:     int64(len(miaoContent)),
		Typeflag: tar.TypeReg,
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write(miaoContent)
	_ = tw.Close()
	_ = gw.Close()

	miaoSum := sha256.Sum256(buf.Bytes())
	miaoDigest := hex.EncodeToString(miaoSum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/AirportR/miaospeed/releases/tags/4.7.7") {
			fmt.Fprintf(w, `{"assets":[{"name":"miaospeed-linux-amd64-4.7.7.tar.gz","digest":"sha256:%s"}]}`, miaoDigest)
			return
		}
		if strings.Contains(r.URL.Path, ".tar.gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(buf.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "4.7.7", "4.7.7")

	dest, err := dm.UpdateMiaospeed(context.Background(), targetPath, "4.7.7", nil)
	if err != nil {
		t.Fatalf("UpdateMiaospeed 失败: %v", err)
	}
	if dest != targetPath {
		t.Fatalf("dest 不匹配: got=%s want=%s", dest, targetPath)
	}

	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("目标文件不存在: %v", err)
	}
	if (fi.Mode() & 0111) == 0 {
		t.Fatalf("目标文件未设置执行权限: %v", fi.Mode())
	}
}

// TestUpdateMiaospeedRejectsOversizedArchive 验证归档下载超过体积上限时中止安装，
// 不落盘目标文件，并清理临时下载文件。
func TestUpdateMiaospeedRejectsOversizedArchive(t *testing.T) {
	oldArchive, oldBinary := maxDependencyArchiveBytes, maxDependencyBinaryBytes
	maxDependencyArchiveBytes = 1024
	defer func() {
		maxDependencyArchiveBytes = oldArchive
		maxDependencyBinaryBytes = oldBinary
	}()

	body := bytes.Repeat([]byte("A"), int(maxDependencyArchiveBytes)+1)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/AirportR/miaospeed/releases/tags/4.7.7") {
			fmt.Fprintf(w, `{"assets":[{"name":"miaospeed-linux-amd64-4.7.7.tar.gz","digest":"sha256:%s"}]}`, digest)
			return
		}
		if strings.Contains(r.URL.Path, ".tar.gz") {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	targetPath := filepath.Join(t.TempDir(), "bin", "miaospeed")
	if _, err := dm.UpdateMiaospeed(context.Background(), targetPath, "4.7.7", nil); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("超过归档体积上限应中止安装，实际 err=%v", err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		t.Fatal("超限时不得写入目标文件")
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(targetPath), ".miaospeed-*")); len(leftovers) != 0 {
		t.Fatalf("超限下载后应删除临时文件，仍残留: %v", leftovers)
	}
}

// TestDownloadVerifiedRemovesTemporaryFileOnFailure 验证下载超限失败时函数会清理
// 传入的临时路径；调用方的 defer 仍可无副作用地再次 Remove。
func TestDownloadVerifiedRemovesTemporaryFileOnFailure(t *testing.T) {
	old := maxDependencyBinaryBytes
	maxDependencyBinaryBytes = 16
	defer func() { maxDependencyBinaryBytes = old }()

	body := bytes.Repeat([]byte("A"), int(maxDependencyBinaryBytes)+1)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/tags/v1.0.0") {
			fmt.Fprintf(w, `{"assets":[{"name":"asset","digest":"sha256:%s"}]}`, digest)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/asset") {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	tmpPath := filepath.Join(t.TempDir(), ".asset-download-tmp")
	if _, err := dm.downloadVerified(context.Background(), "owner/repo", "v1.0.0", "asset", srv.URL+"/asset", tmpPath, nil); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("下载超限应报错，实际: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("下载失败后函数应清理临时文件，实际 stat err=%v", err)
	}
}

// TestDependencyDownloadLimit 验证归档与裸二进制使用不同的体积上限。
func TestDependencyDownloadLimit(t *testing.T) {
	archives := []string{"miaospeed-linux-amd64-4.7.7.tar.gz", "miaospeed-windows-amd64-4.7.7.zip", "asset.tgz"}
	for _, name := range archives {
		if got := dependencyDownloadLimit(name); got != maxDependencyArchiveBytes {
			t.Fatalf("归档 %s 上限 = %d，期望 %d", name, got, maxDependencyArchiveBytes)
		}
	}
	if got := dependencyDownloadLimit("nexttrace_linux_amd64"); got != maxDependencyBinaryBytes {
		t.Fatalf("裸二进制上限 = %d，期望 %d", got, maxDependencyBinaryBytes)
	}
}

func TestUpdateMiaospeedWindowsZip(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "bin", "miaospeed.exe")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	// 写入 LICENSE 文件
	licHeader := &zip.FileHeader{Name: "LICENSE"}
	licWriter, err := zw.CreateHeader(licHeader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = licWriter.Write([]byte("MIT License"))

	// 写入可执行文件
	miaoContent := []byte("fake-windows-miaospeed-binary-content")
	binHeader := &zip.FileHeader{Name: "miaospeed-windows-amd64.exe"}
	binWriter, err := zw.CreateHeader(binHeader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = binWriter.Write(miaoContent)
	_ = zw.Close()

	zipSum := sha256.Sum256(buf.Bytes())
	zipDigest := hex.EncodeToString(zipSum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/AirportR/miaospeed/releases/tags/4.7.7") {
			fmt.Fprintf(w, `{"assets":[{"name":"miaospeed-windows-amd64-4.7.7.zip","digest":"sha256:%s"}]}`, zipDigest)
			return
		}
		if strings.Contains(r.URL.Path, ".zip") {
			w.Header().Set("Content-Type", "application/zip")
			w.Write(buf.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "windows"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "4.7.7", "4.7.7")

	dest, err := dm.UpdateMiaospeed(context.Background(), targetPath, "4.7.7", nil)
	if err != nil {
		t.Fatalf("UpdateMiaospeed 失败: %v", err)
	}
	if dest != targetPath {
		t.Fatalf("dest 不匹配: got=%s want=%s", dest, targetPath)
	}

	content, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("读取安装结果失败: %v", err)
	}
	if string(content) != string(miaoContent) {
		t.Fatalf("文件内容不匹配: got=%s want=%s", string(content), string(miaoContent))
	}
}

// TestReplaceExecutableAndCleanup 验证二进制替换与遗留 .old 清理机制。
func TestReplaceExecutableAndCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "testapp.exe")

	// 1. 目标尚不存在时的替换
	new1 := filepath.Join(tmpDir, "new1.tmp")
	_ = os.WriteFile(new1, []byte("v1"), 0755)
	if err := updater.ReplaceExecutable(new1, targetPath); err != nil {
		t.Fatalf("首次 replaceExecutable 失败: %v", err)
	}
	got, _ := os.ReadFile(targetPath)
	if string(got) != "v1" {
		t.Fatalf("内容不匹配: got=%s want=v1", string(got))
	}

	// 2. 目标已存在时的覆盖替换
	new2 := filepath.Join(tmpDir, "new2.tmp")
	_ = os.WriteFile(new2, []byte("v2"), 0755)
	if err := updater.ReplaceExecutable(new2, targetPath); err != nil {
		t.Fatalf("第二次 replaceExecutable 失败: %v", err)
	}
	got, _ = os.ReadFile(targetPath)
	if string(got) != "v2" {
		t.Fatalf("内容不匹配: got=%s want=v2", string(got))
	}

	// 3. 测试 cleanupOldExecutables
	oldFile := targetPath + ".old"
	_ = os.WriteFile(oldFile, []byte("old-data"), 0644)
	updater.CleanupOldExecutables(targetPath)
	// 在 Linux 上 cleanupOldExecutables 是 no-op，直接验证函数不崩溃
}

// TestResolveBinaryPathFallback 验证当可执行文件位于非 PATH 目录（如二进制同级目录或 /usr/local/bin）时的兜底发现机制。
func TestResolveBinaryPathFallback(t *testing.T) {
	tmpDir := t.TempDir()
	myTool := filepath.Join(tmpDir, "custom-probe")
	if runtime.GOOS == "windows" {
		myTool += ".exe"
	}
	if err := os.WriteFile(myTool, []byte("echo ok"), 0755); err != nil {
		t.Fatal(err)
	}

	// 1. 若传入绝对路径，应当命中
	if p, ok := ResolveBinaryPath(myTool); !ok || p != myTool {
		t.Fatalf("绝对路径解析失败: got p=%s, ok=%v", p, ok)
	}

	// 2. 将临时目录设为 PATH，测试环境变量查找
	oldPath := os.Getenv("PATH")
	defer os.Setenv("PATH", oldPath)
	os.Setenv("PATH", tmpDir)

	if p, ok := ResolveBinaryPath("custom-probe"); !ok || !strings.Contains(p, "custom-probe") {
		t.Fatalf("PATH 中未命中 custom-probe: got p=%s, ok=%v", p, ok)
	}

	// 3. 清空 PATH，确保 exec.LookPath 无法直接命中，验证 fallbackDirs 仍能找到常用工具
	os.Setenv("PATH", "")
	if runtime.GOOS != "windows" {
		if p, ok := ResolveBinaryPath("sh"); !ok || !strings.HasSuffix(p, "/sh") {
			t.Fatalf("清空 PATH 后兜底发现常用目录中的 sh 失败: got p=%s, ok=%v", p, ok)
		}
	}
}

// TestFetchLatestTagRedirectAndFallback 验证免配额的 302 重定向解析与 API 兜底流程。
func TestFetchLatestTagRedirectAndFallback(t *testing.T) {
	// 1. 模拟 HEAD 302 重定向
	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "releases/latest") {
			w.Header().Set("Location", "https://github.com/nxtrace/NTrace-core/releases/tag/v1.7.4")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer redirectSrv.Close()

	dm := newDependencyManager("")
	dm.githubBaseURL = redirectSrv.URL
	tag, err := dm.fetchLatestTagByRedirect(context.Background(), "nxtrace/NTrace-core")
	if err != nil {
		t.Fatalf("fetchLatestTagByRedirect 失败: %v", err)
	}
	if tag != "v1.7.4" {
		t.Fatalf("解析重定向 tag 不匹配: got=%s, want=v1.7.4", tag)
	}

	// 2. 模拟 HEAD 失败后平滑走 API 兜底
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases/latest") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"tag_name":"v2.0.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer apiSrv.Close()

	dmAPI := newDependencyManager("")
	dmAPI.apiBaseURL = apiSrv.URL
	apiTag, err := dmAPI.fetchLatestTag(context.Background(), "test/repo")
	if err != nil {
		t.Fatalf("fetchLatestTagByAPI 失败: %v", err)
	}
	if apiTag != "v2.0.0" {
		t.Fatalf("API tag 不匹配: got=%s, want=v2.0.0", apiTag)
	}
}

// TestUpdateDependencyDispatch 验证统一更新接口分发与未知依赖报错。
func TestUpdateDependencyDispatch(t *testing.T) {
	dm := newDependencyManager("")
	_, err := dm.UpdateDependency(context.Background(), "unknown-dep", "target", "latest", nil)
	if err == nil || !strings.Contains(err.Error(), "未知的依赖") {
		t.Fatalf("期望未知依赖报错，实际: %v", err)
	}
}

// TestUpdateNextTraceVerifiesDigest 验证：上游 API 给出的 SHA-256 摘要与下载内容不一致时拒绝安装，一致时正常安装。
func TestUpdateNextTraceVerifiesDigest(t *testing.T) {
	content := bytes.Repeat([]byte("N"), 150*1024)
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	var tampered atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos/nxtrace/NTrace-core/releases/tags/v1.7.4"):
			d := digest
			if tampered.Load() {
				d = strings.Repeat("0", 64)
			}
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%s"}]}`, d)
		case strings.Contains(r.URL.Path, "releases/download"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "v1.7.4", "4.7.7")
	target := filepath.Join(t.TempDir(), "nexttrace")

	tampered.Store(true)
	if _, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4", nil); err == nil || !strings.Contains(err.Error(), "完整性校验失败") {
		t.Fatalf("摘要不一致应拒绝安装，实际 err=%v", err)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("校验失败时不应写入目标文件")
	}
	tampered.Store(false)
	if _, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4", nil); err != nil {
		t.Fatalf("摘要一致应安装成功: %v", err)
	}
	if _, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4/../../x", nil); err == nil {
		t.Fatal("非法版本号应被拒绝")
	}
}

// TestUpdateNextTraceDigestMissingAborts 验证摘要缺失时 fail-closed：
// API 404、附件未带 digest、API 完全不可达都必须中止安装，且不得覆盖已有二进制。
func TestUpdateNextTraceDigestMissingAborts(t *testing.T) {
	content := bytes.Repeat([]byte("N"), 150*1024)
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"API 404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
		{"附件未提供 digest", func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/releases/tags/") {
				_, _ = w.Write([]byte(`{"assets":[{"name":"nexttrace_linux_amd64","digest":null}]}`))
				return
			}
			_, _ = w.Write(content)
		}},
		{"digest 格式非法", func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/releases/tags/") {
				_, _ = w.Write([]byte(`{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:deadbeef"}]}`))
				return
			}
			_, _ = w.Write(content)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			dm := newDependencyManager(srv.URL)
			dm.apiBaseURL = srv.URL
			dm.githubBaseURL = srv.URL
			dm.goos = "linux"
			dm.goarch = "amd64"
			target := filepath.Join(t.TempDir(), "nexttrace")
			if err := os.WriteFile(target, []byte("old-binary"), 0755); err != nil {
				t.Fatal(err)
			}

			_, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4", nil)
			if err == nil || !strings.Contains(err.Error(), "SHA-256 摘要") {
				t.Fatalf("摘要缺失应中止安装，实际 err=%v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil || string(got) != "old-binary" {
				t.Fatalf("摘要缺失时不得覆盖已有二进制: content=%q err=%v", string(got), err)
			}
		})
	}

	// API 完全不可达（连接被拒绝）同样必须 fail-closed。
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	dm := newDependencyManager("")
	dm.apiBaseURL = deadURL
	dm.githubBaseURL = deadURL
	dm.goos = "linux"
	dm.goarch = "amd64"
	target := filepath.Join(t.TempDir(), "nexttrace")
	if _, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4", nil); err == nil {
		t.Fatal("API 不可达时应中止安装")
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("API 不可达时不应写入目标文件")
	}
}

// TestUpdateNextTraceLatestFailureKeepsInstalled 验证已安装时查询最新版本失败不会回落到写死的旧版本。
func TestUpdateNextTraceLatestFailureKeepsInstalled(t *testing.T) {
	content := bytes.Repeat([]byte("F"), 150*1024)
	sum := sha256.Sum256(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/latest"):
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/releases/tags/v1.7.3"):
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%x"}]}`, sum)
		case strings.Contains(r.URL.Path, "releases/download"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"

	target := filepath.Join(t.TempDir(), "nexttrace")
	if err := os.WriteFile(target, []byte("installed-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := dm.UpdateNextTrace(context.Background(), target, "latest", nil); err == nil || !strings.Contains(err.Error(), "保留现有版本") {
		t.Fatalf("已安装时查询最新版本失败应保持现状，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "installed-binary" {
		t.Fatalf("不得覆盖已安装版本: %q", string(got))
	}
}

// TestUpdateNextTraceLatestFailureFallsBackWhenMissing 验证未安装时才允许安装兜底版本。
func TestUpdateNextTraceLatestFailureFallsBackWhenMissing(t *testing.T) {
	content := bytes.Repeat([]byte("F"), 150*1024)
	sum := sha256.Sum256(content)
	var gotTag atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/latest"):
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			gotTag.Store(strings.TrimPrefix(r.URL.Path, "/repos/nxtrace/NTrace-core/releases/tags/"))
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%x"}]}`, sum)
		case strings.Contains(r.URL.Path, "releases/download"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "v1.7.3", "4.7.7")

	target := filepath.Join(t.TempDir(), "nexttrace")
	if _, err := dm.UpdateNextTrace(context.Background(), target, "latest", nil); err != nil {
		t.Fatalf("未安装时应安装兜底版本: %v", err)
	}
	if got := gotTag.Load(); got != fallbackNexttraceVersion {
		t.Fatalf("兜底版本 = %v，期望 %s", got, fallbackNexttraceVersion)
	}
	if fi, err := os.Stat(target); err != nil || fi.Size() != int64(len(content)) {
		t.Fatalf("兜底安装结果异常: fi=%v err=%v", fi, err)
	}
}

// TestUpdateMiaospeedLatestFailureKeepsInstalled 验证 miaospeed 同样不会在 API 失败时降级。
func TestUpdateMiaospeedLatestFailureKeepsInstalled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"

	target := filepath.Join(t.TempDir(), "miaospeed")
	if err := os.WriteFile(target, []byte("installed-miao"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := dm.UpdateMiaospeed(context.Background(), target, "latest", nil); err == nil || !strings.Contains(err.Error(), "保留现有版本") {
		t.Fatalf("已安装时查询最新版本失败应保持现状，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "installed-miao" {
		t.Fatalf("不得覆盖已安装版本: %q", string(got))
	}
}

// TestExtractTarGzRunnerLayout 验证兼容 4.7.11 起把二进制放在 runner/runner 的 miaospeed 归档。
func TestExtractTarGzRunnerLayout(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := []byte("runner-binary-content")
	if err := tw.WriteHeader(&tar.Header{Name: "runner/runner", Mode: 0755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gw.Close()

	dest := filepath.Join(t.TempDir(), "miaospeed")
	if err := ExtractTarGzFile(&buf, dest); err != nil {
		t.Fatalf("解压 runner/runner 归档失败: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(content) {
		t.Fatalf("解压内容不匹配: %q err=%v", string(got), err)
	}
}

// TestSelfCheckDependencyIgnoresPrereleaseSuffix 验证依赖自检只比较主/次/补丁号：
// 上游 tag 带 -rc 后缀而二进制输出没有（或相反）时应通过。
func TestSelfCheckDependencyIgnoresPrereleaseSuffix(t *testing.T) {
	dm := newDependencyManager("")
	dm.cmdRunner = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if strings.Contains(strings.ToLower(name), "miaospeed") {
			return []byte("version: 4.7.8\n"), nil
		}
		return []byte("NextTrace v1.7.4\n"), nil
	}
	path := filepath.Join(t.TempDir(), "nexttrace")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := dm.selfCheckDependency(context.Background(), "nexttrace", path, "v1.7.4-rc.1"); err != nil {
		t.Fatalf("仅预发布后缀不同不应判定版本不匹配: %v", err)
	}
}

// TestSelfCheckDependencyTimeout 验证 -version 自检有独立超时，依赖卡住不会挂死更新流程。
func TestSelfCheckDependencyTimeout(t *testing.T) {
	old := selfCheckTimeout
	selfCheckTimeout = 50 * time.Millisecond
	defer func() { selfCheckTimeout = old }()

	dm := newDependencyManager("")
	dm.cmdRunner = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	path := filepath.Join(t.TempDir(), "nexttrace")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := dm.selfCheckDependency(context.Background(), "nexttrace", path, "v1.7.4")
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "版本自检失败") {
		t.Fatalf("卡死的自检应超时并报错，实际 err=%v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("自检超时未生效，耗时 %s", elapsed)
	}
}

// TestUpdateNextTraceSelfCheckMismatchAborts 验证下载后的版本自检失败会中止替换，
// 保留已有二进制，避免架构不匹配或损坏的依赖落盘。
func TestUpdateNextTraceSelfCheckMismatchAborts(t *testing.T) {
	content := bytes.Repeat([]byte("F"), 150*1024)
	sum := sha256.Sum256(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/releases/tags/v1.7.4") {
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%x"}]}`, sum)
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
	dm.apiBaseURL = srv.URL
	dm.goos = "linux"
	dm.goarch = "amd64"
	mockDependencyVersion(dm, "v1.0.0", "4.7.7") // 与实际目标 v1.7.4 不一致

	target := filepath.Join(t.TempDir(), "nexttrace")
	if err := os.WriteFile(target, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	_, err := dm.UpdateNextTrace(context.Background(), target, "v1.7.4", nil)
	if err == nil || !strings.Contains(err.Error(), "版本不匹配") {
		t.Fatalf("版本自检不一致应中止，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "old-binary" {
		t.Fatalf("自检失败时不得替换依赖: %q", string(got))
	}
}

// TestDetectLocalVersionTimeout 验证 detectLocalNextTrace/detectLocalMiaospeed
// 在调用方 ctx 没有 deadline 时也会套用独立超时，不会永久阻塞主循环。
func TestDetectLocalVersionTimeout(t *testing.T) {
	old := selfCheckTimeout
	selfCheckTimeout = 50 * time.Millisecond
	defer func() { selfCheckTimeout = old }()

	dm := newDependencyManager("")
	dm.cmdRunner = func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	for name, detect := range map[string]func(context.Context, string) (bool, string, string, error){
		"nexttrace": dm.detectLocalNextTrace,
		"miaospeed": dm.detectLocalMiaospeed,
	} {
		start := time.Now()
		if _, _, _, err := detect(context.Background(), path); err == nil {
			t.Fatalf("%s: 卡死的版本探测应超时报错", name)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("%s: 版本探测超时未生效，耗时 %s", name, elapsed)
		}
	}
}

// TestDetectLocalVersionRealCommandTimeout 用真实子进程验证默认 cmdRunner 的
// exec.CommandContext + WaitDelay 能终止卡住的依赖，而不是一直等待。
func TestDetectLocalVersionRealCommandTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 缺少 /bin/sh")
	}
	old := selfCheckTimeout
	selfCheckTimeout = 100 * time.Millisecond
	oldWait := cmdWaitDelay
	cmdWaitDelay = 100 * time.Millisecond
	defer func() {
		selfCheckTimeout = old
		cmdWaitDelay = oldWait
	}()

	path := filepath.Join(t.TempDir(), "slow-nexttrace")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nsleep 2\n"), 0755); err != nil {
		t.Fatal(err)
	}
	dm := newDependencyManager("")
	start := time.Now()
	if _, _, _, err := dm.detectLocalNextTrace(context.Background(), path); err == nil {
		t.Fatal("卡死的 nexttrace 应超时报错")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("真实子进程超时未生效，耗时 %s", elapsed)
	}
}

// TestDependencyUpdateLock 验证同名依赖串行化、不同依赖互不阻塞。
func TestDependencyUpdateLock(t *testing.T) {
	dm := newDependencyManager("")
	unlock := dm.lockDependency("nexttrace")

	acquired := make(chan struct{})
	go func() {
		unlock2 := dm.lockDependency("NextTrace") // 大小写不同也应视为同一依赖
		close(acquired)
		unlock2()
	}()

	select {
	case <-acquired:
		unlock()
		t.Fatal("同名依赖的第二把锁不应在释放前获取成功")
	case <-time.After(50 * time.Millisecond):
	}

	unlock()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("释放后第二把锁应在 1s 内获取成功")
	}

	// 不同依赖必须可以并行获取，避免 nexttrace 的更新拖住 miaospeed。
	miaoUnlock := dm.lockDependency("miaospeed")
	miaoUnlock()
}

// TestExtractTarGzSizeLimit 验证 tar.gz 解压超过上限时报错并清理临时文件。
func TestExtractTarGzSizeLimit(t *testing.T) {
	old := maxExtractBytes
	maxExtractBytes = 16
	defer func() { maxExtractBytes = old }()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := bytes.Repeat([]byte("A"), 64)
	if err := tw.WriteHeader(&tar.Header{Name: "miaospeed", Mode: 0755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gw.Close()

	dest := filepath.Join(t.TempDir(), "miaospeed")
	err := ExtractTarGzFile(&buf, dest)
	if err == nil || !errors.Is(err, errExtractTooLarge) {
		t.Fatalf("超限 tar.gz 应返回体积上限错误，实际 err=%v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("超限后应删除临时文件，stat err=%v", statErr)
	}
}

// TestExtractZipSizeLimit 验证 zip 解压超过上限时报错并清理临时文件。
func TestExtractZipSizeLimit(t *testing.T) {
	old := maxExtractBytes
	maxExtractBytes = 16
	defer func() { maxExtractBytes = old }()

	zipPath := filepath.Join(t.TempDir(), "miaospeed.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("miaospeed")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte("A"), 64)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "miaospeed")
	err = ExtractZipFile(zipPath, dest)
	if err == nil || !errors.Is(err, errExtractTooLarge) {
		t.Fatalf("超限 zip 应返回体积上限错误，实际 err=%v", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("超限后应删除临时文件，stat err=%v", statErr)
	}
}

// TestFetchAssetDigestPrefersUpstreamSha256 验证优先使用同源 .sha256，
// 且配置 gh-proxy 时不信任该文件（代理可同时替换二进制与校验文件），必须回退到 API。
func TestFetchAssetDigestPrefersUpstreamSha256(t *testing.T) {
	sum := strings.Repeat("a", 64)
	apiSum := strings.Repeat("b", 64)
	var apiHits, sumHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			sumHits.Add(1)
			fmt.Fprintf(w, "%s  nexttrace_linux_amd64\n", sum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%s"}]}`, apiSum)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	got, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err != nil || got != sum {
		t.Fatalf("应优先使用同源 .sha256：got=%q err=%v", got, err)
	}
	if apiHits.Load() != 0 || sumHits.Load() == 0 {
		t.Fatalf("不应触发 API 回退：api=%d sum=%d", apiHits.Load(), sumHits.Load())
	}

	// 配置 gh-proxy 时同源 .sha256 不可信，必须回退到 API。
	dmProxy := newDependencyManager("https://gh-proxy.example/")
	dmProxy.apiBaseURL = srv.URL
	dmProxy.githubBaseURL = srv.URL
	sumHits.Store(0)
	got, err = dmProxy.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err != nil || got != apiSum {
		t.Fatalf("配置 gh-proxy 时应回退到 API：got=%q err=%v", got, err)
	}
	if sumHits.Load() != 0 {
		t.Fatal("配置 gh-proxy 时不应请求同源 .sha256")
	}
}

// TestFetchAssetDigestErrorMentionsAPI 验证摘要获取失败时明确提示需要 api.github.com 连通性。
func TestFetchAssetDigestErrorMentionsAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }))
	defer srv.Close()
	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	_, err := dm.fetchAssetDigest(context.Background(), "nxtrace/NTrace-core", "v1.7.4", "nexttrace_linux_amd64")
	if err == nil || !strings.Contains(err.Error(), "api.github.com") {
		t.Fatalf("错误信息应说明需要 api.github.com 连通性：%v", err)
	}
}

// TestFetchAssetDigestRejectsMismatchedSha256Name 验证 .sha256 里文件名不匹配时不采用（避免错误配对）。
func TestFetchAssetDigestRejectsMismatchedSha256Name(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			fmt.Fprintf(w, "%s  nexttrace_linux_arm64\n", strings.Repeat("c", 64))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL
	if _, err := dm.fetchAssetDigest(context.Background(), "x/y", "v1.7.4", "nexttrace_linux_amd64"); err == nil {
		t.Fatal("文件名不匹配时不应采用该 .sha256")
	}
}

// TestDownloadVerifiedRefusesExistingTempPath 验证临时文件用 O_EXCL 创建：
// 预先放置的路径（可能是指向别处的软链接）会让下载直接失败，绝不会被覆盖。
func TestDownloadVerifiedRefusesExistingTempPath(t *testing.T) {
	content := bytes.Repeat([]byte("D"), 2048)
	sum := sha256.Sum256(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			http.NotFound(w, r)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			fmt.Fprintf(w, `{"assets":[{"name":"nexttrace_linux_amd64","digest":"sha256:%x"}]}`, sum)
		case strings.Contains(r.URL.Path, "/dl"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dm := newDependencyManager("")
	dm.apiBaseURL = srv.URL
	dm.githubBaseURL = srv.URL

	tmp := filepath.Join(t.TempDir(), "pre-existing")
	if err := os.WriteFile(tmp, []byte("attacker-content"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := dm.downloadVerified(context.Background(), "x/y", "v1.7.4", "nexttrace_linux_amd64", srv.URL+"/dl", tmp, nil)
	if err == nil || !strings.Contains(err.Error(), "临时文件") {
		t.Fatalf("已存在的临时路径必须被拒绝，实际 err=%v", err)
	}
	got, readErr := os.ReadFile(tmp)
	if readErr != nil || string(got) != "attacker-content" {
		t.Fatalf("已存在的临时文件不得被覆盖: %q err=%v", string(got), readErr)
	}
}

// TestResolveInstallTargetLeavesNoProbeFile 验证可写性探测使用 os.CreateTemp 且清理干净。
func TestResolveInstallTargetLeavesNoProbeFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nexttrace")
	if got := ResolveInstallTarget(target, "nexttrace"); got != target {
		t.Fatalf("可写目录应返回目标路径，实际 %q", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".mnagent-write-test-") {
			t.Fatalf("写入探测文件未清理：%s", e.Name())
		}
	}
}
