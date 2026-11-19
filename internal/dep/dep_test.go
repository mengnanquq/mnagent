package dep

import (
	"github.com/mengnanquq/mnagent/internal/updater"
)

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

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
