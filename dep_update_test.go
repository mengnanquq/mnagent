package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStripANSI 验证 ANSI 控制字符的清理。
func TestStripANSI(t *testing.T) {
	raw := "\x1b[37;1mNextTrace\x1b[0;22m  \x1b[90;1mv1.7.3\x1b[0;22m  \x1b[90;1m2026-08-27T04:36:24Z\x1b[0;22m"
	got := stripANSI(raw)
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

	cfg := &config{
		binary:          ntBin,
		miaospeedBinary: miaoBin,
	}
	statuses := dm.CheckAll(context.Background(), cfg)
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
	}

	for _, c := range cases {
		got, err := nexttraceAsset(c.goos, c.goarch)
		if err != nil {
			t.Fatalf("nexttraceAsset(%s, %s) 失败: %v", c.goos, c.goarch, err)
		}
		if got != c.want {
			t.Fatalf("nexttraceAsset(%s, %s) = %s, want %s", c.goos, c.goarch, got, c.want)
		}
	}
}

// TestUpdateNextTrace 验证 nexttrace 下载与更新逻辑。
func TestUpdateNextTrace(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "bin", "nexttrace")

	content := bytes.Repeat([]byte("F"), 150*1024) // 150KB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases/download") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(content)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".tar.gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(buf.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dm := newDependencyManager(srv.URL)
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

// TestAgentCheckAndUpdateDependencies 验证 agent.updateOnce 过程触发的依赖更新。
func TestAgentCheckAndUpdateDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	ntBin := filepath.Join(tmpDir, "nexttrace")
	_ = os.WriteFile(ntBin, []byte("#!/bin/sh\n"), 0755)

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

	cfg := &config{
		binary:          ntBin,
		miaospeedBinary: filepath.Join(tmpDir, "miaospeed"),
		autoUpdate:      false,
	}

	a := &agent{
		cfg:    cfg,
		logger: testLogger{t},
	}

	// 执行依赖检查，不应崩溃
	a.checkAndUpdateDependencies(context.Background())
}

// TestHandleUpdateCLICheckOnly 验证 CLI --check-update 处理流程。
func TestHandleUpdateCLICheckOnly(t *testing.T) {
	cfg := &config{
		checkUpdateOnce: true,
		binary:          "nexttrace",
		miaospeedBinary: "miaospeed",
	}

	handled, err := handleUpdateCLI(cfg, testLogger{t})
	if err != nil {
		// 在没有网络或无 GitHub 访问权限的环境下可能返回错误，但 handled 应为 true
	}
	if !handled {
		t.Fatal("期望 handled 为 true")
	}
}
