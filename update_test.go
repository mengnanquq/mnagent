package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestParseVersion 覆盖版本号解析与 semver 比较。
func TestParseVersion(t *testing.T) {
	for _, s := range []string{"v0.1.7", "1.2.3", "v2.0.0-rc1", "0.0.1"} {
		if _, ok := parseVersion(s); !ok {
			t.Errorf("parseVersion(%q) 应成功", s)
		}
	}
	for _, s := range []string{"", "latest", "v1.2", "abc", "v1.2.3.4"} {
		if _, ok := parseVersion(s); ok {
			t.Errorf("parseVersion(%q) 应失败", s)
		}
	}

	cases := []struct {
		a, b string
		want bool // a 是否晚于 b
	}{
		{"v0.1.8", "v0.1.7", true},
		{"v0.1.7", "v0.1.7", false},
		{"v0.2.0", "v0.1.99", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.1.7", "v0.1.7-rc1", true}, // 正式版晚于预发布
		{"v0.1.7-rc2", "v0.1.7-rc1", true},
		{"v0.1.6", "v0.1.7", false},
	}
	for _, c := range cases {
		a, _ := parseVersion(c.a)
		b, _ := parseVersion(c.b)
		if got := a.newerThan(b); got != c.want {
			t.Errorf("%s newerThan %s = %v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// fakeReleaseServer 模拟 GitHub 的 latest 下载重定向：
// /latest/download/<asset> → 302 → /releases/download/vX.Y.Z/<asset>，再 200 返回文件。
type fakeReleaseServer struct {
	version string
	body    []byte
	hits    atomic.Int64
	dlHits  atomic.Int64
}

func (f *fakeReleaseServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/releases/download/") && strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64"):
		f.dlHits.Add(1)
		_, _ = w.Write(f.body)
	case r.URL.Path == "/releases/latest/download/mnagent_linux_amd64":
		f.hits.Add(1)
		http.Redirect(w, r, "/releases/download/"+f.version+"/mnagent_linux_amd64", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

// newTestUpdater 构建指向假服务器的 updater，可注入 restart 回调。
func newTestUpdater(t *testing.T, srv *fakeReleaseServer) (*updater, *atomic.Bool) {
	t.Helper()
	var restarted atomic.Bool
	u := &updater{
		repo:     "owner/repo",
		platform: "linux",
		arch:     "amd64",
		client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		executable: filepath.Join(t.TempDir(), "mnagent"),
		skipFile:   filepath.Join(t.TempDir(), "skip"),
		restart: func() error {
			restarted.Store(true)
			return nil
		},
	}
	// 让 latestURL/指定版本 URL 指向假服务器。
	old := func() {}
	_ = old
	return u, &restarted
}

// TestUpdaterCheck 验证“最新版本识别”与“跳过版本”。
func TestUpdaterCheck(t *testing.T) {
	srv := &fakeReleaseServer{version: "v0.1.8", body: []byte("fake-binary")}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u := &updater{
		repo:     "owner/repo",
		platform: "linux",
		arch:     "amd64",
		client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		executable: filepath.Join(t.TempDir(), "mnagent"),
		skipFile:   filepath.Join(t.TempDir(), "skip"),
		restart:    func() error { return nil },
	}
	// 覆盖 URL 生成：指向假服务器。
	base := ts.URL
	u.urlFor = func(version string) string {
		if version == "" || version == "latest" {
			return base + "/releases/latest/download/" + u.assetName()
		}
		return base + "/releases/download/" + version + "/" + u.assetName()
	}

	// 1) 当前版本等于最新 → 无更新。
	version = "v0.1.8"
	if _, ok, err := u.Check(); err != nil || ok {
		t.Fatalf("同版本应无更新: ok=%v err=%v", ok, err)
	}
	// 2) 旧版本 → 有更新。
	version = "v0.1.7"
	latest, ok, err := u.Check()
	if err != nil || !ok || latest != "v0.1.8" {
		t.Fatalf("旧版本应提示更新: latest=%q ok=%v err=%v", latest, ok, err)
	}
	// 3) 跳过该版本后 → 无更新。
	if err := u.Skip("v0.1.8", 0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := u.Check(); ok {
		t.Fatal("跳过版本后不应再提示更新")
	}
}

// TestUpdaterApply 验证“下载 → 原子替换 → 重启”。
func TestUpdaterApply(t *testing.T) {
	// 填充到 1KB 以上（downloadTo 有最小体积校验）。
	bin := []byte("#!/bin/sh\n# padding for size check\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	srv := &fakeReleaseServer{version: "v0.1.8", body: bin}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	var restarted atomic.Bool
	u := &updater{
		repo:     "owner/repo",
		platform: "linux",
		arch:     "amd64",
		client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		downloadClient: &http.Client{Timeout: time.Second},
		executable:     exe,
		skipFile:       filepath.Join(t.TempDir(), "skip"),
		restart: func() error {
			restarted.Store(true)
			return nil
		},
	}
	base := ts.URL
	u.urlFor = func(version string) string {
		return base + "/releases/download/" + version + "/" + u.assetName()
	}

	if err := u.Apply("v0.1.8"); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bin) {
		t.Fatalf("二进制未被替换: %q", got)
	}
	if !restarted.Load() {
		t.Fatal("应触发重启回调")
	}

	// 验证重启返回错误时的处理
	u.restart = func() error {
		return fmt.Errorf("fake restart error")
	}
	if err := u.Apply("v0.1.8"); err == nil || !strings.Contains(err.Error(), "fake restart error") {
		t.Fatalf("重启失败应返回错误: %v", err)
	}
	// 残留临时文件应被清理。
	entries, _ := os.ReadDir(filepath.Dir(exe))
	for _, e := range entries {
		if len(e.Name()) > 10 && e.Name()[:10] == ".mnagent-u" {
			t.Fatalf("临时文件未清理: %s", e.Name())
		}
	}
}

// TestUpdaterCLISkip 验证 --skip-update 会写入跳过记录（用假 skipFile 路径不可注入，
// 这里直接测 Skip 的持久化：文件包含版本与到期时间）。
func TestUpdaterCLISkip(t *testing.T) {
	u := &updater{skipFile: filepath.Join(t.TempDir(), "skip")}
	if err := u.Skip("v0.9.9", time.Hour); err != nil {
		t.Fatal(err)
	}
	if !u.skipped("v0.9.9") {
		t.Fatal("刚写入的版本应被视为已跳过")
	}
	if u.skipped("v0.9.8") {
		t.Fatal("其它版本不应被跳过")
	}
	// 手动写入一条已过期的记录 → 不再跳过。
	path := u.skipFile
	if err := os.WriteFile(path, []byte("v0.9.7 "+time.Now().Add(-time.Hour).Format(time.RFC3339)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if u.skipped("v0.9.7") {
		t.Fatal("过期版本不应再被跳过")
	}
}

// TestUpdaterCheckHTTP 验证对假服务器的整条“检查更新”HTTP 往返。
func TestUpdaterCheckHTTP(t *testing.T) {
	srv := &fakeReleaseServer{version: "v0.1.9", body: []byte("x")}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u := &updater{
		repo:     "owner/repo",
		platform: "linux",
		arch:     "amd64",
		client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		executable: filepath.Join(t.TempDir(), "mnagent"),
		skipFile:   filepath.Join(t.TempDir(), "skip"),
	}
	base := ts.URL
	u.urlFor = func(version string) string {
		if version == "" || version == "latest" {
			return base + "/releases/latest/download/" + u.assetName()
		}
		return base + "/releases/download/" + version + "/" + u.assetName()
	}

	version = "v0.1.8"
	latest, ok, err := u.Check()
	if err != nil || !ok || latest != "v0.1.9" {
		t.Fatalf("Check = (%q, %v, %v)", latest, ok, err)
	}
	if srv.hits.Load() == 0 {
		t.Fatal("latest 端点未被访问")
	}
	_ = fmt.Sprint()
	_ = context.Background()
}
