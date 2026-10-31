package updater

import (
	"context"
	"crypto/sha256"
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
		if _, ok := ParseVersion(s); !ok {
			t.Errorf("ParseVersion(%q) 应成功", s)
		}
	}
	for _, s := range []string{"", "latest", "v1.2", "abc", "v1.2.3.4"} {
		if _, ok := ParseVersion(s); ok {
			t.Errorf("ParseVersion(%q) 应失败", s)
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
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if got := a.NewerThan(b); got != c.want {
			t.Errorf("%s NewerThan %s = %v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// fakeReleaseServer 模拟 GitHub 的 latest 下载重定向：
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

// TestUpdaterCheck 验证“最新版本识别”与“跳过版本”。
func TestUpdaterCheck(t *testing.T) {
	srv := &fakeReleaseServer{version: "v0.1.8", body: []byte("fake-binary")}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u := New(Config{
		CurrentVersion: "v0.1.8",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     filepath.Join(t.TempDir(), "mnagent"),
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
		Client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	})
	base := ts.URL
	u.URLForFunc = func(version string) string {
		if version == "" || version == "latest" {
			return base + "/releases/latest/download/" + u.AssetName()
		}
		return base + "/releases/download/" + version + "/" + u.AssetName()
	}

	// 1) 当前版本等于最新 → 无更新。
	u.CurrentVersion = "v0.1.8"
	if _, ok, err := u.Check(); err != nil || ok {
		t.Fatalf("同版本应无更新: ok=%v err=%v", ok, err)
	}
	// 2) 旧版本 → 有更新。
	u.CurrentVersion = "v0.1.7"
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
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		DownloadClient: &http.Client{Timeout: time.Second},
		Executable:     exe,
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
		Restart: func() error {
			restarted.Store(true)
			return nil
		},
	})
	base := ts.URL
	u.URLForFunc = func(version string) string {
		if version == "" || version == "latest" {
			return base + "/releases/latest/download/" + u.AssetName()
		}
		return base + "/releases/download/" + version + "/" + u.AssetName()
	}

	if err := u.Apply("v0.1.8"); err != nil {
		t.Fatal(err)
	}
	if !restarted.Load() {
		t.Fatal("未调用 restart 回调")
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bin) {
		t.Fatalf("替换后的内容不一致: %q", string(got))
	}
}

// TestUpdaterCheckHTTP 验证对假服务器的整条“检查更新”HTTP 往返。
func TestUpdaterCheckHTTP(t *testing.T) {
	srv := &fakeReleaseServer{version: "v0.1.9", body: []byte("x")}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	u := New(Config{
		CurrentVersion: "v0.1.8",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Executable: filepath.Join(t.TempDir(), "mnagent"),
		SkipFile:   filepath.Join(t.TempDir(), "skip"),
	})
	base := ts.URL
	u.URLForFunc = func(version string) string {
		if version == "" || version == "latest" {
			return base + "/releases/latest/download/" + u.AssetName()
		}
		return base + "/releases/download/" + version + "/" + u.AssetName()
	}

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

// TestDetectPlatformArch 验证平台架构映射。
func TestDetectPlatformArch(t *testing.T) {
	p, a := DetectPlatformArch()
	if p == "" || a == "" {
		t.Fatalf("DetectPlatformArch() 返回空: platform=%q arch=%q", p, a)
	}
}

// TestUpdaterProxyURL 验证 GitHub 代理前缀转换逻辑。
func TestUpdaterProxyURL(t *testing.T) {
	cases := []struct {
		name    string
		proxy   string
		raw     string
		wantURL string
	}{
		{
			name:    "未配置代理",
			proxy:   "",
			raw:     "https://github.com/foo/bar/releases/download/v1.0.0/asset",
			wantURL: "https://github.com/foo/bar/releases/download/v1.0.0/asset",
		},
		{
			name:    "代理带末尾斜杠",
			proxy:   "https://gh-proxy.com/",
			raw:     "https://github.com/foo/bar/releases/download/v1.0.0/asset",
			wantURL: "https://gh-proxy.com/https://github.com/foo/bar/releases/download/v1.0.0/asset",
		},
		{
			name:    "代理不带末尾斜杠",
			proxy:   "https://gh-proxy.com",
			raw:     "https://github.com/foo/bar/releases/download/v1.0.0/asset",
			wantURL: "https://gh-proxy.com/https://github.com/foo/bar/releases/download/v1.0.0/asset",
		},
		{
			name:    "目标已有代理前缀不重复叠加",
			proxy:   "https://gh-proxy.com/",
			raw:     "https://gh-proxy.com/https://github.com/foo/bar/releases/download/v1.0.0/asset",
			wantURL: "https://gh-proxy.com/https://github.com/foo/bar/releases/download/v1.0.0/asset",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &Updater{GHProxy: tc.proxy}
			got := u.ProxyURL(tc.raw)
			if got != tc.wantURL {
				t.Errorf("ProxyURL(%q) = %q, want %q", tc.raw, got, tc.wantURL)
			}
		})
	}
}

// TestUpdaterCheckWithAPIFallback 验证当 HEAD latest 返回 200 时，能自动回退到 API。
func TestUpdaterCheckWithAPIFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.NotFound(w, r)
		case "/api/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name": "v0.3.6"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	u := New(Config{
		CurrentVersion: "v0.3.5",
		Repo:           "test/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Client: &http.Client{
			Timeout: time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		DownloadClient: ts.Client(),
		Executable:     filepath.Join(t.TempDir(), "mnagent"),
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
	})
	u.LatestURLFunc = func() string {
		return ts.URL + "/latest"
	}
	u.APIURLFunc = func() string {
		return ts.URL + "/api/latest"
	}

	latest, ok, err := u.Check()
	if err != nil {
		t.Fatalf("Check 失败: %v", err)
	}
	if !ok || latest != "v0.3.6" {
		t.Fatalf("Check = (%q, %v)，期望 (v0.3.6, true)", latest, ok)
	}
}

// TestUpdaterAssetNameWindows 验证 Windows 平台资产名带 .exe 后缀。
func TestUpdaterAssetNameWindows(t *testing.T) {
	u := &Updater{Platform: "windows", Arch: "amd64"}
	if got := u.AssetName(); got != "mnagent_windows_amd64.exe" {
		t.Fatalf("AssetName = %q, want mnagent_windows_amd64.exe", got)
	}
	u.Arch = "arm64"
	if got := u.AssetName(); got != "mnagent_windows_arm64.exe" {
		t.Fatalf("AssetName = %q, want mnagent_windows_arm64.exe", got)
	}
}

// TestUpdaterSHA256ChecksumVerification 验证发布了 sha256sums.txt 时哈希匹配则成功，被篡改则拦截报错。
func TestUpdaterSHA256ChecksumVerification(t *testing.T) {
	bin := []byte("#!/bin/sh\n# padding for size check\n")
	for len(bin) < 2048 {
		bin = append(bin, "#"...)
	}
	realHash := fmt.Sprintf("%x", sha256.Sum256(bin))

	var serveMismatched atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sha256sums.txt"):
			hash := realHash
			if serveMismatched.Load() {
				hash = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", hash)
		case strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64"):
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	_ = os.WriteFile(exe, []byte("old-bin"), 0o755)

	u := New(Config{
		CurrentVersion: "v0.1.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		DownloadClient: ts.Client(),
		Executable:     exe,
	})
	u.URLForFunc = func(version string) string {
		return ts.URL + "/releases/download/" + version + "/" + u.AssetName()
	}
	u.ChecksumURLFunc = func(version string) string {
		return ts.URL + "/releases/download/" + version + "/sha256sums.txt"
	}

	// 1. 正确 Hash -> 正常替换
	if err := u.Apply("v0.1.1"); err != nil {
		t.Fatalf("匹配正确 Hash 应成功，但报错: %v", err)
	}

	// 2. 篡改 Hash -> 拦截报错
	serveMismatched.Store(true)
	if err := u.Apply("v0.1.2"); err == nil || !strings.Contains(err.Error(), "完整性校验失败") {
		t.Fatalf("篡改 Hash 期望拦截报错，实际 got err: %v", err)
	}
}
