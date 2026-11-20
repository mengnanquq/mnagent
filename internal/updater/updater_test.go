package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
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
		{"v0.1.7-rc.10", "v0.1.7-rc.9", true}, // 数字段按数值而不是字符串比较
		{"v0.1.7-rc.9", "v0.1.7-rc.10", false},
		{"v0.1.7-rc.100000000000000000000", "v0.1.7-rc.99999999999999999999", true}, // 超长数字不得溢出
		{"v0.1.7-alpha", "v0.1.7-alpha.1", false},
		{"v0.1.7-alpha.1", "v0.1.7-alpha.beta", false},
		{"v0.1.7-beta", "v0.1.7-rc", false},
		{"v0.1.7-rc.1", "v0.1.7-rc.1.1", false},
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
	case strings.HasPrefix(r.URL.Path, "/releases/download/") && strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64.sha256"):
		fmt.Fprintf(w, "%x  mnagent_linux_amd64\n", sha256.Sum256(f.body))
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
	if _, ok, err := u.Check(context.Background()); err != nil || ok {
		t.Fatalf("同版本应无更新: ok=%v err=%v", ok, err)
	}
	// 2) 旧版本 → 有更新。
	u.CurrentVersion = "v0.1.7"
	latest, ok, err := u.Check(context.Background())
	if err != nil || !ok || latest != "v0.1.8" {
		t.Fatalf("旧版本应提示更新: latest=%q ok=%v err=%v", latest, ok, err)
	}
	// 3) 跳过该版本后 → 无更新。
	if err := u.Skip("v0.1.8", 0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := u.Check(context.Background()); ok {
		t.Fatal("跳过版本后不应再提示更新")
	}
}

// TestUpdaterApply 验证“下载 → 原子替换 → 重启”。
func TestUpdaterApply(t *testing.T) {
	// 填充到 1KB 以上（downloadTo 有最小体积校验）；脚本需能响应 -version 自检。
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.8 (linux/amd64, go1.26.0)\"\n")
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
	// 校验文件同样指向本地假服务器，避免测试访问真实 GitHub。
	u.ChecksumURLFunc = func(version string) string {
		return base + "/releases/download/" + version + "/" + u.AssetName() + ".sha256"
	}
	u.ChecksumAPIURLFunc = func(version string) string {
		return base + "/releases/tags/" + version
	}

	if err := u.Apply(context.Background(), "v0.1.8"); err != nil {
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
	prev, err := os.ReadFile(exe + ".prev")
	if err != nil || string(prev) != "old-binary" {
		t.Fatalf(".prev 应保留上一版本: content=%q err=%v", string(prev), err)
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

	latest, ok, err := u.Check(context.Background())
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
			name:    "纯空白代理视为未配置",
			proxy:   " \t\n",
			raw:     "https://github.com/foo/bar/releases/download/v1.0.0/asset",
			wantURL: "https://github.com/foo/bar/releases/download/v1.0.0/asset",
		},
		{
			name:    "代理前后空白会被去除",
			proxy:   "  https://gh-proxy.com/  ",
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

	latest, ok, err := u.Check(context.Background())
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

// TestReleaseArchMatchesAssets 验证 32 位 ARM 使用产物名 arm，而不是 nexttrace 依赖的 armv7。
func TestReleaseArchMatchesAssets(t *testing.T) {
	cases := map[string]string{
		"amd64": "amd64", "arm64": "arm64", "arm": "arm",
		"mipsle": "mipsle", "mips": "mips", "mips64le": "mips64le",
		"mips64": "mips64", "riscv64": "riscv64",
	}
	for goarch, want := range cases {
		if got := ReleaseArch(goarch); got != want {
			t.Fatalf("ReleaseArch(%q) = %q，期望 %q", goarch, got, want)
		}
	}
	if ReleaseArch("arm") == "armv7" {
		t.Fatal("32 位 ARM 资产名不能映射为 armv7，否则自更新必然 404")
	}
}

// TestReleaseWorkflowAssetsMatchUpdater 解析 release.yml 的 matrix，确认 updater 生成的
// 资产名与发布产物完全一致（含 Windows .exe 后缀）。
func TestReleaseWorkflowAssetsMatchUpdater(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("读取 release.yml 失败：%v", err)
	}
	matrixPattern := regexp.MustCompile(`(?m)^\s*-\s*\{\s*goos:\s*([a-z0-9]+)\s*,\s*goarch:\s*([a-z0-9]+)`)
	matches := matrixPattern.FindAllStringSubmatch(string(raw), -1)
	if len(matches) == 0 {
		t.Fatal("未从 release.yml 解析到任何构建 matrix")
	}
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		goos, goarch := m[1], m[2]
		u := &Updater{Platform: goos, Arch: ReleaseArch(goarch)}
		want := "mnagent_" + goos + "_" + goarch
		if goos == "windows" {
			want += ".exe"
		}
		if got := u.AssetName(); got != want {
			t.Errorf("release.yml 产物 %s 与 updater.AssetName()=%s 不一致", want, got)
		}
		seen[want] = true
	}
	for _, required := range []string{"mnagent_linux_amd64", "mnagent_linux_arm", "mnagent_linux_mipsle", "mnagent_windows_amd64.exe"} {
		if !seen[required] {
			t.Errorf("release.yml matrix 缺少必要产物 %s", required)
		}
	}

	// install.sh 的架构映射必须与发布产物一致：armv7l/armv6l 等一律下载 mnagent_linux_arm。
	install, err := os.ReadFile(filepath.Join(root, "install.sh"))
	if err != nil {
		t.Fatalf("读取 install.sh 失败：%v", err)
	}
	foundArm := false
	for _, line := range strings.Split(string(install), "\n") {
		if strings.Contains(line, "armv7l") {
			foundArm = true
			if !strings.Contains(line, `ARCH="arm"`) {
				t.Errorf("install.sh 的 ARM 架构应映射为 arm，实际：%s", strings.TrimSpace(line))
			}
		}
	}
	if !foundArm {
		t.Error("install.sh 未找到 ARM 架构映射")
	}
}

// TestReleaseWorkflowHasNoArmv7Alias 验证 release.yml 已移除临时的
// mnagent_linux_armv7 别名：updater 只按 GOARCH 请求 mnagent_linux_arm，
// 继续发布一个内容重复的别名只会让升级资产选择产生歧义。
func TestReleaseWorkflowHasNoArmv7Alias(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("读取 release.yml 失败：%v", err)
	}
	workflow := string(raw)
	if strings.Contains(workflow, "mnagent_linux_armv7") {
		t.Error("release.yml 不应再生成 mnagent_linux_armv7 别名")
	}
	if !strings.Contains(workflow, "sha256sum -c --strict") {
		t.Error("release.yml 的发布校验应实际比对 .sha256 哈希")
	}
}

// TestUpdaterSHA256ChecksumVerification 验证发布了 <资产>.sha256 时哈希匹配则成功，被篡改则拦截报错。
func TestUpdaterSHA256ChecksumVerification(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.1 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, "#"...)
	}
	realHash := fmt.Sprintf("%x", sha256.Sum256(bin))

	var serveMismatched atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
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
		return ts.URL + "/releases/download/" + version + "/" + u.AssetName() + ".sha256"
	}
	u.ChecksumAPIURLFunc = func(version string) string {
		return ts.URL + "/releases/tags/" + version
	}

	// 1. 正确 Hash -> 正常替换
	if err := u.Apply(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("匹配正确 Hash 应成功，但报错: %v", err)
	}

	// 2. 篡改 Hash -> 拦截报错
	serveMismatched.Store(true)
	if err := u.Apply(context.Background(), "v0.1.2"); err == nil || !strings.Contains(err.Error(), "完整性校验失败") {
		t.Fatalf("篡改 Hash 期望拦截报错，实际 got err: %v", err)
	}
}

// TestUpdaterChecksumFetchFailureAborts 验证：校验文件返回非 200 错误时中止更新，不得跳过校验；非法版本号直接拒绝。
func TestUpdaterChecksumFetchFailureAborts(t *testing.T) {
	bin := make([]byte, 4096)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			http.Error(w, "bad gateway", http.StatusBadGateway)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	_ = os.WriteFile(exe, []byte("old-bin"), 0o755)
	u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64", DownloadClient: ts.Client(), Executable: exe})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/api/releases/tags/" + version }

	if err := u.Apply(context.Background(), "v0.1.1"); err == nil || !strings.Contains(err.Error(), "校验值") {
		t.Fatalf("校验文件 502 时应中止更新，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatal("中止更新时不应替换二进制")
	}
	for _, bad := range []string{"v1.2.3/../../x", "v1.2.3-a/b", "latest", "+1.2.3", "v1.2"} {
		if ValidReleaseTag(bad) {
			t.Fatalf("%q 不应被视为合法版本号", bad)
		}
		if err := u.Apply(context.Background(), bad); err == nil {
			t.Fatalf("非法版本号 %q 应被拒绝", bad)
		}
	}
	for _, good := range []string{"v0.3.96", "1.2.3", "v1.2.3-rc.1"} {
		if !ValidReleaseTag(good) {
			t.Fatalf("%q 应为合法版本号", good)
		}
	}
}

// TestUpdaterChecksumRetriesTransientFailure 验证直连 .sha256 前两次 503、第三次成功时
// 会自动重试并继续安装，而不是因为一次网络抖动就中止更新。
func TestUpdaterChecksumRetriesTransientFailure(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.1 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	checksum := fmt.Sprintf("%x  mnagent_linux_amd64\n", sha256.Sum256(bin))
	var shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			if shaHits.Add(1) < 3 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(checksum))
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not fallback", http.StatusInternalServerError)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64", DownloadClient: ts.Client(), Executable: exe})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("前两次失败、第三次成功时应重试成功: %v", err)
	}
	if got := shaHits.Load(); got != 3 {
		t.Fatalf(".sha256 应请求 3 次，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf(".sha256 最终成功时不应调用 API 兜底，实际 %d 次", got)
	}
}

// TestUpdaterChecksumFallsBackToAPIDigest 验证直连 .sha256 持续失败时，
// 改为直连 api.github.com 的 asset digest；API 前两次失败也会重试。
func TestUpdaterChecksumFallsBackToAPIDigest(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.1 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bin))
	var shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			http.Error(w, "down", http.StatusBadGateway)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			if apiHits.Add(1) < 3 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"assets":[{"name":"mnagent_linux_amd64","digest":"sha256:%s"}]}`, digest)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64", DownloadClient: ts.Client(), Executable: exe})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf(".sha256 失败后应回退到 API digest: %v", err)
	}
	if got := shaHits.Load(); got != checksumFetchAttempts {
		t.Fatalf(".sha256 应尝试 %d 次，实际 %d 次", checksumFetchAttempts, got)
	}
	if got := apiHits.Load(); got != checksumFetchAttempts {
		t.Fatalf("API 应尝试 %d 次，实际 %d 次", checksumFetchAttempts, got)
	}
}

// TestUpdaterChecksumMissingOrInvalidAborts 覆盖拿不到有效校验值的各种情况：
// 404、空文件、哈希不匹配、格式非法、清单中缺少当前资产，全部必须中止更新且不替换二进制。
func TestUpdaterChecksumMissingOrInvalidAborts(t *testing.T) {
	bin := make([]byte, 4096)
	realHash := fmt.Sprintf("%x", sha256.Sum256(bin))
	cases := []struct {
		name         string
		status       int
		checksumBody string
		wantErr      string
	}{
		{"校验文件 404", http.StatusNotFound, "", "404"},
		{"校验文件为空", http.StatusOK, "\n", "为空"},
		{"校验文件只有空白", http.StatusOK, "  \t\n", "为空"},
		{"哈希不匹配", http.StatusOK, strings.Repeat("0", 64) + "  mnagent_linux_amd64\n", "完整性校验失败"},
		{"哈希格式非法", http.StatusOK, "not-a-valid-hash  mnagent_linux_amd64\n", "格式非法"},
		{"清单中缺少当前资产", http.StatusOK, realHash + "  other_asset\n", "未找到当前资产"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, ".sha256") {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.checksumBody))
					return
				}
				_, _ = w.Write(bin)
			}))
			defer ts.Close()

			exe := filepath.Join(t.TempDir(), "mnagent")
			if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64", DownloadClient: ts.Client(), Executable: exe})
			u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
			u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
			u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/api/releases/tags/" + version }

			err := u.Apply(context.Background(), "v0.1.1")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误包含 %q，实际 err=%v", tc.wantErr, err)
			}
			if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
				t.Fatal("校验失败时不应替换二进制")
			}
		})
	}
}

// TestVerifyDownloadedBinary 验证替换前自检能识别版本不符与不可执行文件。
func TestVerifyDownloadedBinary(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok")
	if err := os.WriteFile(okPath, []byte("#!/bin/sh\necho \"mnagent v1.2.3 (linux/amd64, go1.26.0)\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadedBinary(context.Background(), okPath, "v1.2.3"); err != nil {
		t.Fatalf("版本一致应通过: %v", err)
	}
	if err := verifyDownloadedBinary(context.Background(), okPath, "1.2.3"); err != nil {
		t.Fatalf("忽略 v 前缀后应通过: %v", err)
	}
	if err := verifyDownloadedBinary(context.Background(), okPath, "v1.2.4"); err == nil || !strings.Contains(err.Error(), "版本不匹配") {
		t.Fatalf("版本不一致应拒绝，实际 err=%v", err)
	}

	badPath := filepath.Join(dir, "bad")
	if err := os.WriteFile(badPath, []byte("not-an-executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadedBinary(context.Background(), badPath, "v1.2.3"); err == nil {
		t.Fatal("不可执行文件应被拒绝")
	}
}

// TestDownloadAndReplaceRejectsBadBinary 验证自检失败时中止替换，原二进制保持不变。
func TestDownloadAndReplaceRejectsBadBinary(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.9.9 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			fmt.Fprintf(w, "%x  mnagent_linux_amd64\n", sha256.Sum256(bin))
			return
		}
		_, _ = w.Write(bin)
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64", DownloadClient: ts.Client(), Executable: exe})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/api/releases/tags/" + version }

	err := u.Apply(context.Background(), "v0.1.1")
	if err == nil || !strings.Contains(err.Error(), "自检失败") {
		t.Fatalf("二进制版本不符应中止替换，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatalf("自检失败时不得替换二进制: %q", string(got))
	}
}

// TestReplaceExecutableKeepsPrev 验证非 Windows 平台替换时保留 <路径>.prev 供手工回滚。
func TestReplaceExecutableKeepsPrev(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 使用 .old 机制")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "mnagent")
	if err := os.WriteFile(target, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct{ newContent, wantPrev string }{
		{"v2", "v1"},
		{"v3", "v2"},
	} {
		tmp := filepath.Join(dir, "new.tmp")
		if err := os.WriteFile(tmp, []byte(step.newContent), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := ReplaceExecutable(tmp, target); err != nil {
			t.Fatalf("替换失败: %v", err)
		}
		got, _ := os.ReadFile(target)
		if string(got) != step.newContent {
			t.Fatalf("目标内容 = %q，期望 %q", string(got), step.newContent)
		}
		prev, err := os.ReadFile(target + ".prev")
		if err != nil || string(prev) != step.wantPrev {
			t.Fatalf(".prev 内容 = %q (err=%v)，期望 %q", string(prev), err, step.wantPrev)
		}
	}
}

// recordingLogger 记录 Updater 输出的安全告警与普通信息。
type recordingLogger struct {
	mu       sync.Mutex
	warnings []string
	infos    []string
}

func (l *recordingLogger) Warn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, msg)
}

func (l *recordingLogger) Info(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, msg)
}

func (l *recordingLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.warnings...)
}

func (l *recordingLogger) infoSnapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.infos...)
}

// hostRewriteTransport 把对真实 GitHub/代理域名的请求改写到本地 httptest 服务器，
// 用于验证 updater 在不同信任模式下分别访问了直连地址还是代理地址。
type hostRewriteTransport struct {
	routes map[string]string // 原始 host -> 目标 base URL
}

func (t *hostRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if target, ok := t.routes[clone.URL.Host]; ok {
		parsed, err := url.Parse(target)
		if err != nil {
			return nil, err
		}
		clone.URL.Scheme = parsed.Scheme
		clone.URL.Host = parsed.Host
	}
	return noProxyTransport.RoundTrip(clone)
}

var noProxyTransport = &http.Transport{Proxy: nil}

// timeoutTransport 记录请求 host，并阻塞到请求 context 结束后返回其错误，
// 用于验证校验文件请求确实受独立超时约束且失败后 fail-closed。
type timeoutTransport struct {
	mu    sync.Mutex
	hosts []string
}

func (t *timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.hosts = append(t.hosts, req.URL.Host)
	t.mu.Unlock()
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func (t *timeoutTransport) requestedHosts() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.hosts...)
}

// newRewriteClient 构造一个不读取环境代理、按 host 改写到本地测试服务器的客户端。
func newRewriteClient(direct, proxy *httptest.Server) *http.Client {
	return &http.Client{
		Transport: &hostRewriteTransport{routes: map[string]string{
			"github.com":       direct.URL,
			"gh-proxy.example": proxy.URL,
		}},
	}
}

// TestUpdaterProxyFetchesChecksumDirect 验证配置代理时：
// .sha256 校验文件走直连 github.com，二进制仍走代理，且更新成功。
func TestUpdaterProxyFetchesChecksumDirect(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.8 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	checksum := fmt.Sprintf("%x  mnagent_linux_amd64\n", sha256.Sum256(bin))

	var directChecksumHits, directBinaryHits, proxyChecksumHits, proxyBinaryHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			directChecksumHits.Add(1)
			_, _ = w.Write([]byte(checksum))
		case strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64"):
			directBinaryHits.Add(1)
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer direct.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			proxyChecksumHits.Add(1)
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  mnagent_linux_amd64\n"))
		case strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64"):
			proxyBinaryHits.Add(1)
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxy.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     exe,
		GHProxy:        "https://gh-proxy.example/",
		DownloadClient: newRewriteClient(direct, proxy),
	})
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.8"); err != nil {
		t.Fatalf("校验文件直连、二进制走代理时应允许更新: %v", err)
	}
	if got := directChecksumHits.Load(); got != 1 {
		t.Fatalf("校验文件应直连 github.com 请求 1 次，实际 %d 次", got)
	}
	if got := proxyChecksumHits.Load(); got != 0 {
		t.Fatalf("校验文件不得经代理获取，实际代理请求 %d 次", got)
	}
	if got := proxyBinaryHits.Load(); got != 1 {
		t.Fatalf("二进制应经代理下载 1 次，实际 %d 次", got)
	}
	if got := directBinaryHits.Load(); got != 0 {
		t.Fatalf("二进制不应直连下载，实际直连请求 %d 次", got)
	}
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, bin) {
		t.Fatal("更新成功后二进制内容应为代理下载的新版本")
	}
}

// TestUpdaterProxyDirectChecksumFailureFailsClosed 验证直连获取
// .sha256 失败时拒绝更新：即使代理能提供看似有效的校验文件与二进制也不得回退。
func TestUpdaterProxyDirectChecksumFailureFailsClosed(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.8 (linux/amd64, go1.26.0)\"\n")
	checksum := fmt.Sprintf("%x  mnagent_linux_amd64\n", sha256.Sum256(bin))

	var directChecksumHits, proxyChecksumHits, proxyBinaryHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			directChecksumHits.Add(1)
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(bin)
	}))
	defer direct.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			proxyChecksumHits.Add(1)
			_, _ = w.Write([]byte(checksum))
		case strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64"):
			proxyBinaryHits.Add(1)
			_, _ = w.Write(bin)
		default:
			http.NotFound(w, r)
		}
	}))
	defer proxy.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     exe,
		GHProxy:        "https://gh-proxy.example/",
		DownloadClient: newRewriteClient(direct, proxy),
	})
	u.ChecksumAPIURLFunc = func(version string) string { return direct.URL + "/api/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	_, err := u.DownloadAndReplace(context.Background(), "v0.1.8")
	if err == nil {
		t.Fatal("直连获取校验文件失败时应拒绝更新")
	}
	for _, want := range []string{"不经 gh-proxy 镜像", "HTTPS_PROXY", "已中止更新"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息应包含 %q，实际：%v", want, err)
		}
	}
	// 404 属于确定性 4xx，不再重试：只请求一次就回退到 API 来源。
	if got := directChecksumHits.Load(); got != 1 {
		t.Fatalf("确定性 404 应只尝试直连获取校验文件 1 次，实际 %d 次", got)
	}
	if got := proxyChecksumHits.Load(); got != 0 {
		t.Fatalf("直连失败时不得回退到代理获取校验文件，实际代理请求 %d 次", got)
	}
	if got := proxyBinaryHits.Load(); got != 0 {
		t.Fatalf("校验未通过时不得下载二进制，实际代理二进制请求 %d 次", got)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatalf("拒绝更新时不得替换二进制: %q", string(got))
	}
}

// TestChecksumNoRetryOnDeterministic4xx 验证确定性 4xx 不重试，429 仍重试。
func TestChecksumNoRetryOnDeterministic4xx(t *testing.T) {
	origDelay := checksumRetryBaseDelay
	checksumRetryBaseDelay = time.Millisecond
	defer func() { checksumRetryBaseDelay = origDelay }()

	for _, tc := range []struct {
		status int
		want   int32
	}{
		{http.StatusNotFound, 1},
		{http.StatusForbidden, 1},
		{http.StatusTooManyRequests, int32(checksumFetchAttempts)},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			var hits atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(tc.status)
			}))
			defer ts.Close()
			u := New(Config{CurrentVersion: "v0.1.0", Repo: "owner/repo", Platform: "linux", Arch: "amd64"})
			u.ChecksumURLFunc = func(version string) string { return ts.URL + "/" + u.AssetName() + ".sha256" }
			if _, err := u.fetchChecksumFile(context.Background(), "v0.1.1"); err == nil {
				t.Fatal("非 200 响应应返回错误")
			}
			if got := hits.Load(); got != tc.want {
				t.Fatalf("HTTP %d 请求次数 = %d，期望 %d", tc.status, got, tc.want)
			}
		})
	}
}

// TestUpdaterDirectChecksumTimeoutFailsClosed 验证直连获取 .sha256 使用独立短超时：
// 请求超过超时后更新失败且 fail-closed（不下载二进制、不替换现有文件）。
func TestUpdaterDirectChecksumTimeoutFailsClosed(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	transport := &timeoutTransport{}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     exe,
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
		GHProxy:        "https://gh-proxy.example/",
		DownloadClient: &http.Client{Transport: transport, Timeout: 5 * time.Second},
	})
	u.checksumTimeout = 50 * time.Millisecond
	u.verifyBinary = func(context.Context, string, string) error { return nil }
	origDelay, origMax := checksumRetryBaseDelay, checksumRetryMaxDelay
	checksumRetryBaseDelay, checksumRetryMaxDelay = 10*time.Millisecond, 10*time.Millisecond
	defer func() { checksumRetryBaseDelay, checksumRetryMaxDelay = origDelay, origMax }()

	start := time.Now()
	_, err := u.DownloadAndReplace(context.Background(), "v0.1.8")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("直连获取校验文件超时时应拒绝更新")
	}
	for _, want := range []string{"不经 gh-proxy 镜像", "HTTPS_PROXY", "已中止更新"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("错误信息应包含 %q，实际：%v", want, err)
		}
	}
	if elapsed >= time.Second {
		t.Fatalf("校验文件请求应在短超时内失败，实际耗时 %v", elapsed)
	}
	hosts := transport.requestedHosts()
	if len(hosts) != checksumFetchAttempts*2 {
		t.Fatalf(".sha256 与 API 两个来源应各重试 %d 次，实际 hosts=%v", checksumFetchAttempts, hosts)
	}
	for i, host := range hosts {
		want := "github.com"
		if i >= checksumFetchAttempts {
			want = "api.github.com"
		}
		if host != want {
			t.Fatalf("第 %d 次请求应直连 %s，实际 hosts=%v", i+1, want, hosts)
		}
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatalf("超时失败时不得替换二进制: %q", string(got))
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "mnagent-upd-*")); len(leftovers) != 0 {
		t.Fatalf("超时失败后不应创建/残留临时文件: %v", leftovers)
	}
}

// TestUpdaterChecksumURLSelectsDirectWithProxy 验证默认校验文件 URL：
// 配置代理时直连 GitHub；未配置（或仅空白）时保持原始地址。
func TestUpdaterChecksumURLSelectsDirectWithProxy(t *testing.T) {
	const (
		directURL = "https://github.com/owner/repo/releases/download/v0.1.8/mnagent_linux_amd64.sha256"
	)
	cases := []struct {
		name  string
		proxy string
		want  string
	}{
		{name: "代理", proxy: "https://gh-proxy.example/", want: directURL},
		{name: "纯空白代理视同未配置", proxy: " \t\n", want: directURL},
		{name: "无代理", want: directURL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := &Updater{Repo: "owner/repo", Platform: "linux", Arch: "amd64", GHProxy: tc.proxy}
			if got := u.checksumURLFor("v0.1.8"); got != tc.want {
				t.Fatalf("checksumURLFor = %q，期望 %q", got, tc.want)
			}
		})
	}
}

// TestUpdaterNoProxyWarnsSHA256Only 验证无代理时保留 SHA-256 校验，
// 并通过注入的 logger 提示同源校验的局限（不直接写 stderr）。
func TestUpdaterNoProxyWarnsSHA256Only(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.8 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	checksum := fmt.Sprintf("%x  mnagent_linux_amd64\n", sha256.Sum256(bin))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			_, _ = w.Write([]byte(checksum))
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	logger := &recordingLogger{}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		DownloadClient: ts.Client(),
		Executable:     exe,
		Logger:         logger,
	})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/api/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.8"); err != nil {
		t.Fatalf("无代理时应允许更新: %v", err)
	}
	warnings := logger.snapshot()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "仅校验 SHA-256") {
		t.Fatalf("应通过 logger 输出一次安全告警，实际 %v", warnings)
	}
}

// TestDownloadAndReplaceRejectsOversizedBinary 验证下载体积超过上限时中止更新，
// 原二进制不变，且临时文件被清理。
func TestDownloadAndReplaceRejectsOversizedBinary(t *testing.T) {
	oldLimit := maxBinaryBytes
	maxBinaryBytes = 2048
	defer func() { maxBinaryBytes = oldLimit }()

	body := bytes.Repeat([]byte("A"), int(maxBinaryBytes)+1)
	checksum := fmt.Sprintf("%x  mnagent_linux_amd64\n", sha256.Sum256(body))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			_, _ = w.Write([]byte(checksum))
			return
		}
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	dir := t.TempDir()
	exe := filepath.Join(dir, "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		DownloadClient: ts.Client(),
		Executable:     exe,
	})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/api/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.8"); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("超过体积上限应中止更新，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatalf("超过体积上限时不得替换二进制: %q", string(got))
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "mnagent-upd-*")); len(leftovers) != 0 {
		t.Fatalf("超限下载后应删除临时文件，仍残留: %v", leftovers)
	}
}

// TestSkipStateDirPermission 验证跳过版本的状态目录以 0700 创建（不再使用 0755）。
func TestSkipStateDirPermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不适用 POSIX 权限")
	}
	dir := filepath.Join(t.TempDir(), "state", "nested")
	u := &Updater{SkipFile: filepath.Join(dir, "skip-versions")}
	if err := u.Skip("v0.1.8", time.Hour); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("状态目录权限 = %04o，期望 0700", perm)
	}
}

// TestUpdaterCheckAllowsProxy 验证配置代理时 Check 不被拒绝：
// 版本号可以经代理获取（完整性由后续直连 .sha256 与 -version 自检兜底）。
func TestUpdaterCheckAllowsProxy(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/https://github.com/owner/repo/releases/download/v0.1.8/mnagent_linux_amd64", http.StatusFound)
	}))
	defer proxy.Close()
	direct := httptest.NewServer(http.NotFoundHandler())
	defer direct.Close()

	u := New(Config{
		CurrentVersion: "v0.1.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		GHProxy:        "https://gh-proxy.example/",
		Client: &http.Client{
			Transport: &hostRewriteTransport{routes: map[string]string{
				"github.com":       direct.URL,
				"gh-proxy.example": proxy.URL,
			}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Executable: filepath.Join(t.TempDir(), "mnagent"),
		SkipFile:   filepath.Join(t.TempDir(), "skip"),
	})

	latest, ok, err := u.Check(context.Background())
	if err != nil || !ok || latest != "v0.1.8" {
		t.Fatalf("代理配置下 Check 应正常返回版本: latest=%q ok=%v err=%v", latest, ok, err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("版本检查应经代理请求 1 次，实际 %d 次", got)
	}
}

// TestSkipTightensExistingStateDir 验证 MkdirAll 遇到已存在的宽权限目录时会收紧到 0700。
func TestSkipTightensExistingStateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不适用 POSIX 权限")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	u := &Updater{SkipFile: filepath.Join(dir, "skip-versions"), logger: &recordingLogger{}}
	if err := u.Skip("v0.1.8", time.Hour); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Fatalf("已存在的状态目录权限 = %04o，期望收紧到 0700", perm)
	}
}

// TestUpdaterSerializesConcurrentReplacement 验证 Apply/DownloadAndReplace 互斥：
// 并发调用时二进制不会被同时下载/替换。
func TestUpdaterSerializesConcurrentReplacement(t *testing.T) {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.8 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	inner := &fakeReleaseServer{version: "v0.1.8", body: bin}
	var active, maxActive atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/mnagent_linux_amd64") {
			cur := active.Add(1)
			for {
				old := maxActive.Load()
				if cur <= old || maxActive.CompareAndSwap(old, cur) {
					break
				}
			}
			defer active.Add(-1)
			time.Sleep(50 * time.Millisecond)
		}
		inner.ServeHTTP(w, r)
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Config{
		CurrentVersion: "v0.1.7",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		DownloadClient: &http.Client{Timeout: 5 * time.Second},
		Executable:     exe,
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
	})
	u.URLForFunc = func(string) string { return ts.URL + "/releases/download/v0.1.8/" + u.AssetName() }
	u.ChecksumURLFunc = func(string) string { return ts.URL + "/releases/download/v0.1.8/" + u.AssetName() + ".sha256" }
	u.ChecksumAPIURLFunc = func(string) string { return ts.URL + "/releases/tags/v0.1.8" }
	u.verifyBinary = func(context.Context, string, string) error { return nil }

	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = u.DownloadAndReplace(context.Background(), "v0.1.8")
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发更新 %d 失败：%v", i, err)
		}
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("并发替换未串行化：同时下载数峰值 = %d", got)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(bin) {
		t.Fatalf("替换后的内容不一致")
	}
}

// TestCleanupOldExecutablesRemovesStaleUpdateFiles 验证启动清理只删除超过阈值、
// 匹配 mnagent-upd- 前缀的普通文件，不误删新文件、无关文件或目录。
func TestCleanupOldExecutablesRemovesStaleUpdateFiles(t *testing.T) {
	progDir := t.TempDir()
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	t.Setenv("TEMP", tmpDir)
	t.Setenv("TMP", tmpDir)
	old := time.Now().Add(-2 * staleUpdateFileAge)

	writeFile := func(path string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	staleProg := filepath.Join(progDir, "mnagent-upd-stale")
	staleTmp := filepath.Join(tmpDir, "mnagent-upd-stale")
	freshProg := filepath.Join(progDir, "mnagent-upd-fresh")
	unrelated := filepath.Join(progDir, "other-file")
	oldDir := filepath.Join(progDir, "mnagent-upd-dir")
	writeFile(staleProg, 0o600)
	writeFile(staleTmp, 0o600)
	writeFile(unrelated, 0o600)
	if err := os.WriteFile(freshProg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldDir, old, old); err != nil {
		t.Fatal(err)
	}

	CleanupOldExecutables(filepath.Join(progDir, "mnagent"))

	for _, removed := range []string{staleProg, staleTmp} {
		if _, err := os.Stat(removed); !os.IsNotExist(err) {
			t.Fatalf("过期临时文件应被清理：%s (err=%v)", removed, err)
		}
	}
	for _, kept := range []string{freshProg, unrelated, oldDir} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("不应删除 %s：%v", kept, err)
		}
	}
}
