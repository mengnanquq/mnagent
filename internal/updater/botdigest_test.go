package updater

import (
	"context"
	"crypto/sha256"
	"errors"
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

// fakeTokenProvider 是 TokenProvider 的测试实现。
type fakeTokenProvider struct {
	value string
	err   error
}

func (f fakeTokenProvider) Get() (string, error) { return f.value, f.err }

// TestBotDigestClientFetchSuccess 验证请求方法、鉴权头、query 编码与成功解析。
func TestBotDigestClientFetchSuccess(t *testing.T) {
	sum := strings.Repeat("a1b2", 16)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("方法 = %s，期望 GET", r.Method)
		}
		if r.URL.Path != "/agent/release-digest" {
			t.Errorf("路径 = %q，期望 /agent/release-digest", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "mnagent/v0.4.2" {
			t.Errorf("User-Agent = %q", got)
		}
		if got := r.Header.Get("X-Agent-Version"); got != "v0.4.2" {
			t.Errorf("X-Agent-Version = %q", got)
		}
		// repo 中的斜杠必须被编码，避免服务端路由/代理按路径拆分。
		if !strings.Contains(r.URL.RawQuery, "repo=mengnanquq%2Fmnagent") {
			t.Errorf("repo 未编码斜杠：%q", r.URL.RawQuery)
		}
		q := r.URL.Query()
		if q.Get("repo") != "mengnanquq/mnagent" || q.Get("tag") != "v0.4.2" || q.Get("asset") != "mnagent_linux_amd64" {
			t.Errorf("query 参数异常：%v", q)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"release-sha256"}`, sum)
	}))
	defer srv.Close()

	c := &BotDigestClient{
		BaseURL: srv.URL + "/agent/",
		Token:   fakeTokenProvider{value: "tok"},
		Client:  srv.Client(),
		Version: "v0.4.2",
	}
	got, err := c.Fetch(context.Background(), "mengnanquq/mnagent", "v0.4.2", "mnagent_linux_amd64")
	if err != nil {
		t.Fatalf("代取应成功: %v", err)
	}
	if got != sum {
		t.Fatalf("代取结果 = %q，期望 %q", got, sum)
	}
	if hits.Load() != 1 {
		t.Fatalf("应只请求 1 次，实际 %d 次", hits.Load())
	}
}

// TestBotDigestClientFetchErrors 覆盖各种失败响应：都必须返回带状态码/code 的错误。
func TestBotDigestClientFetchErrors(t *testing.T) {
	const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name    string
		status  int
		body    string
		want    []string
		noParse bool
	}{
		{
			name:   "ok 为 false",
			status: http.StatusOK,
			body:   `{"ok":false,"code":"not_found","error":"release asset not found"}`,
			want:   []string{"HTTP 200", "code=not_found", "not_found"},
		},
		{
			name:   "哈希不是 64 位 hex",
			status: http.StatusOK,
			body:   `{"ok":true,"sha256":"not-a-hash"}`,
			want:   []string{"HTTP 200", "SHA-256 非法"},
		},
		{
			name:   "响应体过大",
			status: http.StatusOK,
			body:   `{"ok":true,"sha256":"` + sum + `","padding":"` + strings.Repeat("a", maxBotDigestBody) + `"}`,
			want:   []string{"超过"},
		},
		{
			name:   "不是 JSON",
			status: http.StatusOK,
			body:   "<html>bad gateway</html>",
			want:   []string{"HTTP 200", "解析服务端代取响应失败"},
		},
		{
			name:   "HTTP 404",
			status: http.StatusNotFound,
			body:   `{"ok":false,"code":"not_found","error":"tag not found"}`,
			want:   []string{"HTTP 404", "code=not_found"},
		},
		{
			name:   "HTTP 501 无 JSON",
			status: http.StatusNotImplemented,
			body:   "",
			want:   []string{"HTTP 501", "code=http_501"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := &BotDigestClient{
				BaseURL: srv.URL,
				Token:   fakeTokenProvider{value: "tok"},
				Client:  srv.Client(),
				Version: "v0.4.2",
			}
			_, err := c.Fetch(context.Background(), "mengnanquq/mnagent", "v0.4.2", "mnagent_linux_amd64")
			if err == nil {
				t.Fatal("期望返回错误")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("错误 %q 未包含 %q", err.Error(), want)
				}
			}
		})
	}
}

// TestBotDigestClientFetchTokenErrorSkipsRequest 验证拿不到令牌时直接失败，不发出请求。
func TestBotDigestClientFetchTokenErrorSkipsRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true,"sha256":"` + strings.Repeat("a", 64) + `"}`))
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name  string
		token TokenProvider
	}{
		{"令牌读取失败", fakeTokenProvider{err: errors.New("boom")}},
		{"令牌为空", fakeTokenProvider{value: "  "}},
		{"未配置令牌", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &BotDigestClient{BaseURL: srv.URL, Token: tc.token, Client: srv.Client()}
			if _, err := c.Fetch(context.Background(), "mengnanquq/mnagent", "v0.4.2", "mnagent_linux_amd64"); err == nil {
				t.Fatal("拿不到令牌时应返回错误")
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("拿不到令牌时不得发出请求，实际 %d 次", hits.Load())
	}

	// 空端点同样直接失败，不构造请求。
	c := &BotDigestClient{BaseURL: "  ", Token: fakeTokenProvider{value: "tok"}}
	if _, err := c.Fetch(context.Background(), "mengnanquq/mnagent", "v0.4.2", "mnagent_linux_amd64"); err == nil {
		t.Fatal("缺少端点地址时应返回错误")
	}
}

// relayTestBinary 返回一份大于最小体积要求的测试二进制内容。
func relayTestBinary() []byte {
	bin := []byte("#!/bin/sh\necho \"mnagent v0.1.1 (linux/amd64, go1.26.0)\"\n")
	for len(bin) < 2048 {
		bin = append(bin, '#', '\n')
	}
	return bin
}

// newRelayTestUpdater 构造指向 httptest 服务的 Updater，并跳过真实二进制自检。
func newRelayTestUpdater(t *testing.T, ts *httptest.Server, executable string, botDigest *BotDigestClient) *Updater {
	t.Helper()
	u := New(Config{
		CurrentVersion: "v0.1.0",
		Repo:           "mengnanquq/mnagent",
		Platform:       "linux",
		Arch:           "amd64",
		DownloadClient: ts.Client(),
		Executable:     executable,
		BotDigest:      botDigest,
	})
	u.URLForFunc = func(version string) string { return ts.URL + "/d/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string {
		return ts.URL + "/d/" + version + "/" + u.AssetName() + ".sha256"
	}
	u.ChecksumAPIURLFunc = func(version string) string { return ts.URL + "/releases/tags/" + version }
	u.verifyBinary = func(context.Context, string, string) error { return nil }
	return u
}

// TestUpdaterPrefersBotDigest 验证服务端代取命中时只用一次直连 .sha256 做交叉校验，
// 不再走 API 兜底，也不会重试直连来源。
func TestUpdaterPrefersBotDigest(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	var botHits, shaHits, apiHits, dlHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"release-sha256"}`, sum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		default:
			dlHits.Add(1)
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client(), Version: "v0.4.2"}

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("服务端代取命中时应允许更新: %v", err)
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != 1 {
		t.Fatalf("交叉校验应只直连 .sha256 一次，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("服务端代取命中时不应回退 API，实际 %d 次", got)
	}
	if got := dlHits.Load(); got != 1 {
		t.Fatalf("应下载二进制 1 次，实际 %d 次", got)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(bin) {
		t.Fatal("二进制应被替换为新版本")
	}
}

// TestUpdaterBotDigestFailureFallsBackToDirect 验证服务端返回非 200 时静默回退直连 .sha256。
func TestUpdaterBotDigestFailureFallsBackToDirect(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	for _, status := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var botHits, shaHits, apiHits atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/agent/release-digest":
					botHits.Add(1)
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"ok":false,"code":"upstream_error"}`))
				case strings.HasSuffix(r.URL.Path, ".sha256"):
					shaHits.Add(1)
					fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
				case strings.Contains(r.URL.Path, "/releases/tags/"):
					apiHits.Add(1)
					http.Error(w, "should not be called", http.StatusInternalServerError)
				default:
					_, _ = w.Write(bin)
				}
			}))
			defer ts.Close()

			exe := filepath.Join(t.TempDir(), "mnagent")
			if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			u := newRelayTestUpdater(t, ts, exe, nil)
			u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

			if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
				t.Fatalf("服务端代取失败后应回退直连: %v", err)
			}
			if got := botHits.Load(); got != 1 {
				t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
			}
			if got := shaHits.Load(); got != 1 {
				t.Fatalf("回退后直连 .sha256 应成功 1 次，实际 %d 次", got)
			}
			if got := apiHits.Load(); got != 0 {
				t.Fatalf("直连 .sha256 成功时不应回退 API，实际 %d 次", got)
			}
		})
	}
}

// TestUpdaterBotDigestMismatchAborts 验证交叉校验不一致时 fail-closed：
// 不下载二进制、不回退 API，并提示 -no-bot-checksum。
func TestUpdaterBotDigestMismatchAborts(t *testing.T) {
	bin := relayTestBinary()
	botSum := strings.Repeat("1", 64)
	directSum := strings.Repeat("2", 64)
	var botHits, shaHits, apiHits, dlHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"api-digest"}`, botSum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", directSum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			fmt.Fprintf(w, `{"assets":[{"name":"mnagent_linux_amd64","digest":"sha256:%s"}]}`, directSum)
		default:
			dlHits.Add(1)
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

	err := u.Apply(context.Background(), "v0.1.1")
	if err == nil || !strings.Contains(err.Error(), "不一致") || !strings.Contains(err.Error(), "-no-bot-checksum") {
		t.Fatalf("交叉校验不一致应中止并提示 -no-bot-checksum，实际 err=%v", err)
	}
	if !strings.Contains(err.Error(), "若服务端刚更新/重传资产，可稍后重试") {
		t.Fatalf("不一致错误应提示服务端刚更新/重传资产时可稍后重试，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatal("交叉校验不一致时不得替换二进制")
	}
	if got := dlHits.Load(); got != 0 {
		t.Fatalf("不一致时不应下载二进制，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("不一致时不得继续走 API 兜底，实际 %d 次", got)
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应尝试 1 次，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != 1 {
		t.Fatalf("交叉校验应只请求 1 次，实际 %d 次", got)
	}
}

// TestUpdaterBotDigestCrossCheckDirectFailureUsesBotValue 验证交叉校验直连失败时不阻断，
// 直接采用服务端返回的值完成安装。
func TestUpdaterBotDigestCrossCheckDirectFailureUsesBotValue(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	var shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"release-sha256"}`, sum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			http.Error(w, "down", http.StatusServiceUnavailable)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("交叉校验直连失败时应采用服务端值: %v", err)
	}
	if got := shaHits.Load(); got != 1 {
		t.Fatalf("交叉校验应只请求 1 次（不重试），实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("交叉校验直连失败时不应回退 API，实际 %d 次", got)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(bin) {
		t.Fatal("二进制应被替换为新版本")
	}
}

// TestUpdaterWithoutBotDigestKeepsDirectOrder 验证 BotDigest 为 nil 时行为与旧版一致：
// 直连 .sha256 重试后回退 API digest。
func TestUpdaterWithoutBotDigestKeepsDirectOrder(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	var botHits, shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			fmt.Fprintf(w, `{"ok":true,"sha256":%q}`, sum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			http.Error(w, "down", http.StatusBadGateway)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			fmt.Fprintf(w, `{"assets":[{"name":"mnagent_linux_amd64","digest":"sha256:%s"}]}`, sum)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("无服务端代取时应回退直连 API: %v", err)
	}
	if got := botHits.Load(); got != 0 {
		t.Fatalf("BotDigest 为 nil 时不得请求服务端，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != checksumFetchAttempts {
		t.Fatalf("直连 .sha256 应尝试 %d 次，实际 %d 次", checksumFetchAttempts, got)
	}
	if got := apiHits.Load(); got != 1 {
		t.Fatalf("API 应成功 1 次，实际 %d 次", got)
	}
}

// TestUpdaterAllChecksumSourcesFailSummary 验证三个来源都失败时，错误摘要包含全部来源与次数。
func TestUpdaterAllChecksumSourcesFailSummary(t *testing.T) {
	var botHits, shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			http.Error(w, "bot down", http.StatusInternalServerError)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			http.Error(w, "down", http.StatusBadGateway)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "down", http.StatusInternalServerError)
		default:
			t.Error("校验值获取失败时不应下载二进制")
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

	_, err := u.DownloadAndReplace(context.Background(), "v0.1.1")
	if err == nil {
		t.Fatal("三个来源都失败时应返回错误")
	}
	for _, want := range []string{"服务端代取", "（1次", "直连 .sha256失败", "（3次", "直连 GitHub API", "可信来源"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误摘要 %q 未包含 %q", err.Error(), want)
		}
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("服务端代取应只尝试 1 次，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != checksumFetchAttempts {
		t.Fatalf("直连 .sha256 应尝试 %d 次，实际 %d 次", checksumFetchAttempts, got)
	}
	if got := apiHits.Load(); got != checksumFetchAttempts {
		t.Fatalf("API 应尝试 %d 次，实际 %d 次", checksumFetchAttempts, got)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatal("校验值获取失败时不得替换二进制")
	}
}

// TestUpdaterCrossCheckHTMLUsesBotValueAndLogs 验证 L7：直连返回 200 但内容是 HTML 时
// 视为交叉校验不可用，放行并采用服务端代取值，同时输出 Info 日志。
func TestUpdaterCrossCheckHTMLUsesBotValueAndLogs(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	var shaHits, apiHits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			fmt.Fprintf(w, `{"ok":true,"sha256":%q}`, sum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			_, _ = w.Write([]byte("<html>not a checksum</html>"))
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
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
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.logger = logger
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

	if _, err := u.DownloadAndReplace(context.Background(), "v0.1.1"); err != nil {
		t.Fatalf("直连内容非法时应放行并使用服务端代取值: %v", err)
	}
	if got := shaHits.Load(); got != 1 {
		t.Fatalf("交叉校验应只请求 1 次，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("交叉校验不可用时不应回退 API，实际 %d 次", got)
	}
	if got, _ := os.ReadFile(exe); string(got) != string(bin) {
		t.Fatal("二进制应被替换为新版本")
	}
	const want = "交叉校验未完成（直连不可用），已采用服务端代取值"
	found := false
	for _, msg := range logger.infoSnapshot() {
		if msg == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("应输出 Info 日志 %q，实际 info=%v", want, logger.infoSnapshot())
	}
}

// TestUpdaterChecksumResolutionDeadline 验证所有校验来源都很慢时，
// 总耗时受 checksumResolutionDeadline 约束，不会把各来源的重试层层叠加。
func TestUpdaterChecksumResolutionDeadline(t *testing.T) {
	old := checksumResolutionDeadline
	checksumResolutionDeadline = 200 * time.Millisecond
	defer func() { checksumResolutionDeadline = old }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	u.checksumTimeout = 5 * time.Second
	u.botDigest = &BotDigestClient{BaseURL: ts.URL + "/agent", Token: fakeTokenProvider{value: "tok"}, Client: ts.Client()}

	start := time.Now()
	_, err := u.fetchExpectedChecksum(context.Background(), "v0.1.1")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("所有来源都很慢时应返回错误")
	}
	if elapsed > checksumResolutionDeadline+500*time.Millisecond {
		t.Fatalf("校验值获取耗时 %s 超过整体 deadline %s（含少量调度开销）", elapsed, checksumResolutionDeadline)
	}
	for _, want := range []string{"服务端代取", "直连 .sha256", "GitHub API"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误摘要 %q 未包含来源 %q", err.Error(), want)
		}
	}
	// 预算耗尽必须明确告知，便于区分“来源都失败”与“整体预算用尽”。
	if !strings.Contains(err.Error(), "整体校验值获取预算（200ms）已用尽") {
		t.Errorf("错误摘要 %q 未说明整体校验值获取预算已用尽", err.Error())
	}
}

// TestUpdaterCanceledContextSkipsReplaceAndRestart 验证 ctx 在下载/自检后被取消时，
// 不再替换二进制，也不再重启服务。
func TestUpdaterCanceledContextSkipsReplaceAndRestart(t *testing.T) {
	bin := relayTestBinary()
	sum := fmt.Sprintf("%x", sha256.Sum256(bin))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		default:
			_, _ = w.Write(bin)
		}
	}))
	defer ts.Close()

	exe := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exe, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newRelayTestUpdater(t, ts, exe, nil)
	var restarted atomic.Bool
	u.RestartFunc = func() error {
		restarted.Store(true)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.verifyBinary = func(context.Context, string, string) error {
		cancel()
		return nil
	}

	if err := u.Apply(ctx, "v0.1.1"); err == nil || !strings.Contains(err.Error(), "取消") {
		t.Fatalf("ctx 取消后应中止更新并说明已取消，实际 err=%v", err)
	}
	if got, _ := os.ReadFile(exe); string(got) != "old-bin" {
		t.Fatal("ctx 取消后不得替换二进制")
	}
	if restarted.Load() {
		t.Fatal("ctx 取消后不得重启服务")
	}
}
