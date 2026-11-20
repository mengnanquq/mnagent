package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/tracker"
)

// TestBotDigestClientTrust 验证只有可信端点才构造服务端代取客户端。
func TestBotDigestClientTrust(t *testing.T) {
	tokens := &config.TokenSource{Value: "tok"}
	cases := []struct {
		name    string
		cfg     *config.Config
		wantNil bool
	}{
		{"https 可信端点", &config.Config{BotURL: "https://bot.example.com/agent", Tokens: tokens, BotChecksumTrusted: true}, false},
		{"公网明文 http 不可信", &config.Config{BotURL: "http://bot.example.com/agent", Tokens: tokens, BotChecksumTrusted: false}, true},
		{"显式禁用", &config.Config{BotURL: "https://bot.example.com/agent", Tokens: tokens, BotChecksumTrusted: false}, true},
		{"缺少令牌", &config.Config{BotURL: "https://bot.example.com/agent", BotChecksumTrusted: true}, true},
		{"缺少 BotURL", &config.Config{BotURL: "  ", Tokens: tokens, BotChecksumTrusted: true}, true},
		{"nil 配置", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := botDigestClient(tc.cfg)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("应返回 nil，实际 %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("应返回可用的代取客户端")
			}
			if got.BaseURL != tc.cfg.BotURL || got.Token != tc.cfg.Tokens || got.Version != Version {
				t.Fatalf("客户端字段异常：%+v", got)
			}
		})
	}
}

// TestUpgradeJobUsesBotDigestOnce 验证升级任务通过服务端代取校验值且只请求一次，
// 交叉校验通过后正常安装并回传结果。
func TestUpgradeJobUsesBotDigestOnce(t *testing.T) {
	payload := []byte("#!/bin/sh\necho \"mnagent v1.1.0 (linux/amd64, go1.26.0)\"\n")
	for len(payload) < 2048 {
		payload = append(payload, '#', '\n')
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))

	var botHits, shaHits, apiHits, results atomic.Int32
	var reportedResult model.Result
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/release-digest":
			botHits.Add(1)
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Errorf("代取请求 Authorization = %q", got)
			}
			if got := r.Header.Get("X-Agent-Version"); got != Version {
				t.Errorf("X-Agent-Version = %q，期望 %q", got, Version)
			}
			q := r.URL.Query()
			if q.Get("repo") != "mengnanquq/mnagent" || q.Get("tag") != "v1.1.0" {
				t.Errorf("代取 query 参数异常：%v", q)
			}
			fmt.Fprintf(w, `{"ok":true,"sha256":%q,"source":"release-sha256"}`, sum)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		case r.URL.Path == "/results":
			results.Add(1)
			_ = json.NewDecoder(r.Body).Decode(&reportedResult)
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	cfg := &config.Config{
		BotURL:             srv.URL,
		Tokens:             &config.TokenSource{Value: "tok"},
		BotChecksumTrusted: true,
		PollTimeout:        time.Second,
	}
	exePath := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exePath, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(cfg, testLogger{t})
	u.Executable = exePath
	u.DownloadClient = srv.Client()
	u.URLForFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string {
		return srv.URL + "/dl/" + version + "/" + u.AssetName() + ".sha256"
	}
	u.ChecksumAPIURLFunc = func(version string) string { return srv.URL + "/releases/tags/" + version }
	var restarted atomic.Bool
	u.RestartFunc = func() error {
		restarted.Store(true)
		return nil
	}

	a := &Agent{
		cfg:    cfg,
		logger: testLogger{t},
		client: client.New(cfg),
		update: u,
	}
	skipDependencyCheck(a)

	a.handleUpgradeJob(context.Background(), model.Job{ID: "bot-digest-1", Kind: "upgrade", Target: "v1.1.0"})

	if got := botHits.Load(); got != 1 {
		t.Fatalf("升级任务应使用服务端代取且只请求 1 次，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != 1 {
		t.Fatalf("交叉校验应只请求 .sha256 一次，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("代取命中时不应回退 API，实际 %d 次", got)
	}
	if got := results.Load(); got != 1 {
		t.Fatalf("应回传 1 条结果，实际 %d 条", got)
	}
	if reportedResult.ExitCode != 0 || !strings.Contains(reportedResult.Output, "成功下载并安装 v1.1.0") {
		t.Fatalf("升级结果异常：%+v", reportedResult)
	}
	if !restarted.Load() {
		t.Fatal("升级成功后应触发重启")
	}
	if got, err := os.ReadFile(exePath); err != nil || string(got) != string(payload) {
		t.Fatalf("二进制应被替换为新版本：err=%v", err)
	}
}

// TestUpgradeJobCancelPreventsReplaceAndRestart 验证远程升级注册了 tracker：
// 取消任务会中止下载，且不再替换二进制或重启服务。
func TestUpgradeJobCancelPreventsReplaceAndRestart(t *testing.T) {
	payload := []byte("#!/bin/sh\necho \"mnagent v1.1.0 (linux/amd64, go1.26.0)\"\n")
	for len(payload) < 2048 {
		payload = append(payload, '#', '\n')
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))

	downloadStarted := make(chan struct{})
	results := make(chan model.Result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			fmt.Fprintf(w, "%s  mnagent_linux_amd64\n", sum)
		case strings.HasPrefix(r.URL.Path, "/dl/"):
			select {
			case <-downloadStarted:
			default:
				close(downloadStarted)
			}
			<-r.Context().Done()
		case r.URL.Path == "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			results <- res
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		PollTimeout: time.Second,
	}
	exePath := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exePath, []byte("old-bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := newUpdater(cfg, testLogger{t})
	u.Executable = exePath
	u.DownloadClient = srv.Client()
	u.URLForFunc = func(version string) string { return srv.URL + "/dl/" + version + "/" + u.AssetName() }
	u.ChecksumURLFunc = func(version string) string {
		return srv.URL + "/dl/" + version + "/" + u.AssetName() + ".sha256"
	}
	u.ChecksumAPIURLFunc = func(version string) string { return srv.URL + "/releases/tags/" + version }
	var restarted atomic.Bool
	u.RestartFunc = func() error {
		restarted.Store(true)
		return nil
	}

	trk := tracker.New()
	a := &Agent{
		cfg:     cfg,
		logger:  testLogger{t},
		client:  client.New(cfg),
		update:  u,
		tracker: trk,
	}
	skipDependencyCheck(a)

	done := make(chan struct{})
	go func() {
		a.handleUpgradeJob(context.Background(), model.Job{ID: "cancel-upgrade", Kind: "upgrade", Target: "v1.1.0"})
		close(done)
	}()

	select {
	case <-downloadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("升级任务未开始下载")
	}
	if !trk.Cancel("cancel-upgrade") {
		t.Fatal("应能取消正在执行的升级任务")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("取消后升级任务未及时结束")
	}
	if restarted.Load() {
		t.Fatal("取消后不得重启服务")
	}
	if got, err := os.ReadFile(exePath); err != nil || string(got) != "old-bin" {
		t.Fatalf("取消后不得替换二进制：content=%q err=%v", string(got), err)
	}
	select {
	case res := <-results:
		if res.ExitCode != -1 || !strings.Contains(res.Output, "取消") {
			t.Fatalf("取消结果异常：%+v", res)
		}
	default:
		t.Fatal("取消后应回传结果")
	}
}
