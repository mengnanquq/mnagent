package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/mengnanquq/mnagent/internal/config"
)

func TestHandleDiagCLI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/heartbeat" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	tokFile := filepath.Join(tmpDir, "token")
	_ = os.WriteFile(tokFile, []byte("test-diag-token"), 0600)

	cfg := &config.Config{
		BotURL:             srv.URL,
		Tokens:             &config.TokenSource{Path: tokFile, From: tokFile},
		Binary:             "nexttrace",
		MiaospeedBinary:    "miaospeed",
		GHProxy:            "https://gh-proxy.com/",
		LogLevel:           slog.LevelDebug,
		AllowPrivateProbes: true,
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := handleDiagCLI(cfg, log); err != nil {
		t.Fatalf("handleDiagCLI 失败: %v", err)
	}
}

func TestHandleProbeCLI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{
		ProbeTarget:        srv.URL,
		ProbeKind:          "http",
		AllowPrivateProbes: true,
		LogLevel:           slog.LevelDebug,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if err := handleProbeCLI(context.Background(), cfg, log); err != nil {
		t.Fatalf("handleProbeCLI 失败: %v", err)
	}
}

// TestBuildLocalProbeJob 验证本地探针参数归一化：dns 使用合法 Query、
// http 目标自动补 https://、非法 -probe-kind 直接报错。
func TestBuildLocalProbeJob(t *testing.T) {
	job, err := buildLocalProbeJob(&config.Config{ProbeKind: "", ProbeTarget: "example.com"})
	if err != nil || job.Kind != "ping" || job.Query != "full" {
		t.Fatalf("空 probe-kind 应默认 ping: job=%+v err=%v", job, err)
	}

	job, err = buildLocalProbeJob(&config.Config{ProbeKind: "dns", ProbeTarget: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Kind != "dns" || job.Query != "A" {
		t.Fatalf("dns 探针应使用合法 Query A，实际 job=%+v", job)
	}

	job, err = buildLocalProbeJob(&config.Config{ProbeKind: "http", ProbeTarget: "example.com/path"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Target != "https://example.com/path" {
		t.Fatalf("http 目标缺少 scheme 时应补 https://，实际 %q", job.Target)
	}

	job, err = buildLocalProbeJob(&config.Config{ProbeKind: "http", ProbeTarget: "http://example.com"})
	if err != nil || job.Target != "http://example.com" {
		t.Fatalf("已有 scheme 的目标不应被修改: job=%+v err=%v", job, err)
	}

	if _, err := buildLocalProbeJob(&config.Config{ProbeKind: "nope", ProbeTarget: "example.com"}); err == nil {
		t.Fatal("非法 -probe-kind 应报错")
	}
}
