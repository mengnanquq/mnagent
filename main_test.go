package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"info", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, c := range cases {
		got := parseLogLevel(c.input)
		if got != c.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

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

	cfg := &config{
		botURL:             srv.URL,
		tokens:             &tokenSource{path: tokFile, from: tokFile},
		binary:             "nexttrace",
		miaospeedBinary:    "miaospeed",
		ghProxy:            "https://gh-proxy.com/",
		logLevel:           slog.LevelDebug,
		allowPrivateProbes: true,
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

	cfg := &config{
		probeTarget:        srv.URL,
		probeKind:          "http",
		allowPrivateProbes: true,
		logLevel:           slog.LevelDebug,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if err := handleProbeCLI(context.Background(), cfg, log); err != nil {
		t.Fatalf("handleProbeCLI 失败: %v", err)
	}
}

func TestTokenSourceHandlesUTF8BOM(t *testing.T) {
	tmpDir := t.TempDir()
	tokFile := filepath.Join(tmpDir, "token")
	// 模拟 Windows 记事本/PowerShell 保存带 UTF-8 BOM 的文件 (\xef\xbb\xbf)
	content := []byte("\xef\xbb\xbfmy-secret-token-12345\r\n")
	if err := os.WriteFile(tokFile, content, 0600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}

	ts, err := newTokenSource("", tokFile)
	if err != nil {
		t.Fatalf("newTokenSource 失败: %v", err)
	}

	val, err := ts.get()
	if err != nil {
		t.Fatalf("ts.get() 失败: %v", err)
	}
	if val != "my-secret-token-12345" {
		t.Fatalf("未能正确剔除 UTF-8 BOM，期望 'my-secret-token-12345'，得到 %q (len=%d)", val, len(val))
	}
}
