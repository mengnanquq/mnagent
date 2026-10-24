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
