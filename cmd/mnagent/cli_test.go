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
