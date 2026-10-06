package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig 用给定端点构建最小配置。
func testConfig(endpoint string, tokens *tokenSource) *config {
	if tokens == nil {
		tokens = &tokenSource{value: "tok"}
	}
	return &config{
		botURL:      endpoint,
		tokens:      tokens,
		binary:      "nexttrace",
		minBackoff:  10 * time.Millisecond,
		maxBackoff:  50 * time.Millisecond,
		pollTimeout: 2 * time.Second,
	}
}

func TestClientPollWithoutTask(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jobs" {
			t.Errorf("请求路径不符: %s", r.URL.Path)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("不应再附带查询参数（令牌即身份）: %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("鉴权头 = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	job, err := newClient(testConfig(srv.URL, nil)).poll(context.Background())
	if err != nil || job != nil {
		t.Fatalf("poll = (%v, %v)，期望 (nil, nil)", job, err)
	}
}

func TestClientPollReturnsJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"j1","target":"1.1.1.1","hops":20,"port":443,"protocol":"tcp","timeout_ms":120000}`))
	}))
	defer srv.Close()

	job, err := newClient(testConfig(srv.URL, nil)).poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if job == nil || job.ID != "j1" || job.Target != "1.1.1.1" || job.Hops != 20 || job.Port != 443 || job.Protocol != "tcp" {
		t.Fatalf("任务解析错误: %+v", job)
	}
	if got := job.Timeout(); got != 120*time.Second {
		t.Fatalf("超时 = %s，期望 120s", got)
	}
}

func TestClientPollRejectsMalformedJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"","target":""}`))
	}))
	defer srv.Close()

	if _, err := newClient(testConfig(srv.URL, nil)).poll(context.Background()); err == nil {
		t.Fatal("缺少必需字段的任务应报错")
	}
}

func TestClientPollUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := newClient(testConfig(srv.URL, nil)).poll(context.Background())
	if !errors.Is(err, errUnauthorized) {
		t.Fatalf("期望 errUnauthorized，实际 %v", err)
	}
}

// TestClientSendResultRetries 验证回传失败会退避重试。
func TestClientSendResultRetries(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			http.NotFound(w, r)
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// 重试前会等待 1 秒，这里放宽上下文超时。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := newClient(testConfig(srv.URL, nil)).sendResult(ctx, Result{ID: "j1", Output: "x"}); err != nil {
		t.Fatalf("重试后应成功: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("请求次数 = %d，期望 2", calls.Load())
	}
}

// TestClientSendResultStopsOnUnauthorized 验证鉴权失败不做无意义的重试。
func TestClientSendResultStopsOnUnauthorized(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	if err := newClient(testConfig(srv.URL, nil)).sendResult(context.Background(), Result{ID: "j1"}); err == nil {
		t.Fatal("鉴权失败应返回错误")
	}
	if calls.Load() != 1 {
		t.Fatalf("请求次数 = %d，期望 1（不重试）", calls.Load())
	}
}

// TestTokenSourceReadsFileEachTime 验证令牌轮换无需重启 agent。
func TestTokenSourceReadsFileEachTime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := newTokenSource("", path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.get(); got != "first" {
		t.Fatalf("令牌 = %q", got)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.get(); got != "second" {
		t.Fatalf("轮换后令牌 = %q，期望 second", got)
	}
}

// TestNewTokenSourcePrefersExplicitValue 验证令牌来源优先级。
func TestNewTokenSourcePrefersExplicitValue(t *testing.T) {
	t.Setenv("MNAGENT_TOKEN", "from-env")
	tokens, err := newTokenSource("explicit", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.get(); got != "explicit" {
		t.Fatalf("令牌 = %q，期望 explicit（-token 优先）", got)
	}

	tokens, err = newTokenSource("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := tokens.get(); got != "from-env" {
		t.Fatalf("令牌 = %q，期望 from-env", got)
	}

	// 清掉环境变量后再验证文件来源：文件不存在应直接报错。
	t.Setenv("MNAGENT_TOKEN", "")
	if _, err := newTokenSource("", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("令牌文件缺失应报错")
	}
}

// TestParseConfigValidation 覆盖启动参数校验。
func TestParseConfigValidation(t *testing.T) {
	if _, err := parseConfig([]string{"-token", "t"}); err == nil {
		t.Fatal("缺少 -bot 应报错")
	}
	if _, err := parseConfig([]string{"-bot", "not-a-url", "-token", "t"}); err == nil {
		t.Fatal("非法 -bot 应报错")
	}
	if _, err := parseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/nonexistent/nexttrace"}); err == nil {
		t.Fatal("找不到的 nexttrace 应报错")
	}

	cfg, err := parseConfig([]string{"-bot", "https://x/agent/", "-token", "t", "-nexttrace", "/bin/echo"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.botURL != "https://x/agent" {
		t.Fatalf("botURL 未去除末尾斜杠: %q", cfg.botURL)
	}
	if cfg.tokens == nil {
		t.Fatal("令牌来源应已解析")
	}
}

// TestParseConfigRejectsHostFlag 验证 -host 选项已被移除：令牌即身份，
// 名称由机器人按令牌识别，主机上不再需要（也不再接受）该参数。
func TestParseConfigRejectsHostFlag(t *testing.T) {
	if _, err := parseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-host", "hk", "-nexttrace", "/bin/echo"}); err == nil {
		t.Fatal("-host 已移除，传了应当报错（未知参数）")
	}
	cfg, err := parseConfig([]string{"-bot", "https://x/agent", "-token", "t", "-nexttrace", "/bin/echo"})
	if err != nil {
		t.Fatalf("只给 --bot/--token 应当合法：%v", err)
	}
	if cfg.botURL != "https://x/agent" {
		t.Fatalf("botURL = %q", cfg.botURL)
	}
}
