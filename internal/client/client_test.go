package client

import (
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/model"

	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig 用给定端点构建最小配置。
func testConfig(endpoint string, tokens *config.TokenSource) *config.Config {
	if tokens == nil {
		tokens = &config.TokenSource{Value: "tok"}
	}
	return &config.Config{
		BotURL:      endpoint,
		Tokens:      tokens,
		Binary:      "nexttrace",
		MinBackoff:  10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
		PollTimeout: 2 * time.Second,
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

	job, err := New(testConfig(srv.URL, nil)).poll(context.Background())
	if err != nil || job != nil {
		t.Fatalf("poll = (%v, %v)，期望 (nil, nil)", job, err)
	}
}

// TestClientPollSendsVersion 验证长轮询请求携带版本号（供机器人 /host list 展示）。
func TestClientPollSendsVersion(t *testing.T) {
	original := Version
	Version = "v9.9.9-test"
	t.Cleanup(func() { Version = original })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Version"); got != "v9.9.9-test" {
			t.Errorf("X-Agent-Version = %q，期望 v9.9.9-test", got)
		}
		if got := r.Header.Get("User-Agent"); got != "mnagent/v9.9.9-test" {
			t.Errorf("User-Agent = %q，期望 mnagent/v9.9.9-test", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if _, err := New(testConfig(srv.URL, nil)).poll(context.Background()); err != nil {
		t.Fatalf("poll 失败: %v", err)
	}
}

func TestClientPollReturnsJob(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"j1","target":"1.1.1.1","hops":20,"port":443,"protocol":"tcp","timeout_ms":120000}`))
	}))
	defer srv.Close()

	job, err := New(testConfig(srv.URL, nil)).poll(context.Background())
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

	if _, err := New(testConfig(srv.URL, nil)).poll(context.Background()); err == nil {
		t.Fatal("缺少必需字段的任务应报错")
	}
}

func TestClientPollUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := New(testConfig(srv.URL, nil)).poll(context.Background())
	if !errors.Is(err, model.ErrUnauthorized) {
		t.Fatalf("期望 model.ErrUnauthorized，实际 %v", err)
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
	if err := New(testConfig(srv.URL, nil)).sendResult(ctx, model.Result{ID: "j1", Output: "x"}); err != nil {
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

	if err := New(testConfig(srv.URL, nil)).sendResult(context.Background(), model.Result{ID: "j1"}); err == nil {
		t.Fatal("鉴权失败应返回错误")
	}
	if calls.Load() != 1 {
		t.Fatalf("请求次数 = %d，期望 1（不重试）", calls.Load())
	}
}

func TestClientHeartbeat(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/heartbeat" && r.Method == http.MethodPost {
			count.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := New(testConfig(srv.URL, nil))
	if err := cli.heartbeat(context.Background()); err != nil {
		t.Fatalf("heartbeat 失败: %v", err)
	}
	if got := count.Load(); got != 1 {
		t.Fatalf("心跳请求次数 = %d, want 1", got)
	}
}

// TestClientSendProgress 验证实时流式进度上报及服务端的 cancel 反向取消控制。
func TestClientSendProgress(t *testing.T) {
	var cancelTrigger atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/progress" && r.Method == http.MethodPost {
			var p model.Progress
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Errorf("解析进度 payload 失败: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			if cancelTrigger.Load() {
				_, _ = w.Write([]byte(`{"cancel":true}`))
			} else {
				w.WriteHeader(http.StatusOK)
			}
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := New(testConfig(srv.URL, nil))

	// 1. 正常上报进度
	cancelled, err := cli.sendProgress(context.Background(), model.Progress{
		ID:      "test-p1",
		Current: 1,
		Total:   10,
	})
	if err != nil {
		t.Fatalf("sendProgress 失败: %v", err)
	}
	if cancelled {
		t.Fatal("期望 cancelled 为 false")
	}

	// 2. 服务端要求取消任务
	cancelTrigger.Store(true)
	cancelled, err = cli.sendProgress(context.Background(), model.Progress{
		ID:      "test-p1",
		Current: 2,
		Total:   10,
	})
	if err != nil {
		t.Fatalf("sendProgress 失败: %v", err)
	}
	if !cancelled {
		t.Fatal("期望 cancelled 为 true")
	}
}

// TestClientPollLargePayload 验证支持接收并解析多兆级别（>1MB）的超大任务 Payload。
func TestClientPollLargePayload(t *testing.T) {
	largeTarget := make([]byte, 2<<20) // 2MB
	for i := range largeTarget {
		largeTarget[i] = 'a'
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		job := model.Job{
			ID:        "large-job",
			Target:    string(largeTarget),
			TimeoutMS: 60000,
		}
		_ = json.NewEncoder(w).Encode(job)
	}))
	defer srv.Close()

	job, err := New(testConfig(srv.URL, nil)).poll(context.Background())
	if err != nil {
		t.Fatalf("接收超大任务失败: %v", err)
	}
	if job == nil || job.ID != "large-job" || len(job.Target) != len(largeTarget) {
		t.Fatalf("超大任务数据不完整: len=%d", len(job.Target))
	}
}

func TestClientSendsISP(t *testing.T) {
	var pollISP, hbISP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jobs" {
			pollISP = r.Header.Get("X-Agent-ISP")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path == "/heartbeat" {
			hbISP = r.Header.Get("X-Agent-ISP")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cli := New(testConfig(srv.URL, nil))
	cli.setISP("HKT Limited")

	_, _ = cli.poll(context.Background())
	_ = cli.heartbeat(context.Background())

	if pollISP != "HKT Limited" {
		t.Errorf("poll X-Agent-ISP = %q, want HKT Limited", pollISP)
	}
	if hbISP != "HKT Limited" {
		t.Errorf("heartbeat X-Agent-ISP = %q, want HKT Limited", hbISP)
	}
}
