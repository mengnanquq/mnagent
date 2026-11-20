package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
	"github.com/mengnanquq/mnagent/internal/process"
	"github.com/mengnanquq/mnagent/internal/tracker"
	"github.com/mengnanquq/mnagent/internal/updater"
)

// writeScript 在临时目录写一个可执行的假 nexttrace，并返回其路径。
func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-nexttrace")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRunnerArgvRejectsBadInput 验证 agent 侧会独立校验任务参数。
// 这是对外暴露的执行入口，即使机器人已经校验过也不能盲信网络输入。
func TestRunnerArgvRejectsBadInput(t *testing.T) {
	r := newRunner("nexttrace", nil)
	cases := []struct {
		name string
		job  model.Job
	}{
		{"空目标", model.Job{Target: "  "}},
		{"目标以横线开头", model.Job{Target: "-oProxyCommand=x"}},
		{"目标含 shell 元字符", model.Job{Target: "1.1.1.1;rm -rf /"}},
		{"目标含空格", model.Job{Target: "1.1.1.1 --help"}},
		{"跳数超限", model.Job{Target: "1.1.1.1", Hops: 65}},
		{"跳数为负", model.Job{Target: "1.1.1.1", Hops: -1}},
		{"端口超限", model.Job{Target: "1.1.1.1", Port: 70000}},
		{"协议非法", model.Job{Target: "1.1.1.1", Protocol: "sctp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if args, err := r.argv(tc.job); err == nil {
				t.Fatalf("应拒绝该任务，实际 argv=%v", args)
			}
		})
	}
}

// TestRunnerArgvBuildsExpected 验证合法任务的 argv 形状。
func TestRunnerArgvBuildsExpected(t *testing.T) {
	r := newRunner("nexttrace", nil)
	args, err := r.argv(model.Job{Target: "1.1.1.1", Hops: 20, Port: 443, Protocol: "ICMP"})
	if err != nil {
		t.Fatal(err)
	}
	want := "-j -P icmp -p 443 -m 20 1.1.1.1"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("argv = %q，期望 %q", got, want)
	}

	r.jsonOutput.Store(false)
	args, err = r.argv(model.Job{Target: "google.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(args, " "); got != "google.com" {
		t.Fatalf("argv = %q，期望 google.com", got)
	}
}

// TestRunnerExecutesWithoutShell 验证参数原样传给 nexttrace（不经 shell 解释）。
func TestRunnerExecutesWithoutShell(t *testing.T) {
	script := writeScript(t, `printf '%s\n' "$@"`)
	r := newRunner(script, nil)

	job := model.Job{Target: "1.1.1.1", Hops: 5}
	res := r.run(context.Background(), job)
	if res.ErrText != "" || res.ExitCode != 0 {
		t.Fatalf("执行失败: res.ErrText=%q res.ExitCode=%d", res.ErrText, res.ExitCode)
	}
	lines := strings.Split(strings.TrimSpace(res.Output), "\n")
	want := []string{"-j", "-m", "5", "1.1.1.1"}
	if len(lines) != len(want) {
		t.Fatalf("参数个数 = %d（%q），期望 %d 个: %v", len(lines), res.Output, len(want), want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("参数[%d] = %q，期望 %q", i, lines[i], want[i])
		}
	}
}

// TestRunnerFallsBackWhenJSONUnsupported 验证旧版 nexttrace 不认识 -j 时会去掉该参数重试。
func TestRunnerFallsBackWhenJSONUnsupported(t *testing.T) {
	script := writeScript(t, `if [ "$1" = "-j" ]; then
	echo "flag provided but not defined: -j" >&2
	exit 2
fi
echo "TRACE OK"`)
	r := newRunner(script, nil)

	res := r.run(context.Background(), model.Job{Target: "1.1.1.1"})
	if res.ErrText != "" || res.ExitCode != 0 {
		t.Fatalf("回退后应成功: res.ErrText=%q res.ExitCode=%d res.Output=%q", res.ErrText, res.ExitCode, res.Output)
	}
	if !strings.Contains(res.Output, "TRACE OK") {
		t.Fatalf("输出 = %q", res.Output)
	}
	if r.jsonOutput.Load() {
		t.Fatal("回退后应记住该主机不支持 -j")
	}
	// 后续任务不再附加 -j。
	args, err := r.argv(model.Job{Target: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "1.1.1.1" {
		t.Fatalf("后续 argv = %v，不应再带 -j", args)
	}
}

// TestRunnerTimeout 验证超时会终止命令并给出可读错误。
func TestRunnerTimeout(t *testing.T) {
	old := model.JobMinTimeout
	model.JobMinTimeout = 50 * time.Millisecond
	defer func() { model.JobMinTimeout = old }()

	script := writeScript(t, "sleep 30")
	r := newRunner(script, nil)
	r.waitDelay = 50 * time.Millisecond // 脚本派生的孙进程会占着管道，靠 WaitDelay 兜底

	start := time.Now()
	res := r.run(context.Background(), model.Job{Target: "1.1.1.1"})
	if !strings.Contains(res.ErrText, "执行超时") {
		t.Fatalf("应报告超时，实际 %q", res.ErrText)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("超时未生效，耗时 %s", elapsed)
	}
}

// TestRunnerReportsExitCode 验证非零退出码会被记录。
func TestRunnerReportsExitCode(t *testing.T) {
	r := newRunner(writeScript(t, `echo "boom" >&2; exit 7`), nil)
	res := r.run(context.Background(), model.Job{Target: "1.1.1.1"})
	if res.ExitCode != 7 || !strings.Contains(res.ErrText, "退出码 7") {
		t.Fatalf("code=%d res.ErrText=%q", res.ExitCode, res.ErrText)
	}
}

// TestCappedBuffer 验证输出上限。
func TestCappedBuffer(t *testing.T) {
	buf := process.NewCappedBuffer(4)
	n, err := buf.Write([]byte("abcdefgh"))
	if err != nil || n != 8 {
		t.Fatalf("Write = (%d, %v)，期望 (8, nil)（丢弃内容也要报告完整长度）", n, err)
	}
	if got := buf.String(); got != "abcd" {
		t.Fatalf("内容 = %q，期望 abcd", got)
	}
}

// TestLooksLikeUnknownFlag 覆盖各版本 nexttrace 的未知参数提示。
func TestLooksLikeUnknownFlag(t *testing.T) {
	if !looksLikeUnknownFlag("flag provided but not defined: -j") {
		t.Fatal("应识别 Go flag 的未知参数提示")
	}
	if looksLikeUnknownFlag("traceroute to 1.1.1.1, 30 hops max") {
		t.Fatal("正常输出不应被误判")
	}
}

// TestAgentLoopEndToEnd 用假机器人验证“领取 → 执行 → 回传”整条链路。
func TestAgentLoopEndToEnd(t *testing.T) {
	var results atomic.Int64
	var servedJob atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/jobs":
			if r.URL.RawQuery != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if servedJob.CompareAndSwap(false, true) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"job-1","target":"1.1.1.1","hops":5,"timeout_ms":5000}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/results":
			results.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		Binary:      writeScript(t, `echo "trace ok"`),
		MinBackoff:  10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
		PollTimeout: 2 * time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg), runner: newRunner(cfg.Binary, nil)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for results.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := results.Load(); got != 1 {
		t.Fatalf("结果回传次数 = %d，期望 1", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop 返回错误: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消后 loop 未退出")
	}
}

func TestAgentLoopSequentialHeavyTasksExecuted(t *testing.T) {
	var pollCount atomic.Int32
	var completedJobs sync.Map

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			c := pollCount.Add(1)
			if c == 1 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"heavy-1","kind":"trace","target":"1.1.1.1","hops":5,"timeout_ms":5000}`))
				return
			}
			if c == 2 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"heavy-2","kind":"trace","target":"8.8.8.8","hops":5,"timeout_ms":5000}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			completedJobs.Store(res.ID, true)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		Binary:      writeScript(t, `echo "trace ok"`),
		MinBackoff:  10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
		PollTimeout: 2 * time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg), runner: newRunner(cfg.Binary, nil)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, ok1 := completedJobs.Load("heavy-1")
		_, ok2 := completedJobs.Load("heavy-2")
		if ok1 && ok2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, ok := completedJobs.Load("heavy-1"); !ok {
		t.Fatal("heavy-1 未执行或未回传结果")
	}
	if _, ok := completedJobs.Load("heavy-2"); !ok {
		t.Fatal("heavy-2 未执行或被丢弃")
	}
	cancel()
	_ = <-done
}

// testLogger 把日志输出到测试日志，便于排查失败原因。
type testLogger struct{ t *testing.T }

func (l testLogger) Info(msg string, args ...any)  { l.t.Log(append([]any{msg}, args...)...) }
func (l testLogger) Warn(msg string, args ...any)  { l.t.Log(append([]any{"WARN " + msg}, args...)...) }
func (l testLogger) Debug(msg string, args ...any) {}

// useLocalDependencyManager 让 Agent 的依赖检查指向本地测试服务，避免访问真实 GitHub。
func useLocalDependencyManager(a *Agent, baseURL string) {
	a.depManagerFactory = func(string) *dep.DependencyManager {
		dm := dep.NewDependencyManager("")
		dm.SetGitHubEndpoints(baseURL, baseURL)
		return dm
	}
}

// skipDependencyCheck 让 Agent 跳过依赖检查（测试不关心依赖更新，也避免访问外网）。
func skipDependencyCheck(a *Agent) {
	a.depManagerFactory = func(string) *dep.DependencyManager { return nil }
}

// blockedTransport 让使用 http.DefaultTransport 的请求立即失败，用于隔离外网。
type blockedTransport struct{}

func (blockedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("测试环境禁止访问外网")
}

// TestLoggableTargetRedactsMiaospeed 验证 miaospeed 任务的日志目标不会泄露
// 订阅 token、节点密码/UUID 或整段配置；普通探针目标保持原样便于排查。
func TestLoggableTargetRedactsMiaospeed(t *testing.T) {
	cases := []struct {
		name string
		job  model.Job
		leak string
	}{
		{"订阅URL", model.Job{Kind: "miaospeed", Target: "https://example.com/sub?token=log-secret"}, "log-secret"},
		{"节点URI", model.Job{Kind: "miaospeed", Target: "vless://uuid-secret@example.com:443#node"}, "uuid-secret"},
		{"配置文本", model.Job{Kind: "miaospeed", Target: "proxies:\n  - name: private-node\n    password: pwd-secret"}, "pwd-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loggableTarget(tc.job)
			if strings.Contains(got, tc.leak) || strings.Contains(got, "private-node") {
				t.Fatalf("日志目标泄露敏感内容: %s", got)
			}
		})
	}

	plain := model.Job{Kind: "tcping", Target: "1.1.1.1"}
	if got := loggableTarget(plain); got != plain.Target {
		t.Fatalf("非 miaospeed 目标应保持原样，got=%q", got)
	}
}

// TestIsUpgradeJobNormalizesKind 验证 update/upgrade 判断不受空白与大小写影响。
func TestIsUpgradeJobNormalizesKind(t *testing.T) {
	cases := []struct {
		kind string
		want bool
	}{
		{"upgrade", true},
		{"  Upgrade  ", true},
		{"UPDATE", true},
		{" update ", true},
		{"trace", false},
		{"", false},
		{"   ", false},
	}
	for _, tc := range cases {
		if got := isUpgradeJob(model.Job{Kind: tc.kind}); got != tc.want {
			t.Fatalf("isUpgradeJob(%q) = %v，期望 %v", tc.kind, got, tc.want)
		}
	}
}

// TestHeavyWorkerHandlesNormalizedUpgradeKind 验证 " Upgrade " 会被当作更新任务
// 交给 handleUpgradeJob，而不是误走探针执行路径；结果 Kind 也应归一化。
func TestHeavyWorkerHandlesNormalizedUpgradeKind(t *testing.T) {
	results := make(chan model.Result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/results" {
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			results <- res
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &config.Config{BotURL: srv.URL, Tokens: &config.TokenSource{Value: "tok"}, PollTimeout: time.Second}
	a := &Agent{
		logger:     testLogger{t},
		client:     client.New(cfg),
		heavyQueue: make(chan model.Job, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.tasksWG.Add(1)
	go a.heavyWorker(ctx)
	a.heavyQueue <- model.Job{ID: "up-1", Kind: "  Upgrade  ", Target: "v1.2.3"}

	select {
	case res := <-results:
		if res.ID != "up-1" || res.Kind != "upgrade" {
			t.Fatalf("更新任务结果异常: %+v", res)
		}
		if res.ExitCode != -1 || !strings.Contains(res.Error, "updater not ready") {
			t.Fatalf("应走不支持自更新的更新器路径，实际: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("更新任务未被 heavyWorker 处理")
	}
	cancel()
	a.tasksWG.Wait()
}

// TestSleepRespectsContext 验证退出时不会卡在退避等待上。
func TestSleepRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sleep(ctx, time.Minute) {
		t.Fatal("ctx 已取消时 sleep 应返回 false")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("ctx.Err() = %v", ctx.Err())
	}
}

// TestRunnerReportsStartFailure 验证“进程根本没起来”时会带出真实原因，
// 而不是只报一个无从排查的“退出码 -1”。
func TestRunnerReportsStartFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-nexttrace")
	r := newRunner(missing, nil)
	// 直接验证 exec 层：可执行文件不存在时必须带出真实原因，而不是只报退出码 -1。
	_, code, err := r.execWithBinary(context.Background(), missing, []string{"1.1.1.1"})
	if code != -1 || err == nil {
		t.Fatalf("缺失可执行文件时 code=%d err=%v，期望 -1 与错误", code, err)
	}
	msg := describeRunError(err, code)
	if !strings.Contains(msg, "无法启动 nexttrace") || !strings.Contains(msg, "no such file") {
		t.Fatalf("错误提示应包含真实原因: %q", msg)
	}
	if strings.Contains(msg, "退出码 -1）") {
		t.Fatalf("不应只报退出码 -1: %q", msg)
	}
	// 通过 Runner 执行时，缺失 nexttrace 会先走自动安装；这里注入 nil 工厂避免联网，
	// 并确认返回清晰错误。
	r.depManagerFactory = func(string) *dep.DependencyManager { return nil }
	res := r.run(context.Background(), model.Job{Target: "1.1.1.1"})
	if res.ExitCode != -1 || !strings.Contains(res.ErrText, "无法启动 nexttrace") {
		t.Fatalf("缺失 nexttrace 时应返回明确错误: %+v", res)
	}
}

// fakeProcessState 构造一个“被 SIGKILL 终止”的进程状态。
func fakeProcessState(t *testing.T) *os.ProcessState {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "kill -9 $$")
	if err := cmd.Run(); err == nil {
		t.Fatal("期望进程被信号终止")
	}
	return cmd.ProcessState
}

// TestDescribeRunError 覆盖信号终止与普通失败两种情况的文案。
func TestDescribeRunError(t *testing.T) {
	sig := describeRunError(&exec.ExitError{ProcessState: fakeProcessState(t)}, -1)
	if !strings.Contains(sig, "进程被信号终止") {
		t.Fatalf("信号终止文案异常: %q", sig)
	}
	if got := describeRunError(&exec.ExitError{}, 7); got != "执行失败（退出码 7）" {
		t.Fatalf("普通失败文案异常: %q", got)
	}
}

// TestAgentLoopProbeJobEndToEnd 用假机器人下发一个 ping 任务：
// 验证 agent 走进程内探针并把结构化结果回传（不依赖 nexttrace 与外部二进制）。
func TestAgentLoopProbeJobEndToEnd(t *testing.T) {
	if conn, _, err := probe.ListenICMP(false); err != nil {
		t.Skipf("本机无法创建 ICMP 套接字，跳过：%v", err)
	} else {
		conn.Close()
	}

	type posted struct {
		ID       string          `json:"id"`
		Kind     string          `json:"kind"`
		ExitCode int             `json:"exit_code"`
		Data     json.RawMessage `json:"data"`
	}
	results := make(chan posted, 1)
	var servedJob atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/jobs":
			if servedJob.CompareAndSwap(false, true) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"j1","kind":"ping","target":"127.0.0.1","count":2,"timeout_ms":5000}`))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/results":
			var got posted
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &got); err != nil {
				t.Errorf("结果不是合法 JSON: %v", err)
			}
			results <- got
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		Binary:      "nexttrace",
		MinBackoff:  10 * time.Millisecond,
		MaxBackoff:  50 * time.Millisecond,
		PollTimeout: 2 * time.Second,
	}
	rnr := newRunner(cfg.Binary, nil)
	rnr.allowPrivateProbes = true
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg), runner: rnr}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	var got posted
	select {
	case got = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("未在超时内收到回传结果")
	}
	cancel()
	<-done

	if got.Kind != "ping" || got.ExitCode != 0 {
		t.Fatalf("结果异常: %+v", got)
	}
	var report probe.LatencyReport
	if err := json.Unmarshal(got.Data, &report); err != nil {
		t.Fatalf("Data 不是合法延迟报告: %v", err)
	}
	if report.Kind != probe.KindPing || report.Target != "127.0.0.1" || report.Recv != 2 {
		t.Fatalf("延迟报告异常: %+v", report)
	}
}

// TestRunnerMiaospeedDispatch 验证 runner 对 miaospeed 任务的分发与错误返回，并验证已删除的 speed 别名不再分发。
func TestRunnerMiaospeedDispatch(t *testing.T) {
	r := newRunnerWithMiaospeed("nexttrace", "non-existent-miaospeed-path", nil)

	// 1. 无效目标链接
	res := r.run(context.Background(), model.Job{
		ID:     "miao-1",
		Kind:   "miaospeed",
		Target: "not-a-valid-proxy-uri",
	})
	if res.ExitCode == 0 || !strings.Contains(res.ErrText, "不支持的代理协议") {
		t.Fatalf("应拒绝非法代理 URI: exitCode=%d errText=%q", res.ExitCode, res.ErrText)
	}

	// 2. speed 别名已移除，不再分发至 miaospeed，直接返回未知探针类型
	resSpeed := r.run(context.Background(), model.Job{
		ID:     "miao-2",
		Kind:   "speed",
		Target: "not-a-valid-proxy-uri",
	})
	if resSpeed.ExitCode == 0 || !strings.Contains(resSpeed.ErrText, "未知探针类型") {
		t.Fatalf("speed 不应分发至 miaospeed，应返回未知探针类型: exitCode=%d errText=%q", resSpeed.ExitCode, resSpeed.ErrText)
	}
}

// TestHandleUpgradeJob 验证 agent 接收到远程更新指令后的完整处理与回传。
func TestHandleUpgradeJob(t *testing.T) {
	var reportedResult model.Result
	var reported atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/results":
			var res model.Result
			if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			reportedResult = res
			reported.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cli := client.New(&config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		PollTimeout: 2 * time.Second,
	})

	exePath := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exePath, []byte("fake-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	var restarted atomic.Bool
	u := updater.New(updater.Config{
		CurrentVersion: "v1.0.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     exePath,
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
		Restart: func() error {
			restarted.Store(true)
			return nil
		},
		Client: &http.Client{
			Timeout: 2 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		DownloadClient: srv.Client(),
	})
	u.LatestURLFunc = func() string {
		return srv.URL + "/download"
	}

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	testAgent := &Agent{
		client: cli,
		update: u,
		logger: &testLogger{t: t},
		cfg:    &config.Config{},
	}
	skipDependencyCheck(testAgent)

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/releases/download/v1.0.0/mnagent_linux_amd64")
		w.WriteHeader(http.StatusFound)
	}))
	defer checkSrv.Close()
	u.URLForFunc = func(string) string { return checkSrv.URL }

	testAgent.handleUpgradeJob(context.Background(), model.Job{
		ID:     "upd-1",
		Kind:   "upgrade",
		Target: "latest",
	})

	if !reported.Load() {
		t.Fatal("未回传更新结果")
	}
	if reportedResult.ExitCode != 0 || !strings.Contains(reportedResult.Output, "已是最新版本") {
		t.Fatalf("已是最新版时返回异常: %+v", reportedResult)
	}

	// 2. 测试有新版本时
	reported.Store(false)
	downloadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Location", "/releases/download/v1.1.0/mnagent_linux_amd64")
			w.WriteHeader(http.StatusFound)
			return
		}
		// 下载内容必须是能响应 -version 的可执行脚本（替换前会做自检）。
		payload := []byte("#!/bin/sh\necho \"mnagent v1.1.0 (linux/amd64, go1.26.0)\"\n")
		for len(payload) < 2048 {
			payload = append(payload, '#', '\n')
		}
		if strings.HasSuffix(r.URL.Path, ".sha256") {
			fmt.Fprintf(w, "%x  mnagent_linux_amd64\n", sha256.Sum256(payload))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer downloadSrv.Close()
	u.URLForFunc = func(v string) string { return downloadSrv.URL }
	u.ChecksumURLFunc = func(v string) string {
		return downloadSrv.URL + "/releases/download/" + v + "/mnagent_linux_amd64.sha256"
	}
	u.DownloadClient = downloadSrv.Client()

	testAgent.handleUpgradeJob(context.Background(), model.Job{
		ID:     "upd-2",
		Kind:   "upgrade",
		Target: "latest",
	})

	if !reported.Load() {
		t.Fatal("更新后未回传结果")
	}
	if reportedResult.ExitCode != 0 || !strings.Contains(reportedResult.Output, "成功下载并安装 v1.1.0") {
		t.Fatalf("更新成功结果异常: %+v", reportedResult)
	}
	if !restarted.Load() {
		t.Fatal("更新后必须触发服务重启")
	}
}

// TestEvaluateRemoteTarget 验证远程显式目标版本的升级/降级策略。
func TestEvaluateRemoteTarget(t *testing.T) {
	cases := []struct {
		name           string
		current        string
		target         string
		allowDowngrade bool
		wantNoop       bool
		wantErr        string
	}{
		{"严格升级", "v1.0.0", "v1.1.0", false, false, ""},
		{"同版本视为无操作", "v1.0.0", "1.0.0", false, true, ""},
		{"降级默认拒绝", "v1.1.0", "v1.0.0", false, false, "拒绝降级"},
		{"显式放行后允许降级", "v1.1.0", "v1.0.0", true, false, ""},
		{"dev 构建无法比较时保持原行为", "dev", "v1.0.0", false, false, ""},
		{"目标版本非法", "v1.0.0", "latest", false, false, "格式非法"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			noop, err := evaluateRemoteTarget(tc.current, tc.target, tc.allowDowngrade)
			if noop != tc.wantNoop {
				t.Fatalf("noop = %v，期望 %v", noop, tc.wantNoop)
			}
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误包含 %q，实际 err=%v", tc.wantErr, err)
			}
		})
	}
}

// TestHandleUpgradeJobRejectsRemoteDowngrade 验证远程下发旧版本默认被拒绝且不下载、不重启。
func TestHandleUpgradeJobRejectsRemoteDowngrade(t *testing.T) {
	var reportedResult model.Result
	var reported atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			http.NotFound(w, r)
			return
		}
		var res model.Result
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reportedResult = res
		reported.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cli := client.New(&config.Config{
		BotURL:      srv.URL,
		Tokens:      &config.TokenSource{Value: "tok"},
		PollTimeout: 2 * time.Second,
	})

	var restarted atomic.Bool
	u := updater.New(updater.Config{
		CurrentVersion: "v2.0.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     filepath.Join(t.TempDir(), "mnagent"),
		Restart: func() error {
			restarted.Store(true)
			return nil
		},
	})

	origVersion := Version
	Version = "v2.0.0"
	defer func() { Version = origVersion }()

	// cfg 为 nil 时跳过依赖检查，测试聚焦远程目标版本策略。
	a := &Agent{client: cli, update: u, logger: &testLogger{t: t}}

	a.handleUpgradeJob(context.Background(), model.Job{ID: "down-1", Kind: "upgrade", Target: "v1.9.0"})
	if !reported.Load() {
		t.Fatal("未回传拒绝结果")
	}
	if reportedResult.ExitCode != -1 || !strings.Contains(reportedResult.Output, "拒绝降级") ||
		!strings.Contains(reportedResult.Output, "allow-remote-downgrade") {
		t.Fatalf("降级应被拒绝并提示开关: %+v", reportedResult)
	}
	if restarted.Load() {
		t.Fatal("拒绝降级时不得重启服务")
	}

	// 目标等于当前版本：无操作且回传成功，不触发重启。
	reported.Store(false)
	a.handleUpgradeJob(context.Background(), model.Job{ID: "same-1", Kind: "upgrade", Target: "v2.0.0"})
	if !reported.Load() {
		t.Fatal("未回传同版本结果")
	}
	if reportedResult.ExitCode != 0 || !strings.Contains(reportedResult.Output, "无需更新") {
		t.Fatalf("同版本应视为无操作: %+v", reportedResult)
	}
	if restarted.Load() {
		t.Fatal("同版本时不得重启服务")
	}
}

// TestAgentLoopNonBlockingLightAndCancelQueue 验证重任务在后台排队或执行时，
// 主循环完全非阻塞：可并发执行轻任务，且可即刻响应 cancel 信号打断重任务。
func TestAgentLoopNonBlockingLightAndCancelQueue(t *testing.T) {
	var pollCount atomic.Int32
	var completedResults sync.Map
	tracker := tracker.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			c := pollCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			switch c {
			case 1:
				// 先派发一个耗时重任务
				_, _ = w.Write([]byte(`{"id":"heavy-long","kind":"trace","target":"1.1.1.1","hops":5,"timeout_ms":10000}`))
			case 2:
				// 主循环未阻塞，第 2 次长轮询立即收到轻任务并并发执行
				_, _ = w.Write([]byte(`{"id":"light-quick","kind":"tcping","target":"127.0.0.1","port":9,"count":1,"timeout_ms":2000}`))
			case 3:
				// 主循环继续轮询，第 3 次收到对 heavy-long 的取消指令
				_, _ = w.Write([]byte(`{"id":"heavy-long","kind":"  Cancel  "}`))
			default:
				w.WriteHeader(http.StatusNoContent)
			}
		case "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			completedResults.Store(res.ID, res)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// 模拟需要运行数秒的 nexttrace
	scriptPath := writeScript(t, `sleep 5; echo "trace done"`)

	cfg := &config.Config{
		BotURL:             srv.URL,
		Tokens:             &config.TokenSource{Value: "tok"},
		Binary:             scriptPath,
		MinBackoff:         5 * time.Millisecond,
		MaxBackoff:         20 * time.Millisecond,
		PollTimeout:        1 * time.Second,
		AllowPrivateProbes: true,
	}
	rnr := newRunner(cfg.Binary, nil)
	rnr.allowPrivateProbes = true
	a := &Agent{
		cfg:     cfg,
		logger:  testLogger{t},
		client:  client.New(cfg),
		runner:  rnr,
		tracker: tracker,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	// light-quick 应当在 1 秒内完成回传（证明重任务未阻塞轻任务）
	deadline := time.Now().Add(2 * time.Second)
	var lightOK bool
	for time.Now().Before(deadline) {
		if _, ok := completedResults.Load("light-quick"); ok {
			lightOK = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !lightOK {
		t.Fatal("轻任务未能在重任务运行期间并发完成并回传")
	}

	// heavy-long 应当被 cancel 打断，而不需要等待完整的 5 秒 sleep
	deadlineHeavy := time.Now().Add(2 * time.Second)
	var heavyDone bool
	for time.Now().Before(deadlineHeavy) {
		if _, ok := completedResults.Load("heavy-long"); ok {
			heavyDone = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !heavyDone {
		t.Fatal("heavy-long 未能被 cancel 及时中止")
	}

	cancel()
	_ = <-done
}

// TestAgentLoopConcurrentLightTasks 验证多个轻任务能够并发拉取并执行。
func TestAgentLoopConcurrentLightTasks(t *testing.T) {
	var pollCount atomic.Int32
	var completedResults sync.Map

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			c := pollCount.Add(1)
			if c <= 4 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(fmt.Sprintf(`{"id":"light-%d","kind":"tcping","target":"127.0.0.1","port":9,"count":1,"timeout_ms":2000}`, c)))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			completedResults.Store(res.ID, res)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:             srv.URL,
		Tokens:             &config.TokenSource{Value: "tok"},
		Binary:             "nexttrace",
		MinBackoff:         5 * time.Millisecond,
		MaxBackoff:         20 * time.Millisecond,
		PollTimeout:        1 * time.Second,
		AllowPrivateProbes: true,
	}
	rnr := newRunner(cfg.Binary, nil)
	rnr.allowPrivateProbes = true
	a := &Agent{
		cfg:     cfg,
		logger:  testLogger{t},
		client:  client.New(cfg),
		runner:  rnr,
		tracker: tracker.New(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	allDone := false
	for time.Now().Before(deadline) {
		count := 0
		for i := 1; i <= 4; i++ {
			if _, ok := completedResults.Load(fmt.Sprintf("light-%d", i)); ok {
				count++
			}
		}
		if count == 4 {
			allDone = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	if !allDone {
		t.Fatal("4 个轻任务未能并发全部完成")
	}

	cancel()
	_ = <-done
}

// TestRunTraceMissingBinary 验证未安装 nexttrace 时 runTrace 会优雅返回错误，退出码为 -1。
func TestRunTraceMissingBinary(t *testing.T) {
	r := newRunner("nonexistent-nexttrace-xyz", nil)
	// 注入返回 nil 的工厂：本用例只验证缺失时的错误文案，不访问真实 GitHub。
	r.depManagerFactory = func(string) *dep.DependencyManager { return nil }
	job := model.Job{
		ID:     "trace-missing",
		Kind:   "trace",
		Target: "1.1.1.1",
	}
	res := r.run(context.Background(), job)
	if res.ExitCode != -1 || !strings.Contains(res.ErrText, "无法启动 nexttrace") {
		t.Fatalf("缺失 nexttrace 时未返回预期错误: exitCode=%d errText=%q", res.ExitCode, res.ErrText)
	}
}

// TestRunnerAutoInstallsMissingNexttrace 验证 nexttrace 缺失时 trace 任务会先自动
// 下载安装，再执行本次追踪（不再直接 exec 失败）。
func TestRunnerAutoInstallsMissingNexttrace(t *testing.T) {
	body := "#!/bin/sh\ncase \"$1\" in\n  -V|--version) echo \"NextTrace  v1.7.4\" ;;\n  *) echo \"trace ok\" ;;\nesac\n"
	for len(body) < 150*1024 {
		body += "# padding\n"
	}
	content := []byte(body)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	asset, err := dep.NexttraceAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/releases/latest"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v1.7.4"}`))
		case strings.Contains(r.URL.Path, "/releases/tags/v1.7.4"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"assets":[{"name":%q,"digest":"sha256:%s"}]}`, asset, digest)
		case strings.Contains(r.URL.Path, "/releases/download/"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	target := filepath.Join(t.TempDir(), "bin", "nexttrace")
	r := NewRunnerFull(target, "miaospeed", srv.URL, true, nil)
	r.depManagerFactory = func(proxy string) *dep.DependencyManager {
		dm := dep.NewDependencyManager(proxy)
		dm.SetGitHubEndpoints(srv.URL, srv.URL)
		return dm
	}
	res := r.Run(context.Background(), model.Job{ID: "auto-trace", Kind: "trace", Target: "1.1.1.1", Hops: 3, TimeoutMS: 10000})
	if res.ExitCode != 0 || !strings.Contains(res.Output, "trace ok") {
		t.Fatalf("缺失 nexttrace 时应自动安装并执行成功：%+v", res)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("nexttrace 应安装到配置路径 %s: %v", target, err)
	}
}

// TestRunnerAutoInstallNexttraceUsesBotDigest 验证 nexttrace 缺失触发运行时安装时，
// Runner 会把服务端代取客户端注入依赖管理器，优先使用代取的摘要。
func TestRunnerAutoInstallNexttraceUsesBotDigest(t *testing.T) {
	body := "#!/bin/sh\ncase \"$1\" in\n  -V|--version) echo \"NextTrace  v1.7.4\" ;;\n  *) echo \"trace ok\" ;;\nesac\n"
	for len(body) < 150*1024 {
		body += "# padding\n"
	}
	content := []byte(body)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	var botHits, shaHits, apiHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/agent/release-digest":
			botHits.Add(1)
			if got := r.Header.Get("Authorization"); got != "Bearer tok" {
				t.Errorf("代取请求 Authorization = %q", got)
			}
			fmt.Fprintf(w, `{"ok":true,"sha256":%q}`, digest)
		case strings.HasSuffix(r.URL.Path, ".sha256"):
			shaHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/releases/tags/"):
			apiHits.Add(1)
			http.Error(w, "should not be called", http.StatusInternalServerError)
		case strings.Contains(r.URL.Path, "/releases/latest"):
			_, _ = w.Write([]byte(`{"tag_name":"v1.7.4"}`))
		case strings.Contains(r.URL.Path, "/releases/download/"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	target := filepath.Join(t.TempDir(), "bin", "nexttrace")
	r := NewRunnerFull(target, "miaospeed", srv.URL, true, nil)
	r.depManagerFactory = func(proxy string) *dep.DependencyManager {
		dm := dep.NewDependencyManager(proxy)
		dm.SetGitHubEndpoints(srv.URL, srv.URL)
		return dm
	}
	r.SetBotDigest(&updater.BotDigestClient{
		BaseURL: srv.URL + "/agent",
		Token:   &config.TokenSource{Value: "tok"},
		Client:  srv.Client(),
	})
	res := r.Run(context.Background(), model.Job{ID: "auto-trace-bot", Kind: "trace", Target: "1.1.1.1", Hops: 3, TimeoutMS: 10000})
	if res.ExitCode != 0 || !strings.Contains(res.Output, "trace ok") {
		t.Fatalf("缺失 nexttrace 时应自动安装并执行成功：%+v", res)
	}
	if got := botHits.Load(); got != 1 {
		t.Fatalf("运行时安装应走服务端代取且只请求 1 次，实际 %d 次", got)
	}
	if got := shaHits.Load(); got != 0 {
		t.Fatalf("代取命中时不应回退直连 .sha256，实际 %d 次", got)
	}
	if got := apiHits.Load(); got != 0 {
		t.Fatalf("代取命中时不应回退 GitHub API，实际 %d 次", got)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("nexttrace 应安装到配置路径 %s: %v", target, err)
	}
}

// TestKillProcessGroup 验证进程组杀死函数的边界与执行情况。
func TestKillProcessGroup(t *testing.T) {
	// 1. 空参数或空进程不应崩溃
	process.KillProcessGroup(nil)
	process.KillProcessGroup(&exec.Cmd{})

	// 2. 正常进程杀死
	cmd := exec.CommandContext(context.Background(), "sleep", "10")
	process.SetupCmdProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法启动测试进程: %v", err)
	}
	process.KillProcessGroup(cmd)
	_ = cmd.Wait()
}

func TestRunTraceBlockedPrivateIP(t *testing.T) {
	r := newRunner("nexttrace", nil)
	r.allowPrivateProbes = false

	blockedTargets := []string{
		"127.0.0.1",
		"169.254.169.254",
		"192.168.1.1:80",
		"10.0.0.1",
		"localhost",
	}

	for _, target := range blockedTargets {
		res := r.run(context.Background(), model.Job{
			ID:     "trace-blocked",
			Kind:   "trace",
			Target: target,
		})
		if res.ExitCode != -1 || !strings.Contains(res.ErrText, "安全策略拦截") {
			t.Errorf("目标 %q 期望被安全策略拦截，实际: %+v", target, res)
		}
	}
}

// TestBuildMiaospeedResultDropsDuplicateOutput 验证 miaospeed 结果不再把同一份 JSON
// 同时放进 Output 与 Data：两份相加会让 300+ 节点测速的体积翻倍并撞上机器人结果上限。
func TestBuildMiaospeedResultDropsDuplicateOutput(t *testing.T) {
	data := json.RawMessage(`{"node_name":"HK-01","total_nodes":300}`)

	ok := buildMiaospeedResult(string(data), data, "", 0)
	if ok.ExitCode != 0 || ok.ErrText != "" {
		t.Fatalf("成功结果字段异常: %+v", ok)
	}
	if ok.Output != "" {
		t.Fatalf("有结构化 Data 时不应再重复填充 Output，实际 %d 字节", len(ok.Output))
	}
	if string(ok.Data) != string(data) {
		t.Fatalf("Data 应原样保留，实际 %s", ok.Data)
	}

	// 失败但仍有结构化数据：同样不重复；错误文案单独回传
	fail := buildMiaospeedResult(string(data), data, "测速失败", -1)
	if fail.Output != "" || fail.ErrText != "测速失败" || fail.ExitCode != -1 {
		t.Fatalf("失败结果字段异常: %+v", fail)
	}

	// 没有结构化数据（启动阶段就失败）时保留文本输出供机器人兜底
	bare := buildMiaospeedResult("启动 miaospeed 失败: exec format error", nil, "启动失败", -1)
	if bare.Output == "" || !strings.Contains(bare.Output, "exec format error") {
		t.Fatalf("无结构化数据时应保留文本输出，实际: %+v", bare)
	}
	if len(bare.Data) != 0 {
		t.Fatalf("无结构化数据时 Data 应为空，实际: %s", bare.Data)
	}
}

// TestAgentCheckAndUpdateDependenciesInstallsMissing 验证即使未开启 -auto-update，
// 依赖检查也会自动安装缺失的 nexttrace。
func TestAgentCheckAndUpdateDependenciesInstallsMissing(t *testing.T) {
	body := "#!/bin/sh\ncase \"$1\" in\n  -V|--version) echo \"NextTrace  v1.7.4\" ;;\n  *) echo ok ;;\nesac\n"
	for len(body) < 150*1024 {
		body += "# padding\n"
	}
	content := []byte(body)
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	asset, err := dep.NexttraceAsset(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/nxtrace/NTrace-core/releases/latest"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v1.7.4"}`))
		case strings.Contains(r.URL.Path, "/AirportR/miaospeed/releases/latest"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"4.7.7"}`))
		case strings.Contains(r.URL.Path, "/nxtrace/NTrace-core/releases/tags/v1.7.4"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"assets":[{"name":%q,"digest":"sha256:%s"}]}`, asset, digest)
		case strings.Contains(r.URL.Path, "/releases/download/"):
			_, _ = w.Write(content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	nexttracePath := filepath.Join(dir, "nexttrace")
	miaoPath := filepath.Join(dir, "miaospeed")
	if err := os.WriteFile(miaoPath, []byte("#!/bin/sh\necho \"version: 4.7.7\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Binary: nexttracePath, MiaospeedBinary: miaoPath, AutoUpdate: false}
	a := &Agent{cfg: cfg, logger: testLogger{t}}
	a.depManagerFactory = func(proxy string) *dep.DependencyManager {
		dm := dep.NewDependencyManager(proxy)
		dm.SetGitHubEndpoints(srv.URL, srv.URL)
		return dm
	}
	// 用 gh-proxy 指向本地测试服务，避免访问真实 GitHub。
	a.cfg.GHProxy = srv.URL

	a.checkAndUpdateDependencies(context.Background())
	if _, err := os.Stat(nexttracePath); err != nil {
		t.Fatalf("缺失 nexttrace 应在启动/定期检查中自动安装: %v", err)
	}
}

// TestAgentCheckAndUpdateDependencies 验证 agent.checkAndUpdateDependencies 过程触发的依赖更新。
func TestAgentCheckAndUpdateDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	ntBin := filepath.Join(tmpDir, "nexttrace")
	_ = os.WriteFile(ntBin, []byte("#!/bin/sh\necho \"NextTrace v1.7.3\"\n"), 0755)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "NTrace-core") {
			w.Write([]byte(`{"tag_name":"v1.7.4"}`))
			return
		}
		if strings.Contains(r.URL.Path, "miaospeed") {
			w.Write([]byte(`{"tag_name":"4.7.7"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfg := &config.Config{
		Binary:          ntBin,
		MiaospeedBinary: filepath.Join(tmpDir, "miaospeed"),
		AutoUpdate:      false,
	}

	a := &Agent{
		cfg:    cfg,
		logger: testLogger{t},
	}
	useLocalDependencyManager(a, srv.URL)

	// 执行依赖检查，不应崩溃
	a.checkAndUpdateDependencies(context.Background())
}

// TestHandleUpdateCLICheckOnly 验证 CLI --check-update 处理流程。
func TestHandleUpdateCLICheckOnly(t *testing.T) {
	// 固定让外部请求立即失败：该测试只验证 handled 语义，
	// 不应依赖真实 GitHub 的可达性与响应速度。
	origTransport := http.DefaultTransport
	http.DefaultTransport = blockedTransport{}
	t.Cleanup(func() { http.DefaultTransport = origTransport })

	cfg := &config.Config{
		CheckUpdateOnce: true,
		Binary:          "nexttrace",
		MiaospeedBinary: "miaospeed",
	}

	handled, err := HandleUpdateCLI(cfg, testLogger{t})
	if err != nil {
		// 在没有网络或无 GitHub 访问权限的环境下可能返回错误，但 handled 应为 true
	}
	if !handled {
		t.Fatal("期望 handled 为 true")
	}
}

// TestAgentSendResultHonorsResultTimeout 验证 -result-timeout 不再是无用配置：
// 单次结果回传会按该超时截止，而不是固定等满 6 分钟总预算。
func TestAgentSendResultHonorsResultTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: 50 * time.Millisecond,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}

	start := time.Now()
	err := a.sendResult(model.Result{ID: "slow-result", Kind: "ping"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("服务端响应超过 -result-timeout 时应返回超时错误")
	}
	if elapsed > time.Second {
		t.Fatalf("结果回传耗时 %s，未按 -result-timeout 截止", elapsed)
	}
}

// TestAgentSendResultUsesSharedStopBudget 验证退出阶段在途结果回传使用共享停止预算
// （而不是重新申请 6 分钟），确保不会超过 systemd 的 90s 停止超时。
func TestAgentSendResultUsesSharedStopBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: 5 * time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}
	stopCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	a.setStopContext(stopCtx)

	start := time.Now()
	err := a.sendResult(model.Result{ID: "inflight-result", Kind: "trace"})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("共享停止预算到期后应返回错误")
	}
	if elapsed > time.Second {
		t.Fatalf("退出阶段结果回传耗时 %s，未受共享停止预算约束", elapsed)
	}
}

// TestAgentWaitTasksTimesOut 验证退出时 tasksWG.Wait 带超时，不会被卡死的在途任务无限阻塞。
func TestAgentWaitTasksTimesOut(t *testing.T) {
	a := &Agent{logger: testLogger{t}}
	a.tasksWG.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	a.waitTasks(ctx)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waitTasks 耗时 %s，未在 ctx 到期后返回", elapsed)
	}
	a.tasksWG.Done()
}

// TestAgentResendInFlightGuard 验证同一 jobID 同时只允许一个缓存结果重发。
func TestAgentResendInFlightGuard(t *testing.T) {
	a := &Agent{}
	if !a.beginResend("job-1") {
		t.Fatal("首次重发应获得 in-flight 标记")
	}
	if a.beginResend("job-1") {
		t.Fatal("同一 jobID 的重发正在进行时应拒绝第二个")
	}
	if !a.beginResend("job-2") {
		t.Fatal("不同 jobID 应互不影响")
	}
	a.finishResend("job-1")
	if !a.beginResend("job-1") {
		t.Fatal("重发结束后应允许再次重发")
	}
}

// TestAgentEnqueueHeavyQueueFullRejectsImmediately 验证 heavyQueue 满时不会阻塞主循环，
// 而是立即回传“队列已满”的失败结果；该结果不写去重缓存，服务端重发时能真正重跑。
func TestAgentEnqueueHeavyQueueFullRejectsImmediately(t *testing.T) {
	results := make(chan model.Result, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var res model.Result
		_ = json.NewDecoder(r.Body).Decode(&res)
		results <- res
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}
	a.heavyQueue = make(chan model.Job, 1)
	a.heavyQueue <- model.Job{ID: "queued", Kind: "trace", Target: "1.1.1.1"}

	job := model.Job{ID: "overflow", Kind: "miaospeed", Target: "sub"}
	// 主循环在入队前会先登记去重状态；队列满被拒时必须撤销该登记，
	// 否则服务端重发同一 jobID 会在 TTL 内被当成“正在执行”直接忽略。
	if action, _, _ := a.dedupStore().start(job.ID); action != dedupRun {
		t.Fatalf("入队前应登记为可执行，实际 action=%v", action)
	}
	if a.enqueueHeavy(context.Background(), job) {
		t.Fatal("队列已满时不应入队成功")
	}
	select {
	case res := <-results:
		if res.ID != "overflow" || res.ExitCode != -1 || !strings.Contains(res.Error, "队列已满") {
			t.Fatalf("队列满失败结果异常: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("队列已满时应立即回传失败结果")
	}
	action, cached, _ := a.dedupStore().start("overflow")
	if action != dedupRun || cached != nil {
		t.Fatalf("队列满任务不应写去重缓存，服务端重发时应能重跑，实际 action=%v cached=%+v", action, cached)
	}
}

// TestAgentEnqueueLightQueueFullRejectsImmediately 验证轻任务队列有界：队列满时
// 立即回报“轻任务队列已满”，不在主长轮询路径上阻塞，也不无界堆集协程。
func TestAgentEnqueueLightQueueFullRejectsImmediately(t *testing.T) {
	srv, results := newResultTestServer(t, 1)
	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}
	a.lightQueue = make(chan model.Job, 1)
	a.lightQueue <- model.Job{ID: "queued", Kind: "ping", Target: "1.1.1.1"}

	job := model.Job{ID: "overflow-light", Kind: "ping", Target: "1.1.1.1"}
	if action, _, _ := a.dedupStore().start(job.ID); action != dedupRun {
		t.Fatalf("入队前应登记为可执行，实际 action=%v", action)
	}
	if a.enqueueLight(context.Background(), job) {
		t.Fatal("轻任务队列已满时不应入队成功")
	}
	select {
	case res := <-results:
		if res.ID != "overflow-light" || res.ExitCode != -1 || !strings.Contains(res.Error, "节点轻任务队列已满") {
			t.Fatalf("轻任务队列满失败结果异常: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("轻任务队列满时应立即回传失败结果")
	}
	if action, cached, _ := a.dedupStore().start("overflow-light"); action != dedupRun || cached != nil {
		t.Fatalf("队列满任务不应写入去重缓存，实际 action=%v cached=%+v", action, cached)
	}
}

// TestAgentLightWorkersExitOnCancel 验证固定 worker 池受 ctx 约束，
// waitTasks 不会被常驻 worker 无限阻塞。
func TestAgentLightWorkersExitOnCancel(t *testing.T) {
	a := &Agent{logger: testLogger{t}, lightQueue: make(chan model.Job, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	a.startLightWorkers(ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		a.tasksWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后轻任务 worker 未退出，waitTasks 会被永久阻塞")
	}
}

// newResultTestServer 返回一个接收 /results 的测试服务端与结果通道。
func newResultTestServer(t *testing.T, capacity int) (*httptest.Server, chan model.Result) {
	t.Helper()
	results := make(chan model.Result, capacity)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/results" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var res model.Result
		_ = json.NewDecoder(r.Body).Decode(&res)
		results <- res
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, results
}

// TestAgentEnqueueHeavyReportsExit 验证退出阶段收到的重任务会立即回报“节点正在退出”，
// 而不是静默丢弃让机器人等到超时。
func TestAgentEnqueueHeavyReportsExit(t *testing.T) {
	srv, results := newResultTestServer(t, 1)
	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}
	a.heavyQueue = make(chan model.Job, 1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job := model.Job{ID: "exiting", Kind: "trace", Target: "1.1.1.1"}
	if a.enqueueHeavy(ctx, job) {
		t.Fatal("退出阶段不应再入队")
	}
	select {
	case res := <-results:
		if res.ID != "exiting" || res.ExitCode != -1 || !strings.Contains(res.Error, "正在退出") {
			t.Fatalf("退出阶段失败结果异常: %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("退出阶段应回传未执行原因")
	}
	action, cached, _ := a.dedupStore().start("exiting")
	if action != dedupCompleted || cached == nil || cached.ID != "exiting" {
		t.Fatalf("退出任务应标记为已完成并缓存失败结果，实际 action=%v cached=%+v", action, cached)
	}
}

// TestAgentRejectBusyJobLimitsConcurrency 验证失败结果回传并发达到上限后会直接丢弃
// （结果已在去重缓存中），而不会阻塞主循环或无界地堆集协程。
func TestAgentRejectBusyJobLimitsConcurrency(t *testing.T) {
	srv, results := newResultTestServer(t, 1)
	cfg := &config.Config{
		BotURL:        srv.URL,
		Tokens:        &config.TokenSource{Value: "tok"},
		PollTimeout:   time.Second,
		ResultTimeout: time.Second,
	}
	a := &Agent{cfg: cfg, logger: testLogger{t}, client: client.New(cfg)}

	sem := a.rejectSendLimiter()
	for i := 0; i < maxConcurrentRejectSends; i++ {
		sem <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxConcurrentRejectSends; i++ {
			<-sem
		}
	}()

	done := make(chan struct{})
	go func() {
		a.rejectBusyJob(model.Job{ID: "dropped", Kind: "miaospeed"}, "节点任务队列已满")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("并发上限已满时 rejectBusyJob 不应阻塞")
	}
	select {
	case res := <-results:
		t.Fatalf("并发上限已满时不应再发起回传，实际收到 %+v", res)
	case <-time.After(200 * time.Millisecond):
	}
	// 结果必须已写入缓存，服务端重发时仍能拿到，不是无声丢失。
	if action, cached, _ := a.dedupStore().start("dropped"); action != dedupCompleted || cached == nil {
		t.Fatalf("被丢弃的回传仍应保留在去重缓存中，实际 action=%v cached=%+v", action, cached)
	}
}

// TestRunnerArgvSupportsBracketedIPv6WithPort 验证带端口的 IPv6 trace 目标
// （例如 [2606:4700:4700::1111]:443）不会被参数校验拒绝。
func TestRunnerArgvSupportsBracketedIPv6WithPort(t *testing.T) {
	r := newRunner("nexttrace", nil)
	args, err := r.argv(model.Job{
		Target:   "[2606:4700:4700::1111]:443",
		Protocol: "tcp",
		Port:     443,
		Hops:     16,
	})
	if err != nil {
		t.Fatalf("带端口的 IPv6 目标应被接受: %v", err)
	}
	want := "-j -P tcp -p 443 -m 16 [2606:4700:4700::1111]:443"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("argv = %q，期望 %q", got, want)
	}
}

// TestRunTraceBlocksPrivateIPv6WithPort 验证 [::1]:port 这类带端口的私网 IPv6
// 仍会被 SSRF 守卫拦截。
func TestRunTraceBlocksPrivateIPv6WithPort(t *testing.T) {
	r := newRunner("nexttrace", nil)
	r.allowPrivateProbes = false
	res := r.run(context.Background(), model.Job{Kind: "trace", Target: "[::1]:443"})
	if res.ExitCode != -1 || !strings.Contains(res.ErrText, "安全策略拦截") {
		t.Fatalf("私网 IPv6 目标应被拦截，实际: %+v", res)
	}
}

// TestAgentLoopUpdateCheckNonBlocking 验证自动更新检查在独立协程中执行：
// 版本查询被长时间挂起时，主循环仍能继续长轮询并领取任务。
func TestAgentLoopUpdateCheckNonBlocking(t *testing.T) {
	var pollCount atomic.Int32
	var jobResults sync.Map

	updateStarted := make(chan struct{})
	releaseUpdate := make(chan struct{})
	var startOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseUpdate) }) }

	// 模拟 GitHub 不可达：版本查询请求一直挂到测试结束。
	updateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startOnce.Do(func() { close(updateStarted) })
		<-releaseUpdate
		w.Header().Set("Location", "/releases/download/v9.9.9/mnagent_linux_amd64")
		w.WriteHeader(http.StatusFound)
	}))
	defer updateSrv.Close()
	defer release() // LIFO：必须早于 updateSrv.Close()，否则 Close 会等待挂起的请求。

	botSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jobs":
			c := pollCount.Add(1)
			if c <= 8 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(fmt.Sprintf(`{"id":"light-%d","kind":"tcping","target":"127.0.0.1","port":9,"count":1,"timeout_ms":2000}`, c)))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "/results":
			var res model.Result
			_ = json.NewDecoder(r.Body).Decode(&res)
			jobResults.Store(res.ID, res)
			w.WriteHeader(http.StatusNoContent)
		case "/heartbeat":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer botSrv.Close()

	cfg := &config.Config{
		BotURL:             botSrv.URL,
		Tokens:             &config.TokenSource{Value: "tok"},
		Binary:             "nexttrace",
		MinBackoff:         5 * time.Millisecond,
		MaxBackoff:         20 * time.Millisecond,
		PollTimeout:        time.Second,
		AllowPrivateProbes: true,
		AutoUpdate:         true,
		UpdateInterval:     time.Hour, // 只触发一次，避免重复检查干扰断言
	}
	exePath := filepath.Join(t.TempDir(), "mnagent")
	if err := os.WriteFile(exePath, []byte("fake-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := updater.New(updater.Config{
		CurrentVersion: "v1.0.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Executable:     exePath,
		SkipFile:       filepath.Join(t.TempDir(), "skip"),
		// 超时设得足够长：本测试要验证的是“检查不阻塞主循环”，不是超时本身。
		Client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		DownloadClient: updateSrv.Client(),
	})
	u.LatestURLFunc = func() string { return updateSrv.URL }

	origVersion := Version
	Version = "v1.0.0"
	defer func() { Version = origVersion }()

	rnr := newRunner(cfg.Binary, nil)
	a := &Agent{
		cfg:     cfg,
		logger:  testLogger{t},
		client:  client.New(cfg),
		runner:  rnr,
		tracker: tracker.New(),
		update:  u,
	}
	skipDependencyCheck(a)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		a.tasksWG.Wait()
	})
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.loop(ctx) }()

	select {
	case <-updateStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("自动更新检查未启动")
	}
	pollsAtUpdateStart := pollCount.Load()

	// 更新检查仍然挂起时，主循环必须继续轮询并完成轻任务。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pollCount.Load() > pollsAtUpdateStart {
			if _, ok := jobResults.Load("light-1"); ok {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pollCount.Load() <= pollsAtUpdateStart {
		t.Fatal("更新检查期间主循环未继续轮询（被阻塞）")
	}
	select {
	case <-releaseUpdate:
	default:
		// 更新请求仍在挂起状态即证明主循环没有被更新检查拖住。
	}
	if _, ok := jobResults.Load("light-1"); !ok {
		t.Fatal("更新检查期间主循环未能领取并执行轻任务")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("主循环未能及时退出")
	}
	release()
}

// TestStartAutoUpdateNoReentry 验证自动更新检查不会并发重入。
func TestStartAutoUpdateNoReentry(t *testing.T) {
	var calls atomic.Int32
	block := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(block) }) }
	defer release()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-block
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	defer release()

	u := updater.New(updater.Config{
		CurrentVersion: "v1.0.0",
		Repo:           "owner/repo",
		Platform:       "linux",
		Arch:           "amd64",
		Client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		DownloadClient: srv.Client(),
	})
	u.LatestURLFunc = func() string { return srv.URL }
	u.APIURLFunc = func() string { return srv.URL + "/api" }

	cfg := &config.Config{AutoUpdate: true}
	a := &Agent{cfg: cfg, logger: testLogger{t}, update: u, client: client.New(&config.Config{
		BotURL: "http://127.0.0.1:1",
		Tokens: &config.TokenSource{Value: "tok"},
	})}
	skipDependencyCheck(a)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		a.tasksWG.Wait()
	})
	defer cancel()
	for i := 0; i < 5; i++ {
		a.startAutoUpdate(ctx)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("自动更新检查未发出请求")
	}
	// 挂起期间重复调用不得叠加出第二批请求（之前尚未结束）。
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got > 2 {
		t.Fatalf("自动更新检查发生重入：请求数 %d", got)
	}

	// 释放并等待本轮结束，确认 updateBusy 复位后还能再次启动。
	release()
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && a.updateBusy.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if a.updateBusy.Load() {
		t.Fatal("updateBusy 未复位")
	}
	a.startAutoUpdate(ctx)
	deadline = time.Now().Add(2 * time.Second)
	before := calls.Load()
	for time.Now().Before(deadline) && calls.Load() == before {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() == before {
		t.Fatal("updateBusy 复位后未能重新启动检查")
	}
	cancel()
	a.tasksWG.Wait()
}

// TestLoggableTargetRedactsHTTPAndUnvalidated 验证 http 目标只记录 scheme://host/path，
// 且未通过参数校验的目标不会原样写入日志。
func TestLoggableTargetRedactsHTTPAndUnvalidated(t *testing.T) {
	httpJob := model.Job{Kind: "http", Target: "https://user:secret@example.com/api?token=log-secret#frag"}
	got := loggableTarget(httpJob)
	if strings.Contains(got, "secret") || strings.Contains(got, "user") || strings.Contains(got, "frag") {
		t.Fatalf("http 目标日志未脱敏 userinfo/query/fragment: %s", got)
	}
	if got != "https://example.com/api" {
		t.Fatalf("http 目标日志应保留 scheme://host/path，got=%q", got)
	}

	// 校验失败的目标（含空白/引号等）不得原样写进日志。
	bad := model.Job{Kind: "trace", Target: "1.1.1.1\n--bad-flag"}
	if got := loggableTarget(bad); strings.Contains(got, "--bad-flag") {
		t.Fatalf("未通过校验的目标不应写入日志: %q", got)
	}
	if got := loggableTarget(model.Job{Kind: "trace", Target: "-oProxyCommand=x"}); strings.Contains(got, "ProxyCommand") {
		t.Fatalf("以 - 开头的目标不应写入日志: %q", got)
	}
	// 合法目标保持原样，便于排障。
	if got := loggableTarget(model.Job{Kind: "trace", Target: "example.com:443"}); got != "example.com:443" {
		t.Fatalf("合法 trace 目标应保持原样，got=%q", got)
	}
}
