package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		job  Job
	}{
		{"空目标", Job{Target: "  "}},
		{"目标以横线开头", Job{Target: "-oProxyCommand=x"}},
		{"目标含 shell 元字符", Job{Target: "1.1.1.1;rm -rf /"}},
		{"目标含空格", Job{Target: "1.1.1.1 --help"}},
		{"跳数超限", Job{Target: "1.1.1.1", Hops: 65}},
		{"跳数为负", Job{Target: "1.1.1.1", Hops: -1}},
		{"端口超限", Job{Target: "1.1.1.1", Port: 70000}},
		{"协议非法", Job{Target: "1.1.1.1", Protocol: "sctp"}},
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
	args, err := r.argv(Job{Target: "1.1.1.1", Hops: 20, Port: 443, Protocol: "ICMP"})
	if err != nil {
		t.Fatal(err)
	}
	want := "-j -P icmp -p 443 -m 20 1.1.1.1"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("argv = %q，期望 %q", got, want)
	}

	r.jsonOutput.Store(false)
	args, err = r.argv(Job{Target: "google.com"})
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

	job := Job{Target: "1.1.1.1", Hops: 5}
	out, errText, code := r.run(context.Background(), job)
	if errText != "" || code != 0 {
		t.Fatalf("执行失败: errText=%q code=%d", errText, code)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	want := []string{"-j", "-m", "5", "1.1.1.1"}
	if len(lines) != len(want) {
		t.Fatalf("参数个数 = %d（%q），期望 %d 个: %v", len(lines), out, len(want), want)
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

	out, errText, code := r.run(context.Background(), Job{Target: "1.1.1.1"})
	if errText != "" || code != 0 {
		t.Fatalf("回退后应成功: errText=%q code=%d out=%q", errText, code, out)
	}
	if !strings.Contains(out, "TRACE OK") {
		t.Fatalf("输出 = %q", out)
	}
	if r.jsonOutput.Load() {
		t.Fatal("回退后应记住该主机不支持 -j")
	}
	// 后续任务不再附加 -j。
	args, err := r.argv(Job{Target: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(args, " ") != "1.1.1.1" {
		t.Fatalf("后续 argv = %v，不应再带 -j", args)
	}
}

// TestRunnerTimeout 验证超时会终止命令并给出可读错误。
func TestRunnerTimeout(t *testing.T) {
	old := jobMinTimeout
	jobMinTimeout = 50 * time.Millisecond
	defer func() { jobMinTimeout = old }()

	script := writeScript(t, "sleep 30")
	r := newRunner(script, nil)
	r.waitDelay = 50 * time.Millisecond // 脚本派生的孙进程会占着管道，靠 WaitDelay 兜底

	start := time.Now()
	_, errText, _ := r.run(context.Background(), Job{Target: "1.1.1.1"})
	if !strings.Contains(errText, "执行超时") {
		t.Fatalf("应报告超时，实际 %q", errText)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("超时未生效，耗时 %s", elapsed)
	}
}

// TestRunnerReportsExitCode 验证非零退出码会被记录。
func TestRunnerReportsExitCode(t *testing.T) {
	r := newRunner(writeScript(t, `echo "boom" >&2; exit 7`), nil)
	_, errText, code := r.run(context.Background(), Job{Target: "1.1.1.1"})
	if code != 7 || !strings.Contains(errText, "退出码 7") {
		t.Fatalf("code=%d errText=%q", code, errText)
	}
}

// TestCappedBuffer 验证输出上限。
func TestCappedBuffer(t *testing.T) {
	buf := &cappedBuffer{max: 4}
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
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/jobs":
			if r.URL.Query().Get("host") != "hk" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			select {
			case <-release:
				w.WriteHeader(http.StatusNoContent)
				return
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"job-1","target":"1.1.1.1","hops":5,"timeout_ms":5000}`))
		case "/results":
			results.Add(1)
			close(release)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config{
		botURL:      srv.URL,
		host:        "hk",
		tokens:      &tokenSource{value: "tok"},
		binary:      writeScript(t, `echo "trace ok"`),
		minBackoff:  10 * time.Millisecond,
		maxBackoff:  50 * time.Millisecond,
		pollTimeout: 2 * time.Second,
	}
	a := &agent{cfg: cfg, logger: testLogger{t}, client: newClient(cfg), runner: newRunner(cfg.binary, nil)}

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

// testLogger 把日志输出到测试日志，便于排查失败原因。
type testLogger struct{ t *testing.T }

func (l testLogger) Info(msg string, args ...any)  { l.t.Log(append([]any{msg}, args...)...) }
func (l testLogger) Warn(msg string, args ...any)  { l.t.Log(append([]any{"WARN " + msg}, args...)...) }
func (l testLogger) Debug(msg string, args ...any) {}

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
	r := newRunner(filepath.Join(t.TempDir(), "missing-nexttrace"), nil)
	_, errText, code := r.run(context.Background(), Job{Target: "1.1.1.1"})
	if code != -1 {
		t.Fatalf("退出码 = %d，期望 -1", code)
	}
	if !strings.Contains(errText, "无法启动 nexttrace") || !strings.Contains(errText, "no such file") {
		t.Fatalf("错误提示应包含真实原因: %q", errText)
	}
	if strings.Contains(errText, "退出码 -1）") {
		t.Fatalf("不应只报退出码 -1: %q", errText)
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
