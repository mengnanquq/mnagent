package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// targetPattern 与机器人侧一致：目标只能是 IP/域名（可带 :port），
// 且不允许以 "-" 开头，避免任何参数注入。
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\-]+$`)

// maxOutputBytes 限制单次追踪读入内存的输出（机器人侧同样有上限）。
const maxOutputBytes = 1 << 20

// cappedBuffer 收集命令输出，超过上限后丢弃多余内容。
// stdout 与 stderr 会被并发写入，因此需要加锁。
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

// Write 追加输出；始终返回完整长度，避免进程因写入错误而中断。
func (w *cappedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if remaining := w.max - w.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
		} else {
			w.buf.Write(p)
		}
	}
	return len(p), nil
}

// String 返回已收集的输出。
func (w *cappedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// runner 负责校验任务参数并执行 nexttrace。
type runner struct {
	binary     string
	jsonOutput atomic.Bool // 是否附加 -j（旧版本 nexttrace 不支持时自动关闭）。
	// waitDelay 限制“进程已被杀掉、但仍有子进程占着输出管道”时的额外等待，
	// 避免超时任务因为派生的孙进程而把 agent 卡死。
	waitDelay time.Duration
}

// newRunner 构建执行器，默认请求 JSON 输出。
func newRunner(binary string) *runner {
	r := &runner{binary: binary, waitDelay: 5 * time.Second}
	r.jsonOutput.Store(true)
	return r
}

// run 执行一次任务，返回输出、错误文案与退出码。
// 退出码 -1 表示任务本身非法（未执行）。
func (r *runner) run(ctx context.Context, job Job) (output string, errText string, exitCode int) {
	args, err := r.argv(job)
	if err != nil {
		return "", err.Error(), -1
	}

	runCtx, cancel := context.WithTimeout(ctx, job.Timeout())
	defer cancel()

	out, code, runErr := r.exec(runCtx, args)
	// 旧版 nexttrace（< v1.7）不认识 -j：去掉该参数重试一次，并记住结论。
	if runErr != nil && r.jsonOutput.Load() && looksLikeUnknownFlag(out) {
		r.jsonOutput.Store(false)
		if plain, err := r.argv(job); err == nil {
			out, code, runErr = r.exec(runCtx, plain)
		}
	}

	switch {
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		return out, fmt.Sprintf("执行超时（%s）", job.Timeout()), code
	case runErr != nil:
		return out, fmt.Sprintf("执行失败（退出码 %d）", code), code
	default:
		return out, "", 0
	}
}

// exec 以 argv 方式调用 nexttrace（不经 shell），并捕获受限输出。
func (r *runner) exec(ctx context.Context, args []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.WaitDelay = r.waitDelay
	out := &cappedBuffer{max: maxOutputBytes}
	cmd.Stdout, cmd.Stderr = out, out

	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else {
			code = -1
		}
	}
	return out.String(), code, err
}

// argv 校验任务参数并拼出 argv。
// 即使机器人已经校验过，这里也重新校验一遍：agent 是对外暴露的执行入口，
// 不信任任何来自网络的内容。
func (r *runner) argv(job Job) ([]string, error) {
	target := strings.TrimSpace(job.Target)
	if target == "" || strings.HasPrefix(target, "-") || !targetPattern.MatchString(target) {
		return nil, errors.New("目标地址非法")
	}
	if job.Hops < 0 || job.Hops > 64 {
		return nil, fmt.Errorf("最大跳数非法：%d", job.Hops)
	}
	if job.Port < 0 || job.Port > 65535 {
		return nil, fmt.Errorf("端口非法：%d", job.Port)
	}
	protocol := strings.ToLower(strings.TrimSpace(job.Protocol))
	switch protocol {
	case "", "tcp", "udp", "icmp":
	default:
		return nil, fmt.Errorf("协议非法：%s", job.Protocol)
	}

	args := make([]string, 0, 8)
	if r.jsonOutput.Load() {
		args = append(args, "-j")
	}
	if protocol != "" {
		args = append(args, "-P", protocol)
	}
	if job.Port != 0 {
		args = append(args, "-p", strconv.Itoa(job.Port))
	}
	if job.Hops != 0 {
		args = append(args, "-m", strconv.Itoa(job.Hops))
	}
	return append(args, target), nil
}

// looksLikeUnknownFlag 判断输出是否表明该版本的 nexttrace 不认识某个参数（例如 -j）。
func looksLikeUnknownFlag(out string) bool {
	low := strings.ToLower(out)
	for _, hint := range []string{"flag provided but not defined", "unknown flag", "invalid option"} {
		if strings.Contains(low, hint) {
			return true
		}
	}
	return false
}

// agent 把客户端与执行器串成“领取 → 执行 → 回传”的主循环。
type agent struct {
	cfg    *config
	logger logger
	client *client
	runner *runner
}

// logger 是本包用到的最小日志接口，便于测试注入。
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// loop 不断领取任务并执行，直到 ctx 结束。
func (a *agent) loop(ctx context.Context) error {
	backoff := a.cfg.minBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		job, err := a.client.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errUnauthorized) {
				// 令牌不对：配置问题，用最大间隔重试，避免刷日志。
				a.logger.Warn("鉴权失败，将以最大间隔重试", "error", err, "retry_in", a.cfg.maxBackoff)
				if !sleep(ctx, a.cfg.maxBackoff) {
					return nil
				}
				continue
			}
			a.logger.Warn("轮询失败，稍后重试", "error", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, a.cfg.maxBackoff)
			continue
		}
		backoff = a.cfg.minBackoff
		if job == nil {
			continue // 空响应：立刻再轮询。
		}
		a.execute(ctx, *job)
	}
}

// execute 执行任务并回传结果。
func (a *agent) execute(ctx context.Context, job Job) {
	start := time.Now()
	a.logger.Info("开始执行任务", "job", job.ID, "target", job.Target,
		"hops", job.Hops, "port", job.Port, "protocol", job.Protocol)

	output, errText, exitCode := a.runner.run(ctx, job)

	// 回传不依赖任务上下文：即使任务超时或进程正在退出，也尽量让机器人拿到结果，
	// 否则用户要一直等到超时。
	sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.client.sendResult(sendCtx, Result{ID: job.ID, Output: output, ExitCode: exitCode, Error: errText}); err != nil {
		a.logger.Warn("回传结果失败", "job", job.ID, "error", err)
		return
	}
	entry := []any{"job", job.ID, "target", job.Target, "exit_code", exitCode,
		"duration", time.Since(start).Round(time.Millisecond).String(), "bytes", len(output)}
	if errText != "" {
		a.logger.Warn("任务结束（有错误）", append(entry, "error", errText)...)
		return
	}
	a.logger.Info("任务完成", entry...)
}

// sleep 等待指定时长；ctx 结束时返回 false。
func sleep(ctx context.Context, d time.Duration) bool {
	// 加抖动，避免多台主机同时重连打满机器人。
	jitter := time.Duration(rand.Int64N(int64(d/4) + 1))
	timer := time.NewTimer(d + jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
