package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

// runner 负责校验任务参数并执行 nexttrace 或外部工具。
type runner struct {
	binary          string
	miaospeedBinary string
	ghProxy         string
	jsonOutput      atomic.Bool // 是否附加 -j（旧版本 nexttrace 不支持时自动关闭）。
	// waitDelay 限制“进程已被杀掉、但仍有子进程占着输出管道”时的额外等待，
	// 避免超时任务因为派生的孙进程而把 agent 卡死。
	waitDelay time.Duration
	logger    logger // 可选：记录实际执行的 argv，便于与主机上手跑结果对照。
}

// newRunner 构建执行器，默认请求 JSON 输出。
func newRunner(binary string, log logger) *runner {
	return newRunnerFull(binary, "miaospeed", "", log)
}

// newRunnerWithMiaospeed 构建执行器，可指定 miaospeed 可执行文件路径。
func newRunnerWithMiaospeed(binary, miaospeed string, log logger) *runner {
	return newRunnerFull(binary, miaospeed, "", log)
}

// newRunnerFull 构建执行器，可指定 miaospeed 路径与 GitHub 代理前缀。
func newRunnerFull(binary, miaospeed, ghProxy string, log logger) *runner {
	r := &runner{
		binary:          binary,
		miaospeedBinary: miaospeed,
		ghProxy:         ghProxy,
		waitDelay:       5 * time.Second,
		logger:          log,
	}
	r.jsonOutput.Store(true)
	return r
}

// run 执行一次任务，返回输出、错误文案与退出码。
// 退出码 -1 表示任务本身非法（未执行）。
// runResult 是一次任务的执行结果。
type runResult struct {
	Output   string          // 原始输出（trace）或摘要文本
	Data     json.RawMessage // 结构化探针结果（ping/tcping/http/dns/miaospeed）
	ErrText  string          // 面向用户的错误文案（成功为空）
	ExitCode int
}

func (r *runner) run(ctx context.Context, job Job) runResult {
	// 进程内探针：不依赖外部二进制，OpenWrt 等精简系统同样可用。
	switch kind := probeKind(job); {
	case kind == kindTrace:
		return r.runTrace(ctx, job)
	case isProbeKind(kind):
		return r.runProbeJob(ctx, job, kind)
	case isMiaospeedKind(kind):
		return r.runMiaospeed(ctx, job)
	default:
		// 未知类型立即失败，绝不退化成执行 nexttrace。
		return runResult{ErrText: "未知探针类型：" + job.Kind, ExitCode: -1}
	}
}

// isMiaospeedKind 判断是否为 miaospeed 代理测速任务。
func isMiaospeedKind(kind string) bool {
	switch kind {
	case kindMiaospeed, kindSpeed:
		return true
	default:
		return false
	}
}

// runMiaospeed 执行 miaospeed 代理测速。
func (r *runner) runMiaospeed(ctx context.Context, job Job) runResult {
	runCtx, cancel := context.WithTimeout(ctx, job.Timeout())
	defer cancel()

	output, data, err := runMiaospeedJob(runCtx, r.miaospeedBinary, r.ghProxy, job, r.logger)
	if err != nil {
		return runResult{
			Output:   output,
			Data:     data,
			ErrText:  err.Error(),
			ExitCode: -1,
		}
	}
	return runResult{
		Output:   output,
		Data:     data,
		ExitCode: 0,
	}
}

// runProbeJob 执行 ping/tcping/http/dns 探针并映射为统一结果。
func (r *runner) runProbeJob(ctx context.Context, job Job, kind string) runResult {
	runCtx, cancel := context.WithTimeout(ctx, job.Timeout())
	defer cancel()
	outcome, err := runProbe(runCtx, job)
	result := runResult{Output: outcome.Output, Data: outcome.Data}
	if err != nil {
		result.ErrText = err.Error()
		result.ExitCode = -1
	}
	return result
}

// runTrace 通过外部 nexttrace 执行一次路由追踪。
func (r *runner) runTrace(ctx context.Context, job Job) runResult {
	out, errText, exitCode := r.runNexttrace(ctx, job)
	return runResult{Output: out, ErrText: errText, ExitCode: exitCode}
}

// runNexttrace 组装 argv、执行并处理 -j 兼容回退。
func (r *runner) runNexttrace(ctx context.Context, job Job) (output string, errText string, exitCode int) {
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
		return out, describeRunError(runErr, code), code
	default:
		return out, "", 0
	}
}

// describeRunError 把执行失败的原因描述清楚：
//   - 进程被信号终止：ExitCode() 为 -1，必须把信号名带上；
//   - 正常退出但非零：退出码本身就有意义；
//   - 根本没起来（找不到文件、无执行权限、架构不匹配等）：错误文本是关键，
//     过去只报“退出码 -1”会让这类问题无从排查。
func describeRunError(err error, code int) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code == -1 {
			return fmt.Sprintf("执行失败：进程被信号终止（%s）", exitErr.Error())
		}
		return fmt.Sprintf("执行失败（退出码 %d）", code)
	}
	return "执行失败：无法启动 nexttrace（" + clampText(err.Error(), 300) + "）"
}

// clampText 截断过长的错误文本，避免刷屏。
func clampText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// exec 以 argv 方式调用 nexttrace（不经 shell），并捕获受限输出。
func (r *runner) exec(ctx context.Context, args []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.WaitDelay = r.waitDelay
	if r.logger != nil {
		r.logger.Debug("执行 nexttrace", "argv", strings.Join(append([]string{r.binary}, args...), " "))
	}
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
	update *updater
}

// logger 是本包用到的最小日志接口，便于测试注入。
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// loop 不断领取任务并执行，直到 ctx 结束；启用自动更新时按周期检查新版本。
func (a *agent) loop(ctx context.Context) error {
	backoff := a.cfg.minBackoff
	var nextCheck time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		if a.update != nil && a.cfg.autoUpdate && time.Now().After(nextCheck) {
			if a.updateOnce(ctx) {
				return nil // 已应用更新并重启：进程即将被替换。
			}
			// 加入抖动，避免多个部署实例在完全相同的时间并发请求。
			jitter := time.Duration(rand.Int64N(int64(autoUpdateDefaultJitter)))
			nextCheck = time.Now().Add(a.cfg.updateInterval + jitter)
		}
		job, err := a.client.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, errUpdating) {
				// 更新期间暂停轮询：短暂等待后继续。
				if !sleep(ctx, 3*time.Second) {
					return nil
				}
				continue
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

// newUpdater 构建自更新器（自动更新、check/apply CLI 共用）。
func newUpdater(cfg *config, log logger) *updater {
	exe, err := os.Executable()
	if err != nil {
		exe = cfg.binary // 极少出现；退回 -nexttrace 路径（仅用于日志）
	}
	platform, arch := detectPlatformArch()
	return &updater{
		repo:     "mengnanquq/mnagent",
		platform: platform,
		arch:     arch,
		// 不自动跟随重定向：检查更新要读 Location 头（里面带版本号）。
		client: &http.Client{
			Timeout: updateCheckTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		downloadClient: &http.Client{
			Timeout: updateDownloadTimeout,
		},
		executable: exe,
		skipFile:   filepath.Join(os.TempDir(), "mnagent-skip-versions"),
		ghProxy:    cfg.ghProxy,
		restart: func() error {
			if log != nil {
				log.Info("正在重启服务以应用新版本", "version", version)
			}
			// systemd 或 OpenWrt procd 都会通过各自的 init 重启；未知平台则直接退出，
			// 交由守护进程（如进程管理器）拉起新版本。
			return restartService()
		},
	}
}

// handleUpdateCLI 处理 --check-update / --apply-update / --skip-update。
func handleUpdateCLI(cfg *config, log logger) (handled bool, err error) {
	u := newUpdater(cfg, log)
	exe, _ := os.Executable()
	u.executable = exe
	switch {
	case cfg.skipUpdate != "":
		ver := strings.TrimSpace(cfg.skipUpdate)
		if _, ok := parseVersion(ver); !ok {
			return true, fmt.Errorf("版本号格式非法：%q", ver)
		}
		if err := u.Skip(ver, 0); err != nil {
			return true, err
		}
		fmt.Printf("已跳过版本 %s（24 小时内不再提示）\n", ver)
		return true, nil
	case cfg.checkUpdateOnce:
		latest, ok, err := u.Check()
		if err != nil {
			return true, err
		}
		if ok {
			fmt.Printf("发现新版本：%s（当前 %s）\n", latest, version)
		} else {
			fmt.Printf("已是最新版本（%s）\n", version)
		}
		dm := newDependencyManager(cfg.ghProxy)
		statuses := dm.CheckAll(context.Background(), cfg)
		for _, st := range statuses {
			fmt.Println(st.Summary())
		}
		return true, nil
	case cfg.applyUpdate != "":
		ver := cfg.applyUpdate
		if ver == "latest" {
			l, _, err := u.latestVersion()
			if err != nil {
				return true, err
			}
			ver = l
		} else if _, ok := parseVersion(ver); !ok {
			return true, fmt.Errorf("版本号格式非法：%q", ver)
		}

		// 更新依赖项
		dm := newDependencyManager(cfg.ghProxy)
		statuses := dm.CheckAll(context.Background(), cfg)
		for _, st := range statuses {
			if st.HasUpdate {
				fmt.Printf("正在更新依赖 %s 至 %s ...\n", st.Name, st.LatestVersion)
				if _, err := dm.UpdateDependency(context.Background(), st.Name, st.BinaryPath, st.LatestVersion, log); err != nil {
					fmt.Printf("更新依赖 %s 失败：%v\n", st.Name, err)
				} else {
					fmt.Printf("已更新依赖 %s（%s）\n", st.Name, st.LatestVersion)
				}
			}
		}

		fmt.Printf("正在下载并安装 %s ...\n", ver)
		if err := u.Apply(ver); err != nil {
			return true, err
		}
		fmt.Printf("已安装 %s，服务已重启\n", ver)
		return true, nil
	}
	return false, nil
}

// restartService 重启 mnagent 服务（systemd 或 OpenWrt procd）。
func restartService() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "restart", "mnagent").CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart mnagent 失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if _, err := os.Stat("/etc/init.d/mnagent"); err == nil {
		// OpenWrt procd 服务脚本
		out, err := exec.Command("/etc/init.d/mnagent", "restart").CombinedOutput()
		if err != nil {
			return fmt.Errorf("/etc/init.d/mnagent restart 失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return errors.New("未找到 systemd 或 /etc/init.d/mnagent，无法自动重启（请手动重启服务）")
}

// checkAndUpdateDependencies 检查各依赖项（如 nexttrace、miaospeed）版本，若启用 autoUpdate 则自动更新。
func (a *agent) checkAndUpdateDependencies(ctx context.Context) {
	if a.cfg == nil {
		return
	}
	dm := newDependencyManager(a.cfg.ghProxy)
	statuses := dm.CheckAll(ctx, a.cfg)
	for _, st := range statuses {
		if st.Error != nil {
			a.logger.Warn("检查依赖更新失败", "dependency", st.Name, "error", st.Error)
			continue
		}
		if !st.Installed {
			a.logger.Debug("依赖未安装", "dependency", st.Name, "latest", st.LatestVersion)
			continue
		}
		if st.HasUpdate {
			a.logger.Info("发现依赖新版本", "dependency", st.Name, "current", st.CurrentVersion, "latest", st.LatestVersion)
			if a.cfg.autoUpdate {
				if _, err := dm.UpdateDependency(ctx, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
					a.logger.Warn("自动更新依赖失败", "dependency", st.Name, "version", st.LatestVersion, "error", err)
				} else {
					a.logger.Info("依赖已自动更新", "dependency", st.Name, "version", st.LatestVersion)
				}
			}
		} else {
			a.logger.Debug("依赖已是最新版本", "dependency", st.Name, "version", st.CurrentVersion)
		}
	}
}

// updateOnce 执行一次自动更新检查；返回 true 表示已应用更新（进程将被重启）。
func (a *agent) updateOnce(ctx context.Context) bool {
	// 无论 mnagent 自身是否有更新，先检查并更新依赖项
	a.checkAndUpdateDependencies(ctx)

	if a.update == nil {
		return false
	}
	latest, ok, err := a.update.Check()
	if err != nil {
		a.logger.Warn("检查更新失败", "error", err)
		return false
	}
	if !ok {
		return false
	}
	a.logger.Info("发现新版本，开始更新", "from", version, "to", latest)
	a.client.paused.Store(true) // 更新期间暂停轮询，避免新旧版本交替领取任务。
	defer a.client.paused.Store(false)
	if err := a.update.Apply(latest); err != nil {
		a.logger.Warn("应用更新失败", "version", latest, "error", err)
		return false
	}
	return true
}

// execute 执行任务并回传结果。
func (a *agent) execute(ctx context.Context, job Job) {
	start := time.Now()
	a.logger.Info("开始执行任务", "job", job.ID, "kind", probeKind(job), "target", job.Target,
		"hops", job.Hops, "port", job.Port, "protocol", job.Protocol, "count", job.Count)

	run := a.runner.run(ctx, job)
	output, errText, exitCode := run.Output, run.ErrText, run.ExitCode

	// 回传不依赖任务上下文：即使任务超时或进程正在退出，也尽量让机器人拿到结果，
	// 否则用户要一直等到超时。
	sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := Result{ID: job.ID, Kind: probeKind(job), Output: output, ExitCode: exitCode, Error: errText, Data: run.Data}
	if err := a.client.sendResult(sendCtx, res); err != nil {
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
