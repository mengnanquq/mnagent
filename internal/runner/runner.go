package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/miaospeed"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/probe"
	"github.com/mengnanquq/mnagent/internal/process"
	"github.com/mengnanquq/mnagent/internal/service"
	"github.com/mengnanquq/mnagent/internal/tracker"
	"github.com/mengnanquq/mnagent/internal/updater"
)

var Version = "dev"

// targetPattern 与机器人侧一致：目标只能是 IP/域名（可带 :port），
// 且不允许以 "-" 开头，避免任何参数注入。
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\-]+$`)

// maxOutputBytes 限制单次追踪读入内存的输出（机器人侧同样有上限）。
const maxOutputBytes = 1 << 20

// runner 负责校验任务参数并执行 nexttrace 或外部工具。
type Runner struct {
	binary          string
	miaospeedBinary string
	ghProxy         string
	jsonOutput      atomic.Bool // 是否附加 -j（旧版本 nexttrace 不支持时自动关闭）。
	// waitDelay 限制“进程已被杀掉、但仍有子进程占着输出管道”时的额外等待，
	// 避免超时任务因为派生的孙进程而把 agent 卡死。
	waitDelay          time.Duration
	allowPrivateProbes bool
	logger             Logger // 可选：记录实际执行的 argv，便于与主机上手跑结果对照。
	onProgress         func(model.Progress)
}

// setProgressReporter 注入实时进度回调。
func (r *Runner) SetProgressReporter(fn func(model.Progress)) {
	r.onProgress = fn
}

// newRunner 构建执行器，默认请求 JSON 输出。
func NewRunner(binary string, log Logger) *Runner {
	return newRunnerFull(binary, "miaospeed", "", false, log)
}

// newRunnerWithMiaospeed 构建执行器，可指定 miaospeed 可执行文件路径。
func NewRunnerWithMiaospeed(binary, miaospeed string, log Logger) *Runner {
	return newRunnerFull(binary, miaospeed, "", false, log)
}

// newRunnerFull 构建执行器，可指定 miaospeed 路径与 GitHub 代理前缀。
func NewRunnerFull(binary, miaospeed, ghProxy string, allowPrivate bool, log Logger) *Runner {
	r := &Runner{
		binary:             binary,
		miaospeedBinary:    miaospeed,
		ghProxy:            ghProxy,
		allowPrivateProbes: allowPrivate,
		waitDelay:          5 * time.Second,
		logger:             log,
	}
	r.jsonOutput.Store(true)
	return r
}

// run 执行一次任务，返回输出、错误文案与退出码。
// 退出码 -1 表示任务本身非法（未执行）。
// runResult 是一次任务的执行结果。
type runResult = RunResult

type RunResult struct {
	Output   string          // 原始输出（trace）或摘要文本
	Data     json.RawMessage // 结构化探针结果（ping/tcping/http/dns/miaospeed）
	ErrText  string          // 面向用户的错误文案（成功为空）
	ExitCode int
}

func (r *Runner) Run(ctx context.Context, job model.Job) runResult {
	// 进程内探针：不依赖外部二进制，OpenWrt 等精简系统同样可用。
	switch kind := probe.ProbeKind(job); {
	case kind == probe.KindTrace:
		return r.runTrace(ctx, job)
	case probe.IsProbeKind(kind):
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
	return kind == "miaospeed"
}

// runMiaospeed 执行 miaospeed 代理测速。
func (r *Runner) runMiaospeed(ctx context.Context, job model.Job) runResult {
	// 测速超时由任务内部根据实际节点数量动态计算，外层仅用最大时限兜底，避免长订阅测速被提前截断。
	runCtx, cancel := context.WithTimeout(ctx, model.JobMiaospeedMaxTimeout)
	defer cancel()

	output, data, err := miaospeed.RunJob(runCtx, r.miaospeedBinary, r.ghProxy, job, r.logger, r.onProgress, r.allowPrivateProbes)
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
func (r *Runner) runProbeJob(ctx context.Context, job model.Job, kind string) runResult {
	runCtx, cancel := context.WithTimeout(ctx, job.Timeout())
	defer cancel()
	outcome, err := probe.RunProbe(runCtx, job, r.allowPrivateProbes)
	result := runResult{Output: outcome.Output, Data: outcome.Data}
	if err != nil {
		result.ErrText = err.Error()
		result.ExitCode = -1
	}
	return result
}

// runTrace 通过外部 nexttrace 执行一次路由追踪。
func (r *Runner) runTrace(ctx context.Context, job model.Job) runResult {
	if !r.allowPrivateProbes {
		target := strings.TrimSpace(job.Target)
		if h, _, err := net.SplitHostPort(target); err == nil {
			target = h
		}
		if ip := net.ParseIP(target); ip != nil {
			if probe.IsBlockedProbeIP(ip) {
				return runResult{ErrText: fmt.Sprintf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String()), ExitCode: -1}
			}
		} else {
			resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", target)
			if err != nil || len(ips) == 0 {
				return runResult{ErrText: fmt.Sprintf("安全策略拦截：无法解析目标主机 (%s)", target), ExitCode: -1}
			}
			for _, ip := range ips {
				if probe.IsBlockedProbeIP(ip) {
					return runResult{ErrText: fmt.Sprintf("安全策略拦截：禁止探测私有或云元数据地址 (%s)", ip.String()), ExitCode: -1}
				}
			}
		}
	}
	out, errText, exitCode := r.runNexttrace(ctx, job)
	return runResult{Output: out, ErrText: errText, ExitCode: exitCode}
}

// runNexttrace 组装 argv、执行并处理 -j 兼容回退。
func (r *Runner) runNexttrace(ctx context.Context, job model.Job) (output string, errText string, exitCode int) {
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
	case errors.Is(runCtx.Err(), context.Canceled):
		return out, "任务已取消", code
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
func (r *Runner) exec(ctx context.Context, args []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	process.SetupCmdProcessGroup(cmd)
	cmd.WaitDelay = r.waitDelay
	if r.logger != nil {
		r.logger.Debug("执行 nexttrace", "argv", strings.Join(append([]string{r.binary}, args...), " "))
	}
	out := process.NewCappedBuffer(maxOutputBytes)
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
func (r *Runner) argv(job model.Job) ([]string, error) {
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

// 调度器并发参数。
const defaultMaxConcurrentLight = 8

// agent 把客户端与执行器串成“领取 → 执行 → 回传”的主循环。
type Agent struct {
	cfg     *config.Config
	logger  Logger
	client  *client.Client
	runner  *Runner
	update  *updater.Updater
	tracker *tracker.Tracker

	heavyMu    sync.Mutex
	heavyQueue chan model.Job
	lightSem   chan struct{}
	tasksWG    sync.WaitGroup
}

// logger 是本包用到的最小日志接口，便于测试注入。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

func isHeavy(job model.Job) bool {
	kind := probe.ProbeKind(job)
	return kind == probe.KindTrace || kind == "miaospeed"
}

// loop 不断领取任务并执行，直到 ctx 结束；启用自动更新时按周期检查新版本。
func (a *Agent) Loop(ctx context.Context) error {
	defer a.tasksWG.Wait()
	a.startHeartbeat(ctx)

	if a.heavyQueue == nil {
		a.heavyQueue = make(chan model.Job, 32)
	}
	if a.lightSem == nil {
		a.lightSem = make(chan struct{}, defaultMaxConcurrentLight)
	}

	// 启动重任务专用消费协程：串行化重任务与更新指令，并与主长轮询解耦
	a.tasksWG.Add(1)
	go a.heavyWorker(ctx)

	backoff := a.cfg.MinBackoff
	var nextCheck time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		if a.update != nil && a.cfg.AutoUpdate && time.Now().After(nextCheck) {
			if a.updateOnce(ctx) {
				return nil // 已应用更新并重启：进程即将被替换。
			}
			// 加入抖动，避免多个部署实例在完全相同的时间并发请求。
			jitter := time.Duration(rand.Int64N(int64(updater.DefaultJitter)))
			nextCheck = time.Now().Add(a.cfg.UpdateInterval + jitter)
		}
		job, err := a.client.Poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, model.ErrUpdating) {
				// 更新期间暂停轮询：短暂等待后继续。
				if !sleep(ctx, 3*time.Second) {
					return nil
				}
				continue
			}
			if errors.Is(err, model.ErrUnauthorized) {
				// 令牌不对：配置问题，用最大间隔重试，避免刷日志。
				a.logger.Warn("鉴权失败，将以最大间隔重试", "error", err, "retry_in", a.cfg.MaxBackoff)
				if !sleep(ctx, a.cfg.MaxBackoff) {
					return nil
				}
				continue
			}
			a.logger.Warn("轮询失败，稍后重试", "error", err, "retry_in", backoff)
			if !sleep(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, a.cfg.MaxBackoff)
			continue
		}
		backoff = a.cfg.MinBackoff
		if job == nil {
			continue // 空响应：立刻再轮询。
		}

		// 收到任务取消控制包：立即在 tracker 中取消，无论其在排队还是正在运行
		if job.Kind == "cancel" {
			if a.tracker != nil {
				if a.tracker.Cancel(job.ID) {
					a.logger.Info("已按指令中止正在执行的任务", "job", job.ID)
				} else {
					a.logger.Info("已登记任务取消标记（若在排队将跳过执行）", "job", job.ID)
				}
			}
			continue
		}

		// 收到远程更新控制包或重任务（trace / miaospeed）：投入串行调度队列，不阻塞主循环长轮询
		if isHeavy(*job) || job.Kind == "upgrade" || job.Kind == "update" {
			select {
			case a.heavyQueue <- *job:
			case <-ctx.Done():
				return nil
			}
			continue
		}

		// 轻任务（ping / tcping / http / dns）：
		// 派发至轻任务 worker pool 并发执行，主循环绝不阻塞挂起，秒级处理后续长轮询
		a.tasksWG.Add(1)
		go func(j model.Job) {
			defer a.tasksWG.Done()
			select {
			case a.lightSem <- struct{}{}:
				defer func() { <-a.lightSem }()
			case <-ctx.Done():
				return
			}
			a.execute(ctx, j)
		}(*job)
	}
}

// heavyWorker 串行处理重任务与远程更新，避免多重任务争抢带宽与端口，
// 并与主长轮询完全解耦，使长轮询与轻任务始终保持秒级响应。
func (a *Agent) heavyWorker(ctx context.Context) {
	defer a.tasksWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case j, ok := <-a.heavyQueue:
			if !ok {
				return
			}

			// 检查任务在排队期间是否已被 cancel
			if a.tracker != nil && a.tracker.IsCancelled(j.ID) {
				a.logger.Info("任务在排队期间已被取消，跳过执行", "job", j.ID, "kind", j.Kind)
				continue
			}

			if j.Kind == "upgrade" || j.Kind == "update" {
				a.handleUpgradeJob(ctx, j)
			} else {
				a.execute(ctx, j)
			}
		}
	}
}

// startHeartbeat 启动独立于任务执行的周期心跳协程，确保长任务执行期间服务端 lastSeen 始终保活。
func (a *Agent) startHeartbeat(ctx context.Context) {
	a.tasksWG.Add(1)
	go func() {
		defer a.tasksWG.Done()
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				hbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := a.client.Heartbeat(hbCtx); err != nil {
					a.logger.Debug("保活心跳未送达", "error", err)
				}
				cancel()
			}
		}
	}()
}

func newUpdater(cfg *config.Config, log Logger) *updater.Updater {
	exe, err := os.Executable()
	if err != nil {
		exe = cfg.Binary
	}
	platform, arch := updater.DetectPlatformArch()
	return updater.New(updater.Config{
		CurrentVersion: Version,
		Repo:           "mengnanquq/mnagent",
		Platform:       platform,
		Arch:           arch,
		Executable:     exe,
		SkipFile:       filepath.Join(os.TempDir(), "mnagent-skip-versions"),
		GHProxy:        cfg.GHProxy,
		Restart: func() error {
			if log != nil {
				log.Info("正在重启服务以应用新版本", "Version", Version)
			}
			return service.RestartService()
		},
	})
}

// NewUpdater 创建自身版本更新器。
func NewUpdater(cfg *config.Config, log Logger) *updater.Updater {
	return newUpdater(cfg, log)
}

// handleUpdateCLI 处理 --check-update / --apply-update / --skip-update。
func HandleUpdateCLI(cfg *config.Config, log Logger) (handled bool, err error) {
	u := newUpdater(cfg, log)
	exe, _ := os.Executable()
	u.Executable = exe
	switch {
	case cfg.SkipUpdate != "":
		ver := strings.TrimSpace(cfg.SkipUpdate)
		if _, ok := updater.ParseVersion(ver); !ok {
			return true, fmt.Errorf("版本号格式非法：%q", ver)
		}
		if err := u.Skip(ver, 0); err != nil {
			return true, err
		}
		fmt.Printf("已跳过版本 %s（24 小时内不再提示）\n", ver)
		return true, nil
	case cfg.CheckUpdateOnce:
		latest, ok, err := u.Check()
		if err != nil {
			return true, err
		}
		if ok {
			fmt.Printf("发现新版本：%s（当前 %s）\n", latest, Version)
		} else {
			fmt.Printf("已是最新版本（%s）\n", Version)
		}
		dm := dep.NewDependencyManager(cfg.GHProxy)
		statuses := dm.CheckAll(context.Background(), cfg.Binary, cfg.MiaospeedBinary)
		for _, st := range statuses {
			fmt.Println(st.Summary())
		}
		return true, nil
	case cfg.ApplyUpdate != "":
		ver := cfg.ApplyUpdate
		if ver == "latest" {
			l, _, err := u.LatestVersion()
			if err != nil {
				return true, err
			}
			ver = l
		} else if _, ok := updater.ParseVersion(ver); !ok {
			return true, fmt.Errorf("版本号格式非法：%q", ver)
		}

		// 更新依赖项
		dm := dep.NewDependencyManager(cfg.GHProxy)
		statuses := dm.CheckAll(context.Background(), cfg.Binary, cfg.MiaospeedBinary)
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

// checkAndUpdateDependencies 检查各依赖项（如 nexttrace、miaospeed）版本，若启用 autoUpdate 则自动更新。
func (a *Agent) checkAndUpdateDependencies(ctx context.Context) {
	if a.cfg == nil {
		return
	}
	dm := dep.NewDependencyManager(a.cfg.GHProxy)
	statuses := dm.CheckAll(ctx, a.cfg.Binary, a.cfg.MiaospeedBinary)
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
			if a.cfg.AutoUpdate {
				if _, err := dm.UpdateDependency(ctx, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
					a.logger.Warn("自动更新依赖失败", "dependency", st.Name, "Version", st.LatestVersion, "error", err)
				} else {
					a.logger.Info("依赖已自动更新", "dependency", st.Name, "Version", st.LatestVersion)
				}
			}
		} else {
			a.logger.Debug("依赖已是最新版本", "dependency", st.Name, "Version", st.CurrentVersion)
		}
	}
}

// updateOnce 执行一次自动更新检查；返回 true 表示已应用更新（进程将被重启）。
func (a *Agent) updateOnce(ctx context.Context) bool {
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
	a.logger.Info("发现新版本，开始更新", "from", Version, "to", latest)
	a.client.SetPaused(true) // 更新期间暂停轮询，避免新旧版本交替领取任务。
	defer a.client.SetPaused(false)
	if err := a.update.Apply(latest); err != nil {
		a.logger.Warn("应用更新失败", "Version", latest, "error", err)
		return false
	}
	return true
}

// execute 执行任务并回传结果。
func (a *Agent) execute(ctx context.Context, job model.Job) {
	start := time.Now()
	a.logger.Info("开始执行任务", "job", job.ID, "kind", probe.ProbeKind(job), "target", job.Target,
		"hops", job.Hops, "port", job.Port, "protocol", job.Protocol, "count", job.Count)

	taskCtx, taskCancel := context.WithCancel(ctx)
	defer taskCancel()
	if a.tracker != nil {
		a.tracker.Register(job.ID, taskCancel)
		defer a.tracker.Unregister(job.ID)
	}

	run := a.runner.run(taskCtx, job)
	output, errText, exitCode := run.Output, run.ErrText, run.ExitCode

	// 回传不依赖任务上下文：即使任务超时或进程正在退出，也尽量让机器人拿到结果，
	// 否则用户要一直等到超时。
	sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := model.Result{ID: job.ID, Kind: probe.ProbeKind(job), Output: output, ExitCode: exitCode, Error: errText, Data: run.Data}
	if err := a.client.SendResult(sendCtx, res); err != nil {
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

// handleUpgradeJob 处理来自机器人的远程更新指令。
func (a *Agent) handleUpgradeJob(ctx context.Context, job model.Job) {
	a.logger.Info("收到远程更新指令，开始处理", "job", job.ID, "current_version", Version, "target", job.Target)

	var depNotes []string
	if a.cfg != nil {
		dm := dep.NewDependencyManager(a.cfg.GHProxy)
		statuses := dm.CheckAll(ctx, a.cfg.Binary, a.cfg.MiaospeedBinary)
		for _, st := range statuses {
			if st.Error != nil {
				depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 检查失败：%v", st.Name, st.Error))
				continue
			}
			if !st.Installed {
				continue
			}
			if st.HasUpdate {
				if _, err := dm.UpdateDependency(ctx, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
					depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 更新至 %s 失败：%v", st.Name, st.LatestVersion, err))
				} else {
					depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已成功更新至 %s", st.Name, st.LatestVersion))
				}
			} else {
				depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已是最新版（%s）", st.Name, st.CurrentVersion))
			}
		}
	}
	depSummary := strings.Join(depNotes, "\n")
	if depSummary != "" {
		depSummary = "\n" + depSummary
	}

	if a.update == nil {
		a.sendUpgradeResult(job, -1, "当前运行环境不支持自更新（更新器未就绪）", "updater not ready")
		return
	}

	targetVer := strings.TrimSpace(job.Target)
	if targetVer == "" {
		targetVer = "latest"
	}

	var (
		newVer    string
		hasUpdate bool
		checkErr  error
	)
	if targetVer == "latest" {
		newVer, hasUpdate, checkErr = a.update.Check()
	} else {
		newVer = targetVer
		hasUpdate = true
	}

	if checkErr != nil {
		errMsg := fmt.Sprintf("检查更新失败：%v", checkErr)
		a.logger.Warn(errMsg, "job", job.ID)
		a.sendUpgradeResult(job, -1, errMsg+depSummary, checkErr.Error())
		return
	}

	if !hasUpdate && targetVer == "latest" {
		msg := fmt.Sprintf("当前已是最新版本（%s），无需更新。原有运行参数保持不变。%s", Version, depSummary)
		a.logger.Info("当前已是最新版本", "Version", Version)
		a.sendUpgradeResult(job, 0, strings.TrimSpace(msg), "")
		return
	}

	// 执行下载并原子替换二进制文件
	a.client.SetPaused(true)
	defer a.client.SetPaused(false)

	a.logger.Info("开始下载并替换二进制", "from", Version, "to", newVer)
	installedVer, applyErr := a.update.DownloadAndReplace(newVer)
	if applyErr != nil {
		errMsg := fmt.Sprintf("下载或安装更新失败：%v", applyErr)
		a.logger.Warn(errMsg, "target", newVer, "error", applyErr)
		a.sendUpgradeResult(job, -1, errMsg+depSummary, applyErr.Error())
		return
	}

	// 替换成功后，先向机器人回传成功结果
	successMsg := fmt.Sprintf("✅ 已成功下载并安装 %s（原版本 %s）！\n• 服务正在平滑重启\n• 所有启动参数已由系统服务完整保留%s",
		installedVer, Version, depSummary)
	a.logger.Info("已成功更新并回传结果，即将平滑重启服务", "new_version", installedVer)
	a.sendUpgradeResult(job, 0, strings.TrimSpace(successMsg), "")

	// 重启前通知在途轻任务取消，避免直接硬杀导致任务状态丢失
	if a.tracker != nil {
		a.tracker.CancelAll()
	}

	// 短暂休眠确保结果数据包送出网络缓冲区，随后触发重启
	time.Sleep(500 * time.Millisecond)
	if err := a.update.Restart(); err != nil {
		a.logger.Warn("服务重启失败", "error", err)
	}
}

func (a *Agent) sendUpgradeResult(job model.Job, exitCode int, output, errText string) {
	sendCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := model.Result{
		ID:       job.ID,
		Kind:     job.Kind,
		Output:   output,
		ExitCode: exitCode,
		Error:    errText,
	}
	if err := a.client.SendResult(sendCtx, res); err != nil {
		a.logger.Warn("回传更新结果失败", "job", job.ID, "error", err)
	}
}

// NewAgent 创建一个新的调度代理实例。
func NewAgent(cfg *config.Config, log Logger, cli *client.Client, rnr *Runner, upd *updater.Updater, trk *tracker.Tracker) *Agent {
	return &Agent{
		cfg:     cfg,
		logger:  log,
		client:  cli,
		runner:  rnr,
		update:  upd,
		tracker: trk,
	}
}

func newRunner(binary string, log Logger) *Runner {
	return NewRunner(binary, log)
}

func newRunnerWithMiaospeed(binary, miaospeed string, log Logger) *Runner {
	return NewRunnerWithMiaospeed(binary, miaospeed, log)
}

func newRunnerFull(binary, miaospeed, ghProxy string, allowPrivate bool, log Logger) *Runner {
	return NewRunnerFull(binary, miaospeed, ghProxy, allowPrivate, log)
}

func (r *Runner) run(ctx context.Context, job model.Job) runResult {
	return r.Run(ctx, job)
}

func (r *Runner) setProgressReporter(fn func(model.Progress)) {
	r.SetProgressReporter(fn)
}

func (a *Agent) loop(ctx context.Context) error {
	return a.Loop(ctx)
}

func handleUpdateCLI(cfg *config.Config, log Logger) (handled bool, err error) {
	return HandleUpdateCLI(cfg, log)
}
