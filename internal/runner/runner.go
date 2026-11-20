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
	"github.com/mengnanquq/mnagent/internal/tracker"
	"github.com/mengnanquq/mnagent/internal/updater"
)

var Version = "dev"

// targetPattern 与机器人侧一致：目标只能是 IP/域名（可带 :port，IPv6 可用
// [addr]:port 形式），且不允许以 "-" 开头，避免任何参数注入。
var targetPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]+$`)

// maxOutputBytes 限制单次追踪读入内存的输出（机器人侧同样有上限）。
const maxOutputBytes = 1 << 20

// dependencyInstallMaxTimeout 限制 trace 任务触发依赖下载/安装的时长：
// 安装与任务本身共用一个串行 heavyWorker，不能因为弱网下载把它长期占住。
const dependencyInstallMaxTimeout = 90 * time.Second

// runner 负责校验任务参数并执行 nexttrace 或外部工具。
type Runner struct {
	binary          string
	miaospeedBinary string
	ghProxy         string
	// botDigest 是服务端代取校验值的客户端；nil 表示只走直连来源。
	// 运行时自动安装 nexttrace/miaospeed 时注入依赖管理器。
	botDigest  *updater.BotDigestClient
	jsonOutput atomic.Bool // 是否附加 -j（旧版本 nexttrace 不支持时自动关闭）。
	// waitDelay 限制“进程已被杀掉、但仍有子进程占着输出管道”时的额外等待，
	// 避免超时任务因为派生的孙进程而把 agent 卡死。
	waitDelay          time.Duration
	allowPrivateProbes bool
	logger             Logger // 可选：记录实际执行的 argv，便于与主机上手跑结果对照。
	onProgress         func(model.Progress)

	nexttraceMu        sync.Mutex
	installedNexttrace string
	// depManagerFactory 可选：测试注入依赖管理器，避免访问真实 GitHub。
	depManagerFactory func(ghProxy string) *dep.DependencyManager
}

// setProgressReporter 注入实时进度回调。
func (r *Runner) SetProgressReporter(fn func(model.Progress)) {
	r.onProgress = fn
}

// SetBotDigest 注入服务端代取校验值的客户端（供运行时自动安装依赖使用）。
// nil 表示禁用，退回只走直连来源。
func (r *Runner) SetBotDigest(c *updater.BotDigestClient) {
	if r == nil {
		return
	}
	r.botDigest = c
}

// NewRunnerFull 构建执行器，可指定 miaospeed 路径与 GitHub 代理前缀。
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

// runResult 是 RunResult 的包内简写。
type runResult = RunResult

// RunResult 是一次任务的执行结果。
// ExitCode 为 -1 表示任务本身非法（未执行）。
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

	output, data, err := miaospeed.RunJobWithOptions(runCtx, r.miaospeedBinary, r.ghProxy, job, r.logger, r.onProgress, miaospeed.RunOptions{
		AllowPrivate: r.allowPrivateProbes,
		BotDigest:    r.botDigest,
	})
	if err != nil {
		return buildMiaospeedResult(output, data, err.Error(), -1)
	}
	return buildMiaospeedResult(output, data, "", 0)
}

// buildMiaospeedResult 组装 miaospeed 任务的回传结果。
// 结构化 Data 已携带完整报告，机器人各排版路径都优先读 Data（仅旧版本才回退 Output），
// 因此不再把同一份 JSON 同时塞进 Output：300 节点约 1.8MB、500 节点约 3MB，重复一份会整整翻倍，
// 直接撞上结果体上限。
func buildMiaospeedResult(output string, data json.RawMessage, errText string, exitCode int) runResult {
	res := runResult{Data: data, ErrText: errText, ExitCode: exitCode}
	if len(data) == 0 {
		// 没有结构化数据（例如启动阶段就失败）时保留文本输出，供机器人兜底展示。
		res.Output = output
	}
	return res
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
		port := ""
		if h, p, err := net.SplitHostPort(target); err == nil {
			target, port = h, p
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
			// 直接追踪已校验的 IP：交给 nexttrace 的若仍是域名，它会再次解析，
			// 两次解析之间域名可被切换到内网地址（DNS 重绑定）
			checked := ips[0]
			for _, ip := range ips {
				if ip.To4() != nil {
					checked = ip
					break
				}
			}
			job.Target = checked.String()
			if port != "" {
				job.Target = net.JoinHostPort(checked.String(), port)
			}
		}
	}
	out, errText, exitCode := r.runNexttrace(ctx, job)
	return runResult{Output: out, ErrText: errText, ExitCode: exitCode}
}

// nexttraceBinary 返回可执行的 nexttrace 路径；缺失时自动下载安装一次并缓存结果。
func (r *Runner) nexttraceBinary(ctx context.Context) (string, error) {
	if p, ok := dep.ResolveBinaryPath(r.binary); ok {
		return p, nil
	}
	r.nexttraceMu.Lock()
	cached := r.installedNexttrace
	r.nexttraceMu.Unlock()
	if cached != "" {
		if p, ok := dep.ResolveBinaryPath(cached); ok {
			return p, nil
		}
	}

	dm := r.newDependencyManager()
	if dm == nil {
		return "", fmt.Errorf("未找到 nexttrace 可执行文件（%s）", r.binary)
	}
	if r.logger != nil {
		r.logger.Warn("未找到 nexttrace，正在自动下载安装", "binary", r.binary)
	}
	installed, err := dm.EnsureNextTrace(ctx, r.binary, "latest", r.logger)
	if err != nil {
		return "", err
	}
	r.nexttraceMu.Lock()
	r.installedNexttrace = installed
	r.nexttraceMu.Unlock()
	return installed, nil
}

// newDependencyManager 创建依赖管理器；测试可注入工厂返回 nil 跳过真实下载。
func (r *Runner) newDependencyManager() *dep.DependencyManager {
	var dm *dep.DependencyManager
	if r.depManagerFactory != nil {
		dm = r.depManagerFactory(r.ghProxy)
	} else {
		dm = dep.NewDependencyManager(r.ghProxy)
	}
	if dm != nil {
		dm.SetBotDigest(r.botDigest)
	}
	return dm
}

// runNexttrace 组装 argv、执行并处理 -j 兼容回退。
func (r *Runner) runNexttrace(ctx context.Context, job model.Job) (output string, errText string, exitCode int) {
	args, err := r.argv(job)
	if err != nil {
		return "", err.Error(), -1
	}

	// 依赖安装有独立上限：heavyWorker 是串行的，弱网下载不能无限占住队列。
	// 同时不超过任务自身超时，避免安装比任务预算还长。
	installCtx, cancelInstall := context.WithTimeout(ctx, min(dependencyInstallMaxTimeout, job.Timeout()))
	defer cancelInstall()

	binaryPath, err := r.nexttraceBinary(installCtx)
	if err != nil {
		return "", "执行失败：无法启动 nexttrace（" + clampText(err.Error(), 300) + "）", -1
	}

	runCtx, cancel := context.WithTimeout(ctx, job.Timeout())
	defer cancel()

	out, code, runErr := r.execWithBinary(runCtx, binaryPath, args)
	// 执行前检查通过、执行时却找不到文件（被删除/替换中）：重新安装后重试一次。
	if runErr != nil && isExecNotFound(runErr) {
		if installed, installErr := r.nexttraceBinary(installCtx); installErr == nil {
			binaryPath = installed
			out, code, runErr = r.execWithBinary(runCtx, binaryPath, args)
		}
	}
	// 旧版 nexttrace（< v1.7）不认识 -j：去掉该参数重试一次，并记住结论。
	if runErr != nil && r.jsonOutput.Load() && looksLikeUnknownFlag(out) {
		r.jsonOutput.Store(false)
		if plain, err := r.argv(job); err == nil {
			out, code, runErr = r.execWithBinary(runCtx, binaryPath, plain)
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

// isExecNotFound 判断执行失败是否因为可执行文件不存在（含 LookPath 失败）。
func isExecNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

// execWithBinary 以 argv 方式调用指定 nexttrace 二进制（不经 shell），并捕获受限输出。
func (r *Runner) execWithBinary(ctx context.Context, binary string, args []string) (string, int, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	process.SetupCmdProcessGroup(cmd)
	cmd.WaitDelay = r.waitDelay
	if r.logger != nil {
		r.logger.Debug("执行 nexttrace", "argv", strings.Join(append([]string{binary}, args...), " "))
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
const (
	defaultMaxConcurrentLight = 8
	// lightQueueCapacity 是轻任务有界队列容量。旧实现为每个轻任务即时开协程再
	// 等 lightSem，队列满时协程会无界堆集；改为固定 worker 池 + 有界 channel 后，
	// 入队失败立即回报“队列已满”，常驻内存只取决于队列容量。
	lightQueueCapacity = 128
)

// exitInflightWait 是退出时等待在途任务结束的上限，剩余约 20s 留给
// FailPending 与 heavyQueue 回报（总预算 config.DefaultExitResultTimeout=60s）。
const exitInflightWait = 40 * time.Second

// agent 把客户端与执行器串成“领取 → 执行 → 回传”的主循环。
type Agent struct {
	cfg     *config.Config
	logger  Logger
	client  *client.Client
	runner  *Runner
	update  *updater.Updater
	tracker *tracker.Tracker

	heavyQueue chan model.Job
	lightQueue chan model.Job
	tasksWG    sync.WaitGroup

	// rejectOnce/rejectSem 限制 rejectBusyJob 并发回传的协程数。
	rejectOnce sync.Once
	rejectSem  chan struct{}

	// stopCtx 是主循环退出后的共享停止预算：在途任务回传与未执行任务回报
	// 都受同一个 deadline 约束，总时长不超过 config.DefaultExitResultTimeout。
	stopMu  sync.RWMutex
	stopCtx context.Context

	// loopCancel 取消主循环上下文：自动更新协程在替换完二进制后用它
	// 请求主循环走正常退出流程（由服务管理器拉起新版本）。
	loopCancel context.CancelFunc
	// updateBusy 防止自动更新检查在上一次尚未结束时重复启动。
	updateBusy atomic.Bool
	// updateMu 串行化自动更新与远程升级，避免二者并发替换二进制并互相覆盖 SetPaused 状态。
	updateMu sync.Mutex
	// depManagerFactory 可选：创建依赖检查用的管理器。测试可注入本地端点，
	// 或返回 nil 跳过依赖检查，避免访问真实 GitHub；零值时使用默认实现。
	depManagerFactory dependencyManagerFactory

	dedupOnce sync.Once
	dedup     *jobDedup

	resendMu       sync.Mutex
	resendInFlight map[string]struct{}
}

// logger 是本包用到的最小日志接口，便于测试注入。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

func (a *Agent) Loop(ctx context.Context) error {
	// 主循环返回（包括自更新重启路径）时主动取消内部协程，确保 heavyWorker/
	// 心跳不会继续运行，也避免退出阶段白等 40s 在途任务。
	ctx, cancel := context.WithCancel(ctx)
	a.setLoopCancel(cancel)
	defer func() {
		// 退出/重启时的所有网络写操作共享同一个 60s 停止预算，必须明显小于
		// systemd 的 TimeoutStopSec=80s，否则服务会在回传途中被 SIGKILL。
		stopCtx, cancel := context.WithTimeout(context.Background(), config.DefaultExitResultTimeout)
		defer cancel()
		a.setStopContext(stopCtx)

		// 等待在途任务结束，但绝不能无限等待：超时后直接进入未执行任务回报，
		// 剩余预算留给 FailPending / heavyQueue 清理。
		waitCtx, waitCancel := context.WithTimeout(stopCtx, exitInflightWait)
		a.waitTasks(waitCtx)
		waitCancel()

		if a.client == nil {
			return
		}
		// 退出回报使用共享停止预算：总时长不得超过 systemd 的停止超时。
		if n := a.client.FailPending(stopCtx, "agent 正在重启或退出，任务未执行，请重试"); n > 0 {
			a.logger.Info("已回报未执行的任务", "count", n)
		}
		if n := a.failPendingHeavy(stopCtx, "节点停止，未执行"); n > 0 {
			a.logger.Info("已回报 heavyQueue 中未执行的任务", "count", n)
		}
		if n := a.failPendingLight(stopCtx, "节点停止，未执行"); n > 0 {
			a.logger.Info("已回报轻任务队列中未执行的任务", "count", n)
		}
	}()
	defer cancel() // LIFO：先取消内部协程，再执行上面的退出回报。
	a.startHeartbeat(ctx)

	if a.heavyQueue == nil {
		a.heavyQueue = make(chan model.Job, 32)
	}
	if a.lightQueue == nil {
		a.lightQueue = make(chan model.Job, lightQueueCapacity)
	}

	// 启动重任务专用消费协程：串行化重任务与更新指令，并与主长轮询解耦
	a.tasksWG.Add(1)
	go a.heavyWorker(ctx)

	// 轻任务固定 worker 池：并发数沿用原来的 8，队列有界，主循环入队绝不阻塞。
	a.startLightWorkers(ctx)

	backoff := a.cfg.MinBackoff
	var nextCheck time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		if a.update != nil && a.cfg.AutoUpdate && time.Now().After(nextCheck) {
			// 加入抖动，避免多个部署实例在完全相同的时间并发请求。
			jitter := time.Duration(rand.Int64N(int64(updater.DefaultJitter)))
			nextCheck = time.Now().Add(a.cfg.UpdateInterval + jitter)
			// 自动更新检查/下载是耗时网络操作（GitHub 不可达时可能拖到数十秒），
			// 绝不能占用主循环：放到独立协程执行，本轮长轮询立即继续。
			a.startAutoUpdate(ctx)
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
		if job.NormalizedKind() == "cancel" {
			if a.tracker != nil {
				if a.tracker.Cancel(job.ID) {
					a.logger.Info("已按指令中止正在执行的任务", "job", job.ID)
				} else {
					a.logger.Info("已登记任务取消标记（若在排队将跳过执行）", "job", job.ID)
				}
			}
			continue
		}

		// 同一 jobID 可能因长轮询重连/机器人重试被重复下发：正在执行则跳过，
		// 已完成则重发缓存结果，避免重复跑 trace / miaospeed / 升级。
		switch action, cached, cacheState := a.dedupStore().start(job.ID); action {
		case dedupRunning:
			a.logger.Info("忽略重复下发的任务（正在执行）", "job", job.ID, "kind", probe.ProbeKind(*job))
			continue
		case dedupCompleted:
			// 同一个 jobID 同时只允许一个缓存重发：机器人可能在长轮询重连后
			// 连续重发同一任务，若并发上传同一份大结果会挤占带宽并重复占用连接。
			if !a.beginResend(job.ID) {
				a.logger.Info("忽略重复下发的任务（缓存结果正在重发）", "job", job.ID, "kind", probe.ProbeKind(*job))
				continue
			}
			// 异步重发：缓存结果可能有数 MB，同步上传会阻塞长轮询，
			// 导致后续任务与取消指令迟迟得不到处理。
			a.tasksWG.Add(1)
			go func(j model.Job, cached *model.Result, state dedupCacheState) {
				defer a.tasksWG.Done()
				defer a.finishResend(j.ID)
				a.resendCachedResult(ctx, j, cached, state)
			}(*job, cached, cacheState)
			continue
		}

		// 收到远程更新控制包或重任务（trace / miaospeed）：投入串行调度队列，不阻塞主循环长轮询
		if isHeavy(*job) || isUpgradeJob(*job) {
			if !a.enqueueHeavy(ctx, *job) && ctx.Err() != nil {
				return nil
			}
			continue
		}

		// 轻任务（ping / tcping / http / dns）：
		// 派发至有界队列，由固定 worker 池并发执行；主循环绝不阻塞，也不会
		// 因服务端持续推送轻任务而无界堆集协程。
		if !a.enqueueLight(ctx, *job) && ctx.Err() != nil {
			return nil
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
