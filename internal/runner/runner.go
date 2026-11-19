package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mengnanquq/mnagent/internal/client"
	"github.com/mengnanquq/mnagent/internal/config"
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

// NewRunner 构建执行器，默认请求 JSON 输出。
func NewRunner(binary string, log Logger) *Runner {
	return NewRunnerFull(binary, "miaospeed", "", false, log)
}

// NewRunnerWithMiaospeed 构建执行器，可指定 miaospeed 可执行文件路径。
func NewRunnerWithMiaospeed(binary, miaospeed string, log Logger) *Runner {
	return NewRunnerFull(binary, miaospeed, "", false, log)
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

	heavyMu    sync.Mutex
	heavyQueue chan model.Job
	lightSem   chan struct{}
	tasksWG    sync.WaitGroup

	// stopCtx 是主循环退出后的共享停止预算：在途任务回传与未执行任务回报
	// 都受同一个 deadline 约束，总时长不超过 config.DefaultExitResultTimeout。
	stopMu  sync.RWMutex
	stopCtx context.Context

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
	defer func() {
		// 退出/重启时的所有网络写操作共享同一个 60s 停止预算，必须明显小于
		// systemd 的 TimeoutStopSec=90s，否则服务会在回传途中被 SIGKILL。
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
	}()
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
		if isHeavy(*job) || job.Kind == "upgrade" || job.Kind == "update" {
			if !a.enqueueHeavy(ctx, *job) && ctx.Err() != nil {
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
