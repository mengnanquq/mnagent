package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mengnanquq/mnagent/internal/config"
	"github.com/mengnanquq/mnagent/internal/dep"
	"github.com/mengnanquq/mnagent/internal/model"
	"github.com/mengnanquq/mnagent/internal/service"
	"github.com/mengnanquq/mnagent/internal/updater"
)

// botDigestClient 构造服务端代取校验值的客户端。
// 端点不可信（未启用 / 公网明文 HTTP）、缺少令牌或缺少 BotURL 时返回 nil，
// 相当于退回旧版行为（只走直连校验来源）。
func botDigestClient(cfg *config.Config) *updater.BotDigestClient {
	if cfg == nil || !cfg.BotChecksumTrusted || cfg.Tokens == nil {
		return nil
	}
	baseURL := strings.TrimSpace(cfg.BotURL)
	if baseURL == "" {
		return nil
	}
	return &updater.BotDigestClient{
		BaseURL: baseURL,
		Token:   cfg.Tokens,
		Version: Version,
	}
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
		GHProxy:        cfg.GHProxy,
		Logger:         log,
		BotDigest:      botDigestClient(cfg),
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

// HandleUpdateCLI 处理 --check-update / --apply-update / --skip-update。
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
		latest, ok, err := u.Check(context.Background())
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
			l, _, err := u.LatestVersion(context.Background())
			if err != nil {
				return true, err
			}
			ver = l
		} else if !updater.ValidReleaseTag(ver) {
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
		if err := u.Apply(context.Background(), ver); err != nil {
			return true, err
		}
		fmt.Printf("已安装 %s，服务已重启\n", ver)
		return true, nil
	}
	return false, nil
}

// dependencyManagerFactory 创建依赖管理器。测试可替换为指向本地 httptest 服务的实现，
// 返回 nil 表示跳过依赖检查；生产环境始终使用 dep.NewDependencyManager。
type dependencyManagerFactory func(ghProxy string) *dep.DependencyManager

// newDependencyManager 返回依赖检查使用的管理器；未注入工厂时保持默认行为。
func (a *Agent) newDependencyManager() *dep.DependencyManager {
	ghProxy := ""
	if a.cfg != nil {
		ghProxy = a.cfg.GHProxy
	}
	if a.depManagerFactory != nil {
		return a.depManagerFactory(ghProxy)
	}
	return dep.NewDependencyManager(ghProxy)
}

// dependencyTargetPath 返回依赖的配置路径（用于缺失时自动安装）。
func dependencyTargetPath(cfg *config.Config, name string) string {
	if cfg == nil {
		return name
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "nexttrace":
		if cfg.Binary != "" {
			return cfg.Binary
		}
	case "miaospeed":
		if cfg.MiaospeedBinary != "" {
			return cfg.MiaospeedBinary
		}
	}
	return name
}

// checkAndUpdateDependencies 检查各依赖项（如 nexttrace、miaospeed）版本：
// 缺失的依赖一律安装；已安装的依赖仅在启用 autoUpdate 时更新。
// 并发触发（启动检查、定期检查、测试任务）由 dep.EnsureDependency 去重并冷却失败。
func (a *Agent) checkAndUpdateDependencies(ctx context.Context) {
	if a.cfg == nil {
		return
	}
	dm := a.newDependencyManager()
	if dm == nil {
		return
	}
	statuses := dm.CheckAll(ctx, a.cfg.Binary, a.cfg.MiaospeedBinary)
	for _, st := range statuses {
		if !st.Installed {
			version := st.LatestVersion
			if version == "" {
				version = "latest"
			}
			a.logger.Info("依赖未安装，开始自动下载安装", "dependency", st.Name, "version", version)
			path, err := dm.EnsureDependency(ctx, st.Name, dependencyTargetPath(a.cfg, st.Name), version, a.logger)
			if err != nil {
				a.logger.Warn("自动安装依赖失败", "dependency", st.Name, "error", err)
			} else {
				a.logger.Info("依赖已自动安装", "dependency", st.Name, "path", path)
			}
			continue
		}
		if st.Error != nil {
			a.logger.Warn("检查依赖更新失败", "dependency", st.Name, "error", st.Error)
			continue
		}
		if st.HasUpdate {
			a.logger.Info("发现依赖新版本", "dependency", st.Name, "current", st.CurrentVersion, "latest", st.LatestVersion)
			if a.cfg.AutoUpdate {
				if _, err := dm.EnsureDependency(ctx, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
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

// StartInitialDependencyCheck 在后台检查并补齐缺失依赖（不依赖 -auto-update 是否开启）。
// 该协程注册到 tasksWG 并受 ctx 控制，主循环退出时会等待其结束。
func (a *Agent) StartInitialDependencyCheck(ctx context.Context) {
	if a.cfg == nil {
		return
	}
	a.tasksWG.Add(1)
	go func() {
		defer a.tasksWG.Done()
		a.checkAndUpdateDependencies(ctx)
	}()
}

// startAutoUpdate 在独立协程中执行一次自动更新检查。
// 版本查询与下载都是耗时网络操作（GitHub 不可达时可能数十秒），放在主循环里会阻塞
// 长轮询与轻任务；updateBusy 保证同一时刻只有一轮检查/更新在跑，不会重入。
func (a *Agent) startAutoUpdate(ctx context.Context) {
	if a.update == nil {
		return
	}
	if !a.updateBusy.CompareAndSwap(false, true) {
		a.logger.Debug("上一轮自动更新检查尚未结束，跳过本轮")
		return
	}
	a.tasksWG.Add(1)
	go func() {
		defer a.tasksWG.Done()
		defer a.updateBusy.Store(false)
		if a.updateOnce(ctx) {
			a.logger.Info("更新已应用，请求主循环退出以完成重启", "version", Version)
			a.cancelLoop()
		}
	}()
}

// updateOnce 执行一次自动更新检查；返回 true 表示已应用更新（进程将被重启）。
func (a *Agent) updateOnce(ctx context.Context) bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	// 无论 mnagent 自身是否有更新，先检查并更新依赖项
	a.checkAndUpdateDependencies(ctx)

	if a.update == nil {
		return false
	}
	latest, ok, err := a.update.Check(ctx)
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
	if err := a.update.Apply(ctx, latest); err != nil {
		a.logger.Warn("应用更新失败", "Version", latest, "error", err)
		return false
	}
	return true
}

// execute 执行任务并回传结果。
func evaluateRemoteTarget(current, target string, allowDowngrade bool) (noop bool, err error) {
	cur, okCur := updater.ParseVersion(current)
	if !okCur {
		// dev 或非 semver 构建无法比较，保持原有行为（仍受 ValidReleaseTag 约束）。
		return false, nil
	}
	tgt, okTgt := updater.ParseVersion(target)
	if !okTgt {
		return false, fmt.Errorf("目标版本号格式非法：%q", target)
	}
	if !tgt.NewerThan(cur) && !cur.NewerThan(tgt) {
		return true, nil
	}
	if tgt.NewerThan(cur) {
		return false, nil
	}
	if !allowDowngrade {
		return false, fmt.Errorf("拒绝降级：目标版本 %s 低于当前版本 %s（如确需降级，请在 agent 启动参数中显式添加 -allow-remote-downgrade）", target, current)
	}
	return false, nil
}

// 升级任务阶段预算：
//   - 服务端默认下发 TimeoutMS=120s；任务没带该值时按 120s 计算，带值时用
//     job.Timeout() 并夹取到 [1s, 115s]；
//   - 预算从进入 handleUpgradeJob（任务被接收）开始计时，包含等待 updateMu 的时间；
//     预留 5s 给结果回传。结果回传本身使用独立 ctx（sendResult 自带 result-timeout），
//     不受 workCtx 约束，预留只是时间余量；
//   - 依赖阶段单独限时，超时只跳过依赖，不能拖住自身更新。
const (
	upgradeServerDefaultTimeout = 120 * time.Second
	upgradeResultReserve        = 5 * time.Second
	upgradeMinWorkBudget        = time.Second
)

// upgradeDependencyPhaseTimeout 是升级任务依赖阶段的紧凑预算；其他路径（启动补齐、
// 定期检查、运行时安装、CLI）使用 dep 包的 5 分钟宽松预算。变量便于测试缩短。
var upgradeDependencyPhaseTimeout = 40 * time.Second

// upgradeWorkBudget 计算升级自身更新可用的时间预算：
// 优先使用服务端下发的 TimeoutMS，减去结果回传预留后夹取到合理区间；
// 没带 TimeoutMS 时默认 120s-5s=115s。
func upgradeWorkBudget(job model.Job) time.Duration {
	if job.TimeoutMS <= 0 {
		return upgradeServerDefaultTimeout - upgradeResultReserve
	}
	budget := job.Timeout() - upgradeResultReserve
	if budget < upgradeMinWorkBudget {
		budget = upgradeMinWorkBudget
	}
	if maxBudget := upgradeServerDefaultTimeout - upgradeResultReserve; budget > maxBudget {
		budget = maxBudget
	}
	return budget
}

// acquireUpdateMu 在 ctx 结束前尝试获取更新锁。
// ctx 先到期时返回 false；后台协程稍后拿到锁会立即释放，避免锁被“幽灵”占用。
func (a *Agent) acquireUpdateMu(ctx context.Context) bool {
	acquired := make(chan struct{})
	go func() {
		a.updateMu.Lock()
		close(acquired)
	}()
	select {
	case <-acquired:
		return true
	case <-ctx.Done():
		go func() {
			<-acquired
			a.updateMu.Unlock()
		}()
		return false
	}
}

// isCancellationError 判断错误是否由 ctx 取消/超时导致，
// 用于在真实失败与“取消”之间选择准确的回传文案。
func isCancellationError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

const (
	upgradeCancelledMessage = "升级已取消；如新二进制已落盘将在下次重启生效（本次未重启服务）"
	upgradeBusyMessage      = "节点正忙于其他更新，请稍后重试"
)

// handleUpgradeJob 处理来自机器人的远程更新指令。
func (a *Agent) handleUpgradeJob(ctx context.Context, job model.Job) {
	// 预算从进入处理函数（任务被接收）开始计时，包含等待 updateMu 的时间。
	budget := upgradeWorkBudget(job)

	// taskCtx 只反映取消（调用方退出/tracker 取消）；workCtx 额外叠加本次预算。
	// 两者分开是为了在预算耗尽与主动取消之间给出准确文案，并避免预算耗尽阻止
	// 已安装成功后的重启。
	taskCtx, taskCancel := context.WithCancel(ctx)
	defer taskCancel()
	workCtx, workCancel := context.WithTimeout(taskCtx, budget)
	defer workCancel()

	// 注册 tracker，使远程取消可以中止正在进行的升级与等待。
	if a.tracker != nil {
		a.tracker.Register(job.ID, taskCancel)
		defer a.tracker.Unregister(job.ID)
	}
	if err := taskCtx.Err(); err != nil {
		a.logger.Info("升级任务在开始前已被取消", "job", job.ID, "error", err)
		a.sendUpgradeResult(job, -1, "升级已取消，未做任何修改", err.Error())
		return
	}

	if !a.acquireUpdateMu(workCtx) {
		if err := taskCtx.Err(); err != nil {
			a.logger.Info("升级任务在等待更新锁时被取消", "job", job.ID, "error", err)
			a.sendUpgradeResult(job, -1, "升级已取消，未做任何修改", err.Error())
			return
		}
		a.logger.Warn("节点正忙于其他更新，升级任务等待超过预算", "job", job.ID, "budget", budget)
		a.sendUpgradeResult(job, -1, upgradeBusyMessage, "update lock busy")
		return
	}
	defer a.updateMu.Unlock()

	a.logger.Info("收到远程更新指令，开始处理", "job", job.ID, "current_version", Version, "target", job.Target, "budget", budget)

	var depNotes []string
	if a.cfg != nil {
		depPhaseCtx, depPhaseCancel := context.WithTimeout(workCtx, upgradeDependencyPhaseTimeout)
		if dm := a.newDependencyManager(); dm != nil {
			statuses := dm.CheckAll(depPhaseCtx, a.cfg.Binary, a.cfg.MiaospeedBinary)
			for _, st := range statuses {
				if !st.Installed {
					version := st.LatestVersion
					if version == "" {
						version = "latest"
					}
					if _, err := dm.EnsureDependencyWithin(depPhaseCtx, upgradeDependencyPhaseTimeout, st.Name, dependencyTargetPath(a.cfg, st.Name), version, a.logger); err != nil {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 自动安装失败：%v", st.Name, err))
					} else {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已自动安装", st.Name))
					}
					continue
				}
				if st.Error != nil {
					depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 检查失败：%v", st.Name, st.Error))
					continue
				}
				if st.HasUpdate {
					if _, err := dm.EnsureDependencyWithin(depPhaseCtx, upgradeDependencyPhaseTimeout, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 更新至 %s 失败：%v", st.Name, st.LatestVersion, err))
					} else {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已成功更新至 %s", st.Name, st.LatestVersion))
					}
				} else {
					depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已是最新版（%s）", st.Name, st.CurrentVersion))
				}
			}
		}
		depTimedOut := errors.Is(depPhaseCtx.Err(), context.DeadlineExceeded) && taskCtx.Err() == nil
		depPhaseCancel()
		if depTimedOut {
			depNotes = append(depNotes, fmt.Sprintf("• 依赖更新超过 %s 未完成，已跳过剩余依赖并继续更新自身", upgradeDependencyPhaseTimeout))
			a.logger.Warn("升级时依赖更新超时，跳过剩余依赖", "job", job.ID, "timeout", upgradeDependencyPhaseTimeout)
		}
	}
	depSummary := strings.Join(depNotes, "\n")
	if depSummary != "" {
		depSummary = "\n" + depSummary
	}

	// 依赖阶段可能因取消或整体预算结束：调用方/tracker 结束时不再进入自身更新。
	if err := taskCtx.Err(); err != nil {
		a.logger.Info("升级任务已取消，跳过自身更新", "job", job.ID, "error", err)
		a.sendUpgradeResult(job, -1, upgradeCancelledMessage+depSummary, err.Error())
		return
	}
	if errors.Is(workCtx.Err(), context.DeadlineExceeded) {
		a.logger.Warn("升级任务预算已用尽，跳过自身更新", "job", job.ID, "budget", budget)
		a.sendUpgradeResult(job, -1, fmt.Sprintf("升级任务超过预算（%s），未完成自身更新%s", budget, depSummary), "upgrade budget exhausted")
		return
	}

	if a.update == nil {
		a.sendUpgradeResult(job, -1, "当前运行环境不支持自更新（更新器未就绪）", "updater not ready")
		return
	}

	targetVer := strings.TrimSpace(job.Target)
	if targetVer == "" {
		targetVer = "latest"
	}
	if targetVer != "latest" && !updater.ValidReleaseTag(targetVer) {
		a.sendUpgradeResult(job, -1, fmt.Sprintf("目标版本号格式非法：%q", targetVer)+depSummary, "invalid target version")
		return
	}

	var (
		newVer    string
		hasUpdate bool
		checkErr  error
	)
	if targetVer == "latest" {
		newVer, hasUpdate, checkErr = a.update.Check(workCtx)
	} else {
		allowDowngrade := a.cfg != nil && a.cfg.AllowRemoteDowngrade
		noop, targetErr := evaluateRemoteTarget(Version, targetVer, allowDowngrade)
		if targetErr != nil {
			a.logger.Warn("拒绝远程升级目标", "job", job.ID, "target", targetVer, "error", targetErr)
			a.sendUpgradeResult(job, -1, targetErr.Error()+depSummary, targetErr.Error())
			return
		}
		if noop {
			msg := fmt.Sprintf("目标版本与当前版本相同（%s），无需更新。原有运行参数保持不变。%s", Version, depSummary)
			a.logger.Info("远程升级目标与当前版本相同，跳过", "Version", Version)
			a.sendUpgradeResult(job, 0, strings.TrimSpace(msg), "")
			return
		}
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
	installedVer, applyErr := a.update.DownloadAndReplace(workCtx, newVer)
	if applyErr != nil {
		switch {
		case taskCtx.Err() != nil && isCancellationError(applyErr):
			// 只有确实是取消导致的失败才改写成“已取消”；
			// 真实失败（校验不一致、替换失败等）即使同时收到取消也保留原始原因。
			a.logger.Info("升级已取消，未重启服务", "job", job.ID, "error", taskCtx.Err())
			a.sendUpgradeResult(job, -1, upgradeCancelledMessage+depSummary, taskCtx.Err().Error())
		case errors.Is(workCtx.Err(), context.DeadlineExceeded):
			errMsg := fmt.Sprintf("升级任务超过预算（%s）未完成：%v", budget, applyErr)
			a.logger.Warn(errMsg, "job", job.ID)
			a.sendUpgradeResult(job, -1, errMsg+depSummary, applyErr.Error())
		default:
			errMsg := fmt.Sprintf("下载或安装更新失败：%v", applyErr)
			a.logger.Warn(errMsg, "target", newVer, "error", applyErr)
			a.sendUpgradeResult(job, -1, errMsg+depSummary, applyErr.Error())
		}
		return
	}

	// 替换完成后、重启前再次检查取消：取消升级时不能重启服务。
	if err := taskCtx.Err(); err != nil {
		a.logger.Info("升级已取消，未重启服务", "job", job.ID, "error", err)
		a.sendUpgradeResult(job, -1, upgradeCancelledMessage+depSummary, err.Error())
		return
	}

	// 替换成功后，先向机器人回传成功结果
	successMsg := fmt.Sprintf("✅ 已成功下载并安装 %s（原版本 %s）！\n• 服务正在平滑重启\n• 所有启动参数已由系统服务完整保留%s",
		installedVer, Version, depSummary)
	a.logger.Info("已成功更新并回传结果，即将平滑重启服务", "new_version", installedVer)
	a.sendUpgradeResult(job, 0, strings.TrimSpace(successMsg), "")

	// 重启前通知在途轻任务取消，避免直接硬杀导致任务状态丢失。
	// 先注销自身，避免 CancelAll 把本轮升级的 context 也取消掉。
	if a.tracker != nil {
		a.tracker.Unregister(job.ID)
		a.tracker.CancelAll()
	}

	// 短暂休眠确保结果数据包送出网络缓冲区，随后触发重启。
	// 只受取消影响：预算在安装成功后耗尽也应重启让新版本生效。
	if !sleep(taskCtx, 500*time.Millisecond) {
		a.logger.Info("升级任务在重启前被取消，未重启服务", "job", job.ID)
		return
	}
	// Unregister 之后仍可能收到取消（Cancel 只记录标记）：重启前再确认一次。
	if a.tracker != nil && a.tracker.IsCancelled(job.ID) {
		a.logger.Info("升级任务在重启前被取消，未重启服务", "job", job.ID)
		return
	}
	if err := a.update.Restart(); err != nil {
		a.logger.Warn("服务重启失败", "error", err)
	}
}

func (a *Agent) sendUpgradeResult(job model.Job, exitCode int, output, errText string) {
	res := model.Result{
		ID:       job.ID,
		Kind:     job.NormalizedKind(),
		Output:   output,
		ExitCode: exitCode,
		Error:    errText,
	}
	a.dedupStore().complete(job.ID, &res)
	if err := a.sendResult(res); err != nil {
		a.logger.Warn("回传更新结果失败", "job", job.ID, "error", err)
	}
}

// dedupStore 返回任务去重记录，供主循环与 worker 共用（首次使用时初始化）。
