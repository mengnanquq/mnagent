package runner

import (
	"context"
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

// handleUpgradeJob 处理来自机器人的远程更新指令。
func (a *Agent) handleUpgradeJob(ctx context.Context, job model.Job) {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	a.logger.Info("收到远程更新指令，开始处理", "job", job.ID, "current_version", Version, "target", job.Target)

	var depNotes []string
	if a.cfg != nil {
		if dm := a.newDependencyManager(); dm != nil {
			statuses := dm.CheckAll(ctx, a.cfg.Binary, a.cfg.MiaospeedBinary)
			for _, st := range statuses {
				if !st.Installed {
					version := st.LatestVersion
					if version == "" {
						version = "latest"
					}
					if _, err := dm.EnsureDependency(ctx, st.Name, dependencyTargetPath(a.cfg, st.Name), version, a.logger); err != nil {
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
					if _, err := dm.EnsureDependency(ctx, st.Name, st.BinaryPath, st.LatestVersion, a.logger); err != nil {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 更新至 %s 失败：%v", st.Name, st.LatestVersion, err))
					} else {
						depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已成功更新至 %s", st.Name, st.LatestVersion))
					}
				} else {
					depNotes = append(depNotes, fmt.Sprintf("• 依赖 %s 已是最新版（%s）", st.Name, st.CurrentVersion))
				}
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
		newVer, hasUpdate, checkErr = a.update.Check(ctx)
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
	installedVer, applyErr := a.update.DownloadAndReplace(ctx, newVer)
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
