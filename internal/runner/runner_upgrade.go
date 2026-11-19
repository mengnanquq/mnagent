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
		newVer, hasUpdate, checkErr = a.update.Check()
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
	res := model.Result{
		ID:       job.ID,
		Kind:     job.Kind,
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
