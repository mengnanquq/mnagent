package miaospeed

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/mengnanquq/mnagent/internal/dep"
)

var (
	cachedMiaospeedVerMu sync.RWMutex
	cachedMiaospeedVer   = make(map[string]string)
)

func getMiaospeedVersion(ctx context.Context, binPath string, serverOutput string) string {
	// 1. 如果 server 启动日志中已包含版本号（如 "version: 4.7.7"），直接提取
	if serverOutput != "" {
		cleaned := dep.StripANSI(serverOutput)
		if m := dep.MiaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
			ver := m[1]
			if !strings.HasPrefix(strings.ToLower(ver), "v") {
				ver = "v" + ver
			}
			cachedMiaospeedVerMu.Lock()
			cachedMiaospeedVer[binPath] = ver
			cachedMiaospeedVerMu.Unlock()
			return ver
		}
	}

	// 2. 检查内存缓存
	cachedMiaospeedVerMu.RLock()
	ver, ok := cachedMiaospeedVer[binPath]
	cachedMiaospeedVerMu.RUnlock()
	if ok && ver != "" {
		return ver
	}

	// 3. 尝试调用 -version 或 version
	detCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(detCtx, binPath, "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd2 := exec.CommandContext(detCtx, binPath, "version")
		if out2, err2 := cmd2.CombinedOutput(); err2 == nil {
			out = out2
			err = nil
		}
	}
	cleaned := dep.StripANSI(string(out))
	if m := dep.MiaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
	} else if m := dep.GenericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
	}
	if ver != "" {
		if !strings.HasPrefix(strings.ToLower(ver), "v") {
			ver = "v" + ver
		}
		cachedMiaospeedVerMu.Lock()
		cachedMiaospeedVer[binPath] = ver
		cachedMiaospeedVerMu.Unlock()
		return ver
	}
	return ""
}

// autoInstallMiaospeed 在运行时自动下载并解压 AirportR/miaospeed Release，严格继承使用 ghProxy。
func autoInstallMiaospeed(ctx context.Context, targetPath, ghProxy string, log Logger) (string, error) {
	dm := dep.NewDependencyManager(ghProxy)
	return dm.UpdateMiaospeed(ctx, targetPath, "latest", log)
}
