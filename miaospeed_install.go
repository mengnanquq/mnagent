package main

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	cachedMiaospeedVerMu sync.RWMutex
	cachedMiaospeedVer   = make(map[string]string)
)

func getMiaospeedVersion(ctx context.Context, binPath string, serverOutput string) string {
	// 1. 如果 server 启动日志中已包含版本号（如 "version: 4.7.7"），直接提取
	if serverOutput != "" {
		cleaned := stripANSI(serverOutput)
		if m := miaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
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
	cleaned := stripANSI(string(out))
	if m := miaospeedVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
		ver = m[1]
	} else if m := genericVerPattern.FindStringSubmatch(cleaned); len(m) >= 2 {
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
func autoInstallMiaospeed(ctx context.Context, targetPath, ghProxy string, log logger) (string, error) {
	dm := newDependencyManager(ghProxy)
	return dm.UpdateMiaospeed(ctx, targetPath, "latest", log)
}

func mapMiaospeedArch(arch string) string {
	switch arch {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "arm":
		return "armv7"
	case "386":
		return "386"
	case "mips":
		return "mips-softfloat"
	case "mipsle":
		return "mipsle-softfloat"
	case "riscv64":
		return "riscv64"
	default:
		return arch
	}
}

func applyGHProxy(rawURL, ghProxy string) string {
	ghProxy = strings.TrimSpace(ghProxy)
	if ghProxy == "" {
		return rawURL
	}
	prefix := strings.TrimRight(ghProxy, "/") + "/"
	if strings.HasPrefix(rawURL, prefix) {
		return rawURL
	}
	return prefix + rawURL
}
