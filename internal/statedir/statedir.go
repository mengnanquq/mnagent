// Package statedir 提供 mnagent 的私有状态目录（跳过版本记录、降级安装的依赖等）。
// 这些文件会影响 agent 的更新与执行行为，绝不能放在 /tmp 这类所有本地用户都可写的目录。
package statedir

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// warnWriter 是状态目录告警的输出目标，默认为 stderr；测试可替换以断言告警内容。
var warnWriter io.Writer = os.Stderr

// warnf 输出一条带 WARN 前缀的告警。状态目录被拒绝时仍会退回下一个候选目录，
// 但用户需要知道发生了什么以及如何修复，否则会困惑于「跳过版本记录失效」。
func warnf(format string, args ...any) {
	if warnWriter == nil {
		return
	}
	fmt.Fprintf(warnWriter, "WARN [statedir] "+format+"\n", args...)
}

// candidates 返回按优先级排列的候选目录：系统级目录优先，非特权运行时退回当前用户的缓存目录。
func candidates() []string {
	var dirs []string
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			dirs = append(dirs, filepath.Join(pd, "mnagent"))
		}
	} else {
		dirs = append(dirs, "/var/lib/mnagent")
	}
	if cache, err := os.UserCacheDir(); err == nil && cache != "" {
		dirs = append(dirs, filepath.Join(cache, "mnagent"))
	}
	return dirs
}

// Dir 返回可用的私有状态目录（不存在则以 0700 创建）。
func Dir() (string, error) {
	var lastErr error
	for _, d := range candidates() {
		if err := ensurePrivate(d); err != nil {
			lastErr = err
			continue
		}
		return d, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的状态目录")
	}
	return "", lastErr
}

// Path 返回状态目录下的文件路径；状态目录不可用时返回空串。
func Path(elem ...string) string {
	d, err := Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{d}, elem...)...)
}

// ensurePrivate 确保目录存在、不是符号链接，且（非 Windows 下）不允许属组或其他用户写入。
func ensurePrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s 不是普通目录", dir)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s 允许其他用户写入，拒绝使用", dir)
	}
	if err := checkDirOwner(dir, fi); err != nil {
		// 属主异常通常来自手工拷贝/迁移目录：直接给出可执行的修复命令，
		// 同时仍然拒绝使用该目录（退回下一个候选目录）。
		if runtime.GOOS == "windows" {
			warnf("状态目录属主校验失败：%v", err)
		} else {
			warnf("状态目录属主校验失败：%v；修复后可执行 chown root:root %q 并重启服务", err, dir)
		}
		return err
	}
	// MkdirAll 不会修改已存在目录的权限；旧版本或手工创建可能留下 0755。
	// 仅在属主是当前用户且权限更宽时收紧，失败只告警，不阻止使用。
	tightenDirPerm(dir, fi)
	// 确认当前进程确实能在其中写文件
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// tightenDirPerm 把已存在且属主为当前用户的状态目录权限收紧到 0700。
// 非当前用户拥有的目录不做修改（checkDirOwner 允许 root 拥有，但当前进程无权重置）。
// 失败只告警，不中断状态目录的使用。
func tightenDirPerm(dir string, fi os.FileInfo) {
	if runtime.GOOS == "windows" {
		return
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return
	}
	if !isCurrentUserOwner(fi) {
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		warnf("状态目录权限过宽且无法收紧到 0700，请手动执行 chmod 0700 %q：%v", dir, err)
	}
}
