package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// riskyVarRef 匹配“$VAR 紧跟非 ASCII 字节”的写法。
// 这种写法依赖 shell 的变量名解析：在部分 bash 版本/locale 下，紧跟的多字节字符
// 会被当作变量名的一部分（实测出现过 `$VERSION，` 被解析成 `VERSION<字节>`，
// 在 set -u 下报 “VERSION…: unbound variable”）。一律写 ${VAR} 即可避免。
var riskyVarRef = regexp.MustCompile(`\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]`)

// readInstallScript 读取一键安装脚本。
func readInstallScript(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("读取 install.sh 失败: %v", err)
	}
	return data
}

// TestInstallScriptHasNoRiskyVarRefs 守护“变量引用后紧跟非 ASCII 字符”这一坑：
// 它在某些 bash 版本上会把多字节字符吃进变量名，导致 set -u 下直接报错退出。
func TestInstallScriptHasNoRiskyVarRefs(t *testing.T) {
	data := readInstallScript(t)
	for i, line := range bytes.Split(data, []byte("\n")) {
		if loc := riskyVarRef.Find(line); loc != nil {
			t.Errorf("第 %d 行存在风险写法 %q，请改为 ${VAR}：%s", i+1, loc, strings.TrimSpace(string(line)))
		}
	}
}

// TestInstallScriptIsPosixSh 验证脚本能在 OpenWrt 的 busybox ash 下运行：
// shebang 必须是 /bin/sh，且不能出现 bash 专有语法。
func TestInstallScriptIsPosixSh(t *testing.T) {
	script := string(readInstallScript(t))
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatalf("脚本应使用 #!/bin/sh（OpenWrt 只有 busybox ash）：%q", strings.SplitN(script, "\n", 2)[0])
	}
	// 只匹配真正会引发解析错误的写法，避免注释或字符串里的词（如 --from-source）误报。
	bashisms := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"[[]] 条件表达式", regexp.MustCompile(`\[\[`)},
		{"[[ ]] 条件表达式", regexp.MustCompile(`\]\]`)},
		{"算术命令 (( ))", regexp.MustCompile(`(^|[^$])\(\(`)},
		{"function 关键字", regexp.MustCompile(`(^|[;&|]\s*)function\s`)},
		{"declare", regexp.MustCompile(`(^|[;&|]\s*)declare\s`)},
		{"source 命令", regexp.MustCompile(`(^|[;&|]\s*)source\s`)},
		{"&> 重定向", regexp.MustCompile(`&>`)},
		{"=~ 匹配符", regexp.MustCompile(`=~`)},
		{"${!var} 间接引用", regexp.MustCompile(`\$\{!`)},
		{"${var//} 替换", regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*//`)},
	}
	for i, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		// 去掉行尾注释再检查，避免注释文本（如“# auto | release | source”）误报。
		code := line
		if idx := strings.Index(code, " #"); idx >= 0 {
			code = code[:idx]
		}
		for _, bad := range bashisms {
			if bad.re.MatchString(code) {
				t.Errorf("第 %d 行含 bash 专有写法（%s，busybox ash 可能不支持）：%s", i+1, bad.name, trimmed)
			}
		}
	}
	// pipefail 必须容错启用（ash 不一定支持）。
	if !strings.Contains(script, "(set -o pipefail) 2>/dev/null") {
		t.Error("pipefail 应容错启用，否则 ash 下 set -euo pipefail 会直接报错")
	}
}

// TestInstallScriptSyntax 用 bash 解析脚本，避免发布带语法错误的版本。
func TestInstallScriptSyntax(t *testing.T) {
	script := readInstallScript(t)
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, script, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, shell := range []string{"bash", "sh"} {
		bin, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		// 显式关掉 pipefail 容错分支以外的差异：只做语法解析（-n）。
		if out, err := exec.Command(bin, "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("%s -n 失败: %v\n%s", shell, err, out)
		}
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("未安装 bash，跳过 --help 冒烟")
	}
	out, err := exec.Command(bash, path, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("--help 执行失败: %v\n%s", err, out)
	}
	for _, want := range []string{"--bot", "--host", "--token", "--uninstall", "OpenWrt"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("--help 未提及 %s: %s", want, out)
		}
	}
}

// TestInstallScriptSupportsOpenWrt 覆盖 OpenWrt 相关的关键实现：
// procd 服务、BusyBox 回退、平台/init 目录开关、MIPS 字节序识别、sysupgrade 处理。
func TestInstallScriptSupportsOpenWrt(t *testing.T) {
	script := string(readInstallScript(t))
	for _, want := range []struct{ name, needle string }{
		{"procd 服务标记", "USE_PROCD=1"},
		{"procd 实例定义", "procd_open_instance"},
		{"procd 命令行参数", "procd_set_param command"},
		{"procd 崩溃自动重启", "procd_set_param respawn"},
		{"procd 日志进 syslog", "procd_set_param stdout 1"},
		{"rc.common shebang", "#!/bin/sh /etc/rc.common"},
		{"OpenWrt 平台探测", "/etc/openwrt_release"},
		{"平台可覆盖", "MNAGENT_PLATFORM"},
		{"init 目录可覆盖", "MNAGENT_INIT_DIR"},
		{"无 curl 时回退 uclient-fetch", "uclient-fetch"},
		{"无 install 时回退 cp", "cp -f \"$1\" \"$2\""},
		{"BusyBox adduser 回退", "adduser -S -D -H"},
		{"MIPS 字节序识别", "elf_ei_data"},
		{"sysupgrade 保留二进制", "/etc/sysupgrade.conf"},
		{"卸载同时处理 procd", "\"$INIT_DIR/$SERVICE_NAME\" disable"},
		{"非 root 自我提权", "sudo sh"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Errorf("install.sh 缺少“%s”（应包含 %q）", want.name, want.needle)
		}
	}
}

// TestInstallScriptKeepsKeySafeguards 防止把踩过坑的修复改回去：
// 令牌目录权限、升级时重启、能力来源、安装后自检。
func TestInstallScriptKeepsKeySafeguards(t *testing.T) {
	script := string(readInstallScript(t))
	for _, want := range []struct{ name, needle string }{
		{"令牌目录按服务用户主组授权", `make_dir "$TOKEN_DIR" 0750 root "$RUN_GROUP"`},
		{"服务用户主组取自 id -gn", `RUN_GROUP="$(id -gn "$RUN_USER"`},
		{"默认令牌目录权限修正", `[ "$TOKEN_DIR" = "/etc/mnagent" ]`},
		{"安装后校验服务用户可读令牌", "runuser -u"},
		{"升级时真正重启服务", `systemctl restart "$SERVICE_NAME"`},
		{"原始套接字能力由服务携带", "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN"},
		{"为 nexttrace 准备可写主目录", "StateDirectory=mnagent"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Errorf("install.sh 缺少“%s”（应包含 %q）", want.name, want.needle)
		}
	}
}
