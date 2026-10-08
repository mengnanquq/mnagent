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
// 在 set -u 下报 “VERSION…: unbound variable”）。一律写 ${VAR} 即可杜绝。
var riskyVarRef = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)([\x80-\xff])`)

func readInstallScript(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("读取 install.sh 失败: %v", err)
	}
	return content
}

// TestInstallScriptVariableBracing 校验脚本中被多字节字符紧跟的变量展开都带大括号。
func TestInstallScriptVariableBracing(t *testing.T) {
	script := readInstallScript(t)
	lines := bytes.Split(script, []byte("\n"))
	for idx, line := range lines {
		// 跳过纯注释行
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("#")) {
			continue
		}
		matches := riskyVarRef.FindAllSubmatchIndex(line, -1)
		for _, m := range matches {
			varName := string(line[m[2]:m[3]])
			nextBytes := string(line[m[4]:m[5]])
			t.Errorf("install.sh:%d: 变量引用 $%s 紧跟多字节字符 %q，必须写为 ${%s} 避免被 shell 吞进变量名: %s",
				idx+1, varName, nextBytes, varName, strings.TrimSpace(string(line)))
		}
	}
}

// TestInstallScriptTrClasses 校验脚本中 tr 不使用 [:lower:] / [:upper:] 字符类：
// 在嵌入式平台常用的某些 tr 实现（如 OpenWrt / BusyBox 精简版 tr）中，
// 字符类不被展开，导致将 'u' 替换成 'l'（Linux -> Linlx），引发下载 404。
func TestInstallScriptTrClasses(t *testing.T) {
	script := readInstallScript(t)
	lines := bytes.Split(script, []byte("\n"))
	for idx, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("#")) {
			continue
		}
		if bytes.Contains(line, []byte("[:lower:]")) || bytes.Contains(line, []byte("[:upper:]")) {
			t.Errorf("install.sh:%d: 禁止在 tr 中使用字符类 [:lower:] / [:upper:]，请改用 a-z / A-Z 保证移植性: %s",
				idx+1, strings.TrimSpace(string(line)))
		}
	}
}

// TestInstallScriptUsesSetU 保证脚本保持 set -u（nounset），杜绝未定义变量静默放行。
func TestInstallScriptUsesSetU(t *testing.T) {
	script := readInstallScript(t)
	if !bytes.Contains(script, []byte("set -u")) && !bytes.Contains(script, []byte("set -eu")) {
		t.Errorf("install.sh 应该开启 set -u（nounset）以在变量未定义时报错")
	}
}

// TestInstallScriptSyntax 用系统上的 bash 和 sh 解析脚本，避免发布带语法错误的版本。
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
	for _, want := range []string{"--bot", "--token", "--uninstall", "OpenWrt", "--miaospeed", "--miaospeed-version"} {
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
		{"procd 传递 miaospeed 参数", "-miaospeed $MIAOSPEED_EXEC"},
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
		{"自动更新可写目录", "ReadWritePaths=$PREFIX"},
		{"缺失时自动安装 nexttrace 官方地址", "https://nxtrace.org/nt"},
		{"OpenWrt 优先 opkg 安装 nexttrace", "opkg install nexttrace"},
		{"自动安装 miaospeed 来源", "AirportR/miaospeed"},
		{"自动安装 miaospeed 继承 gh-proxy", `apply_gh_proxy "$url"`},
		{"systemd 传递 miaospeed 参数", "-miaospeed $MIAOSPEED_EXEC"},
		{"GitHub 代理参数解析", "--gh-proxy"},
		{"GitHub 代理函数定义", "apply_gh_proxy"},
		{"服务参数继承代理", `AUTO_UPDATE_ARGS="$AUTO_UPDATE_ARGS -gh-proxy $GH_PROXY"`},
		{"下载文件时显示进度条", "curl -#"},
		{"systemd 默认以 root 运行", `[ -n "$RUN_USER" ] || RUN_USER="root"`},
	} {
		if !strings.Contains(script, want.needle) {
			t.Errorf("install.sh 缺少 %s（应包含 %q）", want.name, want.needle)
		}
	}
}

// TestWindowsInstallScript 校验 Windows 一键安装脚本 install.ps1 的完整性与关键安全逻辑。
func TestWindowsInstallScript(t *testing.T) {
	content, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("读取 install.ps1 失败: %v", err)
	}
	script := string(content)

	checks := []struct {
		name   string
		needle string
	}{
		{"管理员权限检查", "WindowsBuiltInRole]::Administrator"},
		{"UAC 自动提权", "Start-Process powershell.exe -Verb RunAs"},
		{"服务安装与命令", "sc.exe create mnagent"},
		{"服务崩溃自动重启策略", "sc.exe failure mnagent"},
		{"服务启动", "sc.exe start mnagent"},
		{"卸载参数支持", "sc.exe delete mnagent"},
		{"安全通信协议设定", "SecurityProtocolType]::Tls12"},
		{"架构检测 ARM64 与 x64", `PROCESSOR_ARCHITECTURE -eq "ARM64"`},
		{"下载路径代理支持", "Get-ProxiedUrl"},
		{"NextTrace 安装", "nexttrace_windows_"},
		{"MiaoSpeed zip 提取", "Expand-Archive"},
		{"参数定义 -Bot", "[string]$Bot"},
		{"参数定义 -Token", "[string]$Token"},
		{"参数定义 -TokenFile", "[string]$TokenFile"},
		{"参数定义 -Uninstall", "[switch]$Uninstall"},
	}

	for _, c := range checks {
		if !strings.Contains(script, c.needle) {
			t.Errorf("install.ps1 缺少关键逻辑 [%s]，应包含 %q", c.name, c.needle)
		}
	}
}
