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

// TestInstallScriptSyntax 用 bash 解析脚本，避免发布带语法错误的版本。
func TestInstallScriptSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("未安装 bash，跳过语法检查")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, readInstallScript(t), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n 失败: %v\n%s", err, out)
	}
	out, err := exec.Command(bash, path, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("--help 执行失败: %v\n%s", err, out)
	}
	for _, want := range []string{"--bot", "--host", "--token", "--uninstall"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("--help 未列出 %s: %s", want, out)
		}
	}
}

// TestInstallScriptKeepsKeySafeguards 防止把踩过坑的修复改回去：
// 令牌目录权限、升级时重启、能力来源、安装后自检。
func TestInstallScriptKeepsKeySafeguards(t *testing.T) {
	script := string(readInstallScript(t))
	for _, want := range []struct{ name, needle string }{
		{"令牌目录按服务用户主组授权", `install -d -m 0750 -o root -g "$RUN_GROUP" "$TOKEN_DIR"`},
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
