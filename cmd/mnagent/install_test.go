package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// riskyVarRef 匹配“$VAR 紧跟非 ASCII 字节”的写法。
// 这种写法依赖 shell 的变量名解析：在部分 bash 版本/locale 下，紧跟的多字节字符
// 会被当作变量名的一部分（实测出现过 `$VERSION，` 被解析成 `VERSION<字节>`，
// 在 set -u 下报 “VERSION…: unbound variable”）。一律写 ${VAR} 即可杜绝。
var riskyVarRef = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)([\x80-\xff])`)

func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

func readInstallScript(t *testing.T) []byte {
	t.Helper()
	root := findRepoRoot()
	content, err := os.ReadFile(filepath.Join(root, "install.sh"))
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
	for _, want := range []string{"--bot", "--token", "--token-file", "--token-stdin", "--uninstall", "OpenWrt", "--miaospeed", "--miaospeed-version", "--sha256", "--from-source"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("--help 未提及 %s: %s", want, out)
		}
	}
}

// installEnv 把 PATH 前置 fakeBin，并去重覆盖同名变量，避免继承宿主环境里的
// MNAGENT_PLATFORM / MNAGENT_TOKEN 等把测试导向真实安装或真实 /etc。
func installEnv(fakeBin, initDir, defaultToken string, extra ...string) []string {
	overrides := map[string]string{
		"PATH":               fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"MNAGENT_PLATFORM":   "systemd",
		"MNAGENT_INIT_DIR":   initDir,
		"MNAGENT_TOKEN_FILE": defaultToken,
		"MNAGENT_TOKEN":      "",
		"MNAGENT_GH_PROXY":   "",
		"GH_PROXY":           "",
		"MNAGENT_REPO":       "",
		// 避免测试在平台为 none/openwrt 时碰真实的 /var/lib/mnagent。
		"MNAGENT_STATE_DIR": filepath.Join(filepath.Dir(initDir), "state"),
	}
	for _, kv := range extra {
		if k, v, ok := strings.Cut(kv, "="); ok {
			overrides[k] = v
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if _, replaced := overrides[k]; replaced {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

// runInstallScript 以 root 身份执行安装脚本。CI 通常以 root 运行；本地非 root 时
// 借 user namespace（unshare -r）模拟 root，脚本只会写临时目录，不会碰真实 /etc。
func runInstallScript(t *testing.T, scriptPath string, args, env []string, stdin string) (string, error) {
	t.Helper()
	return runInstallScriptTimeout(t, scriptPath, args, env, stdin, 90*time.Second)
}

// runInstallScriptTimeout 与 runInstallScript 相同，但带硬超时：参数解析写错导致
// 无限循环时测试会失败而不是挂住 CI（实测 `--install-miaospeed auto` 曾死循环）。
func runInstallScriptTimeout(t *testing.T, scriptPath string, args, env []string, stdin string, timeout time.Duration) (string, error) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("未找到 sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.CommandContext(ctx, sh, append([]string{scriptPath}, args...)...)
	} else {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("非 root 且未安装 unshare，跳过可执行安装脚本测试")
		}
		if err := exec.Command(unshare, "-r", "--", "true").Run(); err != nil {
			t.Skipf("非 root 且 unshare -r 不可用（%v），跳过可执行安装脚本测试", err)
		}
		cmd = exec.CommandContext(ctx, unshare, append([]string{"-r", "--", sh, scriptPath}, args...)...)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("安装脚本执行超时（%s），疑似参数解析死循环", timeout)
	}
	return string(out), err
}

// TestInstallScriptTokenStdinOnUpgrade 覆盖升级场景：旧 unit 里已有 -token-file 时，
// `--token-file -` 仍必须从 stdin 读取令牌并覆盖写入，不能被继承逻辑静默吞掉。
func TestInstallScriptTokenStdinOnUpgrade(t *testing.T) {
	root := findRepoRoot()
	scriptPath := filepath.Join(root, "install.sh")
	tmp := t.TempDir()
	initDir := filepath.Join(tmp, "systemd")
	fakeBin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(initDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}

	// 假 systemctl：脚本会调用 daemon-reload / enable / restart / is-active。
	fakeSystemctl := filepath.Join(fakeBin, "systemctl")
	if err := os.WriteFile(fakeSystemctl, []byte("#!/bin/sh\ncase \"$1\" in is-active) echo active;; esac\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeAgent := filepath.Join(tmp, "mnagent-fake")
	if err := os.WriteFile(fakeAgent, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	tokenFile := filepath.Join(tmp, "token")
	if err := os.WriteFile(tokenFile, []byte("old-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(initDir, "mnagent.service")
	unit := "[Service]\nExecStart=\"" + fakeAgent + "\" -bot \"https://bot.example/agent\" -token-file \"" + tokenFile + "\"\n"
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}

	baseArgs := []string{
		"--bot", "https://bot.example/agent",
		"--binary", fakeAgent,
		"--prefix", filepath.Join(tmp, "install"),
		"--no-install-nexttrace", "--no-install-miaospeed",
	}

	// 1) --token-file -：升级时也必须读取 stdin 并写入继承到的令牌文件。
	env := installEnv(fakeBin, initDir, filepath.Join(tmp, "default-token"))
	out, err := runInstallScript(t, scriptPath, append(baseArgs, "--token-file", "-"), env, "stdin-token\n")
	if err != nil {
		t.Fatalf("以 --token-file - 安装失败: %v\n%s", err, out)
	}
	got, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "stdin-token" {
		t.Fatalf("升级时 stdin 令牌被忽略，令牌文件内容 = %q（期望 stdin-token）\n输出：\n%s", strings.TrimSpace(string(got)), out)
	}

	// 2) MNAGENT_TOKEN：升级路径下也必须覆盖旧令牌文件。
	//    显式给一个不存在的 --token-file，让继承逻辑照常从旧 unit 取路径。
	env = installEnv(fakeBin, initDir, filepath.Join(tmp, "default-token"), "MNAGENT_TOKEN=env-token")
	out, err = runInstallScript(t, scriptPath, append(baseArgs, "--token-file", filepath.Join(tmp, "absent-token")), env, "")
	if err != nil {
		t.Fatalf("以 MNAGENT_TOKEN 升级失败: %v\n%s", err, out)
	}
	got, err = os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "env-token" {
		t.Fatalf("升级时 MNAGENT_TOKEN 被忽略，令牌文件内容 = %q（期望 env-token）", strings.TrimSpace(string(got)))
	}
}

// TestInstallScriptNormalizesTokenStdinBeforeInherit 静态守护：'-' 归一化必须出现在
// 继承旧 unit 之前，否则升级路径会再次吞掉 stdin 令牌。
func TestInstallScriptNormalizesTokenStdinBeforeInherit(t *testing.T) {
	script := string(readInstallScript(t))
	normalize := strings.Index(script, `if [ "$TOKEN_FILE" = "-" ]`)
	inherit := strings.Index(script, `if [ -n "$existing_cmd" ]`)
	if normalize < 0 || inherit < 0 {
		t.Fatalf("未找到归一化（%d）或继承逻辑（%d）", normalize, inherit)
	}
	if normalize > inherit {
		t.Fatal("--token-file - 的归一化必须放在继承旧 unit 之前，否则升级时会用旧路径覆盖 '-'")
	}
}

// TestInstallScriptNonRootHintKeepsToken 守护非 root 提示：令牌来自 MNAGENT_TOKEN 时，
// 提示的 sudo 命令必须保留该环境变量（sudo 默认会清空），且不能打印令牌明文。
func TestInstallScriptNonRootHintKeepsToken(t *testing.T) {
	script := string(readInstallScript(t))
	if !containsActiveLine(script, `sudo --preserve-env=MNAGENT_TOKEN sh "$0"`) {
		t.Error("本机脚本提权时应使用 sudo --preserve-env=MNAGENT_TOKEN 保留环境变量")
	}
	if !containsActiveLine(script, `sudo env MNAGENT_TOKEN="$MNAGENT_TOKEN" sh "$0"`) {
		t.Error("应提供 sudo env MNAGENT_TOKEN=... 的回退提权方式")
	}
	if !containsActiveLine(script, `sudo env MNAGENT_TOKEN=\"\$MNAGENT_TOKEN\" sh -s --`) {
		t.Error("非 root 提示应给出保留 MNAGENT_TOKEN 的 sudo 命令，并用 $MNAGENT_TOKEN 占位而不是令牌明文")
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "die ") && strings.Contains(line, "MNAGENT_TOKEN") && strings.Contains(line, "$MNAGENT_TOKEN\"") && !strings.Contains(line, `\$MNAGENT_TOKEN`) {
			t.Fatalf("提示中不要展开令牌明文，应使用 $MNAGENT_TOKEN 占位: %s", line)
		}
	}
}

// TestInstallScriptStdinTokenHidesEcho 守护交互式读取令牌时关闭回显，并用 trap 恢复。
func TestInstallScriptStdinTokenHidesEcho(t *testing.T) {
	script := string(readInstallScript(t))
	for _, want := range []string{
		"stty -g",
		"stty -echo",
		`trap 'stty "$STTY_SAVED" 2>/dev/null || true' 0 1 2 15`,
		`trap - 0 1 2 15`,
	} {
		if !containsActiveLine(script, want) {
			t.Errorf("install.sh 缺少安全读取 stdin 令牌所需的 %q", want)
		}
	}
}

// TestURLCheckCharsetConsistent 守护 install.sh 与 install.ps1 的 URL 允许字符集一致：
// 两边都必须拒绝空白/引号/反斜杠/%/$/反引号，同时允许同一组 URL 安全字符（含括号）。
func TestURLCheckCharsetConsistent(t *testing.T) {
	shellScript := string(readInstallScript(t))
	psContent, err := os.ReadFile(filepath.Join(findRepoRoot(), "install.ps1"))
	if err != nil {
		t.Fatalf("读取 install.ps1 失败: %v", err)
	}
	psScript := string(psContent)

	if !containsActiveLine(shellScript, `tr -d 'A-Za-z0-9._~:/?#@!&()*+,;=[]-'`) {
		t.Error("install.sh 的 URL 允许字符集未包含括号，与 install.ps1 不一致")
	}
	if !containsActiveLine(psScript, `^[A-Za-z0-9._~:/?#\[\]@!&()*+,;=-]+$`) {
		t.Error("install.ps1 的 URL 允许字符集应包含括号")
	}
}

// TestInstallScriptQuotesFallbackHint 守护无 init 系统的兜底提示：路径与地址必须带引号，
// 否则含空格的自定义 --prefix/令牌路径复制出来就是错的命令。
func TestInstallScriptQuotesFallbackHint(t *testing.T) {
	script := string(readInstallScript(t))
	if !containsActiveLine(script, `"%s/mnagent" -bot "%s" -token-file "%s" -nexttrace "%s"`) {
		t.Error("无 systemd/procd 时的运行提示应为参数加字面引号")
	}
}

// TestInstallScriptAcceptsParenthesesInURL 验证 sh 版 URL 校验与 ps1 一致地允许括号。
func TestInstallScriptAcceptsParenthesesInURL(t *testing.T) {
	tmp := t.TempDir()
	fakeBin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeAgent := filepath.Join(tmp, "mnagent-fake")
	if err := os.WriteFile(fakeAgent, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := installEnv(fakeBin, filepath.Join(tmp, "init"), filepath.Join(tmp, "token"),
		"MNAGENT_PLATFORM=none", "MNAGENT_TOKEN=paren-token")
	out, err := runInstallScript(t, filepath.Join(findRepoRoot(), "install.sh"), []string{
		"--bot", "https://bot.example/agent(group)",
		"--binary", fakeAgent,
		"--prefix", filepath.Join(tmp, "install"),
		"--no-install-nexttrace", "--no-install-miaospeed",
	}, env, "")
	if err != nil {
		t.Fatalf("URL 中的括号应与 install.ps1 一样被接受: %v\n%s", err, out)
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
		{"procd 传递 miaospeed 参数", `-miaospeed "$MIAOSPEED_EXEC"`},
		{"procd 环境注入 PATH 补齐 /usr/local/bin", `procd_set_param env PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"`},
		{"procd 崩溃自动重启", "procd_set_param respawn"},
		{"procd 停止超时大于退出预算", "procd_set_param term_timeout 70"},
		{"procd 日志进 syslog", "procd_set_param stdout 1"},
		{"rc.common shebang", "#!/bin/sh /etc/rc.common"},
		{"OpenWrt 平台探测", "/etc/openwrt_release"},
		{"平台可覆盖", "MNAGENT_PLATFORM"},
		{"init 目录可覆盖", "MNAGENT_INIT_DIR"},
		{"无 curl 时回退 uclient-fetch", "uclient-fetch"},
		{"无 install 时回退 cp", "cp -f \"$1\" \"$2\""},
		{"BusyBox adduser 回退", "adduser -S -D -H"},
		{"MIPS 字节序识别", "elf_ei_data"},
		{"OpenWrt 自动建立 nexttrace 软链接", `ln -sf "$NEXTTRACE_PATH" "$PREFIX/nexttrace"`},
		{"OpenWrt 自动建立 miaospeed 软链接", `ln -sf "$MIAOSPEED_PATH" "$PREFIX/miaospeed"`},
		{"sysupgrade 保留二进制", "/etc/sysupgrade.conf"},
		{"卸载同时处理 procd", "\"$INIT_DIR/$SERVICE_NAME\" disable"},
		{"非 root 自我提权", "sudo sh"},
	} {
		if !strings.Contains(script, want.needle) {
			t.Errorf("install.sh 缺少“%s”（应包含 %q）", want.name, want.needle)
		}
	}
}

// TestServiceUnitStopTimeout 验证 systemd 单元与 procd 的停止超时都大于 agent 的 60s
// 退出预算（config.DefaultExitResultTimeout），避免在途结果回传途中被强杀。
func TestServiceUnitStopTimeout(t *testing.T) {
	script := string(readInstallScript(t))
	if !strings.Contains(script, "TimeoutStopSec=80") {
		t.Error("install.sh 生成的 systemd 单元缺少 TimeoutStopSec=80")
	}
	tpl, err := os.ReadFile(filepath.Join(findRepoRoot(), "deploy", "mnagent.service"))
	if err != nil {
		t.Fatalf("读取 deploy/mnagent.service 失败：%v", err)
	}
	if !strings.Contains(string(tpl), "TimeoutStopSec=80") {
		t.Error("deploy/mnagent.service 缺少 TimeoutStopSec=80")
	}
	if !strings.Contains(string(tpl), "StateDirectoryMode=0700") {
		t.Error("deploy/mnagent.service 缺少 StateDirectoryMode=0700")
	}
}

// TestServiceUnitHardeningOptions 验证 deploy/mnagent.service 与 install.sh 内联生成的
// systemd 单元都包含保守加固选项，避免模板与安装脚本漂移。
func TestServiceUnitHardeningOptions(t *testing.T) {
	options := []string{
		"ProtectKernelModules=true",
		"ProtectKernelLogs=true",
		"ProtectClock=true",
		"ProtectHostname=true",
		"RestrictNamespaces=true",
		"RestrictRealtime=true",
		"PrivateDevices=true",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET",
	}
	tpl, err := os.ReadFile(filepath.Join(findRepoRoot(), "deploy", "mnagent.service"))
	if err != nil {
		t.Fatalf("读取 deploy/mnagent.service 失败：%v", err)
	}
	script := string(readInstallScript(t))
	for _, opt := range options {
		if !strings.Contains(string(tpl), opt) {
			t.Errorf("deploy/mnagent.service 缺少加固选项 %q", opt)
		}
		if !containsActiveLine(script, opt) {
			t.Errorf("install.sh 生成的 systemd 单元缺少加固选项 %q", opt)
		}
	}
	// SystemCallArchitectures=native 会拒绝 32 位用户态二进制在 64 位内核上的全部系统调用
	// （如树莓派 32 位系统），因此模板与安装脚本都只保留解释性注释，不得真正启用。
	if containsActiveLine(string(tpl), "SystemCallArchitectures=") {
		t.Error("deploy/mnagent.service 不应启用 SystemCallArchitectures")
	}
	if containsActiveLine(script, "SystemCallArchitectures=") {
		t.Error("install.sh 生成的 systemd 单元不应启用 SystemCallArchitectures")
	}
}

// containsActiveLine 判断脚本的非注释行中是否包含 needle。
// 守护断言必须跳过注释，否则把关键调用注释掉、注释文本仍含同一字符串时测试会假通过。
func containsActiveLine(script, needle string) bool {
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

// TestInstallScriptBinaryURLRequiresChecksum 验证 --binary <URL> 拿不到同名 .sha256 时
// 默认中止安装，只有显式 --insecure-skip-verify 才允许继续。
func TestInstallScriptBinaryURLRequiresChecksum(t *testing.T) {
	f := newFakeInstall(t, map[string]string{
		"nexttrace": "#!/bin/sh\nexit 0\n",
		"miaospeed": "#!/bin/sh\nexit 0\n",
	})
	body := "#!/bin/sh\necho 'mnagent v0.0.0'\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mnagent":
			_, _ = w.Write([]byte(body))
		case "/mnagent.sha256":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	scriptPath := filepath.Join(findRepoRoot(), "install.sh")
	args := []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", srv.URL + "/mnagent",
		"--prefix", filepath.Join(f.tmp, "install"),
		"--no-install-nexttrace", "--no-install-miaospeed",
	}
	out, err := runInstallScript(t, scriptPath, args, f.env(), "")
	if err == nil || !strings.Contains(out, "无法获取") || !strings.Contains(out, "--insecure-skip-verify") {
		t.Fatalf("拿不到 .sha256 时应默认中止并提示显式选项，err=%v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(f.tmp, "install", "mnagent")); statErr == nil {
		t.Fatal("默认中止时不应安装二进制")
	}

	out, err = runInstallScript(t, scriptPath, append(args, "--insecure-skip-verify"), f.env(), "")
	if err != nil {
		t.Fatalf("显式 --insecure-skip-verify 时应允许继续安装: %v\n%s", err, out)
	}
	if !strings.Contains(out, "insecure-skip-verify") {
		t.Fatalf("跳过校验时应打印醒目警告，实际输出:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(f.tmp, "install", "mnagent")); statErr != nil {
		t.Fatalf("显式跳过校验后应安装成功: %v", statErr)
	}
}

// TestInstallScriptBinaryLocalWithoutChecksumWarns 验证 --binary 指向本地文件且
// 未提供 --sha256 时只打印一次警告，不中止安装。
func TestInstallScriptBinaryLocalWithoutChecksumWarns(t *testing.T) {
	f := newFakeInstall(t, nil)
	scriptPath := filepath.Join(findRepoRoot(), "install.sh")
	out, err := runInstallScript(t, scriptPath, f.args(), f.env(), "")
	if err != nil {
		t.Fatalf("本地 --binary 无 --sha256 应继续安装: %v\n%s", err, out)
	}
	const warning = "--binary 指向本地文件但未提供 --sha256"
	if got := strings.Count(out, warning); got != 1 {
		t.Fatalf("本地 --binary 无 --sha256 应恰好警告一次，实际 %d 次：\n%s", got, out)
	}
	if _, statErr := os.Stat(filepath.Join(f.tmp, "install", "mnagent")); statErr != nil {
		t.Fatalf("警告不应阻止安装: %v", statErr)
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
		{"下载后强制校验 SHA-256", `verify_sha256 "$PREFIX/.mnagent.new"`},
		{"校验文件为同名 .sha256", `verify_sha256 "$PREFIX/.mnagent.new" "$raw_url" "$asset"`},
		{"使用代理时直连获取校验文件", `download_trusted_artifact "${verify_raw_url}.sha256"`},
		{"显式允许经代理获取校验文件", "--insecure-proxy-checksum"},
		{"--binary 支持显式哈希", `verify_sha256_value "$tmp_bin" "$BINARY_SHA256"`},
		{"--binary 尝试同名 .sha256", `download "${BINARY_SRC}.sha256"`},
		{"--binary 拿不到校验默认中止", `无法获取 ${BINARY_SRC}.sha256，已中止安装`},
		{"显式跳过 --binary 校验选项", "--insecure-skip-verify"},
		{"--from-source main 分支警告", "main 分支最新代码"},
		{"Release 失败不自动源码编译", "download_release || die"},
		{"SHA-256 工具首选 sha256sum", `sha256sum "$sha_file"`},
		{"SHA-256 回退 shasum -a 256", "shasum -a 256"},
		{"SHA-256 回退 openssl dgst -sha256", "openssl dgst -sha256"},
		{"缺失时自动安装 nexttrace", "download_nexttrace"},
		{"nexttrace 摘要取自 GitHub 附件或 API", "fetch_github_asset_digest"},
		{"优先下载 Release 的 .sha256 附件", "${digest_asset}.sha256"},
		{"nexttrace 下载后比对 SHA-256", `[ "$nt_actual" != "$nt_expected" ]`},
		{"通用二进制查找 find_binary", "find_binary()"},
		{"GitHub Releases 直连下载", "download_nexttrace"},
		{"OpenWrt 优先 opkg 安装 nexttrace", "opkg install nexttrace"},
		{"自动安装 miaospeed 来源", "AirportR/miaospeed"},
		{"自动安装 miaospeed 继承 gh-proxy", `apply_gh_proxy "$url"`},
		{"systemd 传递 miaospeed 参数", `-miaospeed "$MIAOSPEED_EXEC"`},
		{"GitHub 代理参数解析", "--gh-proxy"},
		{"GitHub 代理函数定义", "apply_gh_proxy"},
		{"服务参数继承代理", `AUTO_UPDATE_ARGS="$AUTO_UPDATE_ARGS -gh-proxy \"$GH_PROXY\""`},
		{"下载文件时显示进度条", "curl -#"},
		{"严格校验 --bot URL", `validate_url_safe "$BOT_URL" "--bot"`},
		{"严格校验 --gh-proxy URL", `validate_url_safe "$GH_PROXY" "--gh-proxy"`},
		{"支持环境变量令牌", `TOKEN="$MNAGENT_TOKEN"`},
		{"支持从 stdin 读取令牌", "--token-stdin"},
		{"systemd 单元为参数加引号", `ExecStart="$PREFIX/mnagent" -bot "$BOT_URL"`},
		{"systemd 默认以 root 运行", `[ -n "$RUN_USER" ] || RUN_USER="root"`},
	} {
		if !containsActiveLine(script, want.needle) {
			t.Errorf("install.sh 缺少 %s（非注释行应包含 %q）", want.name, want.needle)
		}
	}
}

// TestInstallScriptDoesNotRunRemoteNexttraceScript 守护：不能再以 root 执行
// 未固定版本的远端一键脚本（curl https://nxtrace.org/nt | bash），
// nexttrace 必须走 GitHub Releases 下载并校验摘要。
func TestInstallScriptDoesNotRunRemoteNexttraceScript(t *testing.T) {
	script := string(readInstallScript(t))
	for _, bad := range []string{"nxtrace.org", "NTrace-core/install.sh"} {
		if containsActiveLine(script, bad) {
			t.Errorf("install.sh 非注释行仍引用远端 nexttrace 安装脚本 %q", bad)
		}
	}
	if !containsActiveLine(script, "download_nexttrace") {
		t.Error("install.sh 应通过 download_nexttrace 从 GitHub Releases 安装 nexttrace")
	}
}

// TestInstallScriptVerifiesMiaospeed 守护 miaospeed 自动安装：必须先取 GitHub API 摘要并强制校验，
// 解压后按确切文件名取二进制，禁止再以“第一个类似文件”安装未校验的压缩包。
func TestInstallScriptVerifiesMiaospeed(t *testing.T) {
	script := string(readInstallScript(t))

	for _, want := range []struct{ name, needle string }{
		{"按指定 tag 取上游摘要", `fetch_github_asset_digest "AirportR/miaospeed" "$tar_name" "$miao_tag"`},
		{"优先下载 Release 的 .sha256 附件", "${digest_asset}.sha256"},
		{"摘要缺失即跳过安装", "无法获取 miaospeed"},
		{"下载后比对 SHA-256", `[ "$miao_actual" != "$miao_expected" ]`},
		{"按确切文件名取二进制", `miao_bin_name="miaospeed-${OS}-${miao_arch}"`},
		{"兼容 runner/runner 归档", `"$tmp/runner/runner"`},
	} {
		if !containsActiveLine(script, want.needle) {
			t.Errorf("install.sh 缺少“%s”（非注释行应包含 %q）", want.name, want.needle)
		}
	}
	if containsActiveLine(script, `-name "miaospeed*"`) {
		t.Error("install.sh 不应再用通配符取 miaospeed 压缩包内“第一个匹配”文件")
	}
}

// TestInstallScriptNeverAutoBuildsFromSource 守护：Release 下载失败时不得自动改为编译 main 分支，
// 否则用户会在不知情的情况下从固定版本切到未发布的移动代码。源码编译只能显式 --from-source。
func TestInstallScriptNeverAutoBuildsFromSource(t *testing.T) {
	script := string(readInstallScript(t))
	for _, bad := range []string{"改为从源码编译"} {
		if containsActiveLine(script, bad) {
			t.Errorf("install.sh 非注释行仍包含自动源码编译回退：%q", bad)
		}
	}
	if !containsActiveLine(script, "download_release || die") {
		t.Error("Release 下载失败应直接报错并提示 --from-source/--binary")
	}
	if !containsActiveLine(script, "如确需源码编译请加 --from-source") {
		t.Error("Release 失败提示中应说明 --from-source")
	}
}

// TestWindowsInstallScript 校验 Windows 一键安装脚本 install.ps1 的完整性与关键安全逻辑。
func TestWindowsInstallScript(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(findRepoRoot(), "install.ps1"))
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
		{"仅支持 64 位系统检测", "Is64BitOperatingSystem"},
		{"UAC 提权完整保留参数", "$PSBoundParameters"},
		{"Token 写入防 UTF-8 BOM", "System.Text.UTF8Encoding($false)"},
		{"NextTrace ARM64 资产兼容", "nexttrace-tiny_windows_arm64.exe"},
		{"自动更新展示正确变量", "$enableAutoUpdate"},
		{"下载路径代理支持", "Get-ProxiedUrl"},
		{"NextTrace 安装", "nexttrace_windows_"},
		{"mnagent 下载后校验 SHA-256", "Assert-Sha256"},
		{"Windows 使用 Get-FileHash", "Get-FileHash"},
		{"下载同名 .sha256", "{mnagentUrl}.sha256"},
		{"MiaoSpeed zip 提取", "Expand-Archive"},
		{"NextTrace 摘要取自 GitHub API", `Get-GitHubAssetDigest "nxtrace/NTrace-core"`},
		{"NextTrace 下载后校验摘要", "Assert-AssetSha256 $tmpNt"},
		{"MiaoSpeed 摘要取自 GitHub API", `Get-GitHubAssetDigest "AirportR/miaospeed"`},
		{"MiaoSpeed 下载后校验摘要", "Assert-AssetSha256 $tmpZip"},
		{"MiaoSpeed 按确切文件名取二进制", `$expectedExe = "miaospeed-windows-$arch.exe"`},
		{"参数定义 -Bot", "[string]$Bot"},
		{"参数定义 -Token", "[string]$Token"},
		{"参数定义 -TokenFile", "[string]$TokenFile"},
		{"参数定义 -LogFile", "[string]$LogFile"},
		{"Windows 服务日志文件参数", "-log-file `\"$LogFile`\""},
		{"严格校验 -Bot URL", "Assert-UrlSafe $Bot"},
		{"严格校验 -GhProxy URL", "Assert-UrlSafe $GhProxy"},
		{"支持环境变量令牌", "$env:MNAGENT_TOKEN"},
		{"参数定义 -Uninstall", "[switch]$Uninstall"},
		{"参数定义 -InsecureProxyChecksum", "[switch]$InsecureProxyChecksum"},
		{"校验文件优先直连获取", "Download-ChecksumFile"},
		{"收紧令牌文件 ACL", "icacls.exe"},
		{"先重置令牌文件 ACL", `/reset`},
	}

	for _, c := range checks {
		if !strings.Contains(script, c.needle) {
			t.Errorf("install.ps1 缺少关键逻辑 [%s]，应包含 %q", c.name, c.needle)
		}
	}
	if strings.Contains(script, `"*miaospeed*.exe"`) {
		t.Error("install.ps1 不应再用通配符取 miaospeed 压缩包内“第一个匹配”文件")
	}
}

// TestInstallScriptAutoUpdateOptionalValue 验证 --auto-update [yes|no] 的解析与文档一致，
// 并且非法取值会给出明确提示。
func TestInstallScriptAutoUpdateOptionalValue(t *testing.T) {
	script := string(readInstallScript(t))
	for _, needle := range []string{"--auto-update)", "yes|true|1)", "no|false|0)", "--auto-update 的取值无效"} {
		if !strings.Contains(script, needle) {
			t.Errorf("install.sh 的 --auto-update 解析缺少 %q", needle)
		}
	}
	if strings.Contains(script, `--auto-update)  AUTO_UPDATE="yes"; shift;;`) {
		t.Error("install.sh 仍在使用不支持可选值的旧 --auto-update 解析")
	}
}

// TestReleaseWorkflowRunsTestsOnlyInPrepare 验证 release.yml 只在 prepare 阶段跑一次
// go test，避免每个构建 matrix 重复执行。
func TestReleaseWorkflowRunsTestsOnlyInPrepare(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(findRepoRoot(), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(content)
	const testCmd = "go test ./..."
	if got := strings.Count(workflow, testCmd); got != 1 {
		t.Fatalf("release.yml 中 %q 出现 %d 次，期望只在 prepare 出现 1 次", testCmd, got)
	}
	prepareIdx := strings.Index(workflow, "\n  prepare:")
	buildIdx := strings.Index(workflow, "\n  build:")
	testIdx := strings.Index(workflow, testCmd)
	if prepareIdx < 0 || buildIdx < 0 || testIdx < 0 || !(prepareIdx < testIdx && testIdx < buildIdx) {
		t.Fatalf("go test 应位于 prepare 阶段（prepare=%d test=%d build=%d）", prepareIdx, testIdx, buildIdx)
	}
}

// TestInstallScriptRejectsUnsafeUnitValues 验证所有会写入 systemd/procd 单元的参数
// 都经过白名单校验，含换行/引号/空白/命令分隔符的取值必须在生成单元前被拒绝。
func TestInstallScriptRejectsUnsafeUnitValues(t *testing.T) {
	root := findRepoRoot()
	scriptPath := filepath.Join(root, "install.sh")
	tmp := t.TempDir()
	fakeBin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeAgent := filepath.Join(tmp, "mnagent-fake")
	if err := os.WriteFile(fakeAgent, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(tmp, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseArgs := []string{
		"--bot", "https://bot.example/agent",
		"--token-file", tokenFile,
		"--binary", fakeAgent,
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"update-interval 命令注入", []string{"--update-interval", "6h; touch /tmp/pwn"}, "--update-interval 取值非法"},
		{"update-interval 空值", []string{"--update-interval", ""}, "--update-interval 取值非法"},
		{"prefix 相对路径", []string{"--prefix", "relative/bin"}, "--prefix 必须是绝对路径"},
		{"prefix 含空白", []string{"--prefix", "/tmp/with space"}, "--prefix 含不允许的字符"},
		{"token-file 换行注入", []string{"--token-file", tokenFile + "\nEnvironment=BAD=1"}, "--token-file 含不允许的字符"},
		{"nexttrace 命令注入", []string{"--nexttrace", "/usr/bin/nexttrace;id"}, "--nexttrace 含不允许的字符"},
		{"nexttrace 相对路径", []string{"--nexttrace", "./nexttrace"}, "--nexttrace 必须是绝对路径"},
		{"miaospeed ~ 路径", []string{"--miaospeed", "~/bin/miaospeed"}, "--miaospeed 必须是绝对路径"},
		{"miaospeed 引号注入", []string{"--miaospeed", "/usr/bin/miao\"speed"}, "--miaospeed 含不允许的字符"},
		{"user 命令注入", []string{"--user", "root;id"}, "--user 取值非法"},
		{"user 换行注入", []string{"--user", "root\nEnvironment=BAD=1"}, "--user 不能包含换行字符"},
		{"update-interval 换行注入", []string{"--update-interval", "6h\nEnvironment=BAD=1"}, "--update-interval 不能包含换行字符"},
		{"version 注入", []string{"--version", "v1.2.3;id"}, "--version 取值非法"},
		{"miaospeed-version 注入", []string{"--miaospeed-version", "4.7.8\nEnvironment=BAD=1"}, "--miaospeed-version 不能包含换行字符"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := installEnv(fakeBin, filepath.Join(tmp, "init"), filepath.Join(tmp, "default-token"), "MNAGENT_PLATFORM=none")
			out, err := runInstallScript(t, scriptPath, append(append([]string{}, baseArgs...), tc.args...), env, "")
			if err == nil {
				t.Fatalf("不安全参数应被拒绝，输出：\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("错误信息应包含 %q，实际输出：\n%s", tc.want, out)
			}
		})
	}
}

// extractShellFunction 从 install.sh 文本中提取一个顶层 shell 函数（到行首的 } 为止）。
func extractShellFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("install.sh 中未找到函数 %s", name)
	}
	end := strings.Index(script[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("未找到函数 %s 的结束标记", name)
	}
	return script[start : start+end+len("\n}\n")]
}

// TestInstallScriptProxyChecksumPolicy 直接执行 install.sh 中提取的
// download_trusted_artifact，验证“代理场景优先直连、直连失败默认拒绝、
// 仅 --insecure-proxy-checksum 才回退代理”的策略。
func TestInstallScriptProxyChecksumPolicy(t *testing.T) {
	script := string(readInstallScript(t))
	fn := extractShellFunction(t, script, "download_trusted_artifact")
	harness := `#!/bin/sh
set -eu
log() { :; }
warn() { printf 'WARN:%s\n' "$*" >&2; }
download() {
	case "$1" in
		*raw-ok*)   printf 'raw' > "$2" ;;
		*raw-fail*) return 1 ;;
		*proxied*)  printf 'proxy' > "$2" ;;
		*) return 1 ;;
	esac
}
` + fn + `
download_trusted_artifact "$1" "$2" "$3" " test"
`
	harnessPath := filepath.Join(t.TempDir(), "policy.sh")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatal(err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("未找到 sh")
	}

	run := func(t *testing.T, ghProxy, insecure, rawURL, proxiedURL string) (string, error) {
		t.Helper()
		dest := filepath.Join(t.TempDir(), "artifact")
		cmd := exec.Command(sh, harnessPath, rawURL, proxiedURL, dest)
		cmd.Env = append(os.Environ(), "GH_PROXY="+ghProxy, "INSECURE_PROXY_CHECKSUM="+insecure)
		out, err := cmd.CombinedOutput()
		content := ""
		if data, readErr := os.ReadFile(dest); readErr == nil {
			content = string(data)
		}
		return string(out) + "\x00" + content, err
	}

	// 无代理：直接使用原始 URL。
	out, err := run(t, "", "no", "https://raw-ok/x", "https://proxied/x")
	if err != nil {
		t.Fatalf("无代理时直连下载应成功: %v\n%s", err, out)
	}
	if !strings.HasSuffix(out, "\x00raw") {
		t.Fatalf("无代理时应写入原始内容，实际输出: %q", out)
	}

	// 有代理：直连成功时不走代理。
	out, err = run(t, "https://proxy.example/", "no", "https://raw-ok/x", "https://proxied/x")
	if err != nil {
		t.Fatalf("有代理但直连成功时应成功: %v\n%s", err, out)
	}
	if !strings.HasSuffix(out, "\x00raw") {
		t.Fatalf("直连成功时不得使用代理内容，实际输出: %q", out)
	}

	// 有代理 + 直连失败 + 未加 --insecure-proxy-checksum：必须失败且不落盘。
	out, err = run(t, "https://proxy.example/", "no", "https://raw-fail/x", "https://proxied/x")
	if err == nil {
		t.Fatalf("直连失败且未显式允许代理时必须中止，实际输出: %q", out)
	}
	if !strings.HasSuffix(out, "\x00") {
		t.Fatalf("直连失败时不得写入代理内容，实际输出: %q", out)
	}

	// 显式允许后才回退到代理。
	out, err = run(t, "https://proxy.example/", "yes", "https://raw-fail/x", "https://proxied/x")
	if err != nil {
		t.Fatalf("显式允许后应回退代理并成功: %v\n%s", err, out)
	}
	if !strings.HasSuffix(out, "\x00proxy") {
		t.Fatalf("显式允许后应写入代理内容，实际输出: %q", out)
	}
	if !strings.Contains(out, "WARN:") {
		t.Fatalf("回退代理时应输出安全告警，实际输出: %q", out)
	}
}

// fakeInstall 是一套运行安装脚本用的假环境：临时 init 目录、PATH、伪 systemctl
// 与伪 mnagent 二进制，保证脚本不会碰真实的 /etc 或下载网络资源。
type fakeInstall struct {
	t         *testing.T
	tmp       string
	fakeBin   string
	initDir   string
	fakeAgent string
	tokenFile string
}

func newFakeInstall(t *testing.T, extraBins map[string]string) *fakeInstall {
	t.Helper()
	tmp := t.TempDir()
	f := &fakeInstall{
		t:         t,
		tmp:       tmp,
		fakeBin:   filepath.Join(tmp, "bin"),
		initDir:   filepath.Join(tmp, "systemd"),
		fakeAgent: filepath.Join(tmp, "mnagent-fake"),
		tokenFile: filepath.Join(tmp, "token"),
	}
	for _, dir := range []string{f.fakeBin, f.initDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.writeBin("systemctl", "#!/bin/sh\ncase \"$1\" in is-active) echo active;; esac\nexit 0\n")
	// 默认提供伪 nexttrace/miaospeed：否则测试会真的联网下载依赖，既慢又不稳定。
	if extraBins["nexttrace"] == "" {
		f.writeBin("nexttrace", "#!/bin/sh\nexit 0\n")
	}
	if extraBins["miaospeed"] == "" {
		f.writeBin("miaospeed", "#!/bin/sh\nexit 0\n")
	}
	if err := os.WriteFile(f.fakeAgent, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.tokenFile, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, body := range extraBins {
		f.writeBin(name, body)
	}
	return f
}

func (f *fakeInstall) writeBin(name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.fakeBin, name), []byte(body), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeInstall) env(extra ...string) []string {
	return installEnv(f.fakeBin, f.initDir, filepath.Join(f.tmp, "default-token"), extra...)
}

func (f *fakeInstall) args(extra ...string) []string {
	base := []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", f.fakeAgent,
		"--prefix", filepath.Join(f.tmp, "install"),
	}
	return append(base, extra...)
}

func (f *fakeInstall) unitPath() string {
	return filepath.Join(f.initDir, "mnagent.service")
}

// TestInstallScriptOptionalInstallFlags 覆盖 --install-nexttrace/--install-miaospeed
// 的显式取值解析：非法值立即报错（不得死循环），作为最后一个参数时使用默认值。
func TestInstallScriptOptionalInstallFlags(t *testing.T) {
	f := newFakeInstall(t, map[string]string{
		"miaospeed": "#!/bin/sh\nexit 0\n",
		"nexttrace": "#!/bin/sh\nexit 0\n",
	})
	scriptPath := filepath.Join(findRepoRoot(), "install.sh")

	start := time.Now()
	out, err := runInstallScriptTimeout(t, scriptPath, f.args("--install-miaospeed", "auto"), f.env(), "", 20*time.Second)
	if err == nil || !strings.Contains(out, "--install-miaospeed 的取值无效") {
		t.Fatalf("非法取值应明确报错，err=%v\n%s", err, out)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("非法取值解析耗时 %s，疑似死循环", elapsed)
	}
	out, err = runInstallScriptTimeout(t, scriptPath, f.args("--install-nexttrace", "auto"), f.env(), "", 20*time.Second)
	if err == nil || !strings.Contains(out, "--install-nexttrace 的取值无效") {
		t.Fatalf("--install-nexttrace 非法取值应明确报错，err=%v\n%s", err, out)
	}

	// 作为最后一个参数：使用默认 yes，且不再有取值需要消费。
	out, err = runInstallScriptTimeout(t, scriptPath, f.args("--no-install-nexttrace", "--install-miaospeed"), f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("--install-miaospeed 作为最后一个参数应使用默认值并安装成功: %v\n%s", err, out)
	}
	unit, err := os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), `-miaospeed "`) {
		t.Fatalf("默认 yes 应使用找到的 miaospeed，单元内容：\n%s", unit)
	}

	out, err = runInstallScriptTimeout(t, scriptPath, f.args("--no-install-miaospeed", "--install-nexttrace"), f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("--install-nexttrace 作为最后一个参数应使用默认值并安装成功: %v\n%s", err, out)
	}
	unit, err = os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), `-nexttrace "`) {
		t.Fatalf("默认 yes 应使用找到的 nexttrace，单元内容：\n%s", unit)
	}

	// 带取值的选项缺少取值时给出明确错误而不是 shift 越界。
	out, err = runInstallScriptTimeout(t, scriptPath, []string{"--bot"}, f.env(), "", 20*time.Second)
	if err == nil || !strings.Contains(out, "参数 --bot 缺少取值") {
		t.Fatalf("--bot 缺少取值应明确报错，err=%v\n%s", err, out)
	}
}

// TestInstallScriptValidateDuration 直接执行脚本中的 validate_duration，
// 验证与 Go time.ParseDuration 兼容的取值被接受、其余被拒绝。
func TestInstallScriptValidateDuration(t *testing.T) {
	script := string(readInstallScript(t))
	harness := "#!/bin/sh\nset -eu\n" +
		"die() { printf 'DIE:%s\\n' \"$*\" >&2; exit 1; }\n" +
		extractShellFunction(t, script, "reject_newlines") +
		extractShellFunction(t, script, "validate_duration") +
		"validate_duration \"$1\" test\n"
	harnessPath := filepath.Join(t.TempDir(), "duration.sh")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatal(err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("未找到 sh")
	}
	run := func(value string) (string, error) {
		out, err := exec.Command(sh, harnessPath, value).CombinedOutput()
		return string(out), err
	}
	for _, value := range []string{"1.5h", "500ms", "1h30m", "0", "6h", "30m", "1s", "2h45m30s"} {
		if out, err := run(value); err != nil {
			t.Errorf("合法 duration %q 被拒绝: %v\n%s", value, err, out)
		}
	}
	for _, value := range []string{"", "6h\"\n", "6h\ntouch /tmp/pwn", "6 h", "-1h", "1d", "0.5", "6H", "1h30"} {
		out, err := run(value)
		if err == nil {
			t.Errorf("非法 duration %q 应被拒绝，输出：%s", value, out)
		}
	}
}

// TestInstallScriptInheritsExistingService 验证升级时从已有 unit 继承
// -auto-update / -update-interval / User= / 安装前缀（由 ExecStart 首 token 反推），
// 显式参数仍然优先。
func TestInstallScriptInheritsExistingService(t *testing.T) {
	f := newFakeInstall(t, nil)
	legacyPrefix := filepath.Join(f.tmp, "legacy-bin")
	if err := os.MkdirAll(legacyPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	legacyExec := filepath.Join(legacyPrefix, "mnagent")
	unit := "[Service]\nUser=root\nGroup=root\nExecStart=\"" + legacyExec + "\" -bot \"https://bot.example/agent\" -token-file \"" + f.tokenFile + "\" -auto-update -update-interval \"3h\"\n"
	if err := os.WriteFile(f.unitPath(), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(findRepoRoot(), "install.sh")

	// 不传 --prefix/--auto-update/--update-interval/--user：全部继承旧单元。
	out, err := runInstallScriptTimeout(t, scriptPath, []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", f.fakeAgent,
	}, f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("升级继承失败: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(legacyPrefix, "mnagent")); err != nil {
		t.Fatalf("应把新二进制安装到继承到的前缀 %s: %v", legacyPrefix, err)
	}
	data, err := os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	generated := string(data)
	for _, want := range []string{
		`ExecStart="` + legacyExec + `"`,
		"-auto-update",
		`-update-interval "3h"`,
		"User=root",
		"StateDirectoryMode=0700",
	} {
		if !strings.Contains(generated, want) {
			t.Fatalf("继承后的单元缺少 %q：\n%s", want, generated)
		}
	}
	for _, want := range []string{"已从现有服务配置继承安装前缀", "已从现有服务配置继承自动更新设置", "已从现有服务配置继承更新检查间隔"} {
		if !strings.Contains(out, want) {
			t.Fatalf("升级输出缺少继承提示 %q：\n%s", want, out)
		}
	}

	// 显式参数优先：前缀与间隔都不应被旧单元覆盖。
	explicitPrefix := filepath.Join(f.tmp, "explicit-bin")
	out, err = runInstallScriptTimeout(t, scriptPath, []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", f.fakeAgent,
		"--prefix", explicitPrefix,
		"--auto-update", "yes",
		"--update-interval", "1h",
	}, f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("显式参数覆盖失败: %v\n%s", err, out)
	}
	data, err = os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	generated = string(data)
	if !strings.Contains(generated, `ExecStart="`+explicitPrefix+`/mnagent"`) {
		t.Fatalf("应使用显式 --prefix，实际单元：\n%s", generated)
	}
	if !strings.Contains(generated, `-update-interval "1h"`) {
		t.Fatalf("应使用显式 --update-interval，实际单元：\n%s", generated)
	}

	// --no-auto-update 显式关闭后，即使旧单元启用了自动更新也不应从旧单元继承回来。
	out, err = runInstallScriptTimeout(t, scriptPath, []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", f.fakeAgent,
		"--prefix", explicitPrefix,
		"--no-auto-update",
	}, f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("--no-auto-update 覆盖失败: %v\n%s", err, out)
	}
	data, err = os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ExecStart=") && strings.Contains(line, "-auto-update") {
			t.Fatalf("--no-auto-update 不应被旧单元的 -auto-update 覆盖：%s", line)
		}
	}
}

// TestInstallScriptFallsBackToBareNameForUnsafeResolvedPath 验证 PATH 中解析出的
// 可执行路径含空格时不会 die、也不会写进 unit，而是回退为裸名并告警。
func TestInstallScriptFallsBackToBareNameForUnsafeResolvedPath(t *testing.T) {
	f := newFakeInstall(t, nil)
	spaceDir := filepath.Join(f.tmp, "bin dir")
	if err := os.MkdirAll(spaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spaceDir, "nexttrace"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := f.env("PATH=" + spaceDir + string(os.PathListSeparator) + f.fakeBin + string(os.PathListSeparator) + os.Getenv("PATH"))
	scriptPath := filepath.Join(findRepoRoot(), "install.sh")

	out, err := runInstallScriptTimeout(t, scriptPath, f.args("--no-install-miaospeed"), env, "", 90*time.Second)
	if err != nil {
		t.Fatalf("解析路径不安全时应回退裸名而不是中止安装: %v\n%s", err, out)
	}
	if !strings.Contains(out, "已回退为裸名 nexttrace") {
		t.Fatalf("应输出回退告警：\n%s", out)
	}
	data, err := os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `-nexttrace "nexttrace"`) {
		t.Fatalf("单元应回退为裸名 nexttrace：\n%s", data)
	}
	if strings.Contains(string(data), "bin dir") {
		t.Fatalf("不安全路径不得写入单元：\n%s", data)
	}
}

// TestInstallersAndUpdaterHaveNoSigningResidue 守护：更新/安装链路已完全移除
// Ed25519 签名机制，只保留 SHA-256 校验。
func TestInstallersAndUpdaterHaveNoSigningResidue(t *testing.T) {
	root := findRepoRoot()
	files := []string{
		"install.sh",
		"install.ps1",
		"internal/updater/updater.go",
		filepath.Join(".github", "workflows", "release.yml"),
	}
	forbidden := []string{"signing-pubkey", "SigningPublicKey", "ed25519", ".sig"}
	for _, name := range files {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("读取 %s 失败：%v", name, err)
		}
		lower := strings.ToLower(string(raw))
		for _, needle := range forbidden {
			if strings.Contains(lower, strings.ToLower(needle)) {
				t.Errorf("%s 仍包含已移除的签名相关内容 %q", name, needle)
			}
		}
	}
}

// TestInstallScriptDownloadTimeoutsAndGroupValidation 静态守护：
// 校验文件直连限时、主组名白名单、状态目录 0700。
func TestInstallScriptDownloadTimeoutsAndGroupValidation(t *testing.T) {
	script := string(readInstallScript(t))
	for _, want := range []struct{ name, needle string }{
		{"校验文件直连连接超时", "--connect-timeout 5 --max-time 30"},
		{"直连失败探测也能超时", "--connect-timeout 5 --max-time 15"},
		{"wget 限时与重试", "--timeout=30 --tries=2"},
		{"小文件直连使用 fast 模式", `download "$trusted_raw" "$trusted_dest" fast`},
		{"主组名白名单校验", `case "$RUN_GROUP" in`},
		{"主组名不合法回退", `RUN_GROUP="$RUN_USER"`},
		{"systemd 状态目录 0700", "StateDirectoryMode=0700"},
		{"procd/非 systemd 收紧状态目录", "prepare_state_dir"},
	} {
		if !containsActiveLine(script, want.needle) {
			t.Errorf("install.sh 缺少 %s（应包含 %q）", want.name, want.needle)
		}
	}
}

// TestInstallScriptInheritsUserAndValidatesGroup 覆盖两件事：
//  1. 升级时从旧 unit 的 User= 继承运行用户（用户未显式 --user）；
//  2. 主组名不符合白名单时回退为运行用户并告警，而不是写进 Group=。
//
// 用 PATH 中的假 id 模拟用户/组，避免在测试机上真实创建用户。
func TestInstallScriptInheritsUserAndValidatesGroup(t *testing.T) {
	f := newFakeInstall(t, map[string]string{
		"id": "#!/bin/sh\ncase \"$1\" in -u) echo 0;; -gn) echo mnagent;; *) exit 1;; esac\n",
	})
	legacyPrefix := filepath.Join(f.tmp, "legacy-bin")
	if err := os.MkdirAll(legacyPrefix, 0o755); err != nil {
		t.Fatal(err)
	}
	unit := "[Service]\nUser=mnagent\nGroup=mnagent\nExecStart=\"" + filepath.Join(legacyPrefix, "mnagent") + "\" -bot \"https://bot.example/agent\" -token-file \"" + f.tokenFile + "\"\n"
	if err := os.WriteFile(f.unitPath(), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(findRepoRoot(), "install.sh")
	args := []string{
		"--bot", "https://bot.example/agent",
		"--token-file", f.tokenFile,
		"--binary", f.fakeAgent,
	}
	out, err := runInstallScriptTimeout(t, scriptPath, args, f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("继承 User= 失败: %v\n%s", err, out)
	}
	data, err := os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=mnagent", "Group=mnagent"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("单元缺少 %q：\n%s", want, data)
		}
	}
	if !strings.Contains(out, "已从现有服务配置继承运行用户: mnagent") {
		t.Fatalf("应提示继承运行用户：\n%s", out)
	}

	// 让 id -gn 返回非法组名：必须回退为运行用户并告警，且不写进 Group=。
	f.writeBin("id", "#!/bin/sh\ncase \"$1\" in -u) echo 0;; -gn) echo 'bad group';; *) exit 1;; esac\n")
	out, err = runInstallScriptTimeout(t, scriptPath, args, f.env(), "", 90*time.Second)
	if err != nil {
		t.Fatalf("非法组名应回退而不是中止安装: %v\n%s", err, out)
	}
	if !strings.Contains(out, "主组名（bad group）不合法，回退为 mnagent") {
		t.Fatalf("应输出组名回退告警：\n%s", out)
	}
	data, err = os.ReadFile(f.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Group=mnagent") || strings.Contains(string(data), "bad group") {
		t.Fatalf("非法组名不得写入单元：\n%s", data)
	}
}
