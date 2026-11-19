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
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("未找到 sh")
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command(sh, append([]string{scriptPath}, args...)...)
	} else {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("非 root 且未安装 unshare，跳过可执行安装脚本测试")
		}
		if err := exec.Command(unshare, "-r", "--", "true").Run(); err != nil {
			t.Skipf("非 root 且 unshare -r 不可用（%v），跳过可执行安装脚本测试", err)
		}
		cmd = exec.Command(unshare, append([]string{"-r", "--", sh, scriptPath}, args...)...)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
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
		{"校验文件为同名 .sha256", `sum_url="${url}.sha256"`},
		{"--binary 支持显式哈希", `verify_sha256_value "$tmp_bin" "$BINARY_SHA256"`},
		{"--binary 尝试同名 .sha256", `download "${BINARY_SRC}.sha256"`},
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
		{"严格校验 -Bot URL", "Assert-UrlSafe $Bot"},
		{"严格校验 -GhProxy URL", "Assert-UrlSafe $GhProxy"},
		{"支持环境变量令牌", "$env:MNAGENT_TOKEN"},
		{"参数定义 -Uninstall", "[switch]$Uninstall"},
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
