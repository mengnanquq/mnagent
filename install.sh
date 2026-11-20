#!/bin/sh
# mnagent 一键安装脚本（本项目是它的唯一来源）。
#
# 机器人的 /host add 会生成这样的命令，在目标主机上执行即可：
#   (curl -fsSL <脚本地址> || wget -qO- <脚本地址>) | sh -s -- \
#     --bot https://<机器人地址>/agent --token-file /etc/mnagent/token
# 令牌即身份：机器人按令牌识别主机，主机上不需要（也不接受）名称参数。
#
# 支持两类平台：
#   * systemd（Debian/Ubuntu/CentOS 等）：生成 /etc/systemd/system/mnagent.service，
#     原始套接字能力由单元的 AmbientCapabilities 提供；
#   * OpenWrt（procd）：生成 /etc/init.d/mnagent，以 root 运行（OpenWrt 上没有
#     setcap 与用户体系，而 nexttrace 需要 CAP_NET_RAW）。
# 脚本本身只使用 POSIX sh 语法，以便在 OpenWrt 的 busybox ash 下运行。
set -eu
# busybox ash 是否支持 pipefail 不确定：能开就开，开不了也不影响。
(set -o pipefail) 2>/dev/null && set -o pipefail

REPO="${MNAGENT_REPO:-mengnanquq/mnagent}"
# 平台检测可被 MNAGENT_PLATFORM 覆盖（systemd|openwrt|none），供测试与特殊镜像使用。
PLATFORM="${MNAGENT_PLATFORM:-auto}"
# init 脚本目录可被 MNAGENT_INIT_DIR 覆盖（默认 /etc/systemd/system 或 /etc/init.d）。
INIT_DIR="${MNAGENT_INIT_DIR:-}"

BOT_URL=""
TOKEN=""
TOKEN_FROM_ARG="no"
TOKEN_STDIN="no"
# 默认令牌文件路径可覆盖（测试与非标准部署使用；正常安装用 --token-file 指定即可）。
DEFAULT_TOKEN_FILE="${MNAGENT_TOKEN_FILE:-/etc/mnagent/token}"
TOKEN_FILE="$DEFAULT_TOKEN_FILE"
NEXTTRACE_BIN="nexttrace"
MIAOSPEED_BIN="miaospeed"
MIAOSPEED_VERSION="latest"
RUN_USER=""
RUN_GROUP=""
PREFIX=""
VERSION="latest"
MODE="auto"        # auto | release | source | binary
BINARY_SRC=""
BINARY_SHA256=""
# --binary <URL> 拿不到同名 .sha256 时默认中止；只有显式 --insecure-skip-verify 才继续。
INSECURE_SKIP_VERIFY="no"
UNINSTALL="no"
SERVICE_NAME="mnagent"
AUTO_UPDATE="yes"   # 默认开启自动更新（可 --auto-update no 关闭）
UPDATE_INTERVAL="6h"
INSTALL_NEXTTRACE="yes" # 缺少 nexttrace 时默认自动按照官方脚本/包管理器安装
INSTALL_MIAOSPEED="yes" # 缺少 miaospeed 时默认自动从 GitHub Releases 下载安装
# download_miaospeed 的临时目录（位于 $PREFIX 下，避免 OpenWrt 的 /tmp tmpfs 占用内存）。
MIAOSPEED_TMP_DIR=""
GH_PROXY="${GH_PROXY:-${MNAGENT_GH_PROXY:-}}" # GitHub 代理前缀，例如 https://gh-proxy.com/
# 明文 HTTP 的 --bot 只允许回环/内网地址（与 agent 的 -allow-insecure-http 规则一致）；
# 公网明文 HTTP 必须显式 --allow-insecure-http，否则装完 agent 会拒绝启动、陷入重启循环。
ALLOW_INSECURE_HTTP="no"
# 使用 gh-proxy 时默认只允许直连 github.com 获取 .sha256；显式 --insecure-proxy-checksum
# 才允许经代理获取校验文件（代理可同时替换二进制与同源校验文件）。
INSECURE_PROXY_CHECKSUM="no"
# *_SET 记录用户是否显式传入对应参数：升级继承只补未显式指定的值。
AUTO_UPDATE_SET="no"
UPDATE_INTERVAL_SET="no"
RUN_USER_SET="no"
PREFIX_SET="no"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
# cleanup_partial_install：清理安装过程中的半成品文件（下载失败/中断/校验失败时）。
# 残留的 .mnagent.new 可能被误当成已下载的新版本，或被下次安装沿用。
cleanup_partial_install() {
	[ -n "${PREFIX:-}" ] || return 0
	rm -f "$PREFIX/.mnagent.new" "$PREFIX/.mnagent.new.sha256" "$PREFIX/.mnagent.build.$$" "$PREFIX/.nexttrace.new" 2>/dev/null || true
	if [ -n "${MIAOSPEED_TMP_DIR:-}" ]; then
		rm -rf "$MIAOSPEED_TMP_DIR" 2>/dev/null || true
	fi
}
die()  {
	cleanup_partial_install
	printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2
	exit 1
}

# validate_url_safe <值> <参数名>：URL 只允许安全字符，禁止空白、换行、引号、反斜杠、%、$、反引号等。
# 这些值会被写入 systemd/procd 命令行，必须从源头阻断命令注入与单元文件注入。
validate_url_safe() {
	url_value="$1"
	url_label="$2"
	[ -n "$url_value" ] || die "${url_label} 不能为空"
	case "$url_value" in
		http://*|https://*) ;;
		*) die "${url_label} 必须是完整的 http(s) 地址：${url_value}";;
	esac
	url_leftover="$(printf '%s' "$url_value" | LC_ALL=C tr -d 'A-Za-z0-9._~:/?#@!&()*+,;=[]-')"
	if [ -n "$url_leftover" ]; then
		die "${url_label} 含不允许的字符（只允许 URL 安全字符，禁止空白、换行、引号、反斜杠、%、\$、反引号）"
	fi
}

# validate_abs_path <值> <参数名>：将被写入 systemd/procd 单元的绝对路径只允许安全字符。
# 这些值会原样进入 ExecStart / procd command，必须阻断空白、引号、换行、$、%、反斜杠等。
validate_abs_path() {
	path_value="$1"
	path_label="$2"
	case "$path_value" in
		/*) ;;
		*) die "${path_label} 必须是绝对路径：${path_value}";;
	esac
	path_leftover="$(printf '%s' "$path_value" | LC_ALL=C tr -d 'A-Za-z0-9_./@:+-')"
	if [ -n "$path_leftover" ]; then
		die "${path_label} 含不允许的字符（只允许 A-Za-z0-9_./@:+-，禁止空白、换行、引号、反斜杠、\$、% 等）：${path_value}"
	fi
}

# validate_bin_ref <值> <参数名>：可执行文件参数允许绝对路径，或 PATH 中的裸文件名
# （默认 nexttrace / miaospeed）。裸文件名不允许以 '-'、'.' 开头，避免被当成选项。
validate_bin_ref() {
	bin_value="$1"
	bin_label="$2"
	case "$bin_value" in
		./*|../*|~*)
			die "${bin_label} 必须是绝对路径（收到相对路径或 ~ 形式）：${bin_value}；请用完整绝对路径（例如 /usr/local/bin/${bin_value##*/}），或直接使用 PATH 中的裸名"
			;;
		*/*)
			validate_abs_path "$bin_value" "$bin_label"
			;;
		*)
			case "$bin_value" in
				''|-*|.*) die "${bin_label} 取值非法：${bin_value}";;
			esac
			bin_leftover="$(printf '%s' "$bin_value" | LC_ALL=C tr -d 'A-Za-z0-9_.@:+-')"
			if [ -n "$bin_leftover" ]; then
				die "${bin_label} 含不允许的字符（只允许 A-Za-z0-9_.@:+-，禁止空白、换行、引号、\$ 等）：${bin_value}"
			fi
			;;
	esac
}

# reject_newlines <值> <参数名>：grep 按行匹配，换行会绕过 ^...$ 校验，必须先显式拒绝。
reject_newlines() {
	case "$1" in
		*'
'*) die "${2} 不能包含换行字符";;
	esac
}

# validate_duration <值> <参数名>：接受与 Go time.ParseDuration 兼容的 ASCII 子集，
# 如 500ms、1.5h、1h30m、0。Go 额外支持的 µs/负数不在此列（配置里也用不到）。
validate_duration() {
	duration_value="$1"
	duration_label="$2"
	reject_newlines "$duration_value" "$duration_label"
	[ "$duration_value" = "0" ] && return 0
	printf '%s' "$duration_value" | grep -Eq '^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$' \
		|| die "${duration_label} 取值非法：${duration_value}（只允许 Go duration 形式，如 500ms、1.5h、1h30m、0）"
}

# validate_user_name <值>：systemd/procd 的 User 与 useradd 参数只接受小写系统用户名（可带结尾的 $）。
validate_user_name() {
	user_value="$1"
	reject_newlines "$user_value" "--user"
	printf '%s' "$user_value" | grep -Eq '^[a-z_][a-z0-9_-]*[$]?$' \
		|| die "--user 取值非法：${user_value}（只允许小写字母/数字/_/-，且必须以字母或 _ 开头）"
}

# validate_release_tag <值> <参数名>：latest 或 vX.Y.Z[-pre]；该值会拼入下载 URL 与编译 ldflags。
validate_release_tag() {
	tag_value="$1"
	tag_label="$2"
	if [ "$tag_value" = "latest" ]; then
		return 0
	fi
	reject_newlines "$tag_value" "$tag_label"
	printf '%s' "$tag_value" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
		|| die "${tag_label} 取值非法：${tag_value}（只允许 latest 或 vX.Y.Z[-pre]）"
}

# validate_repo_ref <值>：GitHub owner/repo，会拼入下载 URL。
validate_repo_ref() {
	repo_value="$1"
	reject_newlines "$repo_value" "MNAGENT_REPO"
	printf '%s' "$repo_value" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' \
		|| die "MNAGENT_REPO 取值非法：${repo_value}（应为 owner/repo）"
}

# strip_quotes <值>：兼容旧版单元中带引号的参数，升级时正确继承。
strip_quotes() {
	printf '%s' "$1" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

usage() {
	cat <<'EOF'
用法：
  (curl -fsSL <脚本地址> || wget -qO- <脚本地址>) | sh -s -- --bot <机器人地址>/agent --token-file <令牌文件>

参数：
  --bot <url>          机器人 agent 端点基地址（必填，如 https://mnbot.example.org/agent）
  --token <token>      接入令牌（不推荐：会出现在 argv/命令历史；优先用 --token-file、MNAGENT_TOKEN 或 --token-stdin）
  --token-file <path>  令牌文件路径（默认 /etc/mnagent/token；推荐，升级时会保留；传 - 等价于 --token-stdin）
  --token-stdin        从标准输入读取令牌（仅脚本文件执行时可用，例如 sh install.sh --token-stdin < token.txt）
  --nexttrace <path>   nexttrace 可执行文件路径或名称（默认 nexttrace）
  --miaospeed <path>   miaospeed 可执行文件路径或名称（默认 miaospeed）
  --miaospeed-version <tag> 安装的 miaospeed 版本，默认 latest（取最新 Release）
  --version <tag>      安装的版本标签，默认 latest（取最新 Release）
  --binary <path|url>  直接使用已编译好的 mnagent（本地路径或下载地址）
  --sha256 <hex>       校验 --binary 指定文件的 SHA-256（URL 未提供时尝试同目录 <url>.sha256）
  --insecure-skip-verify  --binary <url> 拿不到同名 .sha256 时仍继续安装
                       （默认中止；仅在确认来源可信时使用）
  --from-source        从源码编译（Release 下载失败时不再自动回退，需显式指定本选项；
                       --version latest 时会编译 main 分支最新代码并打印警告）
  --user <name>        运行服务的用户（默认 root）
  --prefix <dir>       二进制安装目录（systemd 默认 /usr/local/bin，OpenWrt 默认 /usr/bin）
  --auto-update [yes|no] 是否启用自动更新（默认 yes）
  --no-auto-update     关闭自动更新（等同于 --auto-update no）
  --update-interval <dur> 自动更新检查间隔（默认 6h）
  --install-nexttrace [yes|no] 缺少 nexttrace 时是否自动安装（默认 yes）
  --no-install-nexttrace 缺少 nexttrace 时不自动安装（等同于 --install-nexttrace no）
  --install-miaospeed [yes|no] 缺少 miaospeed 时是否自动安装（默认 yes）
  --no-install-miaospeed 缺少 miaospeed 时不自动安装（等同于 --install-miaospeed no）
  --allow-insecure-http -Bot 使用明文 HTTP 连接公网地址时允许继续（默认拒绝；
                       会向 agent 传递 -allow-insecure-http，令牌可能被窃听，慎用）
  --gh-proxy <url>     GitHub 代理前缀，例如 https://gh-proxy.com/
  --insecure-proxy-checksum  使用 --gh-proxy 时允许经代理获取 .sha256 校验文件
                       （默认必须直连 github.com；确认代理可信时才使用）
  --uninstall          卸载：停止并删除服务与二进制（保留令牌与用户）
  -h, --help           显示本帮助

环境变量（高级，一般无需设置）：
  MNAGENT_PLATFORM=systemd|openwrt|none   强制平台检测结果
  MNAGENT_INIT_DIR=<dir>                  覆盖 init/unit 脚本所在目录
  MNAGENT_REPO=<owner/repo>               覆盖 Release 来源仓库
  GH_PROXY=<url>                          GitHub 代理前缀（如 https://gh-proxy.com/）
  MNAGENT_TOKEN=<token>                   接入令牌（避免出现在 argv；与 --token-file 二选一）
  MNAGENT_TOKEN_FILE=<path>              默认令牌文件路径（默认 /etc/mnagent/token；一般无需设置）
  MNAGENT_STATE_DIR=<dir>                 procd/非 systemd 路径使用的状态目录（默认 /var/lib/mnagent）
  MNAGENT_ENDIAN=le|be                    无法自动判定 MIPS 字节序时显式指定（le=小端，be=大端）
EOF
}

# 先处理帮助：非 root 用户查看用法时不应触发提权。
for arg in "$@"; do
	case "$arg" in
		-h|--help) usage; exit 0;;
	esac
done

# 需要 root：非 root 时若脚本为本地文件则通过 sudo 自我提权重跑；管道执行时无法重放
# 已被 sh 读走的脚本，只能给出可复制的提示（不重新下载脚本：避免以 root 执行与用户
# 实际审查内容不一致的远端文件）。
if [ "$(id -u)" != "0" ]; then
	if command -v sudo >/dev/null 2>&1 && [ -f "$0" ]; then
		log "需要 root 权限，正在通过 sudo 重新执行"
		reexec_ok="no"
		if [ -n "${MNAGENT_TOKEN:-}" ]; then
			# sudo 默认清空环境：优先 --preserve-env 按变量名传递，令牌不会出现在 ps 的 argv 中；
			# 若安全策略不允许保留环境，再回退到显式赋值（仅短暂存在于 sudo 的 argv）。
			if sudo --preserve-env=MNAGENT_TOKEN sh "$0" "$@"; then
				reexec_ok="yes"
			elif sudo env MNAGENT_TOKEN="$MNAGENT_TOKEN" sh "$0" "$@"; then
				reexec_ok="yes"
			fi
		elif sudo sh "$0" "$@"; then
			reexec_ok="yes"
		fi
		if [ "$reexec_ok" = "yes" ]; then
			exit 0
		fi
		die "提权失败：请以 root 运行（或用 sudo -i 后再执行本条命令）"
	fi
	if [ -n "${MNAGENT_TOKEN:-}" ]; then
		die "需要 root 权限。sudo 默认会清空 MNAGENT_TOKEN，请显式保留该变量后重试（下面的 \$MNAGENT_TOKEN 由当前 shell 展开，不会打印令牌明文）：
  (curl -fsSL <脚本地址> || wget -qO- <脚本地址>) | sudo env MNAGENT_TOKEN=\"\$MNAGENT_TOKEN\" sh -s -- <原有安装参数>
也可以先 sudo -i 进入 root shell，再原样执行不带 sudo 的安装命令；OpenWrt 请以 root 登录。"
	fi
	die "需要 root 权限（管道安装请用 curl ... | sudo sh -s -- ...；若用 MNAGENT_TOKEN 传令牌，必须写成 sudo env MNAGENT_TOKEN=\"\$MNAGENT_TOKEN\" sh -s -- ...，否则 sudo 会清空该变量；OpenWrt 请以 root 登录）"
fi

# require_arg_count <选项名> <当前 $#>：确保带取值选项后面确实有取值。
# 否则 `shift 2` 在最后一个参数时会越界报错（set -e 下直接退出），且错误信息不明确。
require_arg_count() {
	[ "$2" -ge 2 ] || die "参数 $1 缺少取值（用 --help 查看用法）"
}

while [ $# -gt 0 ]; do
	case "$1" in
		--bot)         require_arg_count --bot $#; BOT_URL="${2:-}"; shift 2;;
		--token)       require_arg_count --token $#; TOKEN="${2:-}"; TOKEN_FROM_ARG="yes"; shift 2;;
		--token-stdin) TOKEN_STDIN="yes"; shift;;
		--token-file)  require_arg_count --token-file $#; TOKEN_FILE="${2:-}"; shift 2;;
		--nexttrace)   require_arg_count --nexttrace $#; NEXTTRACE_BIN="${2:-}"; shift 2;;
		--miaospeed)   require_arg_count --miaospeed $#; MIAOSPEED_BIN="${2:-}"; shift 2;;
		--miaospeed-version) require_arg_count --miaospeed-version $#; MIAOSPEED_VERSION="${2:-}"; shift 2;;
		--version)     require_arg_count --version $#; VERSION="${2:-}"; shift 2;;
		--binary)      require_arg_count --binary $#; BINARY_SRC="${2:-}"; MODE="binary"; shift 2;;
		--sha256)      require_arg_count --sha256 $#; BINARY_SHA256="${2:-}"; shift 2;;
		--insecure-skip-verify) INSECURE_SKIP_VERIFY="yes"; shift;;
		--from-source) MODE="source"; shift;;
		--user)        require_arg_count --user $#; RUN_USER="${2:-}"; RUN_USER_SET="yes"; shift 2;;
		--prefix)      require_arg_count --prefix $#; PREFIX="${2:-}"; PREFIX_SET="yes"; shift 2;;
		--uninstall)   UNINSTALL="yes"; shift;;
		--auto-update)
			AUTO_UPDATE_SET="yes"
			case "${2:-}" in
				yes|true|1) AUTO_UPDATE="yes"; shift 2;;
				no|false|0) AUTO_UPDATE="no"; shift 2;;
				"") AUTO_UPDATE="yes"; shift;;
				-*) AUTO_UPDATE="yes"; shift;;
				*) die "参数 --auto-update 的取值无效：${2}（只支持 yes 或 no）";;
			esac
			;;
		--no-auto-update) AUTO_UPDATE="no"; AUTO_UPDATE_SET="yes"; shift;;
		--update-interval) require_arg_count --update-interval $#; UPDATE_INTERVAL="${2:-}"; UPDATE_INTERVAL_SET="yes"; shift 2;;
		--install-nexttrace)
			case "${2:-}" in
				yes|true|1) INSTALL_NEXTTRACE="yes"; shift 2;;
				no|false|0) INSTALL_NEXTTRACE="no"; shift 2;;
				"") INSTALL_NEXTTRACE="yes"; shift;;
				-*) INSTALL_NEXTTRACE="yes"; shift;;
				*) die "参数 --install-nexttrace 的取值无效：${2}（只支持 yes 或 no）";;
			esac
			;;
		--no-install-nexttrace) INSTALL_NEXTTRACE="no"; shift;;
		--install-miaospeed)
			case "${2:-}" in
				yes|true|1) INSTALL_MIAOSPEED="yes"; shift 2;;
				no|false|0) INSTALL_MIAOSPEED="no"; shift 2;;
				"") INSTALL_MIAOSPEED="yes"; shift;;
				-*) INSTALL_MIAOSPEED="yes"; shift;;
				*) die "参数 --install-miaospeed 的取值无效：${2}（只支持 yes 或 no）";;
			esac
			;;
		--no-install-miaospeed) INSTALL_MIAOSPEED="no"; shift;;
		--gh-proxy)     require_arg_count --gh-proxy $#; GH_PROXY="${2:-}"; shift 2;;
		--insecure-proxy-checksum) INSECURE_PROXY_CHECKSUM="yes"; shift;;
		--allow-insecure-http) ALLOW_INSECURE_HTTP="yes"; shift;;
		*) die "未知参数：$1（用 --help 查看用法）";;
	esac
done

# --token-file - 等价于 --token-stdin：必须在继承旧 unit 之前归一化。
# 否则升级时继承逻辑会把 '-' 覆盖成旧 unit 里的令牌路径，导致 stdin 传入的
# 令牌被静默忽略（沿用旧令牌，甚至以为已经轮换成功）。
if [ "$TOKEN_FILE" = "-" ]; then
	TOKEN_FILE="$DEFAULT_TOKEN_FILE"
	TOKEN_STDIN="yes"
fi

# ---------- 平台与架构 ----------

# detect_platform 输出 systemd / openwrt / none。
detect_platform() {
	case "$PLATFORM" in
		systemd|openwrt|none) echo "$PLATFORM"; return;;
	esac
	if [ -f /etc/openwrt_release ] || { [ -d /etc/init.d ] && [ -x /sbin/ubus ]; }; then
		echo openwrt
	elif [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
		echo systemd
	else
		echo none
	fi
}
PLATFORM="$(detect_platform)"

case "$PLATFORM" in
	openwrt)
		[ -n "$PREFIX" ] || PREFIX="/usr/bin"
		[ -n "$RUN_USER" ] || RUN_USER="root"
		[ -n "$INIT_DIR" ] || INIT_DIR="/etc/init.d"
		;;
	systemd)
		[ -n "$PREFIX" ] || PREFIX="/usr/local/bin"
		[ -n "$RUN_USER" ] || RUN_USER="root"
		[ -n "$INIT_DIR" ] || INIT_DIR="/etc/systemd/system"
		;;
	*)
		[ -n "$PREFIX" ] || PREFIX="/usr/local/bin"
		[ -n "$RUN_USER" ] || RUN_USER="root"
		;;
esac

# elf_ei_data <文件>：读取 ELF 头第 6 字节（1=小端，2=大端）。
# uname -m 在 MIPS 上不区分大小端，只能看现有二进制的 ELF 头。
elf_ei_data() {
	[ -f "$1" ] || return 1
	byte="$(dd if="$1" bs=1 skip=5 count=1 2>/dev/null | od -An -tu1 2>/dev/null | tr -d ' ')"
	if [ -z "$byte" ]; then
		# 没有 od（或标志不被支持）时回退到 hexdump
		byte="$(dd if="$1" bs=1 skip=5 count=1 2>/dev/null | hexdump -e '1/1 "%u"' 2>/dev/null)"
	fi
	printf '%s' "$byte"
}

# is_little_endian：借助 busybox/sh 的 ELF 头判断系统字节序。
# MNAGENT_ENDIAN=le|be 可在无法从现有 ELF 判定（或判定错误）时显式覆盖。
is_little_endian() {
	case "${MNAGENT_ENDIAN:-}" in
		le|LE|little|little-endian) return 0;;
		be|BE|big|big-endian) return 1;;
		"") ;;
		*) warn "MNAGENT_ENDIAN 取值无效：${MNAGENT_ENDIAN}（只支持 le 或 be），将尝试自动探测字节序";;
	esac
	for candidate in /bin/busybox "$(command -v sh 2>/dev/null)" /bin/sh; do
		case "$(elf_ei_data "$candidate" 2>/dev/null || true)" in
			1) return 0;;
			2) return 1;;
		esac
	done
	warn "无法从 ELF 头判定系统字节序，默认按大端(mips)处理；若设备实际为小端，请设置 MNAGENT_ENDIAN=le 后重新安装（大端可设 MNAGENT_ENDIAN=be）"
	return 1
}

# 架构：Release 资产名为 mnagent_<os>_<arch>（均为静态二进制，musl/glibc 通用）。
# 注意不要用 tr 的字符类（[:upper:]/[:lower:]）：部分 BusyBox 构建不支持，会把
# “Linux” 变成 “Linlx” 之类的结果（字符类被当成字面字符集），导致下载地址 404。
case "$(uname -s)" in
	Linux)  OS="linux";;
	Darwin) OS="darwin";;
	*)      OS="$(uname -s | tr 'A-Z' 'a-z')";;   # 显式区间，任何 tr 都支持
esac
MACHINE="$(uname -m)"
case "$MACHINE" in
	x86_64|amd64)   ARCH="amd64";;
	aarch64|arm64)  ARCH="arm64";;
	armv7l|armv7|armv6l|armv6|armv5tel|armv5l|arm) ARCH="arm";;
	mips*)
		if is_little_endian; then
			case "$MACHINE" in mips64*) ARCH="mips64le";; *) ARCH="mipsle";; esac
		else
			case "$MACHINE" in mips64*) ARCH="mips64";; *) ARCH="mips";; esac
		fi
		;;
	riscv64)        ARCH="riscv64";;
	*) die "不支持的架构：${MACHINE}（可用 --binary 指定自行编译的 mnagent）";;
esac

# ---------- 基础工具（OpenWrt 的 BusyBox 可能缺少 install/curl） ----------

# download <url> <输出文件> [fast]
# fast 用于校验文件等小体积文件的直连尝试：限制连接与总耗时，避免网络不
# 通时卡住很久（OpenWrt 上的 wget 默认可能无限重试）。
download() {
	dl_url="$1"
	dl_dest="$2"
	dl_mode="${3:-}"
	if command -v curl >/dev/null 2>&1; then
		if [ "$dl_mode" = "fast" ]; then
			curl -# -fSL --connect-timeout 5 --max-time 30 --retry 2 -o "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
		else
			curl -# -fSL --retry 3 -o "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
		fi
	elif command -v wget >/dev/null 2>&1; then
		if wget --help 2>&1 | grep -q -- '--show-progress'; then
			if [ "$dl_mode" = "fast" ]; then
				wget -q --show-progress --timeout=30 --tries=2 -O "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
			else
				wget -q --show-progress -O "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
			fi
		elif [ "$dl_mode" = "fast" ]; then
			# BusyBox wget 不一定支持长选项，这里用等价的短选项。
			wget -T 30 -t 2 -O "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
		else
			wget -O "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
		fi
	elif command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -O "$dl_dest" "$dl_url" || { rm -f "$dl_dest"; return 1; }
	else
		die "未找到下载工具：请安装 curl（OpenWrt：opkg install curl），或使用 uclient-fetch/wget"
	fi
}

# download_stdout <url> [fast]
# fast 用于 GitHub 校验文件的直连尝试：与 download 的 fast 模式同样限时，避免挂死。
download_stdout() {
	if command -v curl >/dev/null 2>&1; then
		if [ "${2:-}" = "fast" ]; then
			curl -fsSL --connect-timeout 5 --max-time 30 --retry 2 "$1"
		else
			curl -fsSL --retry 3 "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [ "${2:-}" = "fast" ]; then
			wget -qO- -T 30 -t 2 "$1"
		else
			wget -qO- "$1"
		fi
	elif command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O - "$1"
	else
		die "未找到下载工具：请安装 curl（OpenWrt：opkg install curl），或使用 uclient-fetch/wget"
	fi
}

# apply_gh_proxy <url>
# 若配置了 GH_PROXY，为 GitHub 相关目标地址添加代理前缀（例如 https://gh-proxy.com/）。
apply_gh_proxy() {
	target="$1"
	if [ -z "$GH_PROXY" ]; then
		echo "$target"
		return
	fi
	proxy_prefix="$(printf '%s' "$GH_PROXY" | sed 's#/*$##')/"
	case "$target" in
		"$proxy_prefix"*) echo "$target" ;;
		https://github.com/*|https://raw.githubusercontent.com/*)
			echo "${proxy_prefix}${target}"
			;;
		*) echo "$target" ;;
	esac
}

# sha256_of <文件>：输出文件的 SHA-256（小写十六进制）。
# 依次回退 sha256sum（OpenWrt/BusyBox 通常自带）→ shasum -a 256 → openssl dgst -sha256。
sha256_of() {
	sha_file="$1"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$sha_file" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$sha_file" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$sha_file" | awk '{print $NF}'
	else
		return 1
	fi
}

# download_trusted_artifact <原始 URL> <代理 URL> <目标文件> <说明>
# 使用 gh-proxy 时，校验文件必须优先直连 github.com：否则代理可以同时替换
# 二进制与同源 .sha256，校验无法提供任何防篡改能力。直连失败时只有显式
# --insecure-proxy-checksum 才允许退回代理。直连尝试统一限时，避免离线时挂死。
download_trusted_artifact() {
	trusted_raw="$1"
	trusted_proxied="$2"
	trusted_dest="$3"
	trusted_label="$4"
	if [ -z "$GH_PROXY" ]; then
		download "$trusted_raw" "$trusted_dest" fast
		return
	fi
	if download "$trusted_raw" "$trusted_dest" fast; then
		log "已直连 GitHub 获取${trusted_label}（未经 gh-proxy）"
		return 0
	fi
	if [ "$INSECURE_PROXY_CHECKSUM" = "yes" ]; then
		warn "无法直连 GitHub 获取${trusted_label}，按 --insecure-proxy-checksum 改为经代理获取；代理仍可同时替换二进制与校验文件"
		download "$trusted_proxied" "$trusted_dest"
		return
	fi
	return 1
}

# describe_direct_failure <原始 URL>：直连失败时尽量区分 404 与网络错误，仅用于提示。
describe_direct_failure() {
	direct_url="$1"
	if command -v curl >/dev/null 2>&1; then
		direct_code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$direct_url" 2>/dev/null || true)"
		case "$direct_code" in
			404) printf 'GitHub 返回 404（该版本可能未发布此文件或资产名不匹配）';;
			000|'') printf '无法连接 github.com（DNS 解析失败或网络被阻断）';;
			2??) printf '直连可访问但下载中断（HTTP %s）' "$direct_code";;
			*) printf '直连返回 HTTP %s' "$direct_code";;
		esac
		return
	fi
	printf '直连失败（无法区分 404 与网络错误）'
}

# verify_sha256 <文件> <原始校验文件 URL> <资产名>
# 第二个参数是未经 gh-proxy 的原始 URL，由本函数按信任策略决定校验文件从哪里获取。
# 校验文件内容为 "<hash>  <文件名>"（release 工作流生成）。任何一步失败都中止安装，
# 且校验发生在 install_file 之前，失败不会覆盖已有二进制。
verify_sha256() {
	verify_file="$1"
	verify_raw_url="$2"
	verify_asset="$3"
	verify_url="$(apply_gh_proxy "$verify_raw_url")"
	verify_sum_file="${verify_file}.sha256"

	verify_actual="$(sha256_of "$verify_file")" \
		|| die "未找到可用的 SHA-256 工具（sha256sum / shasum / openssl），已中止安装"
	if ! download_trusted_artifact "${verify_raw_url}.sha256" "${verify_url}.sha256" "$verify_sum_file" " SHA-256 校验文件"; then
		rm -f "$verify_sum_file"
		die "无法直连 GitHub 获取 SHA-256 校验文件（$(describe_direct_failure "${verify_raw_url}.sha256")）：${verify_raw_url}.sha256；使用 --gh-proxy 时默认禁止经代理获取校验文件（代理可同时替换二进制与校验文件）。请检查 github.com 连通性，或确认代理可信后加 --insecure-proxy-checksum 重试"
	fi
	# 校验值统一小写：上游可能发布大写哈希，sha256_of 输出为小写，直接比较会误判失败。
	verify_expected="$(awk 'NF >= 1 { print $1; exit }' "$verify_sum_file" | tr 'A-F' 'a-f')"
	verify_name="$(awk 'NF >= 2 { print $2; exit }' "$verify_sum_file")"
	rm -f "$verify_sum_file"
	case "$verify_name" in
		\**) verify_name="${verify_name#?}";;
	esac
	if [ "${#verify_expected}" -ne 64 ]; then
		die "SHA-256 校验文件格式非法：${verify_raw_url}.sha256（已中止安装）"
	fi
	if printf '%s' "$verify_expected" | grep -q '[^0-9a-fA-F]'; then
		die "SHA-256 校验文件格式非法：${verify_raw_url}.sha256（已中止安装）"
	fi
	if [ -n "$verify_name" ] && [ "$(basename "$verify_name")" != "$verify_asset" ]; then
		die "SHA-256 校验文件与资产不匹配：期望 ${verify_asset}，实际 ${verify_name}（已中止安装）"
	fi
	if [ "$verify_expected" != "$verify_actual" ]; then
		die "SHA-256 校验失败：期望 ${verify_expected}，实际 ${verify_actual}（已中止安装，未覆盖旧二进制）"
	fi
	log "SHA-256 校验通过（${verify_asset}）"
}

# verify_sha256_value <文件> <期望哈希> <资产名>
# 用于 --binary/--sha256 这类不依赖校验文件 URL 的场景；格式非法或不一致一律中止。
verify_sha256_value() {
	value_file="$1"
	value_expected="$(printf '%s' "$2" | tr 'A-Z' 'a-z')"
	value_asset="$3"
	value_actual="$(sha256_of "$value_file")" \
		|| die "未找到可用的 SHA-256 工具（sha256sum / shasum / openssl），已中止安装"
	if [ "${#value_expected}" -ne 64 ]; then
		die "SHA-256 值格式非法：${value_expected}（已中止安装）"
	fi
	if printf '%s' "$value_expected" | grep -q '[^0-9a-f]'; then
		die "SHA-256 值格式非法：${value_expected}（已中止安装）"
	fi
	if [ "$value_actual" != "$value_expected" ]; then
		die "SHA-256 校验失败：期望 ${value_expected}，实际 ${value_actual}（已中止安装，未覆盖旧二进制）"
	fi
	log "SHA-256 校验通过（${value_asset}）"
}

# install_file <源> <目标> <权限>
install_file() {
	if command -v install >/dev/null 2>&1; then
		install -m "$3" "$1" "$2"
	else
		cp -f "$1" "$2" && chmod "$3" "$2"
	fi
}

# make_dir <目录> <权限> [属主] [属组]
make_dir() {
	mkdir -p "$1"
	if [ -n "${3:-}" ] && [ -n "${4:-}" ]; then
		chown "$3:$4" "$1" 2>/dev/null || true
	fi
	chmod "$2" "$1"
}

# prepare_state_dir：确保状态目录（updater 的跳过版本记录等）只对服务用户开放。
# systemd 由 StateDirectoryMode=0700 保证；procd/无 init 系统需要这里显式创建并收紧，
# 与 internal/statedir 的 0700/属主校验保持一致。
prepare_state_dir() {
	# 默认与 systemd StateDirectory 一致；测试/非标准部署可用 MNAGENT_STATE_DIR 覆盖。
	state_dir_path="${MNAGENT_STATE_DIR:-/var/lib/mnagent}"
	if mkdir -p "$state_dir_path" 2>/dev/null; then
		chown "$RUN_USER:$RUN_GROUP" "$state_dir_path" 2>/dev/null || true
		chmod 0700 "$state_dir_path" 2>/dev/null \
			|| warn "无法把状态目录 ${state_dir_path} 设为 0700，请手动执行：chmod 0700 ${state_dir_path}"
	else
		warn "无法创建状态目录 ${state_dir_path}：更新记录会退化到用户缓存目录"
	fi
}

# ---------- 卸载 ----------

if [ "$UNINSTALL" = "yes" ]; then
	log "卸载 $SERVICE_NAME"
	case "$PLATFORM" in
		systemd)
			systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
			systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
			rm -f "$INIT_DIR/$SERVICE_NAME.service"
			systemctl daemon-reload >/dev/null 2>&1 || true
			;;
		openwrt)
			"$INIT_DIR/$SERVICE_NAME" stop >/dev/null 2>&1 || true
			"$INIT_DIR/$SERVICE_NAME" disable >/dev/null 2>&1 || true
			rm -f "$INIT_DIR/$SERVICE_NAME" "/etc/rc.d/S95$SERVICE_NAME" "/etc/rc.d/K95$SERVICE_NAME"
			;;
		*)
			warn "未识别的 init 系统：请手动停止并删除 $SERVICE_NAME"
			;;
	esac
	rm -f "$PREFIX/mnagent" "$PREFIX/mnagent.prev" "$PREFIX/.nexttrace.new" "$PREFIX"/mnagent-upd-*
	if [ "$RUN_USER" != "root" ]; then
		log "已卸载（令牌文件 $TOKEN_FILE 与用户 $RUN_USER 保留，如需一并清理请手动删除）"
	else
		log "已卸载（令牌文件 $TOKEN_FILE 保留，如需一并清理请手动删除）"
	fi
	exit 0
fi

# ---------- 参数校验 ----------

# 自动继承已有服务参数（保留原有配置）
existing_cmd=""
if [ "$PLATFORM" = "systemd" ] && [ -f "$INIT_DIR/$SERVICE_NAME.service" ]; then
	existing_cmd="$(grep -E '^ExecStart=' "$INIT_DIR/$SERVICE_NAME.service" | head -n1 | sed 's/^ExecStart=//' || true)"
elif [ "$PLATFORM" = "openwrt" ] && [ -f "$INIT_DIR/$SERVICE_NAME" ]; then
	# 只取 procd command 这一条（含续行反斜杠），不把后面的 procd_set_param env/respawn
	# 一起吞进来；否则它们会被当成 agent 参数继承下去。
	existing_cmd="$(awk '
		capture == 0 {
			if ($0 ~ /procd_set_param[ \t]+command/) {
				sub(/^.*procd_set_param[ \t]+command[ \t]+/, "")
				capture = 1
			} else {
				next
			}
		}
		{
			n = length($0)
			while (n > 0 && (substr($0, n, 1) == " " || substr($0, n, 1) == "\t")) n--
			cont = (n > 0 && substr($0, n, 1) == "\\")
			printf "%s ", substr($0, 1, n - (cont ? 1 : 0))
			if (!cont) exit
		}
	' "$INIT_DIR/$SERVICE_NAME" 2>/dev/null || true)"
fi

# existing_prefix_from_cmd <existing_cmd>：从 ExecStart / procd command 的首个 token
# 反推安装前缀（仅当首 token 是绝对路径时）。升级时用户没显式传 --prefix 即沿用旧位置。
existing_prefix_from_cmd() {
	prefix_cmd="$1"
	prefix_first="$(printf '%s' "$prefix_cmd" | sed -e 's/^[[:space:]]*//' -e 's/.*procd_set_param command[[:space:]]*//' | awk '{print $1}')"
	prefix_first="$(strip_quotes "$prefix_first")"
	case "$prefix_first" in
		/*/*) dirname "$prefix_first";;
	esac
}

# 运行用户同样从现有 unit/init 脚本继承（仅当用户未显式 --user）。
if [ "$RUN_USER_SET" = "no" ]; then
	inherited_user=""
	if [ "$PLATFORM" = "systemd" ] && [ -f "$INIT_DIR/$SERVICE_NAME.service" ]; then
		inherited_user="$(grep -E '^User=' "$INIT_DIR/$SERVICE_NAME.service" | head -n1 | sed 's/^User=//' | tr -d ' \t\r' || true)"
	elif [ "$PLATFORM" = "openwrt" ] && [ -f "$INIT_DIR/$SERVICE_NAME" ]; then
		inherited_user="$(grep -E '^[[:space:]]*procd_set_param user ' "$INIT_DIR/$SERVICE_NAME" | head -n1 | awk '{print $3}' | tr -d '\r' || true)"
	fi
	if [ -n "$inherited_user" ]; then
		RUN_USER="$inherited_user"
		log "已从现有服务配置继承运行用户: $RUN_USER"
	fi
fi

if [ -n "$existing_cmd" ]; then
	if [ -z "$BOT_URL" ]; then
		extracted_bot="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-bot [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_bot" ]; then
			BOT_URL="$extracted_bot"
			log "已从现有服务配置继承 --bot 地址: $BOT_URL"
		fi
	fi
	if [ -z "$TOKEN" ] && [ ! -s "$TOKEN_FILE" ]; then
		extracted_token_file="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-token-file [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_token_file" ] && [ -f "$extracted_token_file" ]; then
			TOKEN_FILE="$extracted_token_file"
			log "已从现有服务配置继承 --token-file 路径: $TOKEN_FILE"
		fi
	fi
	if [ -z "$GH_PROXY" ]; then
		extracted_proxy="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-gh-proxy [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_proxy" ]; then
			GH_PROXY="$extracted_proxy"
			log "已从现有服务配置继承 --gh-proxy 代理: $GH_PROXY"
		fi
	fi
	if [ "$NEXTTRACE_BIN" = "nexttrace" ]; then
		extracted_nt="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-nexttrace [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_nt" ]; then
			NEXTTRACE_BIN="$extracted_nt"
		fi
	fi
	if [ "$MIAOSPEED_BIN" = "miaospeed" ]; then
		extracted_miao="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-miaospeed [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_miao" ]; then
			MIAOSPEED_BIN="$extracted_miao"
		fi
	fi
	if [ "$TOKEN_FROM_ARG" = "no" ] && printf '%s' "$existing_cmd" | grep -q -- '-token '; then
		# 明文令牌不会继承进新单元（也不写日志）：新的服务命令统一改用 -token-file。
		warn "旧服务配置里使用了明文 -token 参数，已改用 -token-file；请确认 ${TOKEN_FILE} 已包含正确令牌"
	fi
	if [ "$ALLOW_INSECURE_HTTP" = "no" ] && printf '%s' "$existing_cmd" | grep -q -- '-allow-insecure-http'; then
		ALLOW_INSECURE_HTTP="yes"
		log "已从现有服务配置继承 -allow-insecure-http 设置"
	fi
	if [ "$AUTO_UPDATE_SET" = "no" ]; then
		if printf '%s' "$existing_cmd" | grep -q -- '-auto-update'; then
			AUTO_UPDATE="yes"
		else
			AUTO_UPDATE="no"
		fi
		log "已从现有服务配置继承自动更新设置: $AUTO_UPDATE"
	fi
	if [ "$UPDATE_INTERVAL_SET" = "no" ]; then
		extracted_interval="$(strip_quotes "$(printf '%s' "$existing_cmd" | grep -o -- '-update-interval [^ ]*' | head -n1 | awk '{print $2}' || true)")"
		if [ -n "$extracted_interval" ]; then
			UPDATE_INTERVAL="$extracted_interval"
			log "已从现有服务配置继承更新检查间隔: $UPDATE_INTERVAL"
		fi
	fi
	if [ "$PREFIX_SET" = "no" ]; then
		extracted_prefix="$(existing_prefix_from_cmd "$existing_cmd")"
		if [ -n "$extracted_prefix" ]; then
			PREFIX="$extracted_prefix"
			log "已从现有服务配置继承安装前缀: $PREFIX"
		fi
	fi
fi

# tokenize_cmd <命令行>：把旧单元的命令行按 shell 引号规则切成“一行一个 token”。
# 只用 awk 实现，以便在 busybox ash 下运行；不支持反斜杠转义（本脚本生成的单元不会产生）。
tokenize_cmd() {
	printf '%s' "$1" | awk '
		{
			line = $0
			n = length(line); i = 1; tok = ""; quote = ""
			while (i <= n) {
				c = substr(line, i, 1)
				if (quote == "") {
					if (c == "\"" || c == "\047") { quote = c }
					else if (c == " " || c == "\t") { if (tok != "") { print tok; tok = "" } }
					else { tok = tok c }
				} else if (c == quote) { quote = "" }
				else { tok = tok c }
				i++
			}
			if (tok != "") print tok
		}'
}

# 可继承的 agent 常驻参数（与 internal/config 的 flag 定义保持一致）。
# 带取值的参数后必须跟一个值；其余为布尔开关。一次性 CLI 参数（-diag、-version、
# -apply-update 等）不在其中：它们出现在服务命令里会让进程立即退出。
AGENT_VALUE_FLAGS=" -bot -token -token-file -nexttrace -miaospeed -min-backoff -max-backoff -poll-timeout -result-timeout -update-interval -gh-proxy -log-level -log-file "
AGENT_BOOL_FLAGS=" -allow-private-probes -allow-remote-downgrade "
# 由本脚本重新生成的参数：跳过它们及其取值，避免旧值覆盖新值或重复追加。
INSTALLER_REGENERATED_FLAGS=" -bot -token -token-file -nexttrace -miaospeed -auto-update -update-interval -gh-proxy -allow-insecure-http "
# 已从 agent 删除的参数：重跑安装时直接忽略，不能让整批自定义参数被连带丢弃。
# 这里只处理安装脚本的参数继承，agent 侧不保留任何兼容层。
REMOVED_AGENT_FLAGS=" -allow-auto-install-deps "

# collect_extra_agent_args <旧命令行>：提取旧单元里手工追加的 agent 参数
# （-log-level、-min-backoff、-result-timeout、-allow-private-probes 等），
# 输出为以空格开头的参数串（可直接拼进 ExecStart）。
# 重跑安装时这些参数必须原样保留，否则升级会静默改掉行为。
# 无法识别（不在上述白名单）或含不安全字符（空白、引号、%、$、反引号、换行等）、
# 缺少取值的参数会让整批被丢弃并 warn：宁可回退默认参数，也不能写出半截参数
# 导致服务起不来。
# mask_collect_bad_token <token>：把被丢弃参数累积到 collect_bad 时脱敏。
# -token / -token-file 及其取值一律掩码；调用方在“上一个参数缺取值”时
# 会用 *** 代替以 '-' 开头的可疑取值，避免把令牌等秘密回显到终端/日志。
mask_collect_bad_token() {
	mcb_tok="$1"
	if [ "${collect_redact_next:-no}" = "yes" ]; then
		collect_bad="$collect_bad ***"
		collect_redact_next="no"
		return 0
	fi
	mcb_flag="${mcb_tok%%=*}"
	case "$mcb_flag" in
		-token|-token-file|--token|--token-file)
			case "$mcb_tok" in
				*=*) collect_bad="$collect_bad ${mcb_flag}=***";;
				*) collect_bad="$collect_bad $mcb_flag"; collect_redact_next="yes";;
			esac
			return 0
			;;
	esac
	collect_bad="$collect_bad $mcb_tok"
}

collect_extra_agent_args() {
	collect_skip="no"
	collect_first="yes"
	collect_expect="no"
	collect_tokens=""
	collect_bad=""
	collect_redact_next="no"
	collect_skip_secret="no"
	set -f # 关闭通配符展开：token 里的 * ? 不能被当成文件名。
	# 只按换行切分（而不是默认空白）：带引号的值里若有空格，必须整体交给后面的
	# 字符白名单校验并整批拒绝，否则会被拆成「半截值 + 多余参数」写进单元。
	collect_old_ifs="$IFS"
	IFS='
'
	for collect_tok in $(tokenize_cmd "$1"); do
		if [ "$collect_first" = "yes" ]; then
			collect_first="no" # 首个 token 是二进制路径，由本脚本重新生成。
			continue
		fi
		if [ "$collect_skip" = "yes" ]; then
			# 跳过上一个（由本脚本重新生成的）参数的取值；取值可能未加引号并含空格，
			# 因此一直跳到下一个 '-' 开头的参数为止，避免把半截取值当成新参数。
			case "$collect_tok" in
				-*)
					collect_skip="no"
					# -token/-token-file 后面以 '-' 开头的值可能是令牌本身，不得回显。
					if [ "$collect_skip_secret" = "yes" ]; then
						collect_bad="$collect_bad ***"
						collect_skip_secret="no"
						continue
					fi
					;;
				*)
					collect_skip_secret="no"
					continue
					;;
			esac
		fi
		case "$collect_tok" in
			-*)
				# 统一 "--flag" 为 "-flag"，并拆出 "-flag=value" 的内联取值。
				collect_flag="${collect_tok%%=*}"
				collect_inline="no"
				case "$collect_tok" in
					*=*) collect_inline="yes" ;;
				esac
				case "$collect_flag" in
					--*) collect_flag="-${collect_flag#--}" ;;
				esac
				if [ "$collect_expect" = "yes" ]; then
					# 上一个参数缺取值（例如 -log-file -log-level）：整批放弃。
					# 该 token 可能是以 '-' 开头的秘密值，统一掩码，不回显原文。
					collect_bad="$collect_bad ***"
					continue
				fi
				case "$INSTALLER_REGENERATED_FLAGS" in
					*" $collect_flag "*)
						if [ "$collect_flag" = "-token" ] || [ "$collect_flag" = "-token-file" ]; then
							collect_skip_secret="yes"
						else
							collect_skip_secret="no"
						fi
						[ "$collect_inline" = "yes" ] || collect_skip="yes"
						continue
						;;
				esac
				case "$REMOVED_AGENT_FLAGS" in
					*" $collect_flag "*)
						log "已忽略已删除的参数：${collect_flag}" >&2
						continue
						;;
				esac
				case "$AGENT_VALUE_FLAGS" in
					*" $collect_flag "*)
						case "$collect_tok" in
							*[!A-Za-z0-9_./:@+=,-]*) mask_collect_bad_token "$collect_tok"; continue;;
						esac
						collect_tokens="$collect_tokens $collect_tok"
						[ "$collect_inline" = "yes" ] || collect_expect="yes"
						continue
						;;
				esac
				case "$AGENT_BOOL_FLAGS" in
					*" $collect_flag "*)
						case "$collect_tok" in
							*[!A-Za-z0-9_./:@+=,-]*) mask_collect_bad_token "$collect_tok"; continue;;
						esac
						collect_tokens="$collect_tokens $collect_tok"
						continue
						;;
				esac
				# 无法识别的参数：整批放弃并告警，避免拼写错误/一次性参数写进单元。
				mask_collect_bad_token "$collect_tok"
				;;
			*)
				if [ "$collect_expect" = "yes" ]; then
					collect_expect="no"
					case "$collect_tok" in
						*[!A-Za-z0-9_./:@+=,-]*) mask_collect_bad_token "$collect_tok"; continue;;
					esac
					collect_tokens="$collect_tokens $collect_tok"
					continue
				fi
				# 既不是参数、也不是已知参数的取值：整批放弃。
				mask_collect_bad_token "$collect_tok"
				;;
		esac
	done
	IFS="$collect_old_ifs"
	set +f
	if [ "$collect_expect" = "yes" ]; then
		collect_bad="$collect_bad <缺少取值>"
	fi
	if [ -n "$collect_bad" ]; then
		warn "旧服务配置中存在无法识别或不安全的参数，已全部忽略（请重新执行安装命令显式指定）：${collect_bad}"
		return 0
	fi
	# 直接原样输出（不加引号）：经过上面的字符白名单后不可能含空白、引号、$、%、；
	# 等 shell/systemd 特殊字符，因此无需额外引号，单元文件也更易读。
	for collect_tok in $collect_tokens; do
		printf ' %s' "$collect_tok"
	done
	return 0
}

EXTRA_AGENT_ARGS=""
if [ -n "$existing_cmd" ]; then
	EXTRA_AGENT_ARGS="$(collect_extra_agent_args "$existing_cmd")"
	if [ -n "$EXTRA_AGENT_ARGS" ]; then
		log "已从现有服务配置继承附加参数:${EXTRA_AGENT_ARGS}"
	fi
fi

# bot_host_from_url <url>：提取 URL 的 host（去掉 scheme、userinfo、端口与 IPv6 方括号）。
# 全部用 shell 参数展开实现，避免 sed 正则把 IPv6 地址的末段误当成端口。
bot_host_from_url() {
	bot_raw="${1#*://}"
	bot_raw="${bot_raw%%/*}"   # 去掉 path
	bot_raw="${bot_raw%%\?*}"  # 去掉 query
	bot_raw="${bot_raw%%#*}"   # 去掉 fragment
	bot_raw="${bot_raw##*@}"   # 去掉 userinfo
	case "$bot_raw" in
		\[*)
			# [IPv6] 或 [IPv6]:port
			bot_raw="${bot_raw#\[}"
			bot_raw="${bot_raw%%\]*}"
			;;
		*:*)
			# host:port：只有末段全是数字时才当作端口剥掉
			case "${bot_raw##*:}" in
				''|*[!0-9]*) ;;
				*) bot_raw="${bot_raw%:*}" ;;
			esac
			;;
	esac
	printf '%s' "$bot_raw" | tr 'A-Z' 'a-z'
}

# is_local_ipv4 <host>：按 agent 的 net.ParseIP 语义严格解析 IPv4（拒绝前导零/非四段），
# 并只接受回环、私网与链路本地地址。
is_local_ipv4() {
	ilh_host="$1"
	case "$ilh_host" in
		*[!0-9.]*|.*|*.|*..*) return 1;;
	esac
	ilh_old_ifs="$IFS"
	IFS=.
	set -- $ilh_host
	IFS="$ilh_old_ifs"
	[ "$#" -eq 4 ] || return 1
	for ilh_octet in "$@"; do
		case "$ilh_octet" in
			''|0?*) return 1;;
		esac
		[ "${#ilh_octet}" -le 3 ] || return 1
		[ "$ilh_octet" -le 255 ] || return 1
	done
	case "$1" in
		127|10) return 0;;
		192) [ "$2" = "168" ] && return 0;;
		169) [ "$2" = "254" ] && return 0;;
		172) [ "$2" -ge 16 ] && [ "$2" -le 31 ] && return 0;;
	esac
	return 1
}

# is_local_ipv6 <host>：用 awk 严格展开 IPv6（支持 :: 压缩、IPv4 嵌入与 IPv4-mapped），
# 仅接受 ::1、fc00::/7 与 fe80::/10，规则与 agent 的 net.IP.IsLoopback/IsPrivate/
# IsLinkLocalUnicast 保持一致。
is_local_ipv6() {
	case "$1" in
		*:*) ;;
		*) return 1;;
	esac
	case "$1" in
		*[!0-9A-Fa-f:.]*) return 1;;
	esac
	awk -v ip="$1" '
		function hexval(s,   i, v, c) {
			if (s == "" || length(s) > 4) return -1
			v = 0
			for (i = 1; i <= length(s); i++) {
				c = tolower(substr(s, i, 1))
				if (c >= "0" && c <= "9") v = v * 16 + (index("0123456789", c) - 1)
				else if (c >= "a" && c <= "f") v = v * 16 + (index("abcdef", c) + 9)
				else return -1
			}
			return v
		}
		function parse_side(s, A,   n, parts, i, v) {
			PN = 0
			if (s == "") return 0
			n = split(s, parts, ":")
			for (i = 1; i <= n; i++) {
				if (parts[i] == "") return -1
				v = hexval(parts[i])
				if (v < 0) return -1
				A[++PN] = v
			}
			return PN
		}
		function v4_local(a, b, c, d) {
			if (a == 127 || a == 10) return 1
			if (a == 192 && b == 168) return 1
			if (a == 169 && b == 254) return 1
			if (a == 172 && b >= 16 && b <= 31) return 1
			return 0
		}
		BEGIN {
			addr = ip
			if (index(addr, ".")) {
				pos = match(addr, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
				if (pos == 0) exit 1
				v4 = substr(addr, pos)
				addr = substr(addr, 1, pos - 1)
				if (substr(addr, length(addr), 1) != ":") exit 1
				n = split(v4, o, ".")
				if (n != 4) exit 1
				for (i = 1; i <= 4; i++) {
					if (o[i] !~ /^[0-9]+$/ || o[i] + 0 > 255) exit 1
					if (length(o[i]) > 1 && substr(o[i], 1, 1) == "0") exit 1
				}
				addr = addr sprintf("%x:%x", o[1] * 256 + o[2], o[3] * 256 + o[4])
			}
			dbl = index(addr, "::")
			GN = 0
			if (dbl > 0) {
				if (index(substr(addr, dbl + 2), "::") > 0) exit 1
				left = substr(addr, 1, dbl - 1)
				right = substr(addr, dbl + 2)
				lcount = parse_side(left, L)
				if (lcount < 0) exit 1
				rcount = parse_side(right, R)
				if (rcount < 0) exit 1
				if (lcount + rcount > 7) exit 1
				zeros = 8 - lcount - rcount
				for (i = 1; i <= 8; i++) {
					if (i <= lcount) G[i] = L[i]
					else if (i <= lcount + zeros) G[i] = 0
					else G[i] = R[i - lcount - zeros]
				}
			} else {
				count = parse_side(addr, G)
				if (count != 8) exit 1
			}
			if (G[1] == 0 && G[2] == 0 && G[3] == 0 && G[4] == 0 && G[5] == 0 && G[6] == 65535)
				exit v4_local(int(G[7] / 256), G[7] % 256, int(G[8] / 256), G[8] % 256) ? 0 : 1
			if (G[1] == 0 && G[2] == 0 && G[3] == 0 && G[4] == 0 && G[5] == 0 && G[6] == 0 && G[7] == 0 && G[8] == 1) exit 0
			if (G[1] >= 64512 && G[1] <= 65023) exit 0
			if (G[1] >= 65152 && G[1] <= 65215) exit 0
			exit 1
		}
	' >/dev/null 2>&1
}

# is_local_bot_host <host>：判断明文 HTTP 目标是否为回环/内网地址（含 localhost）。
# 必须与 agent 的 isLocalHTTPHost 逐条一致：仅 localhost/*.localhost 与字面回环/私网/
# 链路本地 IP 算本地；*.lan/*.local、单标签主机名及字符串前缀（10.example.com、fdic.example.com）
# 都不算，否则会误判为本地而不传 -allow-insecure-http，装完 agent 直接拒启。
is_local_bot_host() {
	case "$1" in
		''|localhost|*.localhost) return 0;;
	esac
	is_local_ipv4 "$1" && return 0
	is_local_ipv6 "$1" && return 0
	return 1
}

[ -n "$BOT_URL" ] || die "缺少 --bot"
validate_url_safe "$BOT_URL" "--bot"
# agent 会拒绝这些形态（客户端直接在地址后拼接 /jobs、/results），
# 安装阶段就拦住，避免装完才因 agent 退出而陷入重启循环。
case "$BOT_URL" in
	*'?'*) die "-bot 不允许包含查询参数（?）：agent 会直接在地址后拼接 /jobs 等路径";;
	*'#'*) die "-bot 不允许包含 fragment（#）";;
esac
bot_authority="${BOT_URL#*://}"
bot_authority="${bot_authority%%/*}"
case "$bot_authority" in
	*@*) die "-bot 不允许包含 userinfo（user:pass@），凭据请改用 --token / --token-file / --token-stdin";;
esac
case "$BOT_URL" in
	http://*)
		bot_host="$(bot_host_from_url "$BOT_URL")"
		if [ -n "$bot_host" ] && ! is_local_bot_host "$bot_host"; then
			if [ "$ALLOW_INSECURE_HTTP" = "yes" ]; then
				warn "-bot 使用明文 HTTP 连接 ${bot_host}：令牌与任务内容可能被窃听，请仅在可信网络使用"
			else
				die "-bot 使用明文 HTTP 连接非回环/内网地址 ${bot_host}，agent 会拒绝启动（令牌与任务内容可能被窃听）。请改用 https://，或确需如此时显式加 --allow-insecure-http"
			fi
		fi
		;;
esac
if [ -n "$GH_PROXY" ]; then
	validate_url_safe "$GH_PROXY" "--gh-proxy"
fi

# 统一白名单校验：以下值都会写入 systemd/procd 单元或下载/编译命令，
# 必须在生成单元、创建用户、写文件之前从源头阻断换行/引号/空白等注入字符。
validate_abs_path "$TOKEN_FILE" "--token-file"
validate_abs_path "$PREFIX" "--prefix"
validate_bin_ref "$NEXTTRACE_BIN" "--nexttrace"
validate_bin_ref "$MIAOSPEED_BIN" "--miaospeed"
validate_duration "$UPDATE_INTERVAL" "--update-interval"
validate_user_name "$RUN_USER"
validate_release_tag "$MIAOSPEED_VERSION" "--miaospeed-version"
validate_release_tag "$VERSION" "--version"
validate_repo_ref "$REPO"
if [ -n "$INIT_DIR" ]; then
	validate_abs_path "$INIT_DIR" "MNAGENT_INIT_DIR"
fi

# 令牌可由 --token-stdin 或 MNAGENT_TOKEN 提供，避免明文出现在 argv/ps/命令历史中。
# 注：'-' 的归一化已在解析参数后、继承旧 unit 之前完成（见上方）。
if [ "$TOKEN_STDIN" = "yes" ] && [ -z "$TOKEN" ]; then
	# 交互式终端输入令牌时关闭回显，避免令牌留在屏幕/终端记录里；
	# 用 trap 0 保证读取失败、Ctrl-C 或 die 等任何退出路径都会恢复回显。
	stty_restore="no"
	if [ -t 0 ] && command -v stty >/dev/null 2>&1; then
		STTY_SAVED="$(stty -g 2>/dev/null || true)"
		if [ -n "${STTY_SAVED:-}" ]; then
			trap 'stty "$STTY_SAVED" 2>/dev/null || true' 0 1 2 15
			stty -echo 2>/dev/null && stty_restore="yes"
		fi
		printf '请输入接入令牌（输入不回显）：' >&2
	fi
	IFS= read -r TOKEN || {
		[ "$stty_restore" = "yes" ] && stty "$STTY_SAVED" 2>/dev/null || true
		die "从标准输入读取令牌失败（管道安装时 stdin 已被脚本占用，请改用 --token-file 或 MNAGENT_TOKEN）"
	}
	TOKEN="$(printf '%s' "$TOKEN" | tr -d '\r\n')"
	if [ "$stty_restore" = "yes" ]; then
		stty "$STTY_SAVED" 2>/dev/null || true
	fi
	trap - 0 1 2 15
	[ -n "$TOKEN" ] || die "从标准输入读取到空令牌"
	log "已从标准输入读取令牌"
fi
if [ -z "$TOKEN" ] && [ -n "${MNAGENT_TOKEN:-}" ]; then
	TOKEN="$MNAGENT_TOKEN"
	log "已从环境变量 MNAGENT_TOKEN 读取令牌"
fi
if [ "$TOKEN_FROM_ARG" = "yes" ]; then
	warn "使用 --token 会把令牌暴露在进程 argv 与命令历史中，建议改用 --token-file、MNAGENT_TOKEN 或 --token-stdin"
fi

# 安装二进制前注册退出清理：die / Ctrl-C / 任意非零退出都会删除半成品文件。
# 放在 stty 的 trap 清理之后注册，避免被 `trap - 0 1 2 15` 一并清掉。
trap 'cleanup_partial_install' 0 1 2 15

# ---------- 安装二进制 ----------

build_from_source() {
	command -v go >/dev/null 2>&1 || die "未找到 go：请先安装 Go，或用 --binary 指定已编译好的 mnagent"
	tmp="$(mktemp -d)"
	log "下载源码并编译（${VERSION}）"
	src_url="https://github.com/$REPO/archive/refs/tags/${VERSION}.tar.gz"
	if [ "$VERSION" = "latest" ]; then
		src_url="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
		warn "================================================================"
		warn "--from-source 在 --version latest 时编译 main 分支最新代码（可能包含未发布改动）！"
		warn "生产环境请用 --version <已发布标签> 编译固定版本。"
		warn "================================================================"
	fi
	download_stdout "$(apply_gh_proxy "$src_url")" | tar -xz -C "$tmp"
	dir="$(ls -d "$tmp"/*/ | head -n1)"
	# 先编译到同目录临时文件再原子 rename：编译失败/中断时不会把正在运行或已安装的
	# mnagent 覆盖成半成品；临时文件落在 $PREFIX 内，rename 才能保证同文件系统原子替换。
	build_out="$PREFIX/.mnagent.build.$$"
	if ! ( cd "$dir" && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$build_out" ./cmd/mnagent ); then
		rm -f "$build_out"
		rm -rf "$tmp"
		die "从源码编译 mnagent 失败（版本 ${VERSION}）"
	fi
	chmod 0755 "$build_out" 2>/dev/null || true
	if ! mv -f "$build_out" "$PREFIX/mnagent"; then
		rm -f "$build_out"
		rm -rf "$tmp"
		die "安装编译产物失败：$PREFIX 不可写"
	fi
	rm -rf "$tmp"
}

download_release() {
	asset="mnagent_${OS}_${ARCH}"
	raw_url="https://github.com/$REPO/releases/latest/download/${asset}"
	if [ "$VERSION" != "latest" ]; then
		raw_url="https://github.com/$REPO/releases/download/${VERSION}/${asset}"
	fi
	url="$(apply_gh_proxy "$raw_url")"
	log "下载 mnagent（${VERSION}，${OS}/${ARCH}）"
	download "$url" "$PREFIX/.mnagent.new" || return 1
	verify_sha256 "$PREFIX/.mnagent.new" "$raw_url" "$asset"
	install_file "$PREFIX/.mnagent.new" "$PREFIX/mnagent" 0755 \
		|| die "安装下载的 mnagent 到 $PREFIX/mnagent 失败（请检查磁盘空间与目录权限）"
	rm -f "$PREFIX/.mnagent.new"
}

mkdir -p "$PREFIX"
# 安装前保留现有二进制：冒烟测试失败时回滚，避免把可用的旧版本覆盖成坏文件。
if [ -f "$PREFIX/mnagent" ]; then
	cp -p "$PREFIX/mnagent" "$PREFIX/mnagent.prev" \
		|| die "备份现有 $PREFIX/mnagent 到 $PREFIX/mnagent.prev 失败（请检查磁盘空间与目录权限）"
	log "已备份现有 mnagent 到 $PREFIX/mnagent.prev"
fi
case "$MODE" in
	binary)
		if [ -f "$BINARY_SRC" ]; then
			if [ -n "$BINARY_SHA256" ]; then
				verify_sha256_value "$BINARY_SRC" "$BINARY_SHA256" "mnagent"
			else
				warn "--binary 指向本地文件但未提供 --sha256：无法校验完整性，将继续安装；建议补充 --sha256 <hex> 校验来源"
			fi
			install_file "$BINARY_SRC" "$PREFIX/mnagent" 0755 \
				|| die "安装本地 --binary 到 $PREFIX/mnagent 失败（请检查磁盘空间与目录权限）"
		else
			log "下载 mnagent：$BINARY_SRC"
			tmp_bin="$PREFIX/.mnagent.new"
			download "$BINARY_SRC" "$tmp_bin" || die "下载失败：$BINARY_SRC"
			if [ -n "$BINARY_SHA256" ]; then
				# 用户显式给出哈希：强制校验，失败即中止（不覆盖已有二进制）。
				verify_sha256_value "$tmp_bin" "$BINARY_SHA256" "mnagent"
			elif download "${BINARY_SRC}.sha256" "${tmp_bin}.sha256"; then
				# 未给 --sha256 时尝试同目录校验文件；只要拿到了就按它校验。
				sum_expected="$(awk 'NF >= 1 { print $1; exit }' "${tmp_bin}.sha256")"
				sum_name="$(awk 'NF >= 2 { print $2; exit }' "${tmp_bin}.sha256")"
				rm -f "${tmp_bin}.sha256"
				case "$sum_name" in
					\**) sum_name="${sum_name#?}";;
				esac
				if [ -n "$sum_name" ] && [ "$(basename "$sum_name")" != "mnagent" ]; then
					die "SHA-256 校验文件与资产不匹配：期望 mnagent，实际 ${sum_name}（已中止安装）"
				fi
				verify_sha256_value "$tmp_bin" "$sum_expected" "mnagent"
			else
				rm -f "${tmp_bin}.sha256"
				if [ "$INSECURE_SKIP_VERIFY" = "yes" ]; then
					warn "================================================================"
					warn "已显式指定 --insecure-skip-verify：无法获取 ${BINARY_SRC}.sha256，将跳过完整性校验继续安装！"
					warn "你已自行承担来源不可信的风险，请确认该地址可信（内网镜像/自建分发需自行负责）。"
					warn "================================================================"
				else
					rm -f "$tmp_bin"
					die "无法获取 ${BINARY_SRC}.sha256，已中止安装（默认拒绝未校验的 --binary 下载）。请改用 --sha256 <hex> 提供校验值，或确认来源可信后显式加 --insecure-skip-verify"
				fi
			fi
			install_file "$tmp_bin" "$PREFIX/mnagent" 0755 \
				|| die "安装下载的 --binary 到 $PREFIX/mnagent 失败（请检查磁盘空间与目录权限）"
			rm -f "$tmp_bin"
		fi
		;;
	source)
		build_from_source
		;;
	auto)
		# Release 下载失败不再自动改为“编译 main 分支”——那会把用户从固定版本悄悄带到
		# 未发布的移动代码。需要源码编译必须显式 --from-source。
		download_release || die "下载 ${OS}/${ARCH} 的 Release 产物失败：该架构可能暂无产物，或网络受限。本脚本不会自动从源码编译；如确需源码编译请加 --from-source，或用 --binary <本地或镜像地址> 指定二进制，例如 --binary https://github.com/$REPO/releases/latest/download/mnagent_${OS}_${ARCH}"
		;;
esac
[ -x "$PREFIX/mnagent" ] || die "mnagent 安装失败"
# 安装后冒烟测试：架构/字节序不匹配、二进制损坏或缺少执行依赖时立即报错，
# 而不是等注册服务后才发现进程起不来（--from-source/--binary/auto 都覆盖）。
if ! mnagent_version_out="$("$PREFIX/mnagent" -version 2>&1)"; then
	smoke_detail="请检查架构/字节序是否匹配，例如 MNAGENT_ENDIAN=le，或二进制是否损坏"
	if [ ! -f "$PREFIX/mnagent.prev" ]; then
		die "安装的二进制无法运行（架构/字节序？），未找到可回滚的旧版本：$PREFIX/mnagent -version 执行失败：${mnagent_version_out:-无输出}；${smoke_detail}"
	fi
	if install_file "$PREFIX/mnagent.prev" "$PREFIX/mnagent" 0755; then
		if smoke_recovered_out="$("$PREFIX/mnagent" -version 2>&1)"; then
			die "安装后冒烟测试失败：$PREFIX/mnagent -version 无法执行（${smoke_detail}）：${mnagent_version_out:-无输出}；已回滚到 $PREFIX/mnagent.prev（恢复后的 -version 输出：${smoke_recovered_out}）"
		fi
		die "安装后冒烟测试失败：$PREFIX/mnagent -version 无法执行（${smoke_detail}）：${mnagent_version_out:-无输出}；已回滚到 $PREFIX/mnagent.prev，但恢复后的文件仍无法运行（${smoke_recovered_out:-无输出}），需要人工介入"
	fi
	die "安装后冒烟测试失败：$PREFIX/mnagent -version 无法执行（${smoke_detail}）：${mnagent_version_out:-无输出}；且回滚失败，请手动恢复 $PREFIX/mnagent.prev"
fi
mnagent_version_out="$(printf '%s' "$mnagent_version_out" | head -n1 | tr -d '\r')"
log "已安装 $PREFIX/mnagent（${mnagent_version_out:-版本未知}）"

# ---------- 运行用户 ----------

# 默认以 root 运行（便于自动更新替换二进制、调用网络诊断工具与重启服务）；
# 若指定了非 root 用户，则创建专用系统用户。
if [ "$RUN_USER" != "root" ]; then
	if ! id -u "$RUN_USER" >/dev/null 2>&1; then
		log "创建系统用户 $RUN_USER"
		if command -v useradd >/dev/null 2>&1; then
			useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER" 2>/dev/null \
				|| useradd -r -s /sbin/nologin "$RUN_USER" \
				|| die "创建用户 $RUN_USER 失败"
		elif command -v adduser >/dev/null 2>&1; then
			# BusyBox adduser：-S 系统用户、-D 不设密码、-H 不建主目录
			adduser -S -D -H -s /sbin/nologin "$RUN_USER" 2>/dev/null \
				|| adduser -S -D -H "$RUN_USER" \
				|| die "创建用户 $RUN_USER 失败"
		else
			die "系统缺少 useradd/adduser，无法创建用户 ${RUN_USER}（可用 --user root 直接以 root 运行）"
		fi
	fi
else
	log "以 root 运行"
fi
# 语法已由 validate_user_name 保证；这里确认用户真实存在（新创建的用户也应能解析）。
id -u "$RUN_USER" >/dev/null 2>&1 || die "运行用户 $RUN_USER 不存在或无法解析"
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"
# 主组名会被写入 systemd 的 Group=，也会作为 chown 的组名，必须与用户名同样做白名单
# 校验（禁止空白/引号/换行/控制字符）。不合法时回退为用户名（同名校验会在 chown
# 失败时降级为仅改属主），并明确告警，而不是把可疑值写进单元。
case "$RUN_GROUP" in
	''|-*|*[!A-Za-z0-9_.-]*)
		warn "运行用户 ${RUN_USER} 的主组名（${RUN_GROUP}）不合法，回退为 ${RUN_USER}；如服务用户无法读取令牌，请确认该组存在并手动修正 Group="
		RUN_GROUP="$RUN_USER"
		;;
esac

# ---------- 令牌 ----------

# 令牌目录：root 拥有、服务用户主组可进入（0750），令牌文件本身 0600 归服务用户。
# 服务用户必须能“穿过”该目录才能读到文件：目录若是 root:root 0750，非 root 服务
# 会因 EACCES 直接退出（mnagent 启动时报“读取令牌失败: permission denied”）。
TOKEN_DIR="$(dirname "$TOKEN_FILE")"
if [ ! -d "$TOKEN_DIR" ]; then
	make_dir "$TOKEN_DIR" 0750 root "$RUN_GROUP"
elif [ "$TOKEN_DIR" = "/etc/mnagent" ]; then
	# 默认目录：修正旧版本可能留下的 root:root 0750（服务用户无法进入）
	chown root:"$RUN_GROUP" "$TOKEN_DIR" 2>/dev/null || true
	chmod 0750 "$TOKEN_DIR"
else
	warn "使用自定义令牌目录 ${TOKEN_DIR}：未改动其权限，请确认 $RUN_USER 能读取 ${TOKEN_FILE}"
fi

if [ -n "$TOKEN" ]; then
	umask 077
	printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
	chown "$RUN_USER":"$RUN_GROUP" "$TOKEN_FILE" 2>/dev/null || chown "$RUN_USER" "$TOKEN_FILE" 2>/dev/null || true
	chmod 0600 "$TOKEN_FILE"
	log "已写入令牌 ${TOKEN_FILE}（0600，属主 ${RUN_USER}）"
elif [ ! -s "$TOKEN_FILE" ]; then
	die "缺少 --token，且 $TOKEN_FILE 不存在；请使用 /host 生成的完整命令"
else
	chown "$RUN_USER":"$RUN_GROUP" "$TOKEN_FILE" 2>/dev/null || chown "$RUN_USER" "$TOKEN_FILE" 2>/dev/null || true
fi

# 自检：以服务用户身份确认能读到令牌（目录缺少进入权限时，非 root 服务启动即退出）。
if [ "$RUN_USER" != "root" ]; then
	if command -v runuser >/dev/null 2>&1; then
		runuser -u "$RUN_USER" -- test -r "$TOKEN_FILE" 2>/dev/null \
			|| warn "服务用户 $RUN_USER 读不到 ${TOKEN_FILE}：请确认 $TOKEN_DIR 的属主/权限为 root:$RUN_GROUP 0750"
	elif command -v su >/dev/null 2>&1; then
		su -s /bin/sh -c "test -r '$TOKEN_FILE'" "$RUN_USER" 2>/dev/null \
			|| warn "服务用户 $RUN_USER 读不到 ${TOKEN_FILE}：请确认 $TOKEN_DIR 的属主/权限为 root:$RUN_GROUP 0750"
	fi
fi

# find_binary <名称或路径>：在系统 PATH 及常用二进制目录中查找可执行文件。
# 兼容 OpenWrt / BusyBox 等 PATH 默认不包含 /usr/local/bin 的环境。
find_binary() {
	_target="$1"
	if [ -f "$_target" ] && [ -x "$_target" ]; then
		printf '%s' "$_target"
		return 0
	fi
	_found="$(command -v "$_target" 2>/dev/null || true)"
	if [ -n "$_found" ] && [ -x "$_found" ]; then
		printf '%s' "$_found"
		return 0
	fi
	for _dir in "$PREFIX" /usr/local/bin /usr/bin /bin /usr/sbin /sbin; do
		if [ -n "$_dir" ] && [ -x "$_dir/$_target" ]; then
			printf '%s' "$_dir/$_target"
			return 0
		fi
	done
	return 1
}

# safe_exec_or_bare <解析后路径> <裸名> <标签>
# 解析后的真实路径同样会写入服务单元：PATH 中可能包含带空白/引号/非 ASCII 的文件名，
# 这类值不能写进 unit。此时不中止安装（二进制本身可用），而是告警并回退为裸名，
# 由服务运行时的 PATH 查找；绝不把不安全值写进单元。
safe_exec_or_bare() {
	safe_exec_value="$1"
	safe_exec_bare="$2"
	safe_exec_label="$3"
	case "$safe_exec_value" in
		/*) ;;
		*) printf '%s' "$safe_exec_bare"; return 0;;
	esac
	safe_exec_leftover="$(printf '%s' "$safe_exec_value" | LC_ALL=C tr -d 'A-Za-z0-9_./@:+-')"
	if [ -n "$safe_exec_leftover" ]; then
		warn "${safe_exec_label} 的解析路径含不能写入服务单元的字符：${safe_exec_value}"
		warn "已回退为裸名 ${safe_exec_bare}（由服务 PATH 查找）。如需固定使用该二进制，请把它移动到无空格/特殊字符的路径，或改用绝对路径参数。"
		printf '%s' "$safe_exec_bare"
		return 0
	fi
	printf '%s' "$safe_exec_value"
}

map_nexttrace_arch() {
	case "$1" in
		amd64) echo "amd64";;
		arm64) echo "arm64";;
		arm)   echo "armv7";;
		386)   echo "386";;
		mips)  echo "mips";;
		mipsle) echo "mipsle";;
		mips64) echo "mips64";;
		mips64le) echo "mips64le";;
		riscv64) echo "riscv64";;
		*) echo "$1";;
	esac
}

download_nexttrace() {
	nt_arch="$(map_nexttrace_arch "$ARCH")"
	nt_asset="nexttrace_${OS}_${nt_arch}"
	if [ "$OS" = "darwin" ]; then
		nt_asset="nexttrace_darwin_universal"
	fi
	url="https://github.com/nxtrace/NTrace-core/releases/latest/download/${nt_asset}"
	url="$(apply_gh_proxy "$url")"
	if [ -n "$GH_PROXY" ]; then
		log "通过 GitHub 代理下载 nexttrace（${OS}/${nt_arch}，代理：${GH_PROXY}）"
	else
		log "从 GitHub Releases 下载 nexttrace（${OS}/${nt_arch}）"
	fi
	if ! download "$url" "$PREFIX/.nexttrace.new"; then
		return 1
	fi
	# 依赖不再做 SHA-256 校验（上游未发布对应 .sha256）：仅经 HTTPS 下载，
	# 由 mnagent 安装后的 -V/-version 自检确认可执行与版本。
	install_file "$PREFIX/.nexttrace.new" "$PREFIX/nexttrace" 0755 \
		|| die "安装 nexttrace 到 $PREFIX/nexttrace 失败（请检查磁盘空间与目录权限）"
	rm -f "$PREFIX/.nexttrace.new"
	NEXTTRACE_PATH="$PREFIX/nexttrace"
}

NEXTTRACE_PATH="$(find_binary "$NEXTTRACE_BIN" || true)"

# 缺少 nexttrace 时自动安装：
# 1. OpenWrt opkg 包管理器（保留原有分支）
# 2. GitHub Releases 预编译二进制，仅经 HTTPS 下载（依赖不做 SHA-256 校验）
# 不再执行远端一键脚本（curl https://nxtrace.org/nt | bash），避免以 root 运行未固定版本的远端代码。
if [ -z "$NEXTTRACE_PATH" ] && [ "$INSTALL_NEXTTRACE" = "yes" ]; then
	log "环境缺少 nexttrace，正在安装..."
	# 1. 如果是 OpenWrt / ImmortalWrt 且有 opkg，优先尝试包管理器官方包
	if [ "$PLATFORM" = "openwrt" ] && command -v opkg >/dev/null 2>&1; then
		log "尝试通过 opkg 安装 nexttrace"
		opkg update >/dev/null 2>&1 || true
		opkg install nexttrace >/dev/null 2>&1 || true
		NEXTTRACE_PATH="$(find_binary "$NEXTTRACE_BIN" || true)"
	fi

	# 2. 直接从 GitHub Releases 下载预编译二进制（不做 SHA-256 校验）
	if [ -z "$NEXTTRACE_PATH" ]; then
		download_nexttrace || true
		# 下载成功时 download_nexttrace 已设置 NEXTTRACE_PATH；不要再用 PATH 中的同名文件覆盖它。
		[ -n "$NEXTTRACE_PATH" ] || NEXTTRACE_PATH="$(find_binary "$NEXTTRACE_BIN" || true)"
	fi

	if [ -n "$NEXTTRACE_PATH" ]; then
		log "nexttrace 安装成功：${NEXTTRACE_PATH}"
	else
		warn "自动安装 nexttrace 失败，请参考官方说明手动安装：https://github.com/nxtrace/NTrace-core"
	fi
fi

# 若已安装在非 PATH 常用目录（如 /usr/local/bin/nexttrace），在 OpenWrt 下自动建立软链接到 $PREFIX 保证全局可用
if [ "$PLATFORM" = "openwrt" ] && [ -n "$NEXTTRACE_PATH" ] && [ -x "$NEXTTRACE_PATH" ]; then
	if [ "$NEXTTRACE_PATH" != "$PREFIX/nexttrace" ] && [ ! -e "$PREFIX/nexttrace" ]; then
		ln -sf "$NEXTTRACE_PATH" "$PREFIX/nexttrace" 2>/dev/null \
			&& log "已建立软链接：${PREFIX}/nexttrace -> ${NEXTTRACE_PATH}" || true
		NEXTTRACE_PATH="$PREFIX/nexttrace"
	fi
fi

[ -n "$NEXTTRACE_PATH" ] || warn "未找到 nexttrace（${NEXTTRACE_BIN}）：请安装后再试，否则追踪会失败"
# 解析后的真实路径同样进入服务单元：PATH 中可能包含带空白/引号的可疑文件名。
# 不合白名单时告警并回退为裸名（依赖运行时 PATH），而不是 die 或写入不安全值。
NEXTTRACE_BARE="nexttrace"
case "$NEXTTRACE_BIN" in
	*/*) ;;
	*) NEXTTRACE_BARE="$NEXTTRACE_BIN";;
esac
NEXTTRACE_EXEC="$(safe_exec_or_bare "${NEXTTRACE_PATH:-$NEXTTRACE_BIN}" "$NEXTTRACE_BARE" "nexttrace 可执行路径")"

map_miaospeed_arch() {
	case "$1" in
		amd64) echo "amd64";;
		arm64) echo "arm64";;
		armv7) echo "armv7";;
		armv6) echo "armv6";;
		386)   echo "386";;
		mips)  echo "mips-softfloat";;
		mipsle) echo "mipsle-softfloat";;
		riscv64) echo "riscv64";;
		*) echo "$1";;
	esac
}

# has_enough_space <目录> <需要 KB>：用 busybox 可用的 df -k 做粗略空间检查。
# 无法读取可用空间时返回 0（不因 df 缺字段而阻止安装）。
has_enough_space() {
	space_dir="$1"
	space_need_kb="$2"
	space_avail_kb="$(df -k "$space_dir" 2>/dev/null | awk 'NR == 2 { print $4; exit }')"
	case "$space_avail_kb" in
		""|*[!0-9]*) return 0;;
	esac
	[ "$space_avail_kb" -ge "$space_need_kb" ]
}

download_miaospeed() {
	miao_arch="$(map_miaospeed_arch "$ARCH")"
	miao_tag="${MIAOSPEED_VERSION:-latest}"

	if [ "$miao_tag" = "latest" ] || [ -z "$miao_tag" ]; then
		# 1. 优先尝试从 GitHub Releases API 获取最新版本（api.github.com 不走代理）
		api_url="https://api.github.com/repos/AirportR/miaospeed/releases/latest"
		tag_query="$(download_stdout "$api_url" 2>/dev/null | grep '"tag_name":' | head -n1 | sed -r 's/.*"tag_name": *"([^"]+)".*/\1/' | tr -d '\r\n' || true)"
		if [ -n "$tag_query" ]; then
			miao_tag="$tag_query"
		fi

		# 2. 若 API 查询失败，尝试从 releases/latest 重定向 Location 头解析
		if [ "$miao_tag" = "latest" ] || [ -z "$miao_tag" ]; then
			if command -v curl >/dev/null 2>&1; then
				loc_tag="$(curl -sIL "https://github.com/AirportR/miaospeed/releases/latest" 2>/dev/null | grep -i '^location:' | head -n1 | sed -r 's#.*tag/([^/[:space:]]+).*#\1#' | tr -d '\r\n' || true)"
				if [ -n "$loc_tag" ]; then
					miao_tag="$loc_tag"
				fi
			fi
		fi

		# 3. 若仍未获取到，尝试从 releases.atom 提取
		if [ "$miao_tag" = "latest" ] || [ -z "$miao_tag" ]; then
			atom_tag="$(download_stdout "https://github.com/AirportR/miaospeed/releases.atom" 2>/dev/null | grep -o 'releases/tag/[^"]*' | head -n1 | sed 's#releases/tag/##' | tr -d '\r\n' || true)"
			if [ -n "$atom_tag" ]; then
				miao_tag="$atom_tag"
			fi
		fi

		# 4. 极端离线/网络受限下的安全保底版本
		if [ "$miao_tag" = "latest" ] || [ -z "$miao_tag" ]; then
			miao_tag="4.7.7"
		fi
	fi

	tar_name="miaospeed-${OS}-${miao_arch}-${miao_tag}.tar.gz"
	url="https://github.com/AirportR/miaospeed/releases/download/${miao_tag}/${tar_name}"
	url="$(apply_gh_proxy "$url")"

	# 临时目录放在 $PREFIX 下而不是 /tmp：OpenWrt 的 /tmp 是 tmpfs，压缩包与
	# 解压后的二进制会直接占用内存。该目录已纳入 cleanup_partial_install 清理。
	tmp="$PREFIX/.miaospeed.tmp.$$"
	MIAOSPEED_TMP_DIR="$tmp"
	if ! has_enough_space "$PREFIX" 40960; then
		warn "安装目录 $PREFIX 可用空间不足 40MB，已跳过 miaospeed 自动安装（可清理空间后重试，或手动安装 miaospeed）"
		return 1
	fi
	rm -rf "$tmp" 2>/dev/null || true
	if ! mkdir -p "$tmp"; then
		warn "无法创建 miaospeed 临时目录：$tmp，已跳过自动安装"
		MIAOSPEED_TMP_DIR=""
		return 1
	fi
	if [ -n "$GH_PROXY" ]; then
		log "通过 GitHub 代理下载 miaospeed（版本：${miao_tag}，${OS}/${miao_arch}，代理：${GH_PROXY}）"
	else
		log "下载 miaospeed（版本：${miao_tag}，${OS}/${miao_arch}）"
	fi
	if ! download "$url" "$tmp/miaospeed.tar.gz"; then
		warn "下载 miaospeed 失败：${url}"
		rm -rf "$tmp"
		return 1
	fi
	# 依赖不再做 SHA-256 校验（上游未发布对应 .sha256）：仅经 HTTPS 下载，
	# 由 mnagent 安装后的 -V/-version 自检确认可执行与版本。

	tar -xzf "$tmp/miaospeed.tar.gz" -C "$tmp" 2>/dev/null || tar -xz -f "$tmp/miaospeed.tar.gz" -C "$tmp" 2>/dev/null || true
	# 按确切文件名取二进制：常规 release 为 miaospeed-<os>-<arch>，
	# 4.7.11 起部分 amd64 归档改用 runner/runner，同样按固定路径匹配，不使用“第一个类似文件”。
	miao_bin_name="miaospeed-${OS}-${miao_arch}"
	miao_file=""
	for miao_candidate in "$tmp/${miao_bin_name}" "$tmp/runner/runner"; do
		if [ -f "$miao_candidate" ] && [ ! -L "$miao_candidate" ]; then
			miao_file="$miao_candidate"
			break
		fi
	done
	if [ -n "$miao_file" ]; then
		install_file "$miao_file" "$PREFIX/miaospeed" 0755 \
			|| die "安装 miaospeed 到 $PREFIX/miaospeed 失败（请检查磁盘空间与目录权限）"
		chmod 0755 "$PREFIX/miaospeed" 2>/dev/null || true
	else
		warn "miaospeed 压缩包内未找到预期二进制（${miao_bin_name}），已跳过安装"
		rm -rf "$tmp"
		return 1
	fi
	rm -rf "$tmp"
}

MIAOSPEED_PATH="$(find_binary "$MIAOSPEED_BIN" || true)"

# 缺少 miaospeed 时，尝试从 GitHub Releases 自动下载安装
if [ -z "$MIAOSPEED_PATH" ] && [ "$INSTALL_MIAOSPEED" = "yes" ]; then
	log "环境缺少 miaospeed，正在从 AirportR/miaospeed 获取并安装..."
	download_miaospeed || true
	MIAOSPEED_PATH="$(find_binary "$MIAOSPEED_BIN" || true)"
	if [ -n "$MIAOSPEED_PATH" ]; then
		log "miaospeed 安装成功：${MIAOSPEED_PATH}"
	else
		warn "自动安装 miaospeed 失败，如需测速请参考官方说明手动安装：https://github.com/AirportR/miaospeed"
	fi
fi

# 在 OpenWrt 下若位于非 $PREFIX 目录，同样建立软链接
if [ "$PLATFORM" = "openwrt" ] && [ -n "$MIAOSPEED_PATH" ] && [ -x "$MIAOSPEED_PATH" ]; then
	if [ "$MIAOSPEED_PATH" != "$PREFIX/miaospeed" ] && [ ! -e "$PREFIX/miaospeed" ]; then
		ln -sf "$MIAOSPEED_PATH" "$PREFIX/miaospeed" 2>/dev/null \
			&& log "已建立软链接：${PREFIX}/miaospeed -> ${MIAOSPEED_PATH}" || true
		MIAOSPEED_PATH="$PREFIX/miaospeed"
	fi
fi

MIAOSPEED_BARE="miaospeed"
case "$MIAOSPEED_BIN" in
	*/*) ;;
	*) MIAOSPEED_BARE="$MIAOSPEED_BIN";;
esac
MIAOSPEED_EXEC="$(safe_exec_or_bare "${MIAOSPEED_PATH:-$MIAOSPEED_BIN}" "$MIAOSPEED_BARE" "miaospeed 可执行路径")"

# 附加到服务命令的公共参数（systemd 与 procd 共用）：自动更新、GitHub 代理，
# 以及公网明文 --bot 所需的 -allow-insecure-http。
AUTO_UPDATE_ARGS=""
if [ "$AUTO_UPDATE" = "yes" ]; then
	AUTO_UPDATE_ARGS=" -auto-update -update-interval \"$UPDATE_INTERVAL\""
fi
if [ "$ALLOW_INSECURE_HTTP" = "yes" ]; then
	AUTO_UPDATE_ARGS="$AUTO_UPDATE_ARGS -allow-insecure-http"
fi
if [ -n "$GH_PROXY" ]; then
	AUTO_UPDATE_ARGS="$AUTO_UPDATE_ARGS -gh-proxy \"$GH_PROXY\""
fi

# ---------- 安装服务 ----------

install_systemd_unit() {
	# 原始套接字能力由服务携带（ambient）并传给子进程 nexttrace：与 NoNewPrivileges
	# 兼容，也不依赖对 nexttrace 二进制执行 setcap（二进制被升级/重装后依然有效）。
	cat > "$INIT_DIR/$SERVICE_NAME.service" <<EOF
[Unit]
Description=mnagent (nexttrace agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
ExecStart="$PREFIX/mnagent" -bot "$BOT_URL" -token-file "$TOKEN_FILE" -nexttrace "$NEXTTRACE_EXEC" -miaospeed "$MIAOSPEED_EXEC"$AUTO_UPDATE_ARGS$EXTRA_AGENT_ARGS
	# nexttrace 需要可写的主目录来存放配置与 IP 库；ProtectSystem=strict 下只有
	# StateDirectory 指向的目录可写。
	StateDirectory=mnagent
	# 跳过版本/依赖状态等文件只允许服务用户访问（与 internal/statedir 的校验一致）。
	StateDirectoryMode=0700
	Environment=HOME=/var/lib/mnagent
	ReadWritePaths=$PREFIX
	Restart=always
	RestartSec=5
	# agent 退出时最多用 60s 回传在途结果（见 config.DefaultExitResultTimeout），
	# 停止超时必须大于它，否则 systemd 会在结果上传完成前 SIGKILL。
	TimeoutStopSec=80
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
	# 保守加固：只限制本服务不可能用到的内核/设备/命名空间能力。
	# 禁止加载/卸载内核模块（nexttrace/miaospeed 都不需要）。
	ProtectKernelModules=true
	# 禁止读取内核日志（/dev/kmsg、syslog），避免泄露内核地址等信息。
	ProtectKernelLogs=true
	# 禁止修改系统时钟（NTP 由宿主机负责，agent 无此需求）。
	ProtectClock=true
	# 禁止修改主机名（agent 不负责主机名管理）。
	ProtectHostname=true
	# 禁止创建新的 mount/pid/net 等命名空间，降低提权面。
	RestrictNamespaces=true
	# 禁止使用实时调度策略，避免抢占宿主机实时任务。
	RestrictRealtime=true
	# 不启用 SystemCallArchitectures=native：32 位用户态二进制跑在 64 位内核上（如树莓派
	# 32 位系统）会被拒绝全部系统调用，导致 agent 无法启动。
	# 提供最小 /dev（保留 null/zero/random/urandom 等），不暴露物理设备。
	PrivateDevices=true
	# 只保留服务实际需要的地址族：本地监听/Unix socket、IPv4/IPv6、netlink、
	# 以及 nexttrace 的原始套接字（AF_PACKET）所需。
	RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "$INIT_DIR/$SERVICE_NAME.service"
	systemctl daemon-reload
	systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
	# 用 restart 而不是 enable --now：后者对已经在运行的服务不做任何事，
	# 升级时会出现“二进制换了、进程还是旧版本”。
	if ! systemctl restart "$SERVICE_NAME"; then
		# 不要让 set -e 直接中断：此时二进制、单元都已就位，更需要把排错提示打出来。
		warn "启动服务失败：请执行 journalctl -u $SERVICE_NAME -e 查看原因（常见原因：-bot 地址不可达或要求 https、令牌错误、缺少 -allow-insecure-http 等启动参数）"
	fi
	status="$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
	if [ -n "$status" ]; then
		log "服务状态：${status}（日志：journalctl -u $SERVICE_NAME -e）"
	else
		log "已注册服务（日志：journalctl -u $SERVICE_NAME -e）"
	fi
}

install_procd_init() {
	# OpenWrt：procd 服务脚本，以 root 运行，日志走 syslog（logread）。
	cat > "$INIT_DIR/$SERVICE_NAME" <<EOF
#!/bin/sh /etc/rc.common
# mnagent：由机器人 /host 生成的一键脚本安装；重跑安装脚本即为升级。

START=95
STOP=10
USE_PROCD=1

	start_service() {
		procd_open_instance
		procd_set_param command "$PREFIX/mnagent" \\
			-bot "$BOT_URL" \\
			-token-file "$TOKEN_FILE" \\
			-nexttrace "$NEXTTRACE_EXEC" \\
			-miaospeed "$MIAOSPEED_EXEC"$AUTO_UPDATE_ARGS$EXTRA_AGENT_ARGS
		procd_set_param env PATH="/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		procd_set_param respawn
		# 退出时 agent 最多用 60s 回传在途结果，停止超时必须大于它，
		# 否则 procd 会在结果上传完成前强杀进程。
		procd_set_param term_timeout 70
		procd_set_param stdout 1
		procd_set_param stderr 1
EOF
	if [ "$RUN_USER" != "root" ]; then
		printf '\tprocd_set_param user %s\n' "$RUN_USER" >> "$INIT_DIR/$SERVICE_NAME"
	fi
	cat >> "$INIT_DIR/$SERVICE_NAME" <<'PROCD_EOF'
	procd_close_instance
}

stop_service() {
	:
}
PROCD_EOF
	chmod 0755 "$INIT_DIR/$SERVICE_NAME"
	"$INIT_DIR/$SERVICE_NAME" enable >/dev/null 2>&1 || true
	"$INIT_DIR/$SERVICE_NAME" restart >/dev/null 2>&1 \
		|| "$INIT_DIR/$SERVICE_NAME" start >/dev/null 2>&1 \
		|| warn "启动服务失败：请查看 logread -e $SERVICE_NAME"
	if command -v pgrep >/dev/null 2>&1 && pgrep -f "$PREFIX/mnagent" >/dev/null 2>&1; then
		log "服务已启动（日志：logread -e ${SERVICE_NAME}）"
	else
		log "已注册服务（日志：logread -e ${SERVICE_NAME}）"
	fi
	# sysupgrade 会保留 /etc，但 /usr 下的二进制需要在 sysupgrade.conf 中登记才会随备份保留。
	if [ -e /etc ] && { [ -w /etc/sysupgrade.conf ] || [ ! -e /etc/sysupgrade.conf ]; }; then
		for path in "$PREFIX/mnagent" "$PREFIX/nexttrace" "$PREFIX/miaospeed" "$NEXTTRACE_EXEC" "$MIAOSPEED_EXEC" "$TOKEN_DIR"; do
			[ -e "$path" ] || continue
			grep -qxF "$path" /etc/sysupgrade.conf 2>/dev/null \
				|| echo "$path" >> /etc/sysupgrade.conf 2>/dev/null \
				|| true  # /etc 不可写（例如非 OpenWrt 环境）时静默跳过
		done
	fi
	warn "OpenWrt 固件升级（sysupgrade）后若服务未启动，重新执行一次本条安装命令即可"
}

case "$PLATFORM" in
	systemd)
		log "写入 systemd 服务 $INIT_DIR/$SERVICE_NAME.service"
		install_systemd_unit
		;;
	openwrt)
		log "写入 procd 服务 $INIT_DIR/$SERVICE_NAME"
		install_procd_init
		prepare_state_dir
		;;
	*)
		warn "未检测到 systemd 或 OpenWrt(procd)：已安装二进制，请自行守护运行"
		prepare_state_dir
		printf '    "%s/mnagent" -bot "%s" -token-file "%s" -nexttrace "%s"%s%s\n' \
			"$PREFIX" "$BOT_URL" "$TOKEN_FILE" "$NEXTTRACE_EXEC" "$AUTO_UPDATE_ARGS" "$EXTRA_AGENT_ARGS" >&2
		if [ -n "$NEXTTRACE_PATH" ] && command -v setcap >/dev/null 2>&1; then
			# 没有 systemd/procd 时只能靠二进制能力，手工前台运行也需要原始套接字权限。
			setcap cap_net_raw,cap_net_admin+eip "$NEXTTRACE_PATH" \
				|| warn "setcap 失败，请手动执行：setcap cap_net_raw,cap_net_admin+eip $NEXTTRACE_PATH"
		fi
		;;
esac

cat <<EOF

================================================================
  ⚡ mnagent 拨测探针部署完成
================================================================
  • 运行平台：${PLATFORM} (${ARCH})
  • 守护服务：${SERVICE_NAME} (已配置开机自启并启动)
  • 追踪引擎：nexttrace (${NEXTTRACE_EXEC})
  • 测速引擎：miaospeed (${MIAOSPEED_EXEC})
  • 自动更新：${AUTO_UPDATE} (检查周期：${UPDATE_INTERVAL})
----------------------------------------------------------------
  👉 验证接入：请在 Telegram 机器人中发送 /host status 查看心跳
================================================================

EOF

if [ "${status:-}" != "active" ] && [ "$PLATFORM" = "systemd" ]; then
	warn "服务当前未处于 active 状态（${status:-unknown}）：请执行 journalctl -u $SERVICE_NAME -e 查看原因；"
	warn "修复后执行 systemctl restart $SERVICE_NAME，或在 Telegram 里发送 /host status 观察是否恢复在线。"
fi
log "安装完成（平台：${PLATFORM}，架构：${ARCH}）。请在 Telegram 里发送 /host list 确认该主机显示 🟢 在线"
