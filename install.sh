#!/bin/sh
# mnagent 一键安装脚本（本项目是它的唯一来源）。
#
# 机器人的 /nexthost add 会生成这样的命令，在目标主机上执行即可：
#   (curl -fsSL <脚本地址> || wget -qO- <脚本地址>) | sh -s -- \
#     --bot https://<机器人地址>/agent --token <令牌>
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
TOKEN_FILE="/etc/mnagent/token"
NEXTTRACE_BIN="nexttrace"
RUN_USER=""
RUN_GROUP=""
PREFIX=""
VERSION="latest"
MODE="auto"        # auto | release | source | binary
BINARY_SRC=""
UNINSTALL="no"
SERVICE_NAME="mnagent"
AUTO_UPDATE="yes"   # 默认开启自动更新（可 --auto-update no 关闭）
UPDATE_INTERVAL="6h"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
用法：
  (curl -fsSL <脚本地址> || wget -qO- <脚本地址>) | sh -s -- --bot <机器人地址>/agent --token <令牌>

参数：
  --bot <url>          机器人 agent 端点基地址（必填，如 https://mnbot.example.org/agent）
  --token <token>      接入令牌（必填；也可省略，前提是 --token-file 已存在）
  --token-file <path>  令牌文件路径（默认 /etc/mnagent/token）
  --nexttrace <path>   nexttrace 可执行文件路径或名称（默认 nexttrace）
  --version <tag>      安装的版本标签，默认 latest（取最新 Release）
  --binary <path|url>  直接使用已编译好的 mnagent（本地路径或下载地址）
  --from-source        从源码编译（不下载 Release）
  --user <name>        运行服务的用户（systemd 默认 mnagent，OpenWrt 默认 root）
  --prefix <dir>       二进制安装目录（systemd 默认 /usr/local/bin，OpenWrt 默认 /usr/bin）
  --uninstall          卸载：停止并删除服务与二进制（保留令牌与用户）
  -h, --help           显示本帮助

环境变量（高级，一般无需设置）：
  MNAGENT_PLATFORM=systemd|openwrt|none   强制平台检测结果
  MNAGENT_INIT_DIR=<dir>                  覆盖 init/unit 脚本所在目录
  MNAGENT_REPO=<owner/repo>               覆盖 Release 来源仓库
EOF
}

# 先处理帮助：非 root 用户查看用法时不应触发提权。
for arg in "$@"; do
	case "$arg" in
		-h|--help) usage; exit 0;;
	esac
done

# 需要 root：非 root 时用 sudo 自我提权重跑（先把脚本落到临时文件），否则给出明确提示。
if [ "$(id -u)" != "0" ]; then
	if command -v sudo >/dev/null 2>&1; then
		log "需要 root 权限，正在通过 sudo 重新执行"
		elevated="$(mktemp)"
		cat > "$elevated"
		if sudo sh "$elevated" "$@"; then
			rm -f "$elevated"
			exit 0
		fi
		rm -f "$elevated"
		die "提权失败：请以 root 运行（或用 sudo -i 后再执行本条命令）"
	fi
	die "需要 root 权限（OpenWrt 请以 root 登录；其他系统请安装 sudo 或用 root 运行）"
fi

while [ $# -gt 0 ]; do
	case "$1" in
		--bot)         BOT_URL="${2:-}"; shift 2;;
		--token)       TOKEN="${2:-}"; shift 2;;
		--token-file)  TOKEN_FILE="${2:-}"; shift 2;;
		--nexttrace)   NEXTTRACE_BIN="${2:-}"; shift 2;;
		--version)     VERSION="${2:-}"; shift 2;;
		--binary)      BINARY_SRC="${2:-}"; MODE="binary"; shift 2;;
		--from-source) MODE="source"; shift;;
		--user)        RUN_USER="${2:-}"; shift 2;;
		--prefix)      PREFIX="${2:-}"; shift 2;;
		--uninstall)   UNINSTALL="yes"; shift;;
		--auto-update)  AUTO_UPDATE="yes"; shift;;
		--no-auto-update) AUTO_UPDATE="no"; shift;;
		--update-interval) UPDATE_INTERVAL="${2:-}"; shift 2;;
		*) die "未知参数：$1（用 --help 查看用法）";;
	esac
done

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
		[ -n "$RUN_USER" ] || RUN_USER="mnagent"
		[ -n "$INIT_DIR" ] || INIT_DIR="/etc/systemd/system"
		;;
	*)
		[ -n "$PREFIX" ] || PREFIX="/usr/local/bin"
		[ -n "$RUN_USER" ] || RUN_USER="mnagent"
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
is_little_endian() {
	for candidate in /bin/busybox "$(command -v sh 2>/dev/null)" /bin/sh; do
		case "$(elf_ei_data "$candidate" 2>/dev/null || true)" in
			1) return 0;;
			2) return 1;;
		esac
	done
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

# download <url> <输出文件>
download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	elif command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O "$2" "$1"
	else
		die "未找到下载工具：请安装 curl（OpenWrt：opkg install curl），或使用 uclient-fetch/wget"
	fi
}

# download_stdout <url>
download_stdout() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$1"
	elif command -v uclient-fetch >/dev/null 2>&1; then
		uclient-fetch -q -O - "$1"
	else
		die "未找到下载工具：请安装 curl（OpenWrt：opkg install curl），或使用 uclient-fetch/wget"
	fi
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
	rm -f "$PREFIX/mnagent"
	if [ "$RUN_USER" != "root" ]; then
		log "已卸载（令牌文件 $TOKEN_FILE 与用户 $RUN_USER 保留，如需一并清理请手动删除）"
	else
		log "已卸载（令牌文件 $TOKEN_FILE 保留，如需一并清理请手动删除）"
	fi
	exit 0
fi

# ---------- 参数校验 ----------

[ -n "$BOT_URL" ] || die "缺少 --bot"
case "$BOT_URL" in
	http://*|https://*) ;;
	*) die "--bot 必须是完整的 http(s) 地址：$BOT_URL";;
esac
# 主机名允许中英文（机器人侧 /nexthost add 可直接写“香港节点”），
# 但必须挡住会被写进服务单元/命令行的特殊字符。

# ---------- 安装二进制 ----------

build_from_source() {
	command -v go >/dev/null 2>&1 || die "未找到 go：请先安装 Go，或用 --binary 指定已编译好的 mnagent"
	tmp="$(mktemp -d)"
	log "下载源码并编译（${VERSION}）"
	if [ "$VERSION" = "latest" ]; then
		download_stdout "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp"
	else
		download_stdout "https://github.com/$REPO/archive/refs/tags/${VERSION}.tar.gz" | tar -xz -C "$tmp"
	fi
	dir="$(ls -d "$tmp"/*/ | head -n1)"
	( cd "$dir" && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$PREFIX/mnagent" . )
	rm -rf "$tmp"
}

download_release() {
	url="https://github.com/$REPO/releases/latest/download/mnagent_${OS}_${ARCH}"
	if [ "$VERSION" != "latest" ]; then
		url="https://github.com/$REPO/releases/download/${VERSION}/mnagent_${OS}_${ARCH}"
	fi
	log "下载 mnagent（${VERSION}，${OS}/${ARCH}）"
	download "$url" "$PREFIX/.mnagent.new" || return 1
	install_file "$PREFIX/.mnagent.new" "$PREFIX/mnagent" 0755
	rm -f "$PREFIX/.mnagent.new"
}

mkdir -p "$PREFIX"
case "$MODE" in
	binary)
		if [ -f "$BINARY_SRC" ]; then
			install_file "$BINARY_SRC" "$PREFIX/mnagent" 0755
		else
			log "下载 mnagent：$BINARY_SRC"
			download "$BINARY_SRC" "$PREFIX/mnagent" || die "下载失败：$BINARY_SRC"
			chmod 0755 "$PREFIX/mnagent"
		fi
		;;
	source)
		build_from_source
		;;
	auto)
		if ! download_release; then
			if command -v go >/dev/null 2>&1; then
				warn "下载 Release 失败（可能还没有 ${OS}/${ARCH} 产物，或网络受限），改为从源码编译"
				build_from_source
			else
				die "下载 ${OS}/${ARCH} 的 Release 产物失败：该架构可能暂无产物，或网络受限；本机没有 go 无法源码编译。可用 --binary <本地或镜像地址> 指定二进制，例如 --binary https://github.com/$REPO/releases/latest/download/mnagent_${OS}_${ARCH}"
			fi
		fi
		;;
esac
[ -x "$PREFIX/mnagent" ] || die "mnagent 安装失败"
log "已安装 $PREFIX/mnagent（$("$PREFIX/mnagent" -version 2>/dev/null || echo "版本未知")）"

# ---------- 运行用户 ----------

# OpenWrt 默认以 root 运行：设备上没有 setcap，而 nexttrace 需要 CAP_NET_RAW；
# 其他平台创建专用系统用户。
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
elif [ "$PLATFORM" = "openwrt" ]; then
	log "以 root 运行（OpenWrt 上无法单独给 nexttrace 授予原始套接字能力）"
fi
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"

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
	die "缺少 --token，且 $TOKEN_FILE 不存在；请使用 /nexthost 生成的完整命令"
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

NEXTTRACE_PATH="$(command -v "$NEXTTRACE_BIN" 2>/dev/null || true)"
[ -n "$NEXTTRACE_PATH" ] || warn "未找到 nexttrace（${NEXTTRACE_BIN}）：请安装后再试，否则追踪会失败"
NEXTTRACE_EXEC="${NEXTTRACE_PATH:-$NEXTTRACE_BIN}"


# 自动更新参数：启用时追加到服务命令（systemd 与 procd 共用）。
AUTO_UPDATE_ARGS=""
if [ "$AUTO_UPDATE" = "yes" ]; then
	AUTO_UPDATE_ARGS=" -auto-update -update-interval $UPDATE_INTERVAL"
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
ExecStart=$PREFIX/mnagent -bot $BOT_URL -token-file $TOKEN_FILE -nexttrace $NEXTTRACE_EXEC$AUTO_UPDATE_ARGS
	# nexttrace 需要可写的主目录来存放配置与 IP 库；ProtectSystem=strict 下只有
	# StateDirectory 指向的目录可写。
	StateDirectory=mnagent
	Environment=HOME=/var/lib/mnagent
	ReadWritePaths=$PREFIX
	Restart=always
RestartSec=5
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

[Install]
WantedBy=multi-user.target
EOF
	chmod 0644 "$INIT_DIR/$SERVICE_NAME.service"
	systemctl daemon-reload
	systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
	# 用 restart 而不是 enable --now：后者对已经在运行的服务不做任何事，
	# 升级时会出现“二进制换了、进程还是旧版本”。
	systemctl restart "$SERVICE_NAME"
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
# mnagent：由机器人 /nexthost 生成的一键脚本安装；重跑安装脚本即为升级。

START=95
STOP=10
USE_PROCD=1

	start_service() {
		procd_open_instance
		procd_set_param command $PREFIX/mnagent \\
			-bot $BOT_URL \\
			-token-file $TOKEN_FILE \\
			-nexttrace $NEXTTRACE_EXEC$AUTO_UPDATE_ARGS
		procd_set_param respawn
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
		for path in "$PREFIX/mnagent" "$TOKEN_DIR"; do
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
		;;
	*)
		warn "未检测到 systemd 或 OpenWrt(procd)：已安装二进制，请自行守护运行"
		printf '    %s/mnagent -bot %s -token-file %s -nexttrace %s\n' \
			"$PREFIX" "$BOT_URL" "$TOKEN_FILE" "$NEXTTRACE_EXEC" >&2
		if [ -n "$NEXTTRACE_PATH" ] && command -v setcap >/dev/null 2>&1; then
			# 没有 systemd/procd 时只能靠二进制能力，手工前台运行也需要原始套接字权限。
			setcap cap_net_raw,cap_net_admin+eip "$NEXTTRACE_PATH" \
				|| warn "setcap 失败，请手动执行：setcap cap_net_raw,cap_net_admin+eip $NEXTTRACE_PATH"
		fi
		;;
esac

log "安装完成（平台：${PLATFORM}，架构：${ARCH}）。请在 Telegram 里发送 /nexthost list 确认该主机显示 🟢 在线"
