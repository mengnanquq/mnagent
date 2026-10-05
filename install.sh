#!/usr/bin/env bash
# mnagent 一键安装脚本（本项目是它的唯一来源）。
#
# 机器人的 /nexthost add 会生成这样的命令，在目标主机上以 root 执行即可：
#   curl -fsSL https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh \
#     | sudo bash -s -- --bot https://<机器人地址>/agent --host <名称> --token <令牌>
# 脚本会按 --version 从本仓库的 Release 下载预编译二进制（无 Release 或网络受限时
# 回退到源码编译），因此发布流程见 .github/workflows/release.yml。
# 功能：下载（或编译）mnagent、创建专用用户、写入令牌、为 nexttrace 授权、
# 安装并启动 systemd 服务；重复执行即为升级。
set -euo pipefail

REPO="${MNAGENT_REPO:-mengnanquq/mnagent}"
BOT_URL=""
HOST_NAME=""
TOKEN=""
TOKEN_FILE="/etc/mnagent/token"
NEXTTRACE_BIN="nexttrace"
RUN_USER="mnagent"
PREFIX="/usr/local/bin"
VERSION="latest"
MODE="auto"        # auto | release | source
BINARY_SRC=""
UNINSTALL="no"
SERVICE_NAME="mnagent"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
用法：
  curl -fsSL <机器人地址>/agent/install.sh | sudo bash -s -- --bot <机器人地址>/agent --host <名称> --token <令牌>

参数：
  --bot <url>          机器人 agent 端点基地址（必填，如 https://mnbot.example.org/agent）
  --host <name>        本机名称，需与机器人的 /nexthost add 名称一致（必填）
  --token <token>      接入令牌（必填；也可省略，前提是 --token-file 已存在）
  --token-file <path>  令牌文件路径（默认 /etc/mnagent/token）
  --nexttrace <path>   nexttrace 可执行文件路径或名称（默认 nexttrace）
  --version <tag>      安装的版本标签，默认 latest（取最新 Release）
  --binary <path|url>  直接使用已编译好的 mnagent（本地路径或下载地址）
  --from-source        从源码编译（不下载 Release）
  --user <name>        运行服务的系统用户（默认 mnagent）
  --prefix <dir>       二进制安装目录（默认 /usr/local/bin）
  --uninstall          卸载：停止并删除服务与二进制（保留令牌与用户）
  -h, --help           显示本帮助
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		--bot)        BOT_URL="${2:-}"; shift 2;;
		--host)       HOST_NAME="${2:-}"; shift 2;;
		--token)      TOKEN="${2:-}"; shift 2;;
		--token-file) TOKEN_FILE="${2:-}"; shift 2;;
		--nexttrace)  NEXTTRACE_BIN="${2:-}"; shift 2;;
		--version)    VERSION="${2:-}"; shift 2;;
		--binary)     BINARY_SRC="${2:-}"; MODE="binary"; shift 2;;
		--from-source) MODE="source"; shift;;
		--user)       RUN_USER="${2:-}"; shift 2;;
		--prefix)     PREFIX="${2:-}"; shift 2;;
		--uninstall)  UNINSTALL="yes"; shift;;
		-h|--help)    usage; exit 0;;
		*) die "未知参数：$1（用 --help 查看用法）";;
	esac
done

[ "$(id -u)" = "0" ] || die "需要 root 权限（请用：curl -fsSL ... | sudo bash -s -- ...）"

stop_service() {
	if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
		systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
	fi
}

if [ "$UNINSTALL" = "yes" ]; then
	log "卸载 $SERVICE_NAME"
	stop_service
	rm -f "/etc/systemd/system/$SERVICE_NAME.service" "$PREFIX/mnagent"
	command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
	log "已卸载（令牌文件 $TOKEN_FILE 与用户 $RUN_USER 保留，如需一并清理请手动删除）"
	exit 0
fi

[ -n "$BOT_URL" ] || die "缺少 --bot"
case "$BOT_URL" in
	http://*|https://*) ;;
	*) die "--bot 必须是完整的 http(s) 地址：$BOT_URL";;
esac
[ -n "$HOST_NAME" ] || die "缺少 --host"
case "$HOST_NAME" in
	*[!A-Za-z0-9._-]*) die "--host 只能包含字母、数字、点、下划线与连字符：$HOST_NAME";;
esac
[ "${#HOST_NAME}" -le 64 ] || die "--host 过长（最多 64 字符）"

# 架构与系统：Release 资产命名为 mnagent_<os>_<arch>。
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
	x86_64|amd64)   ARCH="amd64";;
	aarch64|arm64)  ARCH="arm64";;
	armv7l|armv7)   ARCH="arm";;
	*) die "不支持的架构：$(uname -m)（可用 --binary 指定自行编译的 mnagent）";;
esac

install_binary() {
	case "$MODE" in
		binary)
			if [ -f "$BINARY_SRC" ]; then
				install -m 0755 "$BINARY_SRC" "$PREFIX/mnagent"
			else
				log "下载 mnagent：$BINARY_SRC"
				curl -fsSL --retry 3 -o "$PREFIX/mnagent" "$BINARY_SRC" || die "下载失败：$BINARY_SRC"
				chmod 0755 "$PREFIX/mnagent"
			fi
			;;
		source)
			build_from_source
			;;
		auto)
			if ! download_release; then
				warn "下载 Release 失败（可能还没有发布版本或网络受限），改为从源码编译"
				build_from_source
			fi
			;;
	esac
}

download_release() {
	local url
	if [ "$VERSION" = "latest" ]; then
		url="https://github.com/$REPO/releases/latest/download/mnagent_${OS}_${ARCH}"
	else
		url="https://github.com/$REPO/releases/download/$VERSION/mnagent_${OS}_${ARCH}"
	fi
	log "下载 mnagent（${VERSION}，$OS/${ARCH}）"
	curl -fsSL --retry 3 -o "$PREFIX/.mnagent.new" "$url" || return 1
	install -m 0755 "$PREFIX/.mnagent.new" "$PREFIX/mnagent"
	rm -f "$PREFIX/.mnagent.new"
}

build_from_source() {
	command -v go >/dev/null 2>&1 || die "未找到 go：请先安装 Go，或用 --binary 指定已编译好的 mnagent"
	local tmp
	tmp="$(mktemp -d)"
	log "下载源码并编译（${VERSION}）"
	if [ "$VERSION" = "latest" ]; then
		curl -fsSL --retry 3 "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz -C "$tmp"
	else
		curl -fsSL --retry 3 "https://github.com/$REPO/archive/refs/tags/$VERSION.tar.gz" | tar -xz -C "$tmp"
	fi
	# shellcheck disable=SC2012
	local dir
	dir="$(ls -d "$tmp"/*/ | head -n1)"
	( cd "$dir" && go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PREFIX/mnagent" . )
	rm -rf "$tmp"
}

install_binary
[ -x "$PREFIX/mnagent" ] || die "mnagent 安装失败"
log "已安装 $PREFIX/mnagent（$("$PREFIX/mnagent" -version 2>/dev/null || echo "版本未知")）"

# 运行用户：无 home、不可登录。
if ! id -u "$RUN_USER" >/dev/null 2>&1; then
	log "创建系统用户 $RUN_USER"
	useradd --system --no-create-home --shell /usr/sbin/nologin "$RUN_USER" 2>/dev/null \
		|| adduser -S -D -H -s /sbin/nologin "$RUN_USER" \
		|| die "创建用户 $RUN_USER 失败"
fi

# 取服务用户的真实主组：它一定是该组成员，用主组给令牌目录授权最稳妥
# （不能假设存在与用户名同名的组：useradd --system 在部分发行版不会创建同名组）。
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"

# 令牌目录：root 拥有、服务用户主组可进入（0750），令牌文件本身 0600 归服务用户。
# 服务用户必须能“穿过”该目录才能读到文件：目录若是 root:root 0750，非 root 服务
# 会因 EACCES 直接退出（mnagent 启动时报“读取令牌失败: permission denied”）。
TOKEN_DIR="$(dirname "$TOKEN_FILE")"
if [ ! -d "$TOKEN_DIR" ]; then
	install -d -m 0750 -o root -g "$RUN_GROUP" "$TOKEN_DIR"
elif [ "$TOKEN_DIR" = "/etc/mnagent" ]; then
	# 默认目录：修正旧版本可能留下的 root:root 0750（服务用户无法进入）
	chown root:"$RUN_GROUP" "$TOKEN_DIR" 2>/dev/null || true
	chmod 0750 "$TOKEN_DIR"
else
	warn "使用自定义令牌目录 ${TOKEN_DIR}：未改动其权限，请确认 $RUN_USER 能读取 $TOKEN_FILE"
fi

# 令牌：优先用参数写入；否则要求文件已存在（支持不把令牌写进命令行的场景）。
if [ -n "$TOKEN" ]; then
	umask 077
	printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
	chown "$RUN_USER":"$RUN_GROUP" "$TOKEN_FILE" 2>/dev/null || chown "$RUN_USER" "$TOKEN_FILE" 2>/dev/null || true
	chmod 0600 "$TOKEN_FILE"
	log "已写入令牌 ${TOKEN_FILE}（0600，属主 ${RUN_USER}）"
elif [ ! -s "$TOKEN_FILE" ]; then
	die "缺少 --token，且 $TOKEN_FILE 不存在；请使用 /nexthost 生成的完整命令"
fi

# 自检：以服务用户身份确认能读到令牌。目录缺少执行（进入）权限时，非 root 服务会在
# 启动阶段直接退出（mnagent 报“读取令牌失败: permission denied”），这里提前告警。
if command -v runuser >/dev/null 2>&1 && ! runuser -u "$RUN_USER" -- test -r "$TOKEN_FILE" 2>/dev/null; then
	warn "服务用户 $RUN_USER 读不到 ${TOKEN_FILE}：请确认 $TOKEN_DIR 的属主/权限为 root:$RUN_GROUP 0750"
fi

# nexttrace 做原始套接字追踪需要 CAP_NET_RAW。有 systemd 时由服务的
# AmbientCapabilities 提供（与 NoNewPrivileges 兼容，且 nexttrace 升级/重装后依然有效，
# 不像 setcap 那样会因子文件被替换而失效）；只有需要手工前台运行时才回退到 setcap。
NEXTTRACE_PATH="$(command -v "$NEXTTRACE_BIN" 2>/dev/null || true)"

if ! command -v systemctl >/dev/null 2>&1; then
	warn "未检测到 systemd：请手动运行（并为 nexttrace 授予原始套接字权限）"
	if [ -n "$NEXTTRACE_PATH" ] && command -v setcap >/dev/null 2>&1; then
		setcap cap_net_raw,cap_net_admin+eip "$NEXTTRACE_PATH" || warn "setcap 失败，请手动执行：setcap cap_net_raw,cap_net_admin+eip $NEXTTRACE_PATH"
	fi
	printf '    %s/mnagent -bot %s -host %s -token-file %s\n' "$PREFIX" "$BOT_URL" "$HOST_NAME" "$TOKEN_FILE" >&2
	exit 0
fi
if [ -z "$NEXTTRACE_PATH" ]; then
	warn "未找到 nexttrace（${NEXTTRACE_BIN}）：请安装后再试，否则追踪会失败"
fi

log "写入 systemd 服务 /etc/systemd/system/$SERVICE_NAME.service"
cat >"/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=mnagent (mengnanbot nexttrace agent)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
ExecStart=$PREFIX/mnagent -bot $BOT_URL -host $HOST_NAME -token-file $TOKEN_FILE -nexttrace ${NEXTTRACE_PATH:-$NEXTTRACE_BIN}
# nexttrace 需要可写的主目录来存放配置与 IP 库；ProtectSystem=strict 下只有
# StateDirectory 指向的目录可写。
StateDirectory=mnagent
Environment=HOME=/var/lib/mnagent
Restart=always
RestartSec=5
# 原始套接字权限由服务携带（ambient）并传给子进程 nexttrace；
# 与 NoNewPrivileges 兼容，也不依赖对 nexttrace 二进制执行 setcap。
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

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
# 注意用 restart 而不是 enable --now：后者对“已经在运行”的服务不做任何事，
# 升级时会出现“二进制换了、进程还是旧版本”的情况。
systemctl restart "$SERVICE_NAME"
sleep 1
systemctl --no-pager --lines=5 status "$SERVICE_NAME" || true
log "已重启服务，运行版本：$("$PREFIX/mnagent" -version 2>/dev/null || echo 未知)"

log "安装完成。请在 Telegram 里发送 /nexthost list 确认该主机显示 🟢 在线"
