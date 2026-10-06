# mnagent

运行在追踪主机上的轻量 agent，配合 Telegram 机器人 [@mengnan_dedicated_bot](https://t.me/mengnan_dedicated_bot) 的 `/nexttrace` 使用。

它主动向机器人**长轮询**领取任务、在本机执行 `nexttrace`、再回传结果。因此：

- 主机**不需要公网地址**，不需要端口映射、反向隧道或 VPN——只要能在出站方向访问机器人；
- 主机**不需要 SSH**，不需要开放任何入站端口，机器人也不持有登录这些主机的密钥；
- 机器人下发的只是**已校验的追踪参数**（目标/跳数/端口/协议），执行哪个程序由本机的 `-nexttrace` 参数决定，网络侧无法指定命令；
- 长轮询本身就是心跳，机器人的主机选择键盘可以显示 🟢 在线 / ⚪️ 离线。

## 安装

推荐用机器人生成的**一键命令**（管理员在 Telegram 里执行 `/nexthost add hk 香港节点`，机器人会直接回复下面这条命令）：

```sh
(curl -fsSL https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh \
  || wget -qO- https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh) \
  | sh -s -- --bot https://<机器人地址>/agent --host hk --token <令牌>
```

命令用 `sh` 并带 `wget` 回退，因此 VPS 与 OpenWrt 路由器可以粘同一条；非 root 用户由脚本自己通过 `sudo` 提权重跑。

也可以固定到某个发布版本（脚本与二进制版本一致）：

```sh
SCRIPT=https://github.com/mengnanquq/mnagent/releases/latest/download/install.sh
(curl -fsSL "$SCRIPT" || wget -qO- "$SCRIPT") | sh -s -- --bot https://<机器人地址>/agent --host hk --token <令牌>
```

脚本会自动：从本仓库的 Release 下载预编译二进制（`mnagent_<os>_<arch>`，没有 Release 或网络受限时回退到源码编译）、创建专用用户、写入令牌（0600）、写入 systemd 单元并**重启服务**（因此重复执行即为升级，会真正换上并运行新版本）。原始套接字能力由单元的 `AmbientCapabilities` 提供，并给服务准备了可写的主目录（`StateDirectory=mnagent`）供 `nexttrace` 存放配置与 IP 库。

> 如果主机访问 GitHub 受限：把 `install.sh` 与对应架构的二进制放到内网镜像，用 `--binary https://内网镜像/mnagent_linux_amd64` 指定二进制即可；机器人侧也可用 `MNAGENT_INSTALL_URL` 把生成的脚本地址指向你的镜像。

### 发布

打标签即触发 Actions 构建 linux/darwin × amd64/arm64/arm 的二进制并附加到 Release（含 `install.sh` 与 sha256）：

```bash
git tag v0.1.0 && git push origin v0.1.0
```

### OpenWrt

同一串命令即可在 OpenWrt 上安装，脚本会自动按 procd 方式部署：

- 二进制装到 `/usr/bin/mnagent`，服务脚本写到 `/etc/init.d/mnagent`（`USE_PROCD=1`，`respawn` 自动重启，日志进 syslog）；
- **以 root 运行**：OpenWrt 上没有 `setcap` 与系统用户体系，而 `nexttrace` 需要 `CAP_NET_RAW`（服务脚本里也可通过 `--user` 指定其他用户，若你的系统支持）；
- 不依赖 `curl`/`install`/`useradd`：分别回退到 `uclient-fetch`/`wget`、`cp+chmod`、BusyBox `adduser`；
- 会把二进制与 `/etc/mnagent` 写进 `/etc/sysupgrade.conf`，固件升级后配置与脚本仍在；若服务未随升级恢复，重跑一次安装命令即可；
- 支持的架构（静态二进制，musl 通用）：`armv7l`/`armv6l`/`armv5`（含 OpenWrt 常见路由）、`aarch64`、`x86_64`、`mips`/`mipsle`（大小端由 ELF 头自动识别）、`mips64`/`mips64le`、`riscv64`。

常用排查：

```sh
logread -e mnagent              # 查看 agent 日志
/etc/init.d/mnagent restart      # 重启服务
opkg install nexttrace           # 若未安装 nexttrace（或使用 --nexttrace 指定路径）
```

### 自动更新

mnagent **默认开启自动更新**：每 6 小时（带随机抖动，避免所有主机同时请求）检查一次
GitHub Releases，发现比当前版本新的正式版就下载、原子替换自身并重启服务。

- 关闭：安装脚本加 `--no-auto-update`，或改服务命令去掉 `-auto-update`；
- 手动操作：`mnagent -check-update`（只看有没有新版）、`mnagent -apply-update latest`（立即升级）、
  `mnagent -skip-update v0.1.8`（跳过某个版本 24 小时，避免坏版本反复拉起）；
- 版本号是 `-ldflags "-X main.version=..."` 注入的 tag 名；本地 `go build` 出来的 `dev` 版本
  不参与自动更新（避免开发构建被替换）；
- 更新只在 Release（`releases/latest`）里挑版本，因此发版请打 tag（见下）。

### 脚本参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--bot` / `--host` / `--token` | 必填 | 由 `/nexthost add` 生成的命令已带全 |
| `--token-file` | `/etc/mnagent/token` | 令牌文件路径；省略 `--token` 时要求该文件已存在 |
| `--version` | `latest` | 安装的 Release 标签；也可用 `--from-source` 从源码编译 |
| `--binary <path\|url>` | — | 使用自备的 mnagent（内网镜像时很有用） |
| `--nexttrace` | `nexttrace` | nexttrace 路径或名称 |
| `--user` / `--prefix` | systemd：`mnagent` / `/usr/local/bin`；OpenWrt：`root` / `/usr/bin` | 运行用户与安装目录 |
| `--no-auto-update` | — | 关闭自动更新（默认开启） |
| `--uninstall` | — | 卸载服务与二进制（保留令牌与用户） |

### 手动安装

不使用脚本时（例如没有 systemd 的系统），可自行编译并按 `deploy/mnagent.service`
的写法启动：

```bash
go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o mnagent .
install -m 0755 mnagent /usr/local/bin/mnagent
useradd --system --no-create-home --shell /usr/sbin/nologin mnagent
install -d -m 0750 -o mnagent -g mnagent /etc/mnagent
printf '%s\n' '<令牌>' > /etc/mnagent/token && chmod 0600 /etc/mnagent/token && chown mnagent /etc/mnagent/token
# 手工前台运行时需要自己给 nexttrace 授权（用 systemd 时由单元的 AmbientCapabilities 提供）
setcap cap_net_raw,cap_net_admin+eip "$(command -v nexttrace)"
```

## 机器人侧配置

主机与令牌都由机器人管理（存放在状态数据库里，不再使用配置文件）：

- `/nexthost add <名称> [备注]`：添加主机并生成一键接入命令
- `/nexthost list`：查看主机与 🟢/⚪️ 在线状态
- `/nexthost show <名称>`：重新显示接入命令
- `/nexthost rotate <名称>`：轮换令牌（旧令牌立即失效，主机需重新接入）
- `/nexthost remove <名称>`：删除主机

`name` 必须与 agent 的 `-host` 完全一致；令牌等同该主机的任务接受权，泄露时用 `rotate` 轮换。

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-bot` | 必填 | 机器人 agent 端点基地址，如 `https://mnbot.example.org/agent` |
| `-host` | 必填 | 本机名称，需与机器人配置里的 `name` 一致 |
| `-token` | — | 直接给出令牌（不推荐：会出现在进程列表里） |
| `-token-file` | `/etc/mnagent/token` | 令牌文件路径；每次请求都重新读取，**轮换令牌无需重启** |
| `-nexttrace` | `nexttrace` | nexttrace 可执行文件路径或 PATH 中的名称 |
| `-min-backoff` / `-max-backoff` | `1s` / `1m` | 轮询失败后的重试退避区间（带抖动） |
| `-poll-timeout` | `40s` | 单次长轮询的客户端超时（机器人侧最多保持 20 秒） |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-version` | — | 输出版本后退出 |

令牌也可以放在环境变量 `MNAGENT_TOKEN` 中（优先级：`-token` > `MNAGENT_TOKEN` > `-token-file`）。

## 协议

机器人侧提供两个端点（均在机器人的公网 HTTPS 服务上）：

```
POST /agent/jobs?host=<name>        Authorization: Bearer <token>
   → 200 {"id":"…","target":"1.1.1.1","hops":20,"port":443,"protocol":"tcp","timeout_ms":120000}
   → 204（本次没有任务，agent 立刻重新轮询）

POST /agent/results?host=<name>     {"id":"…","output":"…","exit_code":0,"error":""}
   → 204
```

约定与限制：

- 单台主机同一时刻只会被下发一个任务（机器人侧另有全局并发上限）；
- `timeout_ms` 会被 agent 夹到 5 秒 ~ 10 分钟之间；超时会杀掉命令，并把部分输出一起回传；
- 输出在 agent 侧最多 1 MiB（超出丢弃），机器人侧再做一次上限与展示截断；
- 结果按任务 ID 幂等，回传失败会退避重试 3 次；
- 鉴权失败时 agent 用最大退避间隔重试并打印错误，不会退出。

## 安全模型

| 面向 | 说明 |
| --- | --- |
| 入站暴露 | 无：agent 只发起出站 HTTPS 请求 |
| 令牌 | 每台主机独立令牌，机器人侧用常量时间比较；令牌等同该主机的"任务接受权"，泄露后应立刻轮换 |
| 命令执行 | agent 侧重新校验参数（目标字符集、跳数/端口区间、协议枚举），以 argv 方式直接 `exec`，**不经 shell**；`target` 不允许以 `-` 开头，因此无法注入额外参数 |
| 程序路径 | 由本机 `-nexttrace` 决定，机器人无法指定要执行的程序 |
| 权限 | systemd 平台：专用低权限用户运行，原始套接字能力由单元的 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` 携带并传给 nexttrace（无需 setcap，二进制被替换也不会失效）。OpenWrt：设备上没有 setcap/用户体系，服务以 root 运行（与 OpenWrt 上同类工具的做法一致），请把设备本身当作受信边界 |
| TLS | 默认校验服务器证书；仅在本地联调时可对机器人使用 `http://` |

## 故障排查

| 现象 | 排查方向 |
| --- | --- |
| 日志反复 `鉴权失败` | `-host` 与配置里的 `name` 不一致，或令牌不匹配（对比 `/etc/mnagent/token` 与机器人配置） |
| 机器人显示 ⚪️ 离线 | agent 未运行、`-bot` 地址不可达（出站 443 被拦？）、或机器人的 `/agent/jobs` 未对外暴露 |
| 任务报 `执行超时` | 主机到目标网络不通，或需要更长超时；也可在命令里减少跳数 |
| 任务报 `执行失败（退出码 N）` | 手动在该主机执行同参数 `nexttrace` 复现；注意 `nexttrace -j` 需要 v1.7+，旧版本 agent 会自动去掉 `-j` 重试 |
| 任务报 `无法启动 nexttrace（…）` | 二进制本身有问题：确认路径存在、可执行、架构匹配（`file $(command -v nexttrace)`），必要时在主机上直接运行一次 |
| 任务报 `进程被信号终止（…）` | 二进制启动后被信号杀死，按提示的信号名排查（内存不足、平台不兼容等） |
| 任务报权限/原始套接字错误 | 用 systemd 运行时应由单元的 `AmbientCapabilities` 提供 `CAP_NET_RAW`；检查单元是否被旧版本覆盖（重跑安装脚本会重新生成） |
| 输出为空且无报错 | 检查 `nexttrace` 能否直接运行：`sudo -u mnagent $(command -v nexttrace) -j 1.1.1.1 \| head -3` |
