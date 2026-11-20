# ⚡ mnagent

运行在拨测探针主机上的轻量化高性能 Agent，专为配合网络拨测与节点测速服务端协同工作而设计。

Agent 通过 HTTPS **主动长轮询**接收服务端下发的网络探测与节点测速任务，在本地执行后结构化回传结果。

- 🔒 **网络零暴露**：**无需公网 IP、无需端口映射、无需 SSH**，只要探针能正常出站访问服务端即可。
- 🔑 **令牌即身份**：每台主机单令牌鉴权（`--token` 或动态读取 `--token-file`），在线轮换无需重启。
- 🔄 **全自动运维**：自动探测、补全与静默升级外部依赖（`nexttrace` / `miaospeed`），支持后台自更新与服务端一键远程升级。
- 🛡️ **安全沙箱防线**：默认严格拦截回环、内网私有网段及公有云元数据地址（`169.254.169.254` 等），防御 SSRF；命令参数白名单隔离，不经 Shell 解释器执行。

---

## 📊 支持的探针类型

| 类型 (`kind`) | 执行方式 | 核心输出指标 |
| :--- | :--- | :--- |
| **`trace`** | 调用 `nexttrace` | 逐跳骨干网、AS 机构、物理位置与跳数延迟（原生 JSON 解析） |
| **`ping`** | 进程内原生 ICMP | 丢包率、最小/平均/最大延迟、网络抖动（Jitter），非特权与 Raw Socket 双模 |
| **`tcping`** | 进程内原生 TCP | 端口握手延迟、丢包率与抖动，支持自动拆分目标端口与 IPv6 |
| **`http`** | 进程内原生 HTTP(S) | 状态码、TLS 协议与证书有效期、DNS/建连/TLS/TTFB 分段耗时与标头采集 |
| **`dns`** | 进程内原生解析 | A/AAAA/CNAME/MX/NS/TXT/PTR 解析结果与总耗时 |
| **`miaospeed`** | 调用 `miaospeed` | 代理节点测速，支持 12 大流媒体/AI 解锁判定与逐节点流式进度推流 |

---

## 🚀 快速安装

在 Telegram 中发送 `/host add <节点名>` 即可自动生成已预填参数的一键安装命令：

### Linux / OpenWrt / macOS
```sh
(curl -fsSL https://github.com/mengnanquq/mnagent/releases/latest/download/install.sh \
  || wget -qO- https://github.com/mengnanquq/mnagent/releases/latest/download/install.sh) \
  | MNAGENT_TOKEN='<令牌>' sh -s -- --bot https://<服务端地址>/agent
```

> 非 root 用户请写成 `| sudo env MNAGENT_TOKEN='<令牌>' sh -s -- ...`（sudo 默认会清空环境变量，必须显式保留；不要用 `sudo` 包住整个管道，否则脚本会从终端而不是管道读取）。

### Windows (以管理员身份打开 PowerShell)
```powershell
$env:MNAGENT_TOKEN = '<令牌>'
& ([scriptblock]::Create((irm https://github.com/mengnanquq/mnagent/releases/latest/download/install.ps1))) -Bot "https://<服务端地址>/agent"
Remove-Item Env:MNAGENT_TOKEN
```

> 安装脚本从 **v0.3.102** 起随每个 Release 作为附件发布（`releases/latest/download/install.sh` 与 `install.ps1`）。更早的 Release 没有这两个附件，可改用 raw main 分支的脚本：`https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh`（Windows 对应 `install.ps1`）。为避免令牌出现在进程 argv 与命令历史中，推荐环境变量 `MNAGENT_TOKEN`、`--token-file`（Linux）或 `-TokenFile`（Windows，需先存在令牌文件），也支持 Linux 下的 `--token-stdin`。`--token` 仅为兼容旧命令保留，使用时会打印警告。
>
> **网络受限 / 国内加速**：
> 在安装参数中附加 `--gh-proxy https://gh-proxy.com/`（Windows 添加 `-GhProxy "https://gh-proxy.com/"`），脚本自身、Agent 更新二进制以及依赖下载均会自动经由加速代理（更新所需的 `.sha256` 校验文件除外，见下）。
>
> **⚠️ gh-proxy 信任说明**：
> - 使用 `--gh-proxy` 安装时，二进制仍可经代理下载，但 `.sha256` 校验文件默认**不经 gh-proxy 镜像获取（仍遵循系统 `HTTPS_PROXY` 环境变量）**；获取失败会中止安装并提示。只有在确认代理可信时，才可用 `--insecure-proxy-checksum`（Windows 为 `-InsecureProxyChecksum`）允许经代理获取校验文件。
> - Agent 自动更新在配置了 `-gh-proxy` 时，`.sha256` 校验文件会**不经 gh-proxy 镜像获取（仍遵循系统 `HTTPS_PROXY` 环境变量）**（二进制仍走代理）；获取校验文件失败即拒绝更新（fail-closed），因为代理可同时替换二进制与同源 `.sha256`。这是默认的完整性校验方式。
> - 依赖（nexttrace/miaospeed）的 SHA-256 摘要来自直连的 `api.github.com`，不经代理；安装脚本中的依赖 `.sha256` 附件同样优先直连获取。
> - 为避免离线/被墙时长时间挂起，安装脚本中校验文件的直连尝试限时 30 秒（`curl --connect-timeout 5 --max-time 30` / `wget --timeout=30 --tries=2`），失败提示会区分 404 与网络不可达。
>
> **订阅拉取不使用环境代理**：miaospeed 订阅与进程内探针的 HTTP 客户端均显式设置 `Proxy: nil`，不会读取 `HTTP_PROXY` / `HTTPS_PROXY`。这是为了避免代理自行解析目标地址、绕过按解析 IP 做的 SSRF 校验；如需经代理拉取订阅，请改用服务端中转或本地自定义方案，而不是设置环境代理。
>
> 安装脚本还支持 `--sha256 <hex>`（配合 `--binary <url>` 强制校验自定义二进制）与 `--from-source`（显式从源码编译）。使用 `--binary <url>` 时默认必须能取得同名 `.sha256`（或显式提供 `--sha256`），否则安装会中止；只有在确认自定义来源可信且确实无法提供校验文件时，才可显式加 `--insecure-skip-verify` 跳过校验。`--from-source` 在 `--version latest`（默认）时会编译 main 分支最新代码并打印醒目警告，生产环境建议用 `--version <已发布标签>` 固定版本。Release 下载失败时脚本会直接报错，**不会**自动改为编译 main 分支。

---

## 🔐 更新校验

所有更新与安装仅做 SHA-256 校验；配置 `gh-proxy` 时，`.sha256` 校验文件直连 `github.com` 获取（仍遵循系统 `HTTPS_PROXY` 环境变量），获取失败即拒绝更新或安装。

---

## 🛠️ 服务管理命令

各平台安装脚本均会自动注册为系统原生守护服务（开机自启、崩溃自动拉起）：

| 平台 | 查看状态 | 重启服务 | 查看日志 |
| :--- | :--- | :--- | :--- |
| **Linux (systemd)** | `systemctl status mnagent` | `systemctl restart mnagent` | `journalctl -u mnagent -f` |
| **OpenWrt (procd)** | `/etc/init.d/mnagent status` | `/etc/init.d/mnagent restart` | `logread -e mnagent` |
| **Windows (SCM)** | `Get-Service mnagent` | `Restart-Service mnagent` | 查看服务事件日志 |

---

## 🩺 本地自检与 CLI 探针调试

无需经过 Telegram 服务端，可在探针主机终端直接执行诊断与网络探测：

```sh
# 1. 一键健康体检（依赖完整度、ICMP 套接字权限、DNS、IPv6 及服务端连接测试）
mnagent -diag

# 2. 本地执行单次网络探针测试
mnagent -probe-target 1.1.1.1 -probe-kind ping          # ICMP Ping
mnagent -probe-target 1.1.1.1:443 -probe-kind tcping      # TCPing
mnagent -probe-target https://cloudflare.com -probe-kind http # HTTP 阶段耗时
mnagent -probe-target google.com -probe-kind dns          # DNS 查询
mnagent -probe-target 8.8.8.8 -probe-kind trace           # NextTrace 追踪

# 3. 检查与执行自更新
mnagent -check-update                # 检查 Agent 及依赖版本
mnagent -apply-update latest         # 立即升级到最新版本并平滑重启
```

---

## ⚙️ 常用命令行参数

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| **`-bot <url>`** | 必填 | 服务端 Agent 接口基地址（如 `https://mnbot.example.org/agent`） |
| **`-token <value>`** | — | 接入令牌（亦可通过环境变量 `MNAGENT_TOKEN` 传入） |
| **`-token-file <path>`** | 平台默认路径 | 令牌持久化文件；动态读取，**线上轮换令牌无需重启服务** |
| **`-auto-update`** | `false` | 是否开启后台定时自动检查并升级（一键脚本安装默认开启） |
| **`-gh-proxy <url>`** | — | GitHub 代理加速前缀（支持环境变量 `GH_PROXY`） |
| **`-result-timeout`** | `5m` | 单次结果回传（含大体积 `/results` 上传）的客户端超时 |
| **`-allow-insecure-http`** | `false` | 允许 `-bot` 用明文 HTTP 连接公网地址（默认仅允许回环/内网；明文会暴露令牌） |
| **`-allow-private-probes`** | `false` | 放行对内网私有网段与云元数据地址的探测（默认严格拦截） |
| **`-allow-remote-downgrade`** | `false` | 允许服务端远程指令把 Agent 降级到旧版本（默认只接受高于当前版本的目标；本地 `-apply-update` 不受限） |
| **`-log-level`** | `info` | 日志级别：`debug` / `info` / `warn` / `error` |

---

## 📝 行为变更（v0.3.103）

与升级相关、会影响已有部署的实际行为调整：

- **超过 2MB 的任务结果不再缓存重发**：为避免低内存设备（16MB/32MB Flash 的 OpenWrt）被常驻缓存吃满，单条结果缓存上限为 **2MB**、所有缓存合计 **4MB**。超出上限的任务仍会标记为已完成，但服务端重复下发同一 `jobID` 时只会跳过重复执行并记录 `oversized` 告警，不会再重发缓存结果。
- **miaospeed 单次响应上限 8MB**：单条 WebSocket JSON 响应超过 8MB 会直接报错并放弃，避免异常/恶意服务端把节点内存耗尽（正常 500 节点结果约 3MB）。同时累积缓冲的复用阈值降到 256KB，大缓冲交给 GC 回收。
- **WebSocket 任务缓冲由 64 改为 16**：WS 降级模式下待执行任务队列变短，队列满时立即回报明确的失败结果，而不是阻塞长连接读循环（否则连 ping/ack 都会被拖住），常驻内存更可控。
- **状态目录属主校验**：`/var/lib/mnagent`（Windows 为 `%ProgramData%\mnagent`）必须属于 root/SYSTEM/Administrators 或当前用户，且不允许组/其他用户写入；否则会拒绝使用并输出 `WARN` 告警，Linux 上可执行 `sudo chown root:root /var/lib/mnagent` 修复，详见下文「常见问题排查」。
- **发布新增 `mnagent_linux_armv7` 别名**：内容与 `mnagent_linux_arm` 完全相同（并带 `.sha256`），用于线上 v0.3.102 等旧版 ARM 节点（它们按旧资产名请求），使这些节点能自动升级。等所有 ARM 节点升级完成后，该别名会在 v0.3.104 或之后移除。
- **服务停止超时放宽**：systemd 单元新增 `TimeoutStopSec=80`、OpenWrt procd 新增 `term_timeout 70`，确保退出时能在 60s 预算内回传在途结果，不被守护进程提前强杀（重新执行安装脚本即可更新已有单元）。
- **缓存结果重发同样受 `-result-timeout` 约束**：重复下发任务的缓存结果上传不再使用固定的 6 分钟预算，而是跟随配置的单次回传超时。

---

## ❓ 常见问题排查

- **服务端显示 ⚪️ 离线**：先运行 `mnagent -diag` 检查主机到服务端的 HTTPS 连通性，再确认系统服务运行状态（如 `systemctl status mnagent`）。
- **日志提示 `鉴权失败`**：令牌与服务端不一致；可通过 Telegram `/host rotate` 重新生成，或直接修改令牌文件（Linux: `/etc/mnagent/token`）。
- **报错 `无法启动 nexttrace/miaospeed`**：运行 `mnagent -apply-update latest` 触发依赖自动补全下载；网络受限环境请配置 `-gh-proxy`。
- **Ping 探针报套接字权限不足**：systemd 需配置 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`（重新执行安装脚本会自动修复）；OpenWrt 需以 root 运行。
- **提示 `目标地址属于受限私有/元数据地址`**：默认防御 SSRF 拦截了局域网或云元数据地址；自建内网探测需添加 `-allow-private-probes`。
- **日志提示 `状态目录属主校验失败`**：状态目录（Linux 默认为 `/var/lib/mnagent`）被改成其他用户所有，Agent 会拒绝使用它并退回当前用户的缓存目录（此时跳过版本记录等状态会丢失）。执行 `sudo chown root:root /var/lib/mnagent` 后重启服务即可修复；该目录还要求权限不含组/其他用户的写位（`chmod 755` 或 `700` 均可）。
- **更新后无法启动**：Linux / OpenWrt 上每次替换都会把上一版本保留为 `<二进制路径>.prev`（Windows 为 `.old`，启动时自动清理），可手工 `mv` 回去并重启服务；服务端远程升级只接受更高版本，如需回滚请使用本地 `-apply-update <tag>`。
