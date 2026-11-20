# ⚡ mnagent

运行在拨测探针主机上的轻量化高性能 Agent，专为配合网络拨测与节点测速服务端协同工作而设计。

Agent 通过 HTTPS **主动长轮询**接收服务端下发的网络探测与节点测速任务，在本地执行后结构化回传结果。

- 🔒 **网络零暴露**：**无需公网 IP、无需端口映射、无需 SSH**，只要探针能正常出站访问服务端即可。
- 🔑 **令牌即身份**：每台主机单令牌鉴权（`--token` 或动态读取 `--token-file`），在线轮换无需重启。
- 🔄 **全自动运维**：自动探测、补全与静默升级外部依赖（`nexttrace` / `miaospeed`）。依赖缺失时一律自动下载安装（含 `nexttrace`），并支持后台自更新与服务端一键远程升级。
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
> - Agent 自动更新（v0.4.2 起）的校验值按「服务端代取 → 直连 `.sha256` → 直连 API digest」三级获取：服务端代取只尝试一次（10 秒超时），成功后还会用 5 秒窗口单次直连 `.sha256` 交叉校验，两者不一致立即中止更新（fail-closed）；直连失败时直接采用服务端返回的值。配置 `-gh-proxy` 时，直连 `.sha256` 仍**不经 gh-proxy 镜像获取（仍遵循系统 `HTTPS_PROXY` 环境变量）**（二进制仍走代理），获取校验文件失败即拒绝更新。
> - 依赖（nexttrace/miaospeed，v0.4.3 起）**不做 SHA-256 校验**：上游未发布 `.sha256`，只经 HTTPS（可经 gh-proxy）下载，并在替换前执行 `-V` / `-version` 自检确认可执行且版本匹配，自检失败即中止替换。
> - 为避免离线/被墙时长时间挂起，安装脚本中校验文件的直连尝试限时 30 秒（`curl --connect-timeout 5 --max-time 30` / `wget --timeout=30 --tries=2`），失败提示会区分 404 与网络不可达。
>
> **订阅拉取不使用环境代理**：miaospeed 订阅与进程内探针的 HTTP 客户端均显式设置 `Proxy: nil`，不会读取 `HTTP_PROXY` / `HTTPS_PROXY`。这是为了避免代理自行解析目标地址、绕过按解析 IP 做的 SSRF 校验；如需经代理拉取订阅，请改用服务端中转或本地自定义方案，而不是设置环境代理。
>
> 安装脚本还支持 `--sha256 <hex>`（配合 `--binary <url>` 强制校验自定义二进制）与 `--from-source`（显式从源码编译）。使用 `--binary <url>` 时默认必须能取得同名 `.sha256`（或显式提供 `--sha256`），否则安装会中止；只有在确认自定义来源可信且确实无法提供校验文件时，才可显式加 `--insecure-skip-verify` 跳过校验。`--from-source` 在 `--version latest`（默认）时会编译 main 分支最新代码并打印醒目警告，生产环境建议用 `--version <已发布标签>` 固定版本。Release 下载失败时脚本会直接报错，**不会**自动改为编译 main 分支。

---

## 🔐 更新校验

SHA-256 校验只用于 **mnagent 自身更新**与安装脚本对 mnagent 二进制的校验。依赖 nexttrace/miaospeed **不做** SHA-256 校验，仅经 HTTPS 下载并通过 `-V` / `-version` 自检。Agent 自身更新（v0.4.2 起）的校验值按以下顺序获取：

1. **服务端代取（首选）**：请求 `-bot` 服务端的 `/agent/release-digest`，由部署在海外、可稳定访问 GitHub 的服务端代为获取；令牌走 `Authorization` 头，只尝试一次，超时 10 秒。成功后还会用 5 秒窗口单次直连 `<资产>.sha256` 做交叉校验：两侧都拿到合法值且不一致时立即中止更新（fail-closed，疑似篡改或上游重新上传了资产），**不会**再回退到其他来源；直连失败、超时或格式非法时放行，直接使用服务端返回的值。
2. **直连 `.sha256`**：直连 `github.com` 下载 `<资产>.sha256`，失败按指数退避重试 3 次。
3. **直连 API digest**：直连 `api.github.com` 读取 Release 附件的 `digest` 字段，同样重试 3 次。

服务端代取失败（任何非 200 响应、网络错误、缺少令牌等）只记录 Debug 日志并静默回退到直连来源，同时计入最终错误摘要；三个来源共用 75 秒的整体预算（含交叉校验），不会把各来源的超时与重试层层叠加，三个来源都失败时中止更新，并在错误中明确写出「整体校验值获取预算（75s）已用尽」。配置 `gh-proxy` 时，直连 `.sha256` 与 API 仍不经 gh-proxy 镜像（遵循系统 `HTTPS_PROXY` 环境变量），获取失败即拒绝更新。

依赖（nexttrace/miaospeed）不参与上述校验链：不请求服务端代取、不下载 `<资产>.sha256`、也不读取 `api.github.com` 的 digest。安装时仅要求 HTTPS 传输，下载后执行 `-V`（nexttrace）/ `-version`（miaospeed）自检，确认二进制可执行且版本匹配后才原子替换；自检失败绝不落盘。解压与下载体积上限、空闲超时、失败冷却与单飞（并发只安装一次）等保护仍然生效。

`-bot` 为公网 `http://` 地址时（即使加了 `-allow-insecure-http`），服务端代取会被禁用（启动时输出 WARN），只使用直连来源；`-no-bot-checksum` 可显式禁用服务端代取。依赖（nexttrace/miaospeed）自 v0.4.3 起完全不做 SHA-256 校验，见上。

**CLI 路径的服务端代取只用于 Agent 自身更新**：`-apply-update` 带上 `-bot` 时，会按与常驻模式一致的顺序（`-token` > `MNAGENT_TOKEN` > `-token-file`/默认令牌文件）读取令牌并启用代取；读取不到令牌时**静默忽略**（退出码不受影响），只走直连来源。`-check-update` 只查询版本；`-probe-target` / `-diag-job` 只执行探针/测速任务，依赖下载不做 SHA-256 校验，因此都不会请求代取摘要。`-diag` 也会展示令牌来源与状态。

### ⏱️ 升级与下载时间预算

| 路径 / 阶段 | 超时预算 | 超时后的行为 |
| :--- | :--- | :--- |
| 服务端代取校验值（单次） | 10s | 静默回退直连来源 |
| 代取成功后的交叉校验（单次） | 5s | 放行并使用服务端返回的值 |
| 校验值获取（代取 + 直连 `.sha256` + API 兜底） | 整体 75s | 中止更新，错误中说明整体预算已用尽 |
| 版本查询 / 自身更新校验的小请求（单个 HTTP 客户端） | 20s | 按来源重试或回退 |
| 依赖归档 / 二进制下载 | 无整体超时；连接/TLS 10s、响应头 20s、连续 30s 无数据中止，另受调用方 ctx 约束 | 下载失败；由所在路径决定是否写冷却 |
| 启动补齐 / 定期检查 / 运行时安装 | 单个依赖宽松整体 5m | 自身预算耗尽会写 5 分钟失败冷却，避免每轮重试重复下载；调用方主动取消不写冷却 |
| CLI 依赖更新（`-apply-update`） | 单个依赖宽松整体 5m | 直接报错退出（进程结束，不涉及冷却） |
| 远程升级任务的依赖阶段 | 紧凑 40s（只作用于升级路径） | 跳过剩余依赖，继续更新 Agent 自身 |
| 远程升级任务自身下载/替换 | `job.TimeoutMS − 5s`，默认 115s，夹取到 [1s, 115s]；从任务进入处理函数开始计时（包含等待更新锁） | 预算耗尽则中止；等锁已耗尽预算时直接回报「节点正忙于其他更新，请稍后重试」 |
| 升级结果回传 | 独立的 `-result-timeout` / 整体回传预算 | 不受升级 workCtx 约束；上述预留 5s 仅作为时间余量 |


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
| **`-no-bot-checksum`** | `false` | 禁用服务端代取 SHA-256 校验值（只使用直连 `github.com` / `api.github.com`；服务端疑被入侵或排障时使用） |
| **`-allow-private-probes`** | `false` | 放行对内网私有网段与云元数据地址的探测（默认严格拦截）。只跳过“地址是否落在私网/保留段”这一步：节点测速的协议白名单、payload 结构与禁止字段、server 钉死等安全闸门照常执行 |
| **`-allow-remote-downgrade`** | `false` | 允许服务端远程指令把 Agent 降级到旧版本（默认只接受高于当前版本的目标；本地 `-apply-update` 不受限） |
| **`-log-level`** | `info` | 日志级别：`debug` / `info` / `warn` / `error` |

---

## 📝 行为变更（v0.4.3）

与升级相关、会影响已有部署的实际行为调整：

- **依赖不再做 SHA-256 校验（v0.4.3）**：`nexttrace` / `miaospeed` 的下载与安装不再获取或比对任何 SHA-256——服务端代取、`<资产>.sha256`、`api.github.com` 的 asset digest 三条路径全部移除。依赖只经 HTTPS（可经 `-gh-proxy`）下载，并通过下载后的 `-V` / `-version` 自检（可执行、版本匹配）后才原子替换；自检失败即中止，不覆盖已有二进制。**mnagent 自身更新（含服务端代取、直连 `.sha256`、API digest 与交叉校验）以及 `install.sh` / `install.ps1` 对 mnagent 二进制的 `.sha256` 校验完全不变**。运行时自动安装与 CLI 探针/诊断不再向依赖管理器注入服务端代取客户端，`/agent/release-digest` 只服务 Agent 自身更新；服务端接口白名单保持现状（仍包含这两个仓库，不影响功能）。
- **服务端代取 SHA-256（v0.4.2）**：Agent 自身更新的校验值改为优先由 `-bot` 服务端代取（`GET /agent/release-digest`），服务端不可用或返回非 200 时静默回退到直连来源。Agent 自身更新在代取成功后会额外用一次直连 `.sha256` 交叉校验，不一致立即中止（fail-closed）且不再走 API 兜底。旧服务端（不认识该接口，返回 404）不会影响新探针，只会回退到直连。`-apply-update` 等 CLI 路径带 `-bot` 与令牌时同样启用代取；缺少令牌时静默忽略，不会导致 CLI 报错退出。
- **新增 `-no-bot-checksum`（v0.4.2）**：显式禁用服务端代取校验值。`-bot` 为公网明文 HTTP 地址时默认就禁用（启动日志输出 WARN），即使同时加了 `-allow-insecure-http`；回环/内网 HTTP 与 HTTPS 端点默认启用。
- **旧节点升级说明（v0.4.2）**：v0.4.0 运行的旧探针没有代取逻辑，无法使用服务端提供的哈希；升级途径与以前一致：设置 `HTTPS_PROXY` 让直连 `github.com`/`api.github.com` 走可达代理、在 `-check-update`/`-apply-update` 失败时多次重试，或执行 `install.sh --binary <gh-proxy 地址> --sha256 <核对过的哈希>` 直接安装（Windows 为 `install.ps1 -Binary ... -Sha256 ...`）。升级到 v0.4.2 后即可享受服务端代取。

- **依赖缺失时一律自动下载（v0.4.1）**：不再需要任何开关。`miaospeed` 或 `nexttrace` 缺失时，启动检查、定期检查、测速任务与路由追踪都会自动下载安装；同一依赖并发触发时只下载一次，安装失败后有 5 分钟冷却并返回明确错误。**`-allow-auto-install-deps` 已删除**：服务命令里仍带着它的节点启动时会报“未知参数”，请重新执行一次安装命令（`install.sh` / `install.ps1`）以生成新的服务参数。
- **内联代理配置上限按内存收紧（v0.4.1）**：默认上限 12MB（与服务端 ≤12MB 内联下发契约一致），Linux 上按 `min(12MB, MemTotal/8)` 收紧、最低 2MB；解析时按候选节点上限截断，超出部分不保留 payload，避免低内存设备被超大配置撑爆。
- **订阅下载上限按内存收紧（v0.4.1）**：默认上限 16MB，Linux 上按 `min(16MB, MemTotal/6)` 收紧、最低 2MB；响应带 Content-Length 时会在读取正文前拒绝，超过上限会明确报错并拒绝解析，不再静默截断成半截 YAML/JSON。
- **轻任务队列容量 128（v0.4.1）**：轻任务并发仍为 8，排队上限由“无上限”改为 128；队列已满时立即回报失败但**不写去重缓存**，服务端重发同一任务时会真正重跑。
- **超过 256KB 的结果改走 HTTP（v0.4.1）**：WS 写超时只有 15s，大结果继续走长连接容易拖断连接；超过 `256KB` 的结果直接走 HTTP `/results`（带独立超时与重试）。
- **节点安全检查 DNS 总预算 30s（v0.4.1）**：域名解析阶段有独立 30s 总预算，到点后未完成解析的候选按 fail-closed 剔除；父任务被取消时单独记录“任务已取消”，不误报为 DNS 预算超时。
- **armv7 发布别名已删除（v0.4.1）**：线上 ARM 节点均已升级到支持标准资产名的版本，`mnagent_linux_armv7` 别名不再发布；安装脚本仍统一把 `armv7l/armv6l` 等映射到 `mnagent_linux_arm`。
- **`-bot` 不再接受 userinfo / query / fragment**：`https://user:pass@host/agent`、`...?token=x`、`...#frag` 会在启动时被拒绝（安装脚本同样提前拦截），因为客户端会直接在地址后拼接 `/jobs`、`/results`，既会拼错路径也可能泄露凭据。凭据请用 `-token` / `-token-file`。
- **明文 HTTP 默认只允许本地目标**：只有 `localhost`、`*.localhost` 以及字面回环/私网/链路本地 IP 可直接使用 `http://`；`*.lan`、`*.local`、单标签主机名和普通域名（包括 `10.example.com`、`fdic.example.com` 这类仅字符串前缀相似的域名）都视为非本地，必须显式加 `-allow-insecure-http`（安装脚本为 `--allow-insecure-http` / `-AllowInsecureHttp`），否则 agent 会拒绝启动。安装脚本与 agent 使用同一套严格判定，并把该开关传给 agent。

- **超过 2MB 的任务结果不再缓存重发**：为避免低内存设备（16MB/32MB Flash 的 OpenWrt）被常驻缓存吃满，单条结果缓存上限为 **2MB**、所有缓存合计 **4MB**。超出上限的任务仍会标记为已完成，但服务端重复下发同一 `jobID` 时只会跳过重复执行并记录 `oversized` 告警，不会再重发缓存结果。
- **miaospeed 单次响应上限 8MB**：单条 WebSocket JSON 响应超过 8MB 会直接报错并放弃，避免异常/恶意服务端把节点内存耗尽（正常 500 节点结果约 3MB）。同时累积缓冲的复用阈值降到 256KB，大缓冲交给 GC 回收。
- **WebSocket 任务缓冲由 64 改为 16**：WS 降级模式下待执行任务队列变短，队列满时立即回报明确的失败结果，而不是阻塞长连接读循环（否则连 ping/ack 都会被拖住），常驻内存更可控。
- **状态目录属主校验**：`/var/lib/mnagent`（Windows 为 `%ProgramData%\mnagent`）必须属于 root/SYSTEM/Administrators 或当前用户，且不允许组/其他用户写入；否则会拒绝使用并输出 `WARN` 告警，Linux 上可执行 `sudo chown root:root /var/lib/mnagent` 修复，详见下文「常见问题排查」。
- **服务停止超时放宽**：systemd 单元新增 `TimeoutStopSec=80`、OpenWrt procd 新增 `term_timeout 70`，确保退出时能在 60s 预算内回传在途结果，不被守护进程提前强杀（重新执行安装脚本即可更新已有单元）。
- **缓存结果重发同样受 `-result-timeout` 约束**：重复下发任务的缓存结果上传不再使用固定的 6 分钟预算，而是跟随配置的单次回传超时。

---

## ❓ 常见问题排查

- **服务端显示 ⚪️ 离线**：先运行 `mnagent -diag` 检查主机到服务端的 HTTPS 连通性，再确认系统服务运行状态（如 `systemctl status mnagent`）。
- **日志提示 `鉴权失败`**：令牌与服务端不一致；可通过 Telegram `/host rotate` 重新生成，或直接修改令牌文件（Linux: `/etc/mnagent/token`）。
- **报错 `无法启动 nexttrace/miaospeed`**：运行 `mnagent -apply-update latest` 触发依赖自动补全下载；网络受限环境请配置 `-gh-proxy`。
- **报错 `服务端代取校验值与直连 .sha256 不一致`**：更新已按 fail-closed 中止，二进制未被替换，也不会改用 API 兜底。先确认上游是否重新上传了同一版本的资产（重新执行一次通常即可）；若确认直连来源的值才正确（例如与上游 Release 页面一致），可临时加 `-no-bot-checksum` 只用直连来源重试，或用 `install.sh --binary <gh-proxy 地址> --sha256 <核对过的哈希>` 直接安装。**不要**在未确认来源可信时盲目重试或跳过校验。
- **旧版本（v0.4.0 及更早）无法使用服务端代取的哈希**：这些版本没有 `/agent/release-digest` 客户端逻辑，只能按原来的直连方式升级（设置 `HTTPS_PROXY`、多次重试，或 `install.sh --binary <gh-proxy 地址> --sha256 <核对过的哈希>`）；升级到 v0.4.2 后自动启用。
- **Ping 探针报套接字权限不足**：systemd 需配置 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`（重新执行安装脚本会自动修复）；OpenWrt 需以 root 运行。
- **提示 `目标地址属于受限私有/元数据地址`**：默认防御 SSRF 拦截了局域网或云元数据地址；自建内网探测需添加 `-allow-private-probes`。
- **日志提示 `状态目录属主校验失败`**：状态目录（Linux 默认为 `/var/lib/mnagent`）被改成其他用户所有，Agent 会拒绝使用它并退回当前用户的缓存目录（此时跳过版本记录等状态会丢失）。执行 `sudo chown root:root /var/lib/mnagent` 后重启服务即可修复；该目录还要求权限不含组/其他用户的写位（`chmod 755` 或 `700` 均可）。
- **更新后无法启动**：Linux / OpenWrt 上每次替换都会把上一版本保留为 `<二进制路径>.prev`（Windows 为 `.old`，启动时自动清理），可手工 `mv` 回去并重启服务；服务端远程升级只接受更高版本，如需回滚请使用本地 `-apply-update <tag>`。
