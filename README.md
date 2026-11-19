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
(curl -fsSL https://github.com/mengnanquq/mnagent/releases/download/v0.3.101/install.sh \
  || wget -qO- https://github.com/mengnanquq/mnagent/releases/download/v0.3.101/install.sh) \
  | sh -s -- --bot https://<服务端地址>/agent --token-file /etc/mnagent/token
```

### Windows (以管理员身份打开 PowerShell)
```powershell
& ([scriptblock]::Create((irm https://github.com/mengnanquq/mnagent/releases/download/v0.3.101/install.ps1))) -Bot "https://<服务端地址>/agent" -TokenFile "C:\ProgramData\mnagent\token"
```

> 安装脚本随每个 Release 作为附件发布；请把上面的 `v0.3.101` 换成要安装的 release tag。为避免令牌出现在进程 argv 与命令历史中，推荐 `--token-file`（Linux）或 `-TokenFile`（Windows），也支持环境变量 `MNAGENT_TOKEN` 与 Linux 下的 `--token-stdin`。`--token` 仅为兼容旧命令保留，使用时会打印警告。
>
> **网络受限 / 国内加速**：
> 在安装参数中附加 `--gh-proxy https://gh-proxy.com/`（Windows 添加 `-GhProxy "https://gh-proxy.com/"`），脚本自身、Agent 更新以及依赖下载均会自动经由加速代理。
>
> **⚠️ gh-proxy 信任说明**：自更新与依赖安装会强制校验 SHA-256，但配置代理时二进制与对应的 `.sha256` 校验文件都经同一代理下载，代理运营方理论上可以同时替换两者。也就是说，**启用 gh-proxy 等同于信任该代理运营方**；在可信网络环境下建议不要配置代理，必须使用时请选择你信任的服务。
>
> 安装脚本还支持 `--sha256 <hex>`（配合 `--binary <url>` 强制校验自定义二进制）与 `--from-source`（显式从源码编译）。Release 下载失败时脚本会直接报错，**不会**自动改为编译 main 分支。

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

## ❓ 常见问题排查

- **服务端显示 ⚪️ 离线**：先运行 `mnagent -diag` 检查主机到服务端的 HTTPS 连通性，再确认系统服务运行状态（如 `systemctl status mnagent`）。
- **日志提示 `鉴权失败`**：令牌与服务端不一致；可通过 Telegram `/host rotate` 重新生成，或直接修改令牌文件（Linux: `/etc/mnagent/token`）。
- **报错 `无法启动 nexttrace/miaospeed`**：运行 `mnagent -apply-update latest` 触发依赖自动补全下载；网络受限环境请配置 `-gh-proxy`。
- **Ping 探针报套接字权限不足**：systemd 需配置 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`（重新执行安装脚本会自动修复）；OpenWrt 需以 root 运行。
- **提示 `目标地址属于受限私有/元数据地址`**：默认防御 SSRF 拦截了局域网或云元数据地址；自建内网探测需添加 `-allow-private-probes`。
- **更新后无法启动**：Linux / OpenWrt 上每次替换都会把上一版本保留为 `<二进制路径>.prev`（Windows 为 `.old`，启动时自动清理），可手工 `mv` 回去并重启服务；服务端远程升级只接受更高版本，如需回滚请使用本地 `-apply-update <tag>`。
