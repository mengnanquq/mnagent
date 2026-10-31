# mnagent

运行在拨测与探测主机上的轻量化高性能 agent，配合 Telegram 机器人 [@mengna_app](https://t.me/mengna_app) 使用：
机器人统一调度下发探测与测速任务，agent 在本机高效执行并回传结构化结果，支持路由追踪（`nexttrace`）、网络探针（`ping`、`tcping`、`http`、`dns`）以及代理节点/订阅测速（`miaospeed`）。

它主动向机器人**长轮询**领取任务、在本机执行并回传。因此：

- 主机**不需要公网地址**，不需要端口映射、反向隧道或 VPN——只要主机出站能访问机器人即可；
- 接入只需一个令牌（`--token` 或 `--token-file`）：机器人按令牌识别是哪台主机，主机端不需要（也不接受）名称；
- 主机**不需要开通 SSH**，不需要开放任何入站端口，网络侧完全无监听暴露；
- 机器人下发的只是**已校验的标准化参数**，网络侧无法指定任意系统命令，执行路径由本机配置严格白名单锁定；
- **独立保活心跳**与长轮询协同运作，在大批量节点长时间测速时依然保持心跳刷新，机器人端时刻精准呈现 🟢 在线 / ⚪️ 离线。

---

## 核心特性一览

- ⚡ **多元化网络探针体系**
  - **路由追踪（NextTrace）**：调用 NextTrace 快速探测链路骨干网、AS 信息及逐跳延迟，支持原生 `-j` JSON 结构化解析与自动平滑降级兼容；
  - **ICMP Ping**：原生进程内实现，支持非特权 UDP Ping 与特权 Raw Socket（`CAP_NET_RAW`）双模切换，输出精确丢包率、延迟极值与抖动（Jitter），支持秒级取消；
  - **TCPing**：高精度 TCP 握手延迟测试，**支持目标地址自动安全剥离端口**（如 `example.com:443` 或 IPv6 `[::1]:80`），直连解析后 IP 消除 DNS 抖动干扰；
  - **HTTP/HTTPS 拨测**：深度采集响应状态码、服务端 IP、协议版本（HTTP/1.1、HTTP/2 等）、TLS 握手版本与证书有效期/颁发者，细分 **DNS 解析、TCP 建连、TLS 握手、TTFB 首字节与总耗时**，并采集关键响应标头；
  - **DNS 诊断**：调用系统底层解析器批量查询 A/AAAA/CNAME/MX/NS/TXT/PTR 记录，精确度量域名解析耗时；
  - **出站运营商 (ISP) 智能探测**：启动与轮询时智能识别探针本机的出站网络运营商（如电信、联通、移动、AWS、Cloudflare 等），随长轮询与心跳自动上报至机器人并在监控大盘中展示（支持 `-isp` 手动覆盖）。
- 🚀 **强大的 MiaoSpeed 代理测速引擎**
  - **全协议兼容**：支持单节点 URI（`ss://`, `vmess://`, `trojan://`, `vless://`, `hysteria2://`, `tuic://`, `anytls://`）、订阅链接（HTTP/HTTPS）、Clash YAML、Sing-box JSON、Base64 订阅文本与多行节点清单；
  - **8 大测试模式**：代理连通性、链路拓扑、多线程测速、单线程测速、延迟测试、UDP NAT 类型探测、**流媒体专测（`media`）** 以及全量综合测试；
  - **12 大主流流媒体与 AI 服务原生解锁检测**：全面基于开源 [RegionRestrictionCheck](https://github.com/oneclickvirt/RegionRestrictionCheck) 规则重构，支持 YouTube (Premium 防送中)、Netflix (双片源原生/自制剧识别)、Disney+、Amazon Prime Video、Spotify、TikTok、巴哈姆特动画疯、哔哩哔哩 (港澳台/台限定)、OpenAI (ChatGPT)、Claude、Google Gemini 与维基百科可编辑性检测；
  - **逐节点实时流式上报**：测试进行中，每个切片/节点完成即通过 `/progress` 接口向机器人流式上报结构化数据，前端可实时更新动态卡片，并支持机器人在响应中下发 `cancel: true` 随时中止长任务；
  - **版本自检与动态超时**：自动探测底层 miaospeed 引擎版本并附带于测试报告中；根据订阅节点规模动态计算安全超时，避免长任务被提前截断。
- 🛡️ **企业级安全防御（防范 SSRF 与云元数据盗取）**
  - 探针任务默认严格拦截回环地址（127.0.0.0/8）、内网私有网段（10/8, 172.16/12, 192.168/16）、运营商级 NAT（100.64.0.0/10）、链路本地地址及云服务商实例元数据地址（`169.254.169.254` 等），杜绝利用拨测探针窃取主机与云实例凭证；
  - 针对自建内网探测需求，提供 `--allow-private-probes` 参数按需放行；
  - **凭据脱敏与 SSRF 防护**：测速目标解析与执行异常时自动脱敏订阅链接与代理凭据，杜绝敏感密钥随报错输出；对订阅拉取同样施加严格的 SSRF 回环与元数据防护。
- 🔄 **全生命周期多依赖协同自更新与远程升级**
  - **依赖统一管理（DependencyManager）**：自动探测、定期比对与静默更新外部依赖工具（`nexttrace` 与 `miaospeed`），自动清除终端彩色转义字符（ANSI）；
  - **远程一键升级（Update Job）**：支持从机器人后台一键下发远程升级指令，自动更新依赖与 mnagent 二进制，向机器人回传成功结果后平滑重启，**完整继承原有启动参数与服务配置**；
  - **全链路代理加速**：安装脚本、agent 自身及所有外部依赖的更新均深度支持 `--gh-proxy`（如 `https://gh-proxy.com/`）加速代理。
- 💻 **全平台支持与轻量化构建**
  - 支持 Linux（systemd/init）、OpenWrt（procd 原生守护，sysupgrade 升级固件保留配置）、Windows（原生 SCM 系统服务，无需任何三方包装器）与 macOS；
  - 支持 amd64、arm64、armv7l、mips/mipsle、riscv64 等主流硬件架构，支持 UPX 极限压缩，低内存设备无负担运行。
- 🩺 **强大的本地诊断看板与 CLI 工具**
  - 提供 `-diag` 一键体检看板，秒级检测主机信息、NextTrace / MiaoSpeed 状态、ICMP Raw Socket 权限、系统 DNS、IPv6 双栈连通性、GitHub 代理源及机器人连通性；
  - 提供 `-probe-target` 与 `-probe-kind` 命令行快捷探针测试，无需机器人端即可在终端本地复现网络测试。

---

## 快速安装

推荐使用机器人自动生成的**一键安装命令**（管理员在 Telegram 机器人中执行 `/host add <名称>` 即可获取对应系统预填好的安装命令）：

### Linux / OpenWrt / macOS

```sh
(curl -fsSL https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh \
  || wget -qO- https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh) \
  | sh -s -- --bot https://<机器人地址>/agent --token <令牌>
```

### Windows (PowerShell 管理员)

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1))) -Bot "https://<机器人地址>/agent" -Token "<令牌>"
```

若网络访问 GitHub 受限，可附加 `-GhProxy` 参数使用加速代理：

```powershell
& ([scriptblock]::Create((irm https://gh-proxy.com/https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1))) -Bot "https://<机器人地址>/agent" -Token "<令牌>" -GhProxy "https://gh-proxy.com/"
```

> **网络受限环境说明：**
> 1. **GitHub 代理加速**：在安装命令中附加 `--gh-proxy https://gh-proxy.com/`（Windows 安装命令附加 `-GhProxy "https://gh-proxy.com/"`，或设置环境变量 `GH_PROXY=https://gh-proxy.com/`）。安装脚本、agent 自身自更新以及后台下载 nexttrace 与 miaospeed 均会自动经由加速代理下载。
> 2. **自建内网镜像**：可将预编译二进制放在内网镜像源，通过 `--binary https://内网镜像/mnagent_linux_amd64` 指定；机器人侧也可通过 `MNAGENT_INSTALL_URL` 环境变量将生成命令中的脚本地址直接指向私有源。

### 自动化构建发布

本仓库已深度集成 GitHub Actions 流水线：
- **推送 `main` 分支**：自动根据最新版本生成语义化预发布版本号（如 `v0.4.0-main.<时间戳>.<sha>`），自动交叉编译各平台二进制、压缩打包并发布 Release；
- **打 `v*` 标签**：推送指定 Tag（例如 `git tag v0.5.0 && git push origin v0.5.0`）会自动发布正式 Release。

---

## 平台特定说明

### Linux (systemd)

脚本会自动完成：
1. 从 Release 下载匹配系统与架构的二进制文件（若网络受限或无对应产物则自动回退至源码编译）；
2. 自动检测并安装缺失的 `nexttrace` 与 `miaospeed` 核心依赖；
3. 创建专用系统用户、持久化接入令牌至 `/etc/mnagent/token`（权限 `0600`）；
4. 注册并启动 `/etc/systemd/system/mnagent.service` 系统服务，原始套接字权限由单元的 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` 提供，准备专用数据目录（`StateDirectory=mnagent`）；
5. 重复执行安装脚本即为安全更新升级，会自动平滑重启服务。

常用管理命令：
```sh
systemctl status mnagent         # 查看服务运行状态
journalctl -u mnagent -f         # 实时追踪日志输出
systemctl restart mnagent        # 重启服务
```

### OpenWrt (procd)

同一条 Linux 安装命令可无缝在 OpenWrt 路由器与网关上执行，脚本会自动识别并采用 procd 原生守护进程方案：
- 二进制安装至 `/usr/bin/mnagent`，服务管理脚本写入 `/etc/init.d/mnagent`（`USE_PROCD=1`，开启 `respawn` 异常退出自动拉起，日志自动进 syslog）；
- **以 root 身份运行**：OpenWrt 通常没有非特权系统用户及 `setcap` 支持，而网络底层探测与 `nexttrace` 需要 `CAP_NET_RAW` 权限；
- 兼容极简环境：不依赖 `curl`、`install`、`useradd` 等工具，自动安全回退至 `uclient-fetch`/`wget`、`cp+chmod` 与 BusyBox 指令；
- **固件升级保留**：自动将二进制文件与 `/etc/mnagent` 目录写入 `/etc/sysupgrade.conf`，系统升级固件后配置与程序依然保留；
- 广泛适配主流路由器架构：`armv7l`/`armv6l`/`armv5`、`aarch64`、`x86_64`、`mips`/`mipsle`（ELF 头自动识别大小端）、`mips64`/`mips64le` 与 `riscv64`。

常用排查命令：
```sh
logread -e mnagent              # 查看 agent 运行日志
/etc/init.d/mnagent restart      # 重启服务
/etc/init.d/mnagent status       # 查看运行状态
```

### Windows (原生 SCM 系统服务)

mnagent 原生支持 Windows（x86_64 及 ARM64），并内置 Windows 服务控制管理器（SCM）协议，无需依赖 NSSM 或 WinSW 等三方包装器：
- 脚本自动检测系统架构并下载 `mnagent_windows_<arch>.exe`；
- 自动检测、下载并解压 Windows 版 `nexttrace.exe` 与 `miaospeed.exe` 压缩包并放置于安装目录；
- 写入令牌至安装目录（默认 `C:\Program Files\mnagent`）；
- 注册名为 `mnagent` 的原生 Windows 服务，设置异常崩溃自动重启并随系统开机自启。

常用管理命令（在管理员权限 PowerShell 中执行）：
```powershell
Get-Service mnagent             # 查看服务状态
Restart-Service mnagent         # 重启服务
Stop-Service mnagent            # 停止服务
Start-Service mnagent           # 启动服务
powershell .\install.ps1 -Uninstall # 一键卸载清理服务
```

在前台控制台直接启动调试：
```powershell
.\mnagent.exe -bot https://<机器人地址>/agent -token "<令牌>" -auto-update
```

---

## 支持的探测与测试类型

| 类型 (`kind`) | 说明 | 核心依赖与实现方式 | 详细输出与关键指标 |
| :--- | :--- | :--- | :--- |
| **`trace`**（默认） | 链路路由追踪 | 需要 `nexttrace`（自动探测、下载与更新） | 沿途逐跳 IP、所属 AS 机构、物理地理位置、单跳延迟与链路丢包 |
| **`miaospeed`** | 节点或订阅测速 | 需要 `miaospeed`（自动探测、下载与更新） | 8 种测试模式，12 大主流流媒体与 AI 原生解锁，下行带宽、RTT 延迟、UDP NAT 类型 |
| **`ping`** | ICMP Echo 延迟与丢包探测 | 进程内原生实现（无外部依赖，特权/非特权双模） | 丢包率（%）、最小/平均/最大延迟（ms）、网络抖动（Jitter）、逐次尝试结果 |
| **`tcping`** | TCP 握手连通性与延迟探测 | 进程内原生实现（无外部依赖） | 支持目标自带端口自动拆分，输出握手延迟极值、平均 RTT、丢包率与抖动 |
| **`http`** | HTTP/HTTPS 拨测与阶段耗时分析 | 进程内原生实现（无外部依赖） | 状态码、协议版本、TLS 版本、证书过期时间/颁发者、DNS/连接/TLS/TTFB 分段耗时、响应标头 |
| **`dns`** | 底层域名解析诊断 | 进程内原生实现（无外部依赖） | 支持查询 A/AAAA/CNAME/MX/NS/TXT/PTR，解析总耗时与完整解析记录清单 |

### 网络安全拦截（SSRF 与云元数据保护）

为防止探测客户端被恶意下发目标针对内网或云基础设施发起攻击，mnagent 在进程内探针层内置了严格的安全校验：
- **默认拦截范围**：
  - 本地回环地址（`127.0.0.0/8`, `::1`）；
  - 私有局域网网段（`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`）；
  - 运营商级 NAT 网段（CGNAT `100.64.0.0/10`）；
  - 链路本地与组播地址（`169.254.0.0/16`, `fe80::/10` 等）；
  - **各大公有云实例元数据服务**（如 AWS / GCP / 阿里云 / 腾讯云常见的 `169.254.169.254` 等），有效防范云端凭证（IAM Role Token）失窃。
- **内网环境放行**：若确有内网拨测需求，可在启动参数中添加 `--allow-private-probes` 放行私有 IP 探测。

---

## MiaoSpeed 测速引擎深度解析

`miaospeed` 任务支持测试单个节点链接、订阅 URL 或完整的代理配置文件。任务的 `query` 或 `protocol` 参数支持指定以下测试模式（支持逗号或斜杠组合，未指定时默认执行**全量测试**）：

### 8 大测试模式

1. **代理连通性测试**（`connectivity` / `conn` / `连通性`）：快速测试代理链路可用性、HTTP 响应状态码及基础 RTT 延迟；
2. **拓扑测试**（`topology` / `topo` / `拓扑`）：精准探测入站节点 IP、出站落地国家地区与 ISP 信息，检测 DNS 劫持；
3. **多线程测速**（`multithread` / `multi` / `多线程` / `下载`）：通过并行多连接测定下行峰值带宽与平均速率（可通过 `count` 自定义线程数，默认 4）；
4. **单线程测速**（`singlethread` / `single` / `单线程`）：测试单连接长连接下行速度，真实反映单流吞吐；
5. **延迟测试**（`latency` / `ping` / `延迟`）：精确统计 TCP RTT 握手耗时、HTTP Ping 延迟、丢包率与网络抖动；
6. **UDP 类型测试**（`udp` / `nat` / `stun` / `udp类型`）：通过专用 STUN 服务探测节点的 UDP 转发支持与 NAT 类型（FullCone / Symmetric / RestrictedCone 等）；
7. **流媒体专测**（`media` / `unlock` / `流媒体`）：**仅测试基础出站拓扑并完整跑满 12 大流媒体与 AI 解锁脚本**，极速反馈，不跑下载测速，极其节省服务器流量；
8. **全量测试**（`full` / `all` / `全量`）：综合执行连通性、拓扑、延迟、UDP 类型、带宽测速，并默认执行 12 大主流流媒体与 AI 服务解锁检测。

### 12 大主流流媒体与 AI 服务原生解锁检测

基于开源项目 [RegionRestrictionCheck](https://github.com/oneclickvirt/RegionRestrictionCheck) 深度重构，在每一个代理节点建立的网络连接隧道中运行独立轻量 JavaScript 沙箱：

| 服务分类 | 平台 / 服务 | 解锁探测与判定规则 |
| :--- | :--- | :--- |
| **主流流媒体** | **YouTube** | 探测 YouTube Premium 支持情况，精准识别并拦截 `www.google.cn` 送中状态，输出支持地区代码 |
| | **Netflix** | 双片源探测机制，精准区分原生完整解锁（附带区域代码）、仅支持自制剧（Originals Only）或不可用 |
| | **Disney+** | 探测区域服务可用性，根据重定向路径精确提取支持国家地区代码 |
| | **Amazon Prime Video** | 探测区域访问限制（`isServiceRestricted`），识别所属 Territory 区域 |
| | **Spotify** | 探测账号注册 API 连通性，识别落地国家是否已开放注册 |
| | **TikTok** | 探测落地国家/区域访问支持，精准解析返回的 `region` 地区属性 |
| | **巴哈姆特动画疯** | 设备鉴权与播放 Token 获取，精准识别台湾地区（TW）限定动画播放支持 |
| | **哔哩哔哩 (Bilibili)** | 探测港澳台限定番剧与台湾地区独播剧集解锁状态，精确区分仅大陆/港澳台/台湾支持 |
| **AI 与知识服务** | **OpenAI (ChatGPT)** | 探测网页端与 API 合规端点，精准识别地区受限（Unsupported Country）与数据中心 VPN 封锁 |
| | **Claude** | 探测 Anthropic Claude 登录端点，识别区域不可用（`app-unavailable-in-region`）状态 |
| | **Google Gemini** | 探测 Gemini 核心接口，提取可用国家代码与服务开通状态 |
| | **维基百科 (Wikipedia)** | 探测开放代理与 IP 封禁状态，检测该节点出口 IP 是否具备维基百科自由编辑权限 |

- **前置高速 Geo 探测**：优先经由 Cloudflare trace 双栈端点获取出口 IP，并智能推导落地国家地区；
- **逐节点实时流式上报**：每个节点测试完成瞬间，立即将该节点的结构化结果（延迟、丢包、上下行速率、各流媒体状态、出口信息）通过 `/progress` 接口推送给机器人，避免大订阅等待过久；
- **长任务中途秒级取消**：长轮询支持接收 `cancel` 指令，且在进度推送返回中携带 `cancel: true` 时瞬时中止后序节点测试并回收资源。

---

## 双队列并发调度与保活心跳架构

mnagent 内部采用高效的并发调度架构，兼顾任务处理性能与网络稳定性：

```
                    ┌────────────────────────────────────────────────────────┐
                    │               Telegram Bot / Backend                   │
                    └────────────────────────────────────────────────────────┘
                                ▲                     ▲            ▲
                      /jobs 轮询 │           /heartbeat│    /results│ /progress
                                │                     │            │ (流式上报)
                    ┌───────────┴─────────────────────┴────────────┴────────┐
                    │                        mnagent                        │
                    │                                                       │
                    │  [独立心跳协程] ──每 20 秒──> 保活心跳 (防长任务误判离线)   │
                    │                                                       │
                    │  [长轮询主调度] ──收到任务──────────────────────────────┐ │
                    │                                                       │ │
                    │       ┌───────────────────┐                           │ │
                    │       │   JobTracker 追踪  │ <──秒级取消 (cancel 指令)     │ │
                    │       └───────────────────┘                           │ │
                    │                 │                                     │ │
                    │        任务类型分类判定                                 │ │
                    │        ╱                ╲                             │ │
                    │  重任务 (Heavy)       轻任务 (Light)                   │ │
                    │       │                        │                      │ │
                    │  [串行队列 heavyQueue]    [并发协程池 lightSem]          │ │
                    │  • NextTrace 路由追踪     • ICMP Ping 探针             │ │
                    │  • MiaoSpeed 代理测速     • TCPing 握手探针            │ │
                    │  • Remote Upgrade 升级    • HTTP 拨测探针              │ │
                    │                           • DNS 诊断探针               │ │
                    │  (避免带宽争抢测速失真)      (默认 8 并发，秒级响应)      │ │
                    └───────────────────────────────────────────────────────┘
```

1. **重任务串行队列（`heavyQueue`）**：NextTrace 路由追踪、MiaoSpeed 节点测速与远程升级任务投入专用串行队列，严格保证单节点下网络带宽不被多任务争抢，确保测速与链路追踪结果精准可靠；
2. **轻任务高并发池（`lightSem`）**：Ping、TCPing、HTTP 与 DNS 探针由轻任务协程池并发处理（默认上限 8），主轮询循环永不挂起阻塞；
3. **独立保活心跳协程**：每 20 秒独立向 `/heartbeat` 发送轻量脉冲，无论重任务执行耗时多长，机器人后台的主机在线状态始终常青；
4. **任务追踪与取消（JobTracker）**：支持外部取消正在执行或排队中的任务，瞬时断开网络连接或关闭子进程。

---

## 依赖管理与自动更新

mnagent 内置了全套外部依赖生命周期管理器（`DependencyManager`），协同管理自身与核心依赖组件：

1. **版本自动探测**：自动识别本地系统已安装的 `nexttrace` 与 `miaospeed` 实际版本，精准过滤 ANSI 彩色字符；
2. **静默并行升级**：
   - 自动更新循环（默认每 6 小时触发）自动检查 GitHub Releases；
   - 发现新版时，后台自动并行拉取对应系统与架构的发布资产、安全校验、解压并原子替换可执行文件；
3. **远程升级任务（Remote Upgrade）**：
   - 机器人可直接下发 `update` 或 `upgrade` 任务；
   - agent 接收到任务后，优先更新过期的外部依赖，再下载替换自身，并向机器人回传带有版本变化与依赖升级明细的成功报告；
   - 回传完成后平滑重启服务，**自动继承并保持现有的全部服务参数与配置**；
4. **本地 CLI 运维管理**：
   - **检查更新状态**：`mnagent -check-update` 输出 agent 及依赖的当前版本与最新版本状态矩阵；
   - **立即执行升级**：`mnagent -apply-update latest`（或指定具体版本号如 `v0.4.0`），自动完成依赖更新与自身升级并平滑重启；
   - **临时跳过版本**：`mnagent -skip-update v0.4.1`（24 小时内不再提醒或自动更新该版本）。

---

## 命令行参数一览

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| **`-bot <url>`** | 必填 | 机器人 agent 接口基地址，如 `https://mnbot.example.org/agent` |
| **`-token <value>`** | — | 直接传入接入令牌（不推荐：可能暴露在进程列表） |
| **`-token-file <path>`** | Linux: `/etc/mnagent/token`<br>Windows: `%ProgramData%\mnagent\token` | 令牌文件路径；每次请求动态读取，**在线轮换令牌无需重启 agent** |
| **`-nexttrace <path>`** | `nexttrace` | `nexttrace` 可执行文件路径或系统 PATH 中的名称 |
| **`-miaospeed <path>`** | `miaospeed` | `miaospeed` 可执行文件路径或系统 PATH 中的名称 |
| **`-auto-update`** | `false` | 是否开启后台定时自动更新（使用一键安装脚本安装时默认开启） |
| **`-update-interval`** | `6h` | 自动检查更新的周期（支持 `2h`、`12h` 等格式） |
| **`-isp <name>`** | 自动探测 | 手动指定本探针主机的出口运营商/ISP 名称（如 `香港 HKT`、`四川电信` 等；留空时自动探测） |
| **`-gh-proxy <url>`** | — | GitHub 代理加速前缀（如 `https://gh-proxy.com/`，支持环境变量 `GH_PROXY` / `MNAGENT_GH_PROXY`） |
| **`-allow-private-probes`**| `false` | 是否放行针对内网私有地址、回环及云元数据的探测（默认严格拦截防范 SSRF） |
| **`-diag`** | — | **执行本地环境、系统依赖、套接字特权与网络连通性自检看板后退出** |
| **`-probe-target <target>`**| — | **本地直接执行一次探针网络测试的目标（域名或 IP），快速自测** |
| **`-probe-kind <kind>`** | `ping` | 本地自测探针类型：`ping` / `tcping` / `trace` / `http` / `dns` |
| **`-diag-job <target>`** | — | 本地直接对指定单节点或订阅执行一次全量 MiaoSpeed 测速并打印输出 |
| **`-check-update`** | — | 单次检查 agent 及所有外部依赖是否有更新并输出状态，不执行下载 |
| **`-apply-update <tag\|latest>`** | — | 手动下载并安装指定版本或最新版（自动并行更新依赖）并平滑重启 |
| **`-skip-update <tag>`** | — | 跳过指定版本 24 小时 |
| **`-min-backoff` / `-max-backoff`** | `1s` / `1m` | 轮询失败后的重试退避区间（带随机抖动） |
| **`-poll-timeout`** | `40s` | 单次长轮询客户端超时（服务端通常保持 20 秒） |
| **`-log-level`** | `info` | 日志输出级别：`debug` / `info` / `warn` / `error` |
| **`-version`** | — | 输出版本与平台架构信息后退出 |

> 环境变量优先级：命令行参数 `-token` > 环境变量 `MNAGENT_TOKEN` > 参数 `-token-file`。

---

## 本地健康自检与 CLI 探针调试

### 本地环境诊断看板 (`-diag`)

执行 `mnagent -diag`，系统将在终端直观输出系统依赖与连通性看板：

```text
================================================================
  ⚡ mnagent v0.4.0 本地环境与系统依赖健康自检 (System Diagnostics)
================================================================
  • 主机名称: hk-node-01
  • 操作系统: linux (amd64, 4 CPUs)
  • Go 版本:  go1.23.2
----------------------------------------------------------------
  • NextTrace: 🟢 正常 -> /usr/local/bin/nexttrace (NextTrace v1.3.1)
  • MiaoSpeed: 🟢 正常 -> /usr/local/bin/miaospeed (version: v4.7.7)
----------------------------------------------------------------
  • ICMP 套接字: 🟢 原生套接字权限正常 (CAP_NET_RAW / root 具备)
----------------------------------------------------------------
  • 系统 DNS:    🟢 解析正常 (耗时 12ms, 目标 one.one.one.one -> 1.1.1.1)
  • IPv6 双栈:   🟢 原生 IPv6 出站连通正常 (具备全局单播路由)
----------------------------------------------------------------
  • 更新加速源: 🟢 已启用加速代理 -> https://gh-proxy.com/
  • Release 源: 🟢 访问正常 (耗时 320ms, HTTP 302 Found)
----------------------------------------------------------------
  • 接入凭据:   🟢 已加载 (来自 /etc/mnagent/token: ab12....ef56)
----------------------------------------------------------------
  • 机器人连接: 正在测试出站握手 -> https://bot.example.org/agent
  • 连通结果:   🟢 握手成功 (耗时 86ms, HTTP 200 OK)
================================================================
```

### 快捷本地探针测试 (`-probe-target`)

无需借助 Telegram 机器人，运维人员可直接在主机终端调用内置探针测试目标：

```sh
# 快速执行一次 ICMP Ping 测试
mnagent -probe-target 1.1.1.1 -probe-kind ping

# 快速测试 TCP 端口握手延迟（支持自动拆分端口）
mnagent -probe-target 1.1.1.1:443 -probe-kind tcping

# 快速测试 HTTP 阶段耗时与标头采集
mnagent -probe-target https://www.cloudflare.com -probe-kind http

# 快速测试域名 DNS 解析
mnagent -probe-target google.com -probe-kind dns

# 快速执行一次 NextTrace 路由追踪
mnagent -probe-target 8.8.8.8 -probe-kind trace
```

---

## 通信协议规范

agent 与服务端之间采用标准 HTTPS 通信协议，无需任何反向代理隧道：

```
POST /agent/jobs                    Authorization: Bearer <token>
                                    X-Agent-Version: <version>
                                    X-Agent-ISP: <isp_name>
   → 200 {"id":"...","kind":"trace","target":"1.1.1.1","hops":20,"port":443,"protocol":"tcp","timeout_ms":120000}
   → 204 (无等待任务，agent 立即发起下一轮长轮询)

POST /agent/progress                Authorization: Bearer <token>
                                    {"id":"...","current":3,"total":10,"node_name":"香港 01","stage":"测速中","node_data":{...}}
   → 200 {"cancel":false}           (若返回 {"cancel":true}，agent 立即中止该任务)

POST /agent/results                 Authorization: Bearer <token>
                                    {"id":"...","kind":"trace","output":"...","exit_code":0,"data":{...}}
   → 204 / 200

POST /agent/heartbeat               Authorization: Bearer <token>
   → 204 / 200 (独立协程周期保活)
```

- **任务状态幂等**：回传结果携带唯一任务 ID，网络抖动失败时自动按指数退避重试 3 次；
- **动态版本感知**：每次长轮询与请求均上报 `X-Agent-Version` 头，机器人侧在 `/host list` 中实时显示各主机当前运行版本；
- **海量任务下发容量（16 MiB）**：长轮询任务体读取上限由 1 MiB 提升至 16 MiB，原生支持海量节点大订阅与大型代理配置直传下发；
- **输出截断保护**：探测原始输出在 agent 侧做了 1 MiB 缓冲区安全截断，防止海量无序日志撑爆内存。

---

## 安全防御架构

| 安全维度 | 防御设计与实现策略 |
| :--- | :--- |
| **入站零暴露** | agent 仅发起出站 HTTPS 请求，不需要映射端口、开通公网 IP 或配置 SSH，从根源消除端口扫描威胁 |
| **令牌与鉴权** | 每台主机具备独立随机令牌，服务端使用常量时间比对（Constant-Time Compare）防止时序攻击；支持在线热轮换 |
| **命令防注入** | 机器人仅下发严格校验后的目标与参数；agent 重新执行白名单校验，使用 `exec.Command` 直接传递参数数组（`argv`），**完全不经过 Shell 解释器**，禁止目标携带 `-` 前缀参数注入 |
| **SSRF 防护** | 默认封锁私有地址、回环地址、链路本地与云服务商实例元数据接口（`169.254.169.254` 等），防御内网横向穿透 |
| **权限最小化** | systemd 模式下使用独立低权限专用系统用户，由单元的 `AmbientCapabilities` 精确授予 `CAP_NET_RAW` 与 `CAP_NET_ADMIN` 能力，无需对二进制设置 SUID/setcap |
| **传输层加密** | 默认强制校验 TLS/HTTPS 证书，拒绝非安全明文传输 |

---

## 机器人管理指令与故障排查

### Telegram 管理命令

- `/host add <名称> [备注]`：添加主机并生成对应系统的一键安装命令；
- `/host list`：查看全网主机列表、版本号与 🟢 在线 / ⚪️ 离线状态；
- `/host show <名称>`：重新展示该主机的接入命令与配置详情；
- `/host rotate <名称>`：立即轮换主机令牌（旧令牌瞬时失效，主机重新写入新令牌即可恢复）；
- `/host remove <名称>`：解绑并移除指定主机。

### 常见故障排查表

| 现象 | 排查方向与解决方案 |
| :--- | :--- |
| **日志反复提示 `鉴权失败`** | 令牌与服务端不一致或已被轮换：执行 `/host rotate <名称>` 获取新接入命令，或直接编辑更新 `/etc/mnagent/token`（Windows 下编辑安装目录的 `token` 文件） |
| **机器人显示 ⚪️ 离线** | 1. 运行 `mnagent -diag` 检查机器人端点连通性；<br>2. 检查主机出站 443 端口是否受限；<br>3. 检查系统服务是否处于活跃状态（`systemctl status mnagent` 或 `Get-Service mnagent`） |
| **任务提示 `执行失败：无法启动 nexttrace/miaospeed`** | 1. 执行 `mnagent -diag` 排查依赖就绪情况；<br>2. 执行 `mnagent -check-update` 查看依赖状态；<br>3. 执行 `mnagent -apply-update latest` 自动补全并下载对应架构二进制 |
| **任务报 `目标地址属于受限私有/元数据地址`** | 探针触发了 SSRF 防护规则；若确需拨测内网目标，请在启动参数中添加 `--allow-private-probes` |
| **Windows 提示权限拒绝或服务无法注册** | Windows 注册系统服务需要管理员特权，请右键选择“以管理员身份运行”PowerShell 窗口重新执行安装命令 |
| **Windows 缺少依赖或报安全软件拦截** | 检查安装目录（`C:\Program Files\mnagent`）是否存在对应文件；检查 Windows Defender 或杀毒软件告警日志，将安装目录加入排除信任项 |
| **Ping 探针报权限错误或 Raw Socket 失败** | systemd 下确认单元包含 `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`（重跑安装脚本即可自动修复）；OpenWrt 下确认以 root 运行 |
| **测速过程进度不更新** | 节点网络异常或订阅节点无法连通；miaospeed 内部针对死节点已设置 3.5s 快速超时与零重试机制，若需中途退出可在 Telegram 机器人侧点击取消 |
