# mnagent

运行在拨测主机上的轻量 agent，配合 Telegram 机器人 [@mengnan_dedicated_bot](https://t.me/mengnan_dedicated_bot) 使用：
机器人下发探测任务，agent 在本机执行并回传结果（`/nexttrace`、`/ping`、`/tcping`、`/http`、`/dns`、`/miaospeed`）。

它主动向机器人**长轮询**领取任务、在本机执行 `nexttrace`、再回传结果。因此：

- 主机**不需要公网地址**，不需要端口映射、反向隧道或 VPN——只要能在出站方向访问机器人；
- 接入只需一个令牌（`--token`）：机器人按令牌识别是哪台主机，主机上不需要填名称；
- 主机**不需要 SSH**，不需要开放任何入站端口，机器人也不持有登录这些主机的密钥；
- 机器人下发的只是**已校验的追踪参数**（目标/跳数/端口/协议），执行哪个程序由本机的 `-nexttrace` 参数决定，网络侧无法指定命令；
- 长轮询本身就是心跳，机器人的主机选择键盘可以显示 🟢 在线 / ⚪️ 离线。

## 安装

推荐用机器人生成的**一键命令**（管理员在 Telegram 里执行 `/host add 香港节点`，机器人会根据平台需要提供接入命令）：

### Linux / OpenWrt / macOS

```sh
(curl -fsSL https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh \
  || wget -qO- https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.sh) \
  | sh -s -- --bot https://<机器人地址>/agent --token <令牌>
```

### Windows (PowerShell 管理员)

```powershell
irm https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1 | iex -args -Bot "https://<机器人地址>/agent" -Token "<令牌>"
```

命令里只有令牌：**令牌即身份**，机器人按令牌识别是哪台主机，主机上不需要（也不接受）名称参数。

Linux 下脚本会自动：从本仓库的 Release 下载预编译二进制（`mnagent_<os>_<arch>`，没有 Release 或网络受限时回退到源码编译）、创建专用用户、写入令牌（0600）、写入 systemd 单元并**重启服务**（因此重复执行即为升级，会真正换上并运行新版本）。原始套接字能力由单元的 `AmbientCapabilities` 提供，并给服务准备了可写的主目录（`StateDirectory=mnagent`）供 `nexttrace` 存放配置与 IP 库。

> 如果主机访问 GitHub 受限：
> 1. 可以使用 GitHub 加速代理（如 `https://gh-proxy.com/`），在安装命令中添加 `--gh-proxy https://gh-proxy.com/`（Windows 为 `-GhProxy "https://gh-proxy.com/"`，或设置环境变量 `GH_PROXY=https://gh-proxy.com/`）。安装脚本以及后续 agent 后台自更新都会自动通过代理下载 Release 资产与源码包。
> 2. 或者把安装脚本与对应架构的二进制放到内网镜像，用 `--binary https://内网镜像/mnagent_linux_amd64` 指定二进制即可；机器人侧也可用 `MNAGENT_INSTALL_URL` 把生成的脚本地址指向你的镜像。

### 发布

项目配置了自动构建与发布流水线（GitHub Actions）：
- **推送 `main` 分支**：自动根据最新版本计算并递增生成语义化版本号（如 `v0.3.5-main.<时间戳>.<sha>`），自动编译全平台二进制并发布 Release。
- **打 `v*` 标签**：推送指定 Tag（例如 `git tag v0.4.0 && git push origin v0.4.0`）会自动发布正式 Release。

构建产物涵盖 Linux、Windows（amd64/arm64）、macOS (darwin) 各主流系统及 amd64/arm64/arm/mips/mipsle/riscv64 等架构。

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

### 支持的探测类型

| `kind` | 说明 | 依赖 |
| --- | --- | --- |
| `trace`（默认） | 执行 `nexttrace -j` 路由追踪 | 需要 nexttrace 可执行文件（自动检测与更新） |
| `miaospeed` / `speed` | 调用 [AirportR/miaospeed](https://github.com/AirportR/miaospeed) 执行代理节点或订阅测速（支持 7 种测试模式与 9 大流媒体/AI原生解锁检测） | 需要 miaospeed 可执行文件（自动检测与更新） |
| `ping` | ICMP echo，输出丢包与延迟（min/avg/max/抖动） | 无（进程内实现；非特权 ping socket 或 CAP_NET_RAW） |
| `tcping` | TCP 握手延迟 | 无 |
| `http` | HTTP(S) 请求：状态码、服务端 IP、证书到期、DNS/连接/TLS/首字节分段耗时 | 无 |
| `dns` | 用主机自身解析器查 A/AAAA/CNAME/MX/NS/TXT/PTR | 无 |

#### MiaoSpeed 测速支持的测试模式

`miaospeed` 任务支持单节点链接（`ss://`, `vmess://`, `trojan://`, `vless://`, `hysteria2://`）或订阅地址（`http(s)://`）。任务的 `query` 或 `protocol` 可指定以下测试类型（未指定默认执行**全量测试**，也支持以英文逗号拼接多个模式）：

1. **代理连通性测试**（`connectivity` / `conn` / `连通性`）：测试代理可用性、HTTP 响应状态码及 RTT 延迟；
2. **拓扑测试**（`topology` / `topo` / `拓扑`）：测试链路入站/出站国家地区、落地 IP 及 DNS 劫持检测；
3. **多线程测速**（`multithread` / `multi` / `多线程` / `下载`）：多连接并行下行带宽测速（可通过 `count` 自定义线程数，默认 4）；
4. **单线程测速**（`singlethread` / `single` / `单线程`）：单连接下行带宽测速；
5. **延迟测试**（`latency` / `ping` / `延迟`）：精确测量 TCP RTT 延迟、HTTP Ping 延迟、丢包率与抖动；
6. **UDP 类型测试**（`udp` / `nat` / `stun` / `udp类型`）：通过 STUN 服务器探测代理节点的 UDP 支持与 NAT 类型（FullCone / Symmetric / RestrictedCone 等）；
7. **全量测试**（`full` / `all` / `全量`）：综合执行连通性、拓扑、延迟、UDP 类型、下行测速，并默认包含九大主流流媒体与 AI 服务原生解锁检测。

#### 九大主流流媒体与 AI 服务原生解锁检测

全量模式或解锁测试中，agent 内置了对 9 大主流流媒体与 AI 服务的原生解锁检测脚本：

- **流媒体服务**：
  - **YouTube**：检测 YouTube 区域解锁及 YouTube Premium 支持；
  - **Netflix**：精确识别是原生完整解锁、仅支持自制剧（Originals Only）还是不可用；
  - **Disney+**：检测 Disney+ 区域可用性；
  - **Spotify**：检测落地节点区域注册及音源播放限制；
  - **TikTok**：检测 TikTok 落地国家/区域访问支持；
  - **Bilibili**：检测港澳台及东南亚限定影视番剧的解锁情况；
- **AI 与知识服务**：
  - **OpenAI (ChatGPT)**：检测 ChatGPT 网页端/API 访问权限与国家封锁状态；
  - **Claude**：检测 Anthropic Claude 的区域支持与可用性；
  - **Wikipedia**：检测维基百科访问连通性与重定向状态。

探测结果在回传后将以结构化格式直接呈现在 Telegram 机器人测速报告中。

### 自动更新与多依赖管理

mnagent **默认开启自动更新与多依赖协同管理**：每 6 小时（带随机抖动，避免所有主机同时请求）检查一次版本，发现新版本即无缝静默升级并重启服务。

除了 mnagent 自身外，agent 还内置了统一的外部依赖生命周期管理器（`DependencyManager`），全面支持外部依赖 **nexttrace** 与 **miaospeed** 的版本检测与自动更新：

1. **版本自动探测**：自动识别本地已安装的 `nexttrace` 与 `miaospeed` 实际版本，精准剔除 ANSI 终端彩色转义字符；
2. **多依赖远程比对**：定期请求 GitHub Releases 检索官方最新稳定版本；
3. **静默并行升级**：
   - 当检测到新版依赖时，后台会自动下载对应系统与架构的发布资产、解压并安全替换二进制；
   - 通过配置 `--gh-proxy` 加速代理后，agent 自身及所有外部依赖的更新下载均会自动走加速代理；
4. **手动运维管理**：
   - 检查状态：`mnagent -check-update` 会同时输出 mnagent 自身及 `nexttrace`、`miaospeed` 的当前版本与最新版本状态；
   - 立即升级：`mnagent -apply-update latest` 会先并行拉取更新过期的外部依赖，再更新 mnagent 自身并平滑重启服务；
   - 跳过版本：`mnagent -skip-update v0.1.8`（跳过某个版本 24 小时，避免问题版本反复触发更新）。

### 脚本参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--bot` / `--token` | 必填 | 由 `/host add` 生成的命令已带全 |
| `--token-file` | `/etc/mnagent/token` | 令牌文件路径；省略 `--token` 时要求该文件已存在 |
| `--version` | `latest` | 安装的 Release 标签；也可用 `--from-source` 从源码编译 |
| `--binary <path\|url>` | — | 使用自备的 mnagent（内网镜像时很有用） |
| `--nexttrace` | `nexttrace` | nexttrace 路径或名称 |
| `--miaospeed` | `miaospeed` | miaospeed 路径或名称 |
| `--miaospeed-version` | `latest` | 安装的 miaospeed 版本，默认 `latest`（取官方最新 Release） |
| `--user` / `--prefix` | 默认 `root` / `/usr/local/bin`（OpenWrt 为 `/usr/bin`） | 运行用户与安装目录 |
| `--auto-update` | `yes` | 是否启用自动更新（支持 `yes`/`no`） |
| `--no-auto-update` | — | 关闭自动更新（等同于 `--auto-update no`） |
| `--update-interval` | `6h` | 自动更新检查间隔（如 `2h`、`12h`） |
| `--gh-proxy <url>` | — | GitHub 代理前缀（如 `https://gh-proxy.com/`），安装脚本与 agent 自更新均生效 |
| `--install-nexttrace` | `yes` | 缺少 nexttrace 时是否按官方规范自动安装（默认开启） |
| `--no-install-nexttrace` | — | 缺少 nexttrace 时不自动安装（等同于 `--install-nexttrace no`） |
| `--install-miaospeed` | `yes` | 缺少 miaospeed 时是否从 Release 自动下载安装（默认开启） |
| `--no-install-miaospeed` | — | 缺少 miaospeed 时不自动安装（等同于 `--install-miaospeed no`） |
| `--uninstall` | — | 卸载服务与二进制（保留令牌与用户） |

### 手动安装

不使用脚本时（例如没有 systemd 的系统），可自行编译并按 `deploy/mnagent.service`
的写法启动：

```bash
go build -trimpath -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o mnagent .
install -m 0755 mnagent /usr/local/bin/mnagent
install -d -m 0750 /etc/mnagent
printf '%s\n' '<令牌>' > /etc/mnagent/token && chmod 0600 /etc/mnagent/token
# 手工非 root 运行时需要自己给 nexttrace 授权（用 systemd 且以 root 运行或由单元的 AmbientCapabilities 提供）
setcap cap_net_raw,cap_net_admin+eip "$(command -v nexttrace)"
```

### Windows

mnagent 原生支持 Windows（x86_64 及 ARM64），并内置 Windows 服务控制管理器（SCM）协议，无需任何第三方包装器即可作为原生系统服务后台运行。

在 PowerShell 中执行以下**一键安装命令**（自动提权并注册开机自启系统服务）：

```powershell
irm https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1 | iex -args -Bot "https://<机器人地址>/agent" -Token "<令牌>"
```

若网络访问 GitHub 受限，可附加 `-GhProxy` 参数使用加速代理：

```powershell
irm https://gh-proxy.com/https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1 | iex -args -Bot "https://<机器人地址>/agent" -Token "<令牌>" -GhProxy "https://gh-proxy.com/"
```

脚本将自动执行以下操作：
1. 检测操作系统架构（amd64 或 arm64），从 Release 下载对应版本的 `mnagent_windows_<arch>.exe`；
2. 自动检测并下载配置 `nexttrace.exe` 与 `miaospeed.exe`（自动解压 Windows zip 包）；
3. 写入接入令牌至安装目录（默认 `C:\Program Files\mnagent`）；
4. 注册名为 `mnagent` 的原生 Windows 系统服务，配置崩溃后自动重启与开机自启，并立即启动服务。

#### `install.ps1` 脚本参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-Bot` | 必填 | 机器人 agent 接口地址（如 `https://mnbot.example.org/agent`） |
| `-Token` | 必填（或 `-TokenFile`） | 接入令牌 |
| `-TokenFile` | — | 现存令牌文件路径 |
| `-InstallDir` | `C:\Program Files\mnagent` | agent 及依赖的安装目录 |
| `-Version` | `latest` | mnagent 安装版本（默认最新 Release） |
| `-GhProxy` | — | GitHub 代理加速前缀（如 `https://gh-proxy.com/`） |
| `-AutoUpdate` / `-NoAutoUpdate` | 开启 | 是否开启后台定时自动更新（默认开启） |
| `-UpdateInterval` | `6h` | 自动检查更新的周期（默认 6 小时） |
| `-InstallNextTrace` / `-NoInstallNextTrace` | 开启 | 是否自动下载并安装 Windows 版 `nexttrace.exe` |
| `-InstallMiaoSpeed` / `-NoInstallMiaoSpeed` | 开启 | 是否自动下载并安装 Windows 版 `miaospeed.exe` |
| `-MiaoSpeedVersion` | `latest` | 指定 miaospeed 版本（默认最新 Release） |
| `-Uninstall` | — | 停止并卸载 Windows 服务，清理服务注册 |

常用管理命令：
- **查看服务状态**：`Get-Service mnagent`
- **停止服务**：`Stop-Service mnagent` （或 `net stop mnagent`）
- **启动服务**：`Start-Service mnagent` （或 `net start mnagent`）
- **重启服务**：`Restart-Service mnagent`
- **一键卸载服务**：`powershell .\install.ps1 -Uninstall`

若需在前台控制台直接调试运行：
```powershell
.\mnagent.exe -bot https://mnbot.example.org/agent -token "<令牌>" -auto-update
```

## 机器人侧配置

主机与令牌都由机器人管理（存放在状态数据库里，不再使用配置文件）：

- `/host add <名称> [备注]`：添加主机并生成一键接入命令
- `/host list`：查看主机与 🟢/⚪️ 在线状态
- `/host show <名称>`：重新显示接入命令
- `/host rotate <名称>`：轮换令牌（旧令牌立即失效，主机需重新接入）
- `/host remove <名称>`：删除主机

名称只用于展示与 `/nexttrace @名称` 选择；令牌等同该主机的任务接受权，泄露时用 `rotate` 轮换。

## 参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-bot` | 必填 | 机器人 agent 端点基地址，如 `https://mnbot.example.org/agent` |
| `-token` | — | 直接给出令牌（不推荐：会出现在进程列表里） |
| `-token-file` | Linux 默认为 `/etc/mnagent/token`<br>Windows 默认为 `%ProgramData%\mnagent\token` | 令牌文件路径；每次请求都重新读取，**轮换令牌无需重启** |
| `-nexttrace` | `nexttrace` | nexttrace 可执行文件路径或 PATH 中的名称 |
| `-miaospeed` | `miaospeed` | miaospeed 可执行文件路径或 PATH 中的名称 |
| `-min-backoff` / `-max-backoff` | `1s` / `1m` | 轮询失败后的重试退避区间（带抖动） |
| `-poll-timeout` | `40s` | 单次长轮询的客户端超时（机器人侧最多保持 20 秒） |
| `-auto-update` | `false` | 是否开启后台定期自动更新（通过 `install.sh` / `install.ps1` 安装时默认开启，协同更新依赖） |
| `-update-interval` | `6h` | 自动更新检查间隔 |
| `-gh-proxy` | — | GitHub 代理前缀（如 `https://gh-proxy.com/`，环境变量 `GH_PROXY` / `MNAGENT_GH_PROXY` 同效） |
| `-check-update` | — | 单次检查 mnagent 及核心依赖（nexttrace、miaospeed）是否有新版本并输出状态矩阵，不执行下载 |
| `-apply-update <tag\|latest>` | — | 手动下载并安装指定版本或最新版（自动并行更新过期依赖），安装完成后退出并重启服务 |
| `-skip-update <tag>` | — | 跳过指定版本 24 小时（自动更新不再提示或应用） |
| `-log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-version` | — | 输出版本后退出 |

令牌也可以放在环境变量 `MNAGENT_TOKEN` 中（优先级：`-token` > `MNAGENT_TOKEN` > `-token-file`）。

## 协议

机器人侧提供两个端点（均在机器人的公网 HTTPS 服务上）：

```
POST /agent/jobs                    Authorization: Bearer <token>
   → 200 {"id":"…","target":"1.1.1.1","hops":20,"port":443,"protocol":"tcp","timeout_ms":120000}
   → 204（本次没有任务，agent 立刻重新轮询）

POST /agent/results                 {"id":"…","output":"…","exit_code":0,"error":""}
   → 204
```

约定与限制：

- 单台主机同一时刻只会被下发一个任务（机器人侧另有全局并发上限）；
- 每次长轮询都会带上自身版本：`X-Agent-Version: <tag>` 头（同时保留 `User-Agent: mnagent/<tag>`），机器人用它把版本显示在 `/host list` 里，便于确认各主机是否已升级；
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
| 日志反复 `鉴权失败` | 令牌与机器人不一致或已被轮换：用 `/host rotate <名称>` 生成新命令重跑安装（或对比 `/etc/mnagent/token` / Windows 下 `%ProgramData%\mnagent\token`） |
| 机器人显示 ⚪️ 离线 | agent 未运行、`-bot` 地址不可达（出站 443 被拦？）、或机器人的 `/agent/jobs` 未对外暴露 |
| 任务报 `执行超时` | 主机到目标网络不通，或需要更长超时；也可在命令里减少跳数 |
| 任务报 `执行失败（退出码 N）` | 手动在该主机执行同参数命令复现；注意 `nexttrace -j` 需要 v1.7+，旧版本 agent 会自动去掉 `-j` 重试 |
| 任务报 `无法启动 nexttrace/miaospeed（…）` | 检查二进制路径与架构匹配；执行 `mnagent -check-update` 查看依赖状态，或使用 `mnagent -apply-update latest` 自动补全/更新依赖 |
| Windows 下管理服务报拒绝访问 | Windows 服务注册与启停需要系统管理员权限，请右键选择“以管理员身份运行”PowerShell 窗口 |
| Windows 下缺少依赖或报防病毒拦截 | 检查安装目录（默认 `C:\Program Files\mnagent`）下是否存在对应可执行文件；排查 Windows Defender 或杀毒软件拦截隔离日志并添加排除项 |
| 任务报 `进程被信号终止（…）` | 二进制启动后被信号杀死，按提示的信号名排查（内存不足、平台不兼容等） |
| 任务报权限/原始套接字错误 | 用 systemd 运行时应由单元的 `AmbientCapabilities` 提供 `CAP_NET_RAW`；检查单元是否被旧版本覆盖（重跑安装脚本会重新生成） |
| 输出为空且无报错 | 检查 `nexttrace` 能否直接运行：`sudo -u mnagent $(command -v nexttrace) -j 1.1.1.1 \| head -3` |
