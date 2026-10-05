# mnagent

运行在追踪主机上的轻量 agent，配合 [mengnanbot](../mengnanbot) 的 `/nexttrace` 使用。

它主动向机器人**长轮询**领取任务、在本机执行 `nexttrace`、再回传结果。因此：

- 主机**不需要公网地址**，不需要端口映射、反向隧道或 VPN——只要能在出站方向访问机器人；
- 主机**不需要 SSH**，不需要开放任何入站端口，机器人也不持有登录这些主机的密钥；
- 机器人下发的只是**已校验的追踪参数**（目标/跳数/端口/协议），执行哪个程序由本机的 `-nexttrace` 参数决定，网络侧无法指定命令；
- 长轮询本身就是心跳，机器人的主机选择键盘可以显示 🟢 在线 / ⚪️ 离线。

## 安装

```bash
# 编译（在任意一台有 Go 的机器上，交叉编译成静态二进制）
go build -o mnagent .
GOOS=linux GOARCH=amd64 go build -o mnagent-linux-amd64 .

# 主机上：创建专用用户与目录
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mnagent
sudo install -m 0755 mnagent-linux-amd64 /usr/local/bin/mnagent
sudo install -d -m 0750 -o mnagent -g mnagent /etc/mnagent

# 写入令牌（与机器人 nexttrace_hosts.json 中该主机的 token/tokenFile 一致）
openssl rand -hex 32 | sudo tee /etc/mnagent/token >/dev/null
sudo chown mnagent:mnagent /etc/mnagent/token && sudo chmod 0600 /etc/mnagent/token

# nexttrace 需要原始套接字权限：给二进制授予 CAP_NET_RAW，而不是把服务跑成 root
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/nexttrace
```

然后安装 systemd 单元（把 `-bot` 与 `-host` 改成实际值）：

```bash
sudo cp deploy/mnagent.service /etc/systemd/system/
sudo systemctl edit mnagent     # 或直接编辑单元里的 ExecStart
sudo systemctl enable --now mnagent
journalctl -u mnagent -f
```

启动日志中出现 `mnagent 已启动`，并且机器人的主机键盘显示该主机为 🟢 即接入成功。

## 机器人侧配置

在机器人运行目录的 `nexttrace_hosts.json` 中登记这台主机：

```json
{
  "hosts": [
    { "name": "hk", "label": "香港节点", "tokenFile": "/etc/mengnanbot/hk.token" }
  ]
}
```

`tokenFile` 与 `token` 二者填一个即可（`tokenFile` 优先，便于把令牌与仓库分离）。
`name` 必须与 agent 的 `-host` 完全一致；`token` 必须与该主机上的令牌一致。

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
| 权限 | 建议专用用户 + 对 nexttrace 二进制 `setcap cap_net_raw,cap_net_admin+eip`，不要以 root 运行 |
| TLS | 默认校验服务器证书；仅在本地联调时可对机器人使用 `http://` |

## 故障排查

| 现象 | 排查方向 |
| --- | --- |
| 日志反复 `鉴权失败` | `-host` 与配置里的 `name` 不一致，或令牌不匹配（对比 `/etc/mnagent/token` 与机器人配置） |
| 机器人显示 ⚪️ 离线 | agent 未运行、`-bot` 地址不可达（出站 443 被拦？）、或机器人的 `/agent/jobs` 未对外暴露 |
| 任务报 `执行超时` | 主机到目标网络不通，或需要更长超时；也可在命令里减少跳数 |
| 任务报 `执行失败（退出码 N）` | 手动在该主机执行同参数 `nexttrace` 复现；注意 `nexttrace -j` 需要 v1.7+，旧版本 agent 会自动去掉 `-j` 重试 |
| 输出为空 | 检查 `nexttrace` 是否具备 `cap_net_raw`（`getcap $(command -v nexttrace)`） |
