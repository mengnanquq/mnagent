<#
.SYNOPSIS
    mnagent Windows 一键安装与服务配置脚本

.DESCRIPTION
    自动从 GitHub Releases 下载 mnagent_windows_<arch>.exe、
    可选下载 nexttrace.exe 与 miaospeed.exe、写入令牌并注册为原生自启的 Windows 服务。

.EXAMPLE
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/mengnanquq/mnagent/main/install.ps1))) -Bot "https://mnbot.example.org/agent" -Token "your_token"

.EXAMPLE
    .\install.ps1 -Bot "https://mnbot.example.org/agent" -Token "your_token" -AutoUpdate
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Bot,

    [Parameter(Position=1)]
    [string]$Token,

    [string]$TokenFile,
    [string]$InstallDir = "",
    [string]$LogFile = "",
    [string]$Version = "latest",
    [string]$GhProxy = "",
    [switch]$AutoUpdate,
    [switch]$NoAutoUpdate,
    [string]$UpdateInterval = "6h",
    [switch]$InstallNextTrace,
    [switch]$NoInstallNextTrace,
    [switch]$InstallMiaoSpeed,
    [switch]$NoInstallMiaoSpeed,
    [string]$MiaoSpeedVersion = "latest",
    [switch]$InsecureProxyChecksum,
    [switch]$AllowInsecureHttp,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# 严格校验会写入服务 ImagePath 的 URL：只允许 URL 安全字符，拒绝空白、换行、引号、
# 反斜杠、%、$、反引号与控制字符，避免命令/参数注入。
function Assert-UrlSafe([string]$value, [string]$name) {
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$name 不能为空"
    }
    if ($value -match '[\s"''\\%$`]') {
        throw "$name 含不允许的字符（禁止空白、换行、引号、反斜杠、%、`$、反引号）: $value"
    }
    if ($value.IndexOfAny([char[]](0..31) + [char]127) -ge 0) {
        throw "$name 含控制字符: $value"
    }
    if ($value -notmatch '^[A-Za-z0-9._~:/?#\[\]@!&()*+,;=-]+$') {
        throw "$name 含 URL 安全字符之外的字符: $value"
    }
}

# 判断 IPv4 字节是否为回环/私网/链路本地（与 agent 的 IsLoopback/IsPrivate/IsLinkLocalUnicast 一致）。
function Test-PrivateIPv4Bytes([byte[]]$b) {
    return [bool](($b[0] -eq 127) -or ($b[0] -eq 10) -or
        ($b[0] -eq 192 -and $b[1] -eq 168) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 169 -and $b[1] -eq 254))
}

# 判断明文 HTTP 目标是否为回环/内网地址（agent 侧才是权威校验，这里提前拦截）。
# 必须与 internal/config.isLocalHTTPHost 逐条一致：仅 localhost/*.localhost 与字面
# 回环/私网/链路本地 IP；*.lan/*.local、单标签主机名与字符串前缀都不算本地。
function Test-LocalBotHost([string]$hostName) {
    if ([string]::IsNullOrWhiteSpace($hostName)) { return $true }
    $h = $hostName.ToLowerInvariant().TrimStart('[').TrimEnd(']')
    if ($h -eq "localhost" -or $h.EndsWith(".localhost")) { return $true }

    # 严格 IPv4：四段十进制、无前导零（与 Go net.ParseIP 一致）。
    $v4Pattern = '^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
    if ($h -match $v4Pattern) {
        $v4 = [System.Net.IPAddress]::Parse($h)
        return Test-PrivateIPv4Bytes $v4.GetAddressBytes()
    }

    # 仅把含冒号且通过 .NET 严格解析的值当作 IPv6 字面量；否则视为域名。
    if ($h.Contains(":") -and $h -match '^[0-9A-Fa-f:.]+$') {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($h, [ref]$ip) -and
            $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            if ($ip.IsIPv4MappedToIPv6) {
                return Test-PrivateIPv4Bytes $ip.MapToIPv4().GetAddressBytes()
            }
            if ($ip.IsIPv6Loopback -or $ip.IsIPv6LinkLocal) { return $true }
            $b = $ip.GetAddressBytes()
            # fc00::/7（唯一本地地址）。
            return [bool](($b[0] -band 0xFE) -eq 0xFC)
        }
    }
    return $false
}

# 默认安装路径确定（优先真正的 64 位 Program Files 目录）
$programFilesDir = ${env:ProgramW6432}
if (-not $programFilesDir) { $programFilesDir = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $programFilesDir "mnagent"
}
# -LogFile 未显式指定时先尝试从旧服务 ImagePath 继承，真正继承不到才用默认值。
$logFileExplicit = $PSBoundParameters.ContainsKey("LogFile") -and -not [string]::IsNullOrWhiteSpace($LogFile)

function Show-Usage {
    Write-Host @"
mnagent Windows 一键安装脚本

用法:
  .\install.ps1 -Bot <URL> -Token <令牌> [选项...]

必选参数:
  -Bot <URL>                 机器人 agent 接口地址（如 https://mnbot.example.org/agent）
  -Token <令牌>              接入令牌（与 -TokenFile 二选一）
  -TokenFile <路径>          现存令牌文件路径

常用选项:
  -InstallDir <目录>         安装目录（默认: C:\Program Files\mnagent）
  -LogFile <路径>            服务日志文件（默认: <安装目录>\mnagent.log，5MB × 3 轮转）
  -Version <版本>            mnagent 版本号（默认: latest）
  -GhProxy <URL>             GitHub 代理加速前缀（如 https://gh-proxy.com/）
  -InsecureProxyChecksum     使用 -GhProxy 时允许经代理获取 .sha256 校验文件
                              （默认必须直连 github.com；确认代理可信时才使用）
  -AllowInsecureHttp         -Bot 使用明文 HTTP 连接公网地址时允许继续（默认拒绝；
                              会向 agent 传递 -allow-insecure-http，令牌可能被窃听，慎用）
  -AutoUpdate                开启自动检查更新（默认开启）
  -NoAutoUpdate              关闭自动更新
  -UpdateInterval <间隔>     自动更新检查间隔（默认: 6h）
  -NoInstallNextTrace        不自动安装/更新 nexttrace.exe
  -NoInstallMiaoSpeed        不自动安装/更新 miaospeed.exe
  -Uninstall                 卸载 mnagent Windows 服务并清理二进制
  -Help                      显示本帮助信息

一键执行示例:
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Bot "https://bot.example.org/agent" -Token "my-token"
"@ -ForegroundColor Cyan
}

if ($Help) {
    Show-Usage
    exit 0
}

# 1. 确保以管理员权限运行（UAC 自动提权并完整保留传递参数）
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($MyInvocation.MyCommand.Path) {
        Write-Host "需要管理员权限，正在尝试通过 UAC 提权重新运行..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        $forwardArgs = @()
        foreach ($key in $PSBoundParameters.Keys) {
            $val = $PSBoundParameters[$key]
            if ($val -is [System.Management.Automation.SwitchParameter]) {
                if ($val.IsPresent) {
                    $forwardArgs += "-$key"
                }
            } else {
                $forwardArgs += "-$key"
                $forwardArgs += "`"$val`""
            }
        }
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"") + $forwardArgs + $args
        Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
        exit
    } else {
        Write-Error "错误：安装或卸载 mnagent Windows 服务需要管理员权限。请在管理员 PowerShell 中重试！"
        exit 1
    }
}

# 2. 卸载流程
if ($Uninstall) {
    Write-Host "正在卸载 mnagent Windows 服务..." -ForegroundColor Yellow
    $svc = Get-Service -Name "mnagent" -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne "Stopped") {
            Write-Host "正在停止 mnagent 服务..."
            Stop-Service -Name "mnagent" -Force -ErrorAction SilentlyContinue
            try {
                $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
            } catch {}
        }
        & sc.exe delete mnagent | Out-Null
        Write-Host "已删除 mnagent Windows 服务。" -ForegroundColor Green
    } else {
        Write-Host "未找到 mnagent Windows 服务。" -ForegroundColor Gray
    }

    # 清理残留子进程
    Get-Process -Name "mnagent", "nexttrace", "miaospeed" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    if (Test-Path $InstallDir) {
        # 递归删除必须可验证：只删看起来真是安装目录（含 mnagent.exe）的目录；
        # 非默认安装目录还需要额外输入 DELETE 确认，避免 -InstallDir 误传导致误删。
        $defaultInstallDir = Join-Path $programFilesDir "mnagent"
        $installFull = [System.IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
        $defaultFull = [System.IO.Path]::GetFullPath($defaultInstallDir).TrimEnd('\')
        $hasBinary = Test-Path (Join-Path $InstallDir "mnagent.exe")
        if (-not $hasBinary) {
            Write-Warning "目录 $InstallDir 下没有 mnagent.exe，不像是安装目录，已跳过递归删除（请手动确认后清理）。"
        } else {
            $confirm = Read-Host "是否删除安装目录 $InstallDir 及配置文件？[y/N]"
            if ($confirm -match '^[Yy]') {
                $allowDelete = $true
                if (-not [string]::Equals($installFull, $defaultFull, [StringComparison]::OrdinalIgnoreCase)) {
                    Write-Warning "$InstallDir 不是默认安装目录（$defaultInstallDir），递归删除存在误删其他文件的风险。"
                    $confirm2 = Read-Host "如确认要删除该目录，请再次输入 DELETE"
                    if ($confirm2 -cne "DELETE") {
                        Write-Host "已取消目录删除。" -ForegroundColor Yellow
                        $allowDelete = $false
                    }
                }
                if ($allowDelete) {
                    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "已清理安装目录: $InstallDir" -ForegroundColor Green
                }
            }
        }
    }
    Write-Host "mnagent 卸载完成。" -ForegroundColor Green
    exit 0
}

# 现有服务的 ImagePath：既要判断旧配置是否已允许明文 HTTP，也要在重装时继承手工参数。
$existingImagePath = ""
try {
    $existingImagePath = [string](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mnagent" -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
} catch {
    $existingImagePath = ""
}

# 与 install.sh 一致：未显式传 -LogFile 时继承旧服务里手工追加的 -log-file，
# 避免重装把用户自定义日志路径重置为默认值；继承不到时才使用 <安装目录>\mnagent.log。
if (-not $logFileExplicit) {
    $logFileMatch = [regex]::Match($existingImagePath, '(?:^|\s)-{1,2}log-file(?:\s+|=)"([^"]+)"')
    if (-not $logFileMatch.Success) {
        $logFileMatch = [regex]::Match($existingImagePath, '(?:^|\s)-{1,2}log-file[=\s]+(\S+)')
    }
    if ($logFileMatch.Success -and -not [string]::IsNullOrWhiteSpace($logFileMatch.Groups[1].Value)) {
        $LogFile = $logFileMatch.Groups[1].Value
        Write-Host "已从现有服务配置继承 -log-file: $LogFile" -ForegroundColor Gray
    }
}
if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $LogFile = Join-Path $InstallDir "mnagent.log"
}

# 3. 校验参数
if ([string]::IsNullOrWhiteSpace($Bot)) {
    Write-Error "错误：必须指定 -Bot（例如 https://mnbot.example.org/agent）"
    Show-Usage
    exit 1
}

$Bot = $Bot.TrimEnd('/')
if (-not ($Bot -match '^https?://.+')) {
    Write-Error "错误：-Bot 必须是合法的 http/https 地址，收到: $Bot"
    exit 1
}
Assert-UrlSafe $Bot "-Bot"
# agent 会拒绝这些形态（客户端直接在地址后拼接 /jobs、/results），安装阶段就拦住，
# 避免装完才因 agent 退出而陷入重启循环。
if ($Bot.Contains("?") -or $Bot.Contains("#")) {
    Write-Error "错误：-Bot 不允许包含查询参数或 fragment（?/#），agent 会直接在地址后拼接 /jobs 等路径"
    exit 1
}
$botUri = $null
if (-not [System.Uri]::TryCreate($Bot, [System.UriKind]::Absolute, [ref]$botUri)) {
    Write-Error "错误：-Bot 不是合法地址: $Bot"
    exit 1
}
if (-not [string]::IsNullOrEmpty($botUri.UserInfo)) {
    Write-Error "错误：-Bot 不允许包含 userinfo（user:pass@），凭据请改用 -Token / -TokenFile"
    exit 1
}
if (-not [string]::IsNullOrWhiteSpace($GhProxy)) {
    Assert-UrlSafe $GhProxy "-GhProxy"
}

# 明文 HTTP 仅允许回环/内网/单标签主机名（与 agent 的 -allow-insecure-http 规则一致）；
# 升级时若旧服务已带 -allow-insecure-http，则保持允许，避免重装后 agent 直接退出。
$enableInsecureHttp = [bool]$AllowInsecureHttp
if (-not $enableInsecureHttp -and $existingImagePath -match '(^|\s)-allow-insecure-http(\s|$)') {
    $enableInsecureHttp = $true
    Write-Host "已从现有服务配置继承 -allow-insecure-http 设置。" -ForegroundColor Gray
}
if ($Bot -match '^http://' -and -not (Test-LocalBotHost $botUri.Host)) {
    if (-not $enableInsecureHttp) {
        Write-Error "错误：-Bot 使用明文 HTTP 连接非回环/内网地址 $($botUri.Host)，agent 会拒绝启动（令牌与任务内容可能被窃听）。请改用 https://，或确需如此时加 -AllowInsecureHttp"
        exit 1
    }
    Write-Warning "-Bot 使用明文 HTTP 连接 $($botUri.Host)：令牌与任务内容可能被窃听，请仅在可信网络使用。"
}

# -InstallDir / -LogFile 会拼进服务 ImagePath（双引号包裹）与 icacls 命令行：
# 引号会提前结束参数、% 会在 ExpandString 类型的 ImagePath 里被 SCM 展开、
# 换行/控制字符会破坏注册表值，均一律拒绝；末尾反斜杠会转义 ImagePath 的
# 结束引号，也必须拒绝。
function Assert-ImagePathValue([string]$value, [string]$name) {
    if ([string]::IsNullOrWhiteSpace($value)) { throw "$name 不能为空" }
    if ($value.IndexOfAny([char[]](0..31) + [char]127) -ge 0) {
        throw "$name 含控制字符（含换行）: $value"
    }
    if ($value -match '["%$`]') {
        throw "$name 含不允许的字符（禁止引号、%、`$、反引号）: $value"
    }
    if ($value -notmatch '^[A-Za-z]:[\\/]') {
        throw "$name 必须是绝对路径（如 C:\Program Files\mnagent）: $value"
    }
    if ($value.EndsWith('\') -or $value.EndsWith('/')) {
        throw "$name 不能以路径分隔符结尾: $value"
    }
}
Assert-ImagePathValue $InstallDir "-InstallDir"
Assert-ImagePathValue $LogFile "-LogFile"

# -Version 会拼入下载 URL，-UpdateInterval 会拼入 ImagePath：必须限定为安全格式。
if ($Version -ne "latest" -and $Version -notmatch '^v?\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') {
    Write-Error "错误：-Version 取值非法：$Version（只允许 latest 或 vX.Y.Z[-pre]）"
    exit 1
}
if ($UpdateInterval -notmatch '^([0-9]+(\.[0-9]+)?(ns|us|ms|s|m|h))+$') {
    Write-Error "错误：-UpdateInterval 取值非法：$UpdateInterval（只允许 Go duration 形式，如 6h、30m、1h30m）"
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Token) -and [string]::IsNullOrWhiteSpace($TokenFile)) {
    if (-not [string]::IsNullOrWhiteSpace($env:MNAGENT_TOKEN)) {
        $Token = $env:MNAGENT_TOKEN
    } else {
        Write-Error "错误：必须指定 -Token、-TokenFile 或环境变量 MNAGENT_TOKEN"
        Show-Usage
        exit 1
    }
}

# 默认启用状态处理
$enableAutoUpdate = -not $NoAutoUpdate
$enableNextTrace = -not $NoInstallNextTrace
$enableMiaoSpeed = -not $NoInstallMiaoSpeed

# 4. 检测系统架构（阻断 32 位操作系统）
$is64 = [System.Environment]::Is64BitOperatingSystem
if (-not $is64) {
    Write-Error "错误：mnagent 仅支持 64 位 Windows 系统 (amd64 / arm64)。"
    exit 1
}
$procArch = $env:PROCESSOR_ARCHITEW6432
if (-not $procArch) { $procArch = $env:PROCESSOR_ARCHITECTURE }
$arch = if ($procArch -eq "ARM64" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
Write-Host "检测到系统平台: Windows ($arch)" -ForegroundColor Cyan

# 5. 安全协议配置 (启用 TLS 1.2，若环境支持则额外启用 TLS 1.3)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Enum]::Parse([Net.SecurityProtocolType], "Tls13")
} catch {
    # 忽略不支持 Tls13 的旧版 .NET Framework
}

function Get-ProxiedUrl([string]$rawUrl) {
    if ([string]::IsNullOrWhiteSpace($GhProxy)) { return $rawUrl }
    $p = $GhProxy.TrimEnd('/') + '/'
    if ($rawUrl.StartsWith($p)) { return $rawUrl }
    return $p + $rawUrl
}

function Download-File([string]$url, [string]$destination, [switch]$NoProxy) {
    $proxied = if ($NoProxy) { $url } else { Get-ProxiedUrl $url }
    Write-Host "正在下载: $proxied" -ForegroundColor Gray
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "mnagent-installer")
    $wc.DownloadFile($proxied, $destination)
}

# 获取校验文件：使用 -GhProxy 时必须优先直连 github.com，否则代理可同时替换
# 二进制与同源 .sha256；只有显式 -InsecureProxyChecksum 才允许退回代理。
function Download-ChecksumFile([string]$url, [string]$destination) {
    if ([string]::IsNullOrWhiteSpace($GhProxy)) {
        Download-File $url $destination
        return
    }
    try {
        Download-File $url $destination -NoProxy
        Write-Host "已直连 GitHub 获取校验文件（未经 gh-proxy）" -ForegroundColor Gray
        return
    } catch {
        if (Test-Path $destination) { Remove-Item -Path $destination -Force -ErrorAction SilentlyContinue }
        if (-not $InsecureProxyChecksum) {
            throw "无法直连 github.com 获取 SHA-256 校验文件。使用 -GhProxy 时默认禁止经代理获取校验文件（代理可同时替换二进制与校验文件）；请检查网络，或确认代理可信后加 -InsecureProxyChecksum 重试。原始错误: $_"
        }
        Write-Warning "无法直连 GitHub 获取校验文件，按 -InsecureProxyChecksum 改为经代理获取；代理仍可同时替换二进制与校验文件"
        Download-File $url $destination
    }
}

function Assert-Sha256([string]$filePath, [string]$checksumUrl, [string]$assetName) {
    $sumPath = "$filePath.sha256"
    try {
        Download-ChecksumFile $checksumUrl $sumPath
    } catch {
        if (Test-Path $sumPath) { Remove-Item -Path $sumPath -Force -ErrorAction SilentlyContinue }
        throw "下载 SHA-256 校验文件失败（已中止安装）: $_"
    }
    try {
        $expected = ((Get-Content -Path $sumPath -TotalCount 1) -split '\s+')[0]
        if ([string]::IsNullOrWhiteSpace($expected) -or $expected -notmatch '^[0-9a-fA-F]{64}$') {
            throw "SHA-256 校验文件格式非法（已中止安装）"
        }
        $actual = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
        if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw "SHA-256 校验失败：期望 $expected，实际 $actual（已中止安装，未覆盖旧二进制）"
        }
    } finally {
        Remove-Item -Path $sumPath -Force -ErrorAction SilentlyContinue
    }
    Write-Host "SHA-256 校验通过（$assetName）" -ForegroundColor Green
}

# 从 GitHub Releases API 取指定资产的 SHA-256 摘要（上一步为已发布的 digest 字段）。
# 取不到（API 不可达/限流/附件缺失/无 digest）返回空串，由调用方中止安装。
function Get-GitHubAssetDigest([string]$repo, [string]$assetName, [string]$tag = "latest") {
    $apiUrl = if ([string]::IsNullOrWhiteSpace($tag) -or $tag -eq "latest") {
        "https://api.github.com/repos/$repo/releases/latest"
    } else {
        "https://api.github.com/repos/$repo/releases/tags/$tag"
    }
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "mnagent-installer")
        $json = $wc.DownloadString($apiUrl) | ConvertFrom-Json
        $asset = @($json.assets | Where-Object { $_.name -eq $assetName }) | Select-Object -First 1
        if (-not $asset) { return "" }
        $digest = [string]$asset.digest
        if ($digest -match '^sha256:([0-9a-fA-F]{64})$') { return $Matches[1] }
        return ""
    } catch {
        return ""
    }
}

# 校验下载文件的 SHA-256；摘要缺失或格式非法一律中止，绝不“没校验就安装”。
function Assert-AssetSha256([string]$filePath, [string]$expected, [string]$assetName) {
    if ([string]::IsNullOrWhiteSpace($expected) -or $expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw "无法获取 $assetName 的 SHA-256 摘要（已中止安装）"
    }
    $actual = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
    if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$assetName SHA-256 校验失败：期望 $expected，实际 $actual（已丢弃下载文件）"
    }
    Write-Host "$assetName SHA-256 校验通过。" -ForegroundColor Green
}

function Get-GitHubLatestTag([string]$repo) {
    $apiUrl = "https://api.github.com/repos/$repo/releases/latest"
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", "mnagent-installer")
        $json = $wc.DownloadString($apiUrl) | ConvertFrom-Json
        return $json.tag_name
    } catch {
        return ""
    }
}

# 移动或替换可执行文件（具备 Windows 文件锁重试与 .old 降级机制）
function Move-ExecutableSafely([string]$source, [string]$destination) {
    if (Test-Path $destination) {
        $oldFile = "$destination.old"
        if (Test-Path $oldFile) { Remove-Item -Path $oldFile -Force -ErrorAction SilentlyContinue }
        try {
            Move-Item -Path $destination -Destination $oldFile -Force -ErrorAction Stop
        } catch {
            $oldFile = "$destination.old.$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())"
            Move-Item -Path $destination -Destination $oldFile -Force -ErrorAction SilentlyContinue
        }
    }
    Move-Item -Path $source -Destination $destination -Force
    if (Test-Path "$destination.old") { Remove-Item -Path "$destination.old" -Force -ErrorAction SilentlyContinue }
}

# 把服务 ImagePath 按 Windows 命令行规则切成参数（支持 "..." 引号，引号内不切分）。
function Split-ServiceArguments([string]$commandLine) {
    $tokens = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
    $inQuotes = $false
    $hasToken = $false
    foreach ($ch in $commandLine.ToCharArray()) {
        if ($ch -eq '"') {
            $inQuotes = -not $inQuotes
            $hasToken = $true
            continue
        }
        if (-not $inQuotes -and [char]::IsWhiteSpace($ch)) {
            if ($hasToken) {
                $tokens.Add($current.ToString())
                $current.Clear() | Out-Null
                $hasToken = $false
            }
            continue
        }
        $current.Append($ch) | Out-Null
        $hasToken = $true
    }
    if ($hasToken) { $tokens.Add($current.ToString()) }
    return ,$tokens
}

# 可继承的 agent 常驻参数（与 internal/config 的 flag 定义保持一致）。
# 带取值的参数后必须跟一个值；其余为布尔开关。一次性 CLI 参数（-diag、-version 等）
# 不在其中：它们出现在服务 ImagePath 里会让进程启动后立即退出。
$agentValueFlags = @("-bot", "-token", "-token-file", "-nexttrace", "-miaospeed", "-min-backoff", "-max-backoff",
    "-poll-timeout", "-result-timeout", "-update-interval", "-gh-proxy", "-log-level", "-log-file")
$agentBoolFlags = @("-allow-private-probes", "-allow-remote-downgrade")
# 由本脚本重新生成的参数：跳过它们及其取值，避免旧值覆盖新值或重复追加。
$installerRegeneratedFlags = @("-bot", "-token", "-token-file", "-nexttrace", "-miaospeed", "-auto-update",
    "-update-interval", "-gh-proxy", "-log-file", "-allow-insecure-http", "-allow-auto-install-deps")

# 读取旧服务 ImagePath，取出本脚本不重新生成的 agent 参数（如手工追加的 -log-level、
# -allow-private-probes、-min-backoff），重跑安装时原样保留，避免升级静默丢弃用户配置。
# 无法识别（不在白名单）、缺少取值或含不安全字符（空白、引号、%、$、反引号等）时
# 整批放弃并告警：宁可回退到默认参数，也不能写出半截参数导致服务起不来。
function Get-InheritedServiceArgs([string]$commandLine) {
    if ([string]::IsNullOrWhiteSpace($commandLine)) { return @() }
    $tokens = Split-ServiceArguments $commandLine
    if ($tokens.Count -le 1) { return @() }
    $kept = New-Object System.Collections.Generic.List[string]
    $bad = New-Object System.Collections.Generic.List[string]
    $skipValue = $false
    $expectValue = $false
    # 白名单字符集：拒绝空白、引号、%、$、反引号、通配符与 shell/SCM 元字符。
    $safePattern = '^[A-Za-z0-9_.:\\/@+=,-]+$'
    for ($i = 1; $i -lt $tokens.Count; $i++) {
        $tok = $tokens[$i]
        if ([string]::IsNullOrWhiteSpace($tok)) { continue }
        $isFlag = $tok.StartsWith("-")
        if ($skipValue) {
            # 跳过上一个（由本脚本重新生成的）参数的取值；取值可能未加引号并含空格
            # （如 C:\Program Files\mnagent\x.log），因此一直跳到下一个 '-' 开头的参数。
            if (-not $isFlag) { continue }
            $skipValue = $false
        }
        if (-not $isFlag) {
            if (-not $expectValue) {
                # 既不是参数、也不是已知参数的取值：整批放弃。
                $bad.Add($tok)
                continue
            }
            $expectValue = $false
            if ($tok -notmatch $safePattern) { $bad.Add($tok); continue }
            $kept.Add($tok)
            continue
        }
        if ($expectValue) {
            # 上一个参数缺取值（例如 -log-level -log-file）：整批放弃。
            $bad.Add($tok)
            continue
        }
        $flag = $tok
        $hasInlineValue = $false
        $eq = $tok.IndexOf('=')
        if ($eq -gt 0) {
            $flag = $tok.Substring(0, $eq)
            $hasInlineValue = $true
        }
        if ($flag.StartsWith("--")) { $flag = "-" + $flag.Substring(2) }
        if ($installerRegeneratedFlags -contains $flag) {
            if (-not $hasInlineValue) { $skipValue = $true }
            continue
        }
        if ($tok -notmatch $safePattern) { $bad.Add($tok); continue }
        if ($agentValueFlags -contains $flag) {
            $kept.Add($tok)
            if (-not $hasInlineValue) { $expectValue = $true }
            continue
        }
        if ($agentBoolFlags -contains $flag) {
            $kept.Add($tok)
            continue
        }
        # 无法识别的参数：整批放弃并告警，避免拼写错误/一次性参数写进 ImagePath。
        $bad.Add($tok)
    }
    if ($expectValue) { $bad.Add("<缺少取值>") }
    if ($bad.Count -gt 0) {
        Write-Warning "旧服务配置中存在无法识别或不安全的参数，已全部忽略（请重新执行安装命令显式指定）：$($bad -join ' ')"
        return @()
    }
    return $kept.ToArray()
}

# 6. 准备安装目录
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

# 状态目录（跳过版本记录、降级依赖等）默认在 %ProgramData%\mnagent，由 agent 自己使用。
# Windows 没有 POSIX 权限位，internal/statedir 会拒绝 DACL 允许 Everyone/
# Authenticated Users/Users 写入的目录，因此这里显式创建并只授权给
# SYSTEM 与 Administrators（与令牌文件同样的 SID 写法，避免非英文系统匹配失败）。
$stateDir = ""
if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
    $stateDir = Join-Path $env:ProgramData "mnagent"
    try {
        if (-not (Test-Path $stateDir)) {
            New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        }
        & icacls.exe "$stateDir" /reset | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls /reset 退出码 $LASTEXITCODE" }
        & icacls.exe "$stateDir" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "icacls 收紧 DACL 退出码 $LASTEXITCODE" }
        Write-Host "已收紧状态目录权限（仅 SYSTEM 与 Administrators 可写）: $stateDir" -ForegroundColor Green
    } catch {
        throw "收紧状态目录 DACL 失败（agent 会因目录不安全而拒绝使用，影响自动更新记录）：$_"
    }
}

$mnagentBin = Join-Path $InstallDir "mnagent.exe"
$tokenPath = Join-Path $InstallDir "token"
$nexttraceBin = Join-Path $InstallDir "nexttrace.exe"
$miaospeedBin = Join-Path $InstallDir "miaospeed.exe"

# 7. 若服务运行中，更新前先安全停止并清理可能占用的进程
$existingSvc = Get-Service -Name "mnagent" -ErrorAction SilentlyContinue
if ($existingSvc -and $existingSvc.Status -ne "Stopped") {
    Write-Host "正在停止已有的 mnagent 服务..." -ForegroundColor Yellow
    Stop-Service -Name "mnagent" -Force -ErrorAction SilentlyContinue
    try {
        $existingSvc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(10))
    } catch {}
    Get-Process -Name "mnagent", "nexttrace", "miaospeed" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# 8. 下载 mnagent
Write-Host "开始下载 mnagent 二进制..." -ForegroundColor Cyan
$mnagentVer = $Version
if ($mnagentVer -eq "latest") {
    $tag = Get-GitHubLatestTag "mengnanquq/mnagent"
    if ($tag) { $mnagentVer = $tag }
}

$mnagentAsset = "mnagent_windows_${arch}.exe"
$mnagentUrl = if ($mnagentVer -eq "latest") {
    "https://github.com/mengnanquq/mnagent/releases/latest/download/$mnagentAsset"
} else {
    "https://github.com/mengnanquq/mnagent/releases/download/$mnagentVer/$mnagentAsset"
}

$tmpMnagent = Join-Path $InstallDir ".mnagent-install.tmp"
try {
    Download-File $mnagentUrl $tmpMnagent
    Assert-Sha256 $tmpMnagent "${mnagentUrl}.sha256" $mnagentAsset
    if ((Get-Item $tmpMnagent).Length -lt 100KB) {
        throw "下载的 mnagent 文件体积过小，可能发生错误"
    }
    Move-ExecutableSafely $tmpMnagent $mnagentBin
} catch {
    if (Test-Path $tmpMnagent) { Remove-Item -Path $tmpMnagent -Force }
    throw "安装 mnagent 失败（下载或完整性校验未通过）: $_"
}

# 9. 写入接入令牌 (使用 UTF-8 无 BOM 编码，避免认证 401 失败)
Write-Host "正在写入接入令牌..." -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($Token)) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tokenPath, $Token.Trim(), $utf8NoBom)
} elseif (-not [string]::IsNullOrWhiteSpace($TokenFile) -and (Test-Path $TokenFile)) {
    Copy-Item -Path $TokenFile -Destination $tokenPath -Force
}

# 令牌文件必须收紧 ACL：移除继承（可能包含 Users/Everyone 等）、只授予 SYSTEM 与
# Administrators 完全控制。服务由本脚本以 LocalSystem 创建，因此无需额外账户；
# 若后续改为其他账户运行，需要一并授予该账户读权限。
if (Test-Path $tokenPath) {
    # 先 /reset 清除复制/继承可能带来的显式 ACE（Users、Everyone、Interactive 等），
    # 再移除继承并只授予 SYSTEM 与 Administrators 完全控制。
    # 用 SID 而不是本地化名称，避免非英文 Windows 上匹配不到 SYSTEM/Administrators：
    # *S-1-5-18 = SYSTEM，*S-1-5-32-544 = BUILTIN\Administrators。
    & icacls.exe "$tokenPath" /reset | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "重置令牌文件 ACL 失败（icacls 退出码 $LASTEXITCODE）：$tokenPath"
    }
    & icacls.exe "$tokenPath" /inheritance:r /grant:r "*S-1-5-18:(F)" "*S-1-5-32-544:(F)" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "收紧令牌文件 ACL 失败（icacls 退出码 $LASTEXITCODE）：$tokenPath"
    }
    Write-Host "已收紧令牌文件权限（仅 SYSTEM 与 Administrators 可访问）。" -ForegroundColor Green
} else {
    Write-Warning "令牌文件 $tokenPath 不存在，无法收紧 ACL；服务启动后可能无法读取令牌。"
}

# 10. 下载 NextTrace（若启用）
if ($enableNextTrace) {
    Write-Host "正在配置 nexttrace..." -ForegroundColor Cyan
    $ntAsset = if ($arch -eq "arm64") {
        "nexttrace-tiny_windows_arm64.exe"
    } else {
        "nexttrace_windows_${arch}.exe"
    }
    $ntUrl = "https://github.com/nxtrace/NTrace-core/releases/latest/download/$ntAsset"
    $ntDigest = Get-GitHubAssetDigest "nxtrace/NTrace-core" $ntAsset "latest"
    $tmpNt = Join-Path $InstallDir ".nexttrace-install.tmp"
    try {
        Download-File $ntUrl $tmpNt
        Assert-AssetSha256 $tmpNt $ntDigest $ntAsset
        Move-ExecutableSafely $tmpNt $nexttraceBin
        Write-Host "nexttrace 安装成功。" -ForegroundColor Green
    } catch {
        Write-Warning "下载或校验 nexttrace 失败，已跳过安装（mnagent 启动后可在后台自动重试）: $_"
        if (Test-Path $tmpNt) { Remove-Item -Path $tmpNt -Force }
    }
}

# 11. 下载 MiaoSpeed（若启用）
if ($enableMiaoSpeed) {
    Write-Host "正在配置 miaospeed..." -ForegroundColor Cyan
    $miaoVer = $MiaoSpeedVersion
    if ($miaoVer -eq "latest") {
        $tag = Get-GitHubLatestTag "AirportR/miaospeed"
        if ($tag) {
            $miaoVer = $tag.TrimStart('v')
        } else {
            $miaoVer = "4.7.8"
        }
    }
    $miaoZip = "miaospeed-windows-$arch-$miaoVer.zip"
    $miaoUrl = "https://github.com/AirportR/miaospeed/releases/download/$miaoVer/$miaoZip"
    $miaoDigest = Get-GitHubAssetDigest "AirportR/miaospeed" $miaoZip $miaoVer
    # 解压到独立的临时目录，避免污染安装目录；结束后整体清理。
    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mnagent-miaospeed-" + [Guid]::NewGuid().ToString("N"))
    $tmpZip = Join-Path $workDir "miaospeed.zip"
    $tmpExtract = Join-Path $workDir "extract"
    try {
        New-Item -ItemType Directory -Force -Path $workDir | Out-Null
        Download-File $miaoUrl $tmpZip
        Assert-AssetSha256 $tmpZip $miaoDigest $miaoZip
        Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
        # 按确切文件名取二进制（release 内命名为 miaospeed-windows-<arch>.exe），不再用通配符取第一个匹配。
        $expectedExe = "miaospeed-windows-$arch.exe"
        $extractedExe = Get-ChildItem -Path $tmpExtract -Filter $expectedExe -Recurse -File | Select-Object -First 1
        if (-not $extractedExe) {
            throw "压缩包内未找到预期二进制 $expectedExe（已跳过安装）"
        }
        Move-ExecutableSafely $extractedExe.FullName $miaospeedBin
        Write-Host "miaospeed 安装成功。" -ForegroundColor Green
    } catch {
        Write-Warning "下载/校验/解压 miaospeed 失败，已跳过安装（mnagent 启动后可在后台自动重试）: $_"
    } finally {
        if (Test-Path $workDir) { Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# 12. 注册并配置 Windows 服务
Write-Host "正在配置 Windows 原生系统服务..." -ForegroundColor Cyan

# 旧服务已存在时，把手工追加的 agent 参数（-log-level、-allow-private-probes 等）继承下来。
$inheritedArgs = @()
if ($existingSvc) {
    $inheritedArgs = @(Get-InheritedServiceArgs $existingImagePath)
}

$serviceArgs = @(
    "-bot `"$Bot`"",
    "-token-file `"$tokenPath`"",
    "-nexttrace `"$nexttraceBin`"",
    "-miaospeed `"$miaospeedBin`"",
    "-log-file `"$LogFile`""
)
if ($enableAutoUpdate) {
    $serviceArgs += "-auto-update"
    $serviceArgs += "-update-interval `"$UpdateInterval`""
}
if (-not [string]::IsNullOrWhiteSpace($GhProxy)) {
    $serviceArgs += "-gh-proxy `"$GhProxy`""
}
if ($enableInsecureHttp) {
    $serviceArgs += "-allow-insecure-http"
}
# 安装时已自动安装过 miaospeed，运行时再允许一次自动补装以保持既有行为；
# agent 的该开关默认关闭（远程任务不应单方面触发以 root 下载安装依赖）。
$serviceArgs += "-allow-auto-install-deps"
if ($inheritedArgs.Count -gt 0) {
    $serviceArgs += $inheritedArgs
    Write-Host "已从现有服务配置继承附加参数: $($inheritedArgs -join ' ')" -ForegroundColor Gray
}

$binPathValue = "`"$mnagentBin`" " + ($serviceArgs -join " ")

if ($existingSvc) {
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mnagent" -Name "ImagePath" -Value $binPathValue -Type ExpandString -Force -ErrorAction Stop
        Set-Service -Name "mnagent" -StartupType Automatic -DisplayName "mnagent Service" -ErrorAction SilentlyContinue
        Write-Host "已更新现有 mnagent 服务配置。" -ForegroundColor Green
    } catch {
        & sc.exe config mnagent binPath= $binPathValue start= auto | Out-Null
        Write-Host "已更新现有 mnagent 服务配置。" -ForegroundColor Green
    }
} else {
    try {
        New-Service -Name "mnagent" -BinaryPathName $binPathValue -DisplayName "mnagent Service" -StartupType Automatic -ErrorAction Stop | Out-Null
        Write-Host "已创建 mnagent Windows 服务。" -ForegroundColor Green
    } catch {
        # 回退使用原生 sc.exe create（直接传参，避免 cmd.exe 引号嵌套问题）
        $scRes = & sc.exe create mnagent binPath= $binPathValue start= auto DisplayName= "mnagent Service"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "已创建 mnagent Windows 服务。" -ForegroundColor Green
        } else {
            throw "注册 Windows 服务失败: $scRes"
        }
    }
}

# 设置描述与失败自动重启
try {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mnagent" -Name "Description" -Value "Telegram Bot 测速与网络追踪轻量 Agent" -Force -ErrorAction SilentlyContinue
} catch {
    & sc.exe description mnagent "Telegram Bot 测速与网络追踪轻量 Agent" | Out-Null
}
try {
    & sc.exe failure mnagent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
} catch {}

# 13. 启动服务
Write-Host "正在启动 mnagent 服务..." -ForegroundColor Cyan
try {
    Start-Service -Name "mnagent" -ErrorAction Stop
} catch {
    & sc.exe start mnagent | Out-Null
}
Start-Sleep -Seconds 2

$svcStatus = Get-Service -Name "mnagent" -ErrorAction SilentlyContinue
if ($svcStatus -and $svcStatus.Status -eq "Running") {
    Write-Host @"

============================================================
  ⚡ mnagent Windows 服务已成功安装并启动！
============================================================
  • 安装目录: $InstallDir
  • 日志文件: $LogFile
  • 主执行程序: $mnagentBin
  • 服务名称: mnagent (自启状态: 自动)
  • 追踪引擎: nexttrace ($nexttraceBin)
  • 测速引擎: miaospeed ($miaospeedBin)
  • 自动更新: $(if ($enableAutoUpdate) { "启用 (每 $UpdateInterval)" } else { "未启用" })
------------------------------------------------------------
  👉 验证接入：请在 Telegram 机器人中发送 /host status 查看心跳
============================================================
  常用管理命令:
    查看状态: Get-Service mnagent
    启动服务: Start-Service mnagent  (或 net start mnagent)
    停止服务: Stop-Service mnagent   (或 net stop mnagent)
    卸载服务: powershell .\install.ps1 -Uninstall
============================================================
"@ -ForegroundColor Green
} else {
    Write-Warning "服务已创建，但状态为 $($svcStatus.Status)。请运行 'Get-Service mnagent' 或查看 Windows 事件查看器排查。"
}
