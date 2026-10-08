<#
.SYNOPSIS
    mnagent Windows 一键安装与服务配置脚本

.DESCRIPTION
    自动从 GitHub Releases 下载 mnagent_windows_<arch>.exe、
    可选下载 nexttrace.exe 与 miaospeed.exe、写入令牌并注册为原生自启的 Windows 服务。

.EXAMPLE
    irm https://github.com/mengnanquq/mnagent/releases/latest/download/install.ps1 | iex -args -Bot "https://mnbot.example.org/agent" -Token "your_token"

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
    [string]$InstallDir = "$env:ProgramFiles\mnagent",
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
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

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
  -Version <版本>            mnagent 版本号（默认: latest）
  -GhProxy <URL>             GitHub 代理加速前缀（如 https://gh-proxy.com/）
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

# 1. 确保以管理员权限运行
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    if ($MyInvocation.MyCommand.Path) {
        Write-Host "需要管理员权限，正在尝试通过 UAC 提权重新运行..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"") + $args
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
        if ($svc.Status -eq "Running") {
            Write-Host "正在停止 mnagent 服务..."
            Stop-Service -Name "mnagent" -Force -ErrorAction SilentlyContinue
        }
        & sc.exe delete mnagent | Out-Null
        Write-Host "已删除 mnagent Windows 服务。" -ForegroundColor Green
    } else {
        Write-Host "未找到 mnagent Windows 服务。" -ForegroundColor Gray
    }

    if (Test-Path $InstallDir) {
        $confirm = Read-Host "是否删除安装目录 $InstallDir 及配置文件？[y/N]"
        if ($confirm -match '^[Yy]') {
            Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "已清理安装目录: $InstallDir" -ForegroundColor Green
        }
    }
    Write-Host "mnagent 卸载完成。" -ForegroundColor Green
    exit 0
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

if ([string]::IsNullOrWhiteSpace($Token) -and [string]::IsNullOrWhiteSpace($TokenFile)) {
    Write-Error "错误：必须指定 -Token 或 -TokenFile"
    Show-Usage
    exit 1
}

# 默认启用状态处理
$enableAutoUpdate = -not $NoAutoUpdate
$enableNextTrace = -not $NoInstallNextTrace
$enableMiaoSpeed = -not $NoInstallMiaoSpeed

# 4. 检测系统架构
$is64 = [System.Environment]::Is64BitOperatingSystem
$arch = if ($is64) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    "386"
}
Write-Host "检测到系统平台: Windows ($arch)" -ForegroundColor Cyan

# 5. 安全协议配置 (启用 TLS 1.2 / 1.3)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

function Get-ProxiedUrl([string]$rawUrl) {
    if ([string]::IsNullOrWhiteSpace($GhProxy)) { return $rawUrl }
    $p = $GhProxy.TrimEnd('/') + '/'
    if ($rawUrl.StartsWith($p)) { return $rawUrl }
    return $p + $rawUrl
}

function Download-File([string]$url, [string]$destination) {
    $proxied = Get-ProxiedUrl $url
    Write-Host "正在下载: $proxied" -ForegroundColor Gray
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "mnagent-installer")
    $wc.DownloadFile($proxied, $destination)
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

# 6. 准备安装目录
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$mnagentBin = Join-Path $InstallDir "mnagent.exe"
$tokenPath = Join-Path $InstallDir "token"
$nexttraceBin = Join-Path $InstallDir "nexttrace.exe"
$miaospeedBin = Join-Path $InstallDir "miaospeed.exe"

# 7. 若服务运行中，更新前先停止
$existingSvc = Get-Service -Name "mnagent" -ErrorAction SilentlyContinue
if ($existingSvc -and $existingSvc.Status -eq "Running") {
    Write-Host "正在停止正在运行的 mnagent 服务..." -ForegroundColor Yellow
    Stop-Service -Name "mnagent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
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
    if ((Get-Item $tmpMnagent).Length -lt 100KB) {
        throw "下载的 mnagent 文件体积过小，可能发生错误"
    }
    Move-Item -Path $tmpMnagent -Destination $mnagentBin -Force
} catch {
    if (Test-Path $tmpMnagent) { Remove-Item -Path $tmpMnagent -Force }
    throw "下载 mnagent 失败: $_"
}

# 9. 写入接入令牌
Write-Host "正在写入接入令牌..." -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($Token)) {
    [System.IO.File]::WriteAllText($tokenPath, $Token.Trim(), [System.Text.Encoding]::UTF8)
} elseif (-not [string]::IsNullOrWhiteSpace($TokenFile) -and (Test-Path $TokenFile)) {
    Copy-Item -Path $TokenFile -Destination $tokenPath -Force
}

# 10. 下载 NextTrace（若启用）
if ($enableNextTrace) {
    Write-Host "正在配置 nexttrace..." -ForegroundColor Cyan
    $ntAsset = "nexttrace_windows_${arch}.exe"
    $ntUrl = "https://github.com/nxtrace/NTrace-core/releases/latest/download/$ntAsset"
    $tmpNt = Join-Path $InstallDir ".nexttrace-install.tmp"
    try {
        Download-File $ntUrl $tmpNt
        Move-Item -Path $tmpNt -Destination $nexttraceBin -Force
        Write-Host "nexttrace 安装成功。" -ForegroundColor Green
    } catch {
        Write-Warning "下载 nexttrace 失败，mnagent 启动后可在后台自动重试: $_"
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
            $miaoVer = "4.7.7"
        }
    }
    $miaoArch = switch ($arch) {
        "amd64" { "amd64" }
        "arm64" { "arm64" }
        "386"   { "386" }
        default { $arch }
    }
    $miaoZip = "miaospeed-windows-$miaoArch-$miaoVer.zip"
    $miaoUrl = "https://github.com/AirportR/miaospeed/releases/download/$miaoVer/$miaoZip"
    $tmpZip = Join-Path $InstallDir ".miaospeed-dl.zip"
    $tmpExtract = Join-Path $InstallDir ".miaospeed-extracted"
    try {
        Download-File $miaoUrl $tmpZip
        if (Test-Path $tmpExtract) { Remove-Item -Path $tmpExtract -Recurse -Force }
        Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
        $extractedExe = Get-ChildItem -Path $tmpExtract -Filter "*miaospeed*.exe" -Recurse | Select-Object -First 1
        if ($extractedExe) {
            Move-Item -Path $extractedExe.FullName -Destination $miaospeedBin -Force
            Write-Host "miaospeed 安装成功。" -ForegroundColor Green
        }
    } catch {
        Write-Warning "下载/解压 miaospeed 失败，mnagent 启动后可在后台自动重试: $_"
    } finally {
        if (Test-Path $tmpZip) { Remove-Item -Path $tmpZip -Force }
        if (Test-Path $tmpExtract) { Remove-Item -Path $tmpExtract -Recurse -Force }
    }
}

# 12. 注册并配置 Windows 服务
Write-Host "正在配置 Windows 原生系统服务..." -ForegroundColor Cyan

$serviceArgs = @(
    "-bot `"$Bot`"",
    "-token-file `"$tokenPath`"",
    "-nexttrace `"$nexttraceBin`"",
    "-miaospeed `"$miaospeedBin`""
)
if ($enableAutoUpdate) {
    $serviceArgs += "-auto-update"
    $serviceArgs += "-update-interval `"$UpdateInterval`""
}
if (-not [string]::IsNullOrWhiteSpace($GhProxy)) {
    $serviceArgs += "-gh-proxy `"$GhProxy`""
}

$binPathValue = "`"$mnagentBin`" " + ($serviceArgs -join " ")

if ($existingSvc) {
    & sc.exe config mnagent binPath= $binPathValue start= auto | Out-Null
    Write-Host "已更新现有 mnagent 服务配置。" -ForegroundColor Green
} else {
    & sc.exe create mnagent binPath= $binPathValue start= auto DisplayName= "mnagent Service" | Out-Null
    Write-Host "已创建 mnagent Windows 服务。" -ForegroundColor Green
}

# 设置描述与失败自动重启
& sc.exe description mnagent "Telegram Bot 测速与网络追踪轻量 Agent" | Out-Null
& sc.exe failure mnagent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

# 13. 启动服务
Write-Host "正在启动 mnagent 服务..." -ForegroundColor Cyan
& sc.exe start mnagent | Out-Null
Start-Sleep -Seconds 2

$svcStatus = Get-Service -Name "mnagent" -ErrorAction SilentlyContinue
if ($svcStatus -and $svcStatus.Status -eq "Running") {
    Write-Host @"

============================================================
  mnagent Windows 服务已成功安装并启动！
============================================================
  安装目录: $InstallDir
  主执行程序: $mnagentBin
  服务名称: mnagent (自启状态: 自动)
  管理命令:
    查看状态: Get-Service mnagent
    启动服务: Start-Service mnagent  (或 net start mnagent)
    停止服务: Stop-Service mnagent   (或 net stop mnagent)
    卸载服务: powershell .\install.ps1 -Uninstall
============================================================
"@ -ForegroundColor Green
} else {
    Write-Warning "服务已创建，但状态为 $($svcStatus.Status)。请运行 'Get-Service mnagent' 或查看 Windows 事件查看器排查。"
}
