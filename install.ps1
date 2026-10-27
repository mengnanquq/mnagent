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
    [string]$ISP = "",
    [string]$InstallDir = "",
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

# 默认安装路径确定（优先真正的 64 位 Program Files 目录）
$programFilesDir = ${env:ProgramW6432}
if (-not $programFilesDir) { $programFilesDir = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $programFilesDir "mnagent"
}

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

# 6. 准备安装目录
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
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
    if ((Get-Item $tmpMnagent).Length -lt 100KB) {
        throw "下载的 mnagent 文件体积过小，可能发生错误"
    }
    Move-ExecutableSafely $tmpMnagent $mnagentBin
} catch {
    if (Test-Path $tmpMnagent) { Remove-Item -Path $tmpMnagent -Force }
    throw "下载 mnagent 失败: $_"
}

# 9. 写入接入令牌 (使用 UTF-8 无 BOM 编码，避免认证 401 失败)
Write-Host "正在写入接入令牌..." -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($Token)) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tokenPath, $Token.Trim(), $utf8NoBom)
} elseif (-not [string]::IsNullOrWhiteSpace($TokenFile) -and (Test-Path $TokenFile)) {
    Copy-Item -Path $TokenFile -Destination $tokenPath -Force
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
    $tmpNt = Join-Path $InstallDir ".nexttrace-install.tmp"
    try {
        Download-File $ntUrl $tmpNt
        Move-ExecutableSafely $tmpNt $nexttraceBin
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
            $miaoVer = "4.7.8"
        }
    }
    $miaoZip = "miaospeed-windows-$arch-$miaoVer.zip"
    $miaoUrl = "https://github.com/AirportR/miaospeed/releases/download/$miaoVer/$miaoZip"
    $tmpZip = Join-Path $InstallDir ".miaospeed-dl.zip"
    $tmpExtract = Join-Path $InstallDir ".miaospeed-extracted"
    try {
        Download-File $miaoUrl $tmpZip
        if (Test-Path $tmpExtract) { Remove-Item -Path $tmpExtract -Recurse -Force }
        Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
        $extractedExe = Get-ChildItem -Path $tmpExtract -Filter "*miaospeed*.exe" -Recurse | Select-Object -First 1
        if ($extractedExe) {
            Move-ExecutableSafely $extractedExe.FullName $miaospeedBin
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
if (-not [string]::IsNullOrWhiteSpace($ISP)) {
    $serviceArgs += "-isp `"$ISP`""
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
