#Requires -Version 5.1
<#
.SYNOPSIS
    把建置產物安裝為 CairnAgent 服務（本機開發／測試機用），或以 -Uninstall 移除。

.DESCRIPTION
    安裝步驟：
      1. 停止並移除既有 CairnAgent 服務（若存在）
      2. 複製建置產物到 %ProgramFiles%\Cairn\（CairnAgent.exe、CairnConsole.exe 與同目錄 DLL/PDB）
      3. 複製 rules\*.yaml 到 %ProgramData%\Cairn\rules\（既有檔先備份到 rules.bak-<時間>）
      4. config\policy.default.json → %ProgramData%\Cairn\policy.json（已存在則保留，-ForceConfig 覆蓋）
      5. CairnAgent.exe --install（SCM 註冊，服務名 CairnAgent，CONVENTIONS C-2.2）
      6. 設定 SCM 失敗自動重啟（R-06 ②）、啟用 WER 本機 dump（part2 §2.8.1）
      7. 啟動服務並等待 Running

    -Uninstall：停止服務 → CairnAgent.exe --uninstall（失敗則 sc.exe delete）→ 刪除 %ProgramFiles%\Cairn。
    資料目錄 %ProgramData%\Cairn 預設保留；加 -PurgeData 一併刪除（含 DB、隔離區、稽核鏈），
    並移除名稱前綴為「Cairn - Block 」的防火牆規則。

.PARAMETER BuildDir
    建置輸出根目錄，預設 <repo>\build\x64-debug。Release 用 build\x64-release。

.PARAMETER InstallDir
    預設 %ProgramFiles%\Cairn。

.PARAMETER NoStart
    安裝後不啟動服務。

.PARAMETER ForceConfig
    覆蓋既有的 %ProgramData%\Cairn\policy.json。

.PARAMETER AddDefenderExclusion
    將安裝目錄與資料目錄加入 Defender 排除（R-14 ①；僅限開發／測試機）。

.PARAMETER Uninstall
    移除服務與安裝目錄。

.PARAMETER PurgeData
    搭配 -Uninstall：一併刪除 %ProgramData%\Cairn 與 Cairn 防火牆規則。

.EXAMPLE
    .\tools\Install-Dev.ps1

.EXAMPLE
    .\tools\Install-Dev.ps1 -BuildDir .\build\x64-release -AddDefenderExclusion

.EXAMPLE
    .\tools\Install-Dev.ps1 -Uninstall -PurgeData
#>
[CmdletBinding()]
param(
    [string]$BuildDir,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Cairn'),
    [switch]$NoStart,
    [switch]$ForceConfig,
    [switch]$AddDefenderExclusion,
    [switch]$Uninstall,
    [switch]$PurgeData
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force
Assert-Admin 'Install-Dev.ps1（安裝／移除 Windows 服務）'

$repo     = Get-CairnRepoRoot
$dataDir  = Get-CairnDataDir
$svcName  = 'CairnAgent'
if (-not $BuildDir) { $BuildDir = Join-Path $repo 'build\x64-debug' }

function Stop-CairnService {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    if ($svc.Status -ne 'Stopped') {
        Write-Host "停止服務 $svcName ..."
        & sc.exe stop $svcName | Out-Null
        $deadline = (Get-Date).AddSeconds(30)   # OnStop 上限 20 秒（part2 §2.1.2）+ 餘裕
        while ((Get-Service $svcName).Status -ne 'Stopped' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if ((Get-Service $svcName).Status -ne 'Stopped') {
            Write-Warning '服務 30 秒內未停止，強制結束 CairnAgent.exe'
            Get-Process -Name CairnAgent -ErrorAction SilentlyContinue | Stop-Process -Force
        }
    }
}

function Remove-CairnService {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    $exe = Join-Path $InstallDir 'CairnAgent.exe'
    $removed = $false
    if (Test-Path $exe) {
        & $exe --uninstall
        if ($LASTEXITCODE -eq 0) { $removed = $true }
        else { Write-Warning "CairnAgent.exe --uninstall 離開碼 $LASTEXITCODE，改用 sc.exe delete" }
    }
    if (-not $removed) { & sc.exe delete $svcName | Out-Null }
    # SCM 在所有 handle 關閉前會把服務標為「待刪除」
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Service -Name $svcName -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
}

# ============================================================
if ($Uninstall) {
    Write-Section '移除 Cairn'
    Stop-CairnService
    Remove-CairnService
    # llama-server 應隨 Job Object 一併結束；若仍殘留即為 W3 出場條件 6 的缺陷，此處只警告不代殺
    if (Get-Process -Name llama-server -ErrorAction SilentlyContinue) {
        Write-Warning 'llama-server 仍在執行——Job Object 未生效（W3 出場條件 6 的缺陷），請記錄後手動結束'
    }
    if (Test-Path $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
    if ($PurgeData) {
        Write-Host "刪除資料目錄 $dataDir"
        if (Test-Path $dataDir) { Remove-Item -LiteralPath $dataDir -Recurse -Force }
        $fw = @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Cairn - Block *' })
        foreach ($r in $fw) { Remove-NetFirewallRule -Name $r.Name }
        if ($fw.Count) { Write-Host "已移除 $($fw.Count) 條 Cairn 防火牆規則" }
    } else {
        Write-Host "保留資料目錄 $dataDir（加 -PurgeData 刪除）"
    }
    Write-Host '移除完成。' -ForegroundColor Green
    exit 0
}

# ============================================================
Write-Section "安裝 Cairn（來源：$BuildDir）"
$agentSrc   = Join-Path $BuildDir 'src\svc\CairnAgent.exe'
$consoleSrc = Join-Path $BuildDir 'src\ui\CairnConsole.exe'
if (-not (Test-Path $agentSrc)) {
    throw "找不到 $agentSrc。請先建置：cmake --preset x64-debug; cmake --build --preset x64-debug"
}
if (-not (Test-Path $consoleSrc)) { Write-Warning "找不到 $consoleSrc，只安裝服務（UI 需另行建置）" }

Stop-CairnService
Remove-CairnService

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($src in @($agentSrc, $consoleSrc)) {
    if (-not (Test-Path $src)) { continue }
    $dir = Split-Path $src
    Copy-Item -LiteralPath $src -Destination $InstallDir -Force
    # 同目錄的 DLL（/MD 動態 CRT/MFC 於開發機由 VS 提供；此處只帶建置輸出內的 DLL）與 PDB
    Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Extension -in '.dll', '.pdb' } |
        ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $InstallDir -Force }
}
Write-Host "已複製執行檔到 $InstallDir"

# --- 資料目錄、規則、組態 ---
$rulesDst = Join-Path $dataDir 'rules'
New-Item -ItemType Directory -Force -Path $dataDir, $rulesDst | Out-Null
$existing = @(Get-ChildItem -LiteralPath $rulesDst -Filter '*.yaml' -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0) {
    $bak = Join-Path $dataDir ("rules.bak-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
    New-Item -ItemType Directory -Path $bak | Out-Null
    $existing | ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination $bak }
    Write-Host "既有規則已備份到 $bak"
}
Copy-Item -Path (Join-Path $repo 'rules\*.yaml') -Destination $rulesDst -Force
$schema = Join-Path $repo 'rules\_schema.json'
if (Test-Path $schema) { Copy-Item -LiteralPath $schema -Destination $rulesDst -Force }
Write-Host "已複製規則到 $rulesDst（$(@(Get-ChildItem $rulesDst -Filter *.yaml).Count) 個檔案）"

$policySrc = Join-Path $repo 'config\policy.default.json'
$policyDst = Join-Path $dataDir 'policy.json'
if ((Test-Path $policySrc) -and ((-not (Test-Path $policyDst)) -or $ForceConfig)) {
    Copy-Item -LiteralPath $policySrc -Destination $policyDst -Force
    Write-Host "已寫入 $policyDst"
} elseif (Test-Path $policyDst) {
    Write-Host "保留既有 $policyDst（-ForceConfig 可覆蓋）"
}

# --- 註冊服務 ---
$agentExe = Join-Path $InstallDir 'CairnAgent.exe'
& $agentExe --install
if ($LASTEXITCODE -ne 0) { throw "CairnAgent.exe --install 失敗（離開碼 $LASTEXITCODE）" }

# SCM 失敗自動重啟：5 秒、10 秒、30 秒；一天後重置計數（R-06 ②）
& sc.exe failure $svcName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# WER 本機 dump（DumpType 2 = full）
$wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\CairnAgent.exe'
New-Item -Path $wer -Force | Out-Null
Set-ItemProperty -Path $wer -Name DumpType -Value 2 -Type DWord
Set-ItemProperty -Path $wer -Name DumpCount -Value 5 -Type DWord

if ($AddDefenderExclusion) {
    try {
        Add-MpPreference -ExclusionPath $InstallDir, $dataDir
        Write-Host '已加入 Defender 排除（R-14 ①）'
    } catch {
        Write-Warning "加入 Defender 排除失敗：$($_.Exception.Message)（Tamper Protection 開啟時需手動設定）"
    }
}

if (-not $NoStart) {
    & sc.exe start $svcName | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Service $svcName).Status -ne 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    $st = (Get-Service $svcName).Status
    if ($st -ne 'Running') {
        throw "服務未進入 Running（目前 $st）。查看 $dataDir\logs\ 與「事件檢視器 → Windows 記錄 → 應用程式」"
    }
    Write-Host '服務已啟動。' -ForegroundColor Green
    Write-Host '驗證：.\tools\Invoke-Rpc.ps1 -Method health'
}
Write-Host "UI：`"$InstallDir\CairnConsole.exe`""
exit 0
