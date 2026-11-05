<#
.SYNOPSIS
    以系統管理員執行 WINDOWS-FIRST-RUN §4–§5 中需要提升權限的驗證步驟，結果寫入 reports\admin-verify-<時間>.log。

.DESCRIPTION
    步驟（任一步失敗即停止並在日誌標示）：
      1. 前置檢查        tools\Check-Prereqs.ps1
      2. svc 測試        ctest -R "svc\." （x64-debug；若已建置 x64-asan 也跑）
      3. 錄製 Sysmon 樣本 每個 EID 最新一筆 → reports\recorded\（含使用者資訊，不進版控）
      4. 安裝服務        tools\Install-Dev.ps1（僅在指定 -Install 時）
      5. RPC 冒煙        tools\Invoke-Rpc.ps1 -Method health.get（僅在 -Install 時）

    不指定 -Install 時不會變更系統（只讀取與執行測試）。

.PARAMETER Install
    執行步驟 4、5：把建置產物安裝成 CairnAgent 服務並做 RPC 冒煙測試。

.EXAMPLE
    # 系統管理員 PowerShell
    .\tools\Invoke-AdminVerify.ps1
.EXAMPLE
    .\tools\Invoke-AdminVerify.ps1 -Install
#>
param([switch]$Install)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw '請以系統管理員身分執行' }

New-Item -ItemType Directory -Force reports | Out-Null
$log = Join-Path $repo ("reports\admin-verify-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $log | Out-Null
try {
    function Step([string]$Title, [scriptblock]$Body) {
        Write-Host "`n===== $Title =====" -ForegroundColor Cyan
        $global:LASTEXITCODE = 0
        & $Body
        if ($LASTEXITCODE) { throw "$Title 失敗（exit $LASTEXITCODE）" }
        Write-Host "===== $Title：OK" -ForegroundColor Green
    }

    Step '1. 前置檢查' { & "$PSScriptRoot\Check-Prereqs.ps1" }

    foreach ($preset in 'x64-debug', 'x64-asan') {
        if (-not (Test-Path "build\$preset\CMakeCache.txt")) { Write-Host "略過 $preset（尚未建置）"; continue }
        Step "2. svc 測試（$preset，管理員）" {
            & "$PSScriptRoot\build.ps1" -Preset $preset -NoTest
            if ($LASTEXITCODE) { return }
            ctest --test-dir "build\$preset" -R 'svc\.' --output-on-failure
        }
    }

    Step '3. 錄製 Sysmon 樣本' {
        $out = Join-Path $repo 'reports\recorded'
        New-Item -ItemType Directory -Force $out | Out-Null
        Start-Process cmd.exe '/c exit' -Wait -WindowStyle Hidden
        Resolve-DnsName example.com -ErrorAction SilentlyContinue | Out-Null
        foreach ($id in 1, 3, 5, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25, 26) {
            $e = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = $id } -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($e) { [IO.File]::WriteAllText("$out\eid_${id}_recorded.xml", $e.ToXml(), (New-Object Text.UTF8Encoding($false))) }
            else { Write-Host "EID $id：目前沒有事件（可能被 sysmon.xml 過濾或尚未發生）" }
        }
        $ps = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($ps) { [IO.File]::WriteAllText("$out\ps_4104_recorded.xml", $ps.ToXml(), (New-Object Text.UTF8Encoding($false))) }
        Write-Host "已寫入 $out（含使用者名稱與路徑；放進 tests\fixtures 前須去識別化）"
    }

    if ($Install) {
        Step '4. 安裝服務' { & "$PSScriptRoot\Install-Dev.ps1" }
        Step '5. RPC 冒煙（health.get）' {
            Start-Sleep -Seconds 10   # 等服務完成啟動與第一次健康度取樣
            & "$PSScriptRoot\Invoke-Rpc.ps1" -Method health.get -Json
        }
    } else {
        Write-Host "`n未指定 -Install：略過服務安裝與 RPC 冒煙（§5）"
    }
    Write-Host "`n全部完成。日誌：$log" -ForegroundColor Green
} finally {
    Stop-Transcript | Out-Null
}
