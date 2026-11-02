#Requires -Version 5.1
<#
.SYNOPSIS
    以 Application Verifier 驗證記憶體與 handle 正確性（part2 §2.8.1；W1-13、W3 出場條件 2、W4-5）。

.DESCRIPTION
    Application Verifier 是唯一能可靠抓到 handle 洩漏與跨執行緒 double-close 的工具（part2 §2.8.1）。
    本腳本：啟用 Basics（Heaps / Handles / Locks / Memory / Exceptions）→ 執行情境 → 匯出日誌 →
    統計記錄筆數 → 停用。記錄數 > 0 → 離開碼 1。

    情境：
      Tests    ：在 AppVerifier 下跑 cairn_tests_svc.exe 與 cairn_tests_core.exe（全部 svc/core 測試）
      Response ：在 AppVerifier 下跑回應動作相關的 svc 測試（Quarantine / ProcessResponder / Firewall /
                 ConfirmationToken）——COM 與 CNG 是 handle 洩漏的高風險區（W3 出場條件 2）。
                 加 -AlertId 時，另對執行中的 CairnAgent 服務以 RPC 實際做一次
                 suspend_process → revert 往返。
      Soak     ：對 CairnAgent 服務啟用 AppVerifier 並重啟服務，跑 -Hours 小時實機負載
                 （預設 4 小時，W4-5 / M0-P13），期間以 Load-Test.ps1 -Profile Office 產生負載。

    ⚠ 啟用 AppVerifier 的設定存在 IFEO 登錄檔；腳本以 try/finally 保證結束時停用，
      若被強制中斷，請手動執行：appverif.exe -disable * -for CairnAgent.exe

.PARAMETER Scenario
    Tests / Response / Soak。

.PARAMETER BuildDir
    測試執行檔所在建置目錄，預設 <repo>\build\x64-debug。

.PARAMETER Hours
    Soak 時長，預設 4。

.PARAMETER AlertId
    Response 情境下，用於實機 RPC 往返的告警 id（需有對應的存活程序）。

.PARAMETER OutputDir
    日誌輸出目錄，預設 <repo>\reports\appverif-<時間>。

.EXAMPLE
    .\tools\Run-AppVerifier.ps1 -Scenario Response
    # W3 出場條件 2：→ 0 筆 handle / heap 記錄

.EXAMPLE
    .\tools\Run-AppVerifier.ps1 -Scenario Soak -Hours 4
#>
[CmdletBinding()]
param(
    [ValidateSet('Tests', 'Response', 'Soak')][string]$Scenario = 'Tests',
    [string]$BuildDir,
    [double]$Hours = 4,
    [long]$AlertId = 0,
    [string]$OutputDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force
Assert-Admin 'Application Verifier（寫入 IFEO 登錄檔）'

$repo = Get-CairnRepoRoot
if (-not $BuildDir) { $BuildDir = Join-Path $repo 'build\x64-debug' }
if (-not $OutputDir) { $OutputDir = Join-Path $repo ("reports\appverif-{0:yyyyMMdd-HHmmss}" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$appverif = Join-Path $env:WINDIR 'System32\appverif.exe'
if (-not (Test-Path $appverif)) {
    throw "找不到 $appverif。請安裝 Windows SDK 的「Application Verifier for x64」元件（Windows SDK 安裝程式 → Application Verifier）。"
}
$layers = @('Heaps', 'Handles', 'Locks', 'Memory', 'Exceptions')

function Enable-Verifier([string]$Image) {
    & $appverif -enable @layers -for $Image | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "appverif -enable 失敗（$Image，離開碼 $LASTEXITCODE）" }
    Write-Host "已對 $Image 啟用：$($layers -join ', ')"
}

function Disable-Verifier([string]$Image) {
    & $appverif -disable * -for $Image | Out-Null
}

function Export-VerifierLog([string]$Image) {
    # 匯出最新的 AppVerifier 日誌並計算記錄筆數（logEntry 節點）。
    $file = Join-Path $OutputDir ("{0}.xml" -f [IO.Path]::GetFileNameWithoutExtension($Image))
    & $appverif -export log -for $Image -with To=$file | Out-Null
    if (-not (Test-Path $file)) {
        Write-Warning "$Image 沒有可匯出的日誌（可能從未在啟用狀態下執行過）"
        return [pscustomobject]@{ Image = $Image; Entries = $null; File = $null }
    }
    [xml]$x = Get-Content -LiteralPath $file -Raw -Encoding UTF8
    $entries = @($x.SelectNodes("//*[local-name()='logEntry']"))
    # 依 layer 彙總，方便判讀是 heap 還是 handle 問題
    $byLayer = $entries | Group-Object { $_.GetAttribute('LayerName') } | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host ("{0}: {1} 筆記錄 {2}" -f $Image, $entries.Count, ($byLayer -join ' '))
    return [pscustomobject]@{ Image = $Image; Entries = $entries.Count; File = $file }
}

function Invoke-TestExe([string]$Exe, [string]$Filter) {
    if (-not (Test-Path $Exe)) { throw "找不到 $Exe；請先 cmake --build --preset x64-debug" }
    $testArgs = @("--gtest_output=xml:$(Join-Path $OutputDir ((Split-Path $Exe -Leaf) + '.gtest.xml'))")
    if ($Filter) { $testArgs += "--gtest_filter=$Filter" }
    Write-Host "執行 $Exe $($testArgs -join ' ')"
    & $Exe @testArgs
    return $LASTEXITCODE
}

$results = @()
$testFailures = 0
$coreExe = Join-Path $BuildDir 'tests\cairn_tests_core.exe'
$svcExe  = Join-Path $BuildDir 'tests\cairn_tests_svc.exe'

switch ($Scenario) {
    'Tests' {
        foreach ($exe in @($coreExe, $svcExe)) {
            $img = Split-Path $exe -Leaf
            Enable-Verifier $img
            try { if ((Invoke-TestExe $exe '') -ne 0) { $testFailures++ } }
            finally { $results += Export-VerifierLog $img; Disable-Verifier $img }
        }
    }
    'Response' {
        $img = Split-Path $svcExe -Leaf
        Enable-Verifier $img
        try {
            # 測試名稱模式對齊 tests/svc 下的回應動作測試（QuarantineRoundTrip / ProcessResponder / ConfirmationTokenStore / Firewall）
            if ((Invoke-TestExe $svcExe '*Quarantine*:*ProcessResponder*:*ConfirmationToken*:*Firewall*:*ResponseExecutor*') -ne 0) { $testFailures++ }
        } finally { $results += Export-VerifierLog $img; Disable-Verifier $img }

        if ($AlertId -gt 0) {
            Write-Section "實機 RPC 往返（alert $AlertId：suspend_process → revert）"
            Enable-Verifier 'CairnAgent.exe'
            try {
                & sc.exe stop CairnAgent | Out-Null; Start-Sleep -Seconds 5
                & sc.exe start CairnAgent | Out-Null; Start-Sleep -Seconds 10
                $prep = Invoke-CairnRpc -Method 'response.prepare' -Params @{ alert_id = "$AlertId"; action = 'suspend_process' }
                $exec = Invoke-CairnRpc -Method 'response.execute' -Params @{ alert_id = "$AlertId"; action = 'suspend_process'; confirmation_token = $prep.confirmation_token; reason = 'Run-AppVerifier Response 情境' }
                # 還原：第一次不帶 token → 服務回 CONFIRMATION_REQUIRED（error.data.details.confirmation_token），再帶 token 重送
                $ref = if ($exec.audit_entry_id) { "$($exec.audit_entry_id)" } else { "$($exec.action_id)" }
                if ($ref) {
                    $first = Invoke-CairnRpcCall -Method 'response.revert' -Params @{ alert_id = "$AlertId"; audit_id = $ref }
                    $tok = $null
                    if ($first.error -and $first.error.data -and $first.error.data.details) { $tok = $first.error.data.details.confirmation_token }
                    if ($tok) {
                        [void](Invoke-CairnRpc -Method 'response.revert' -Params @{ alert_id = "$AlertId"; audit_id = $ref; confirmation_token = $tok; reason = 'Run-AppVerifier Response 情境' })
                    } else {
                        Write-Warning "response.revert 未回傳 confirmation_token：$($first | ConvertTo-Json -Depth 6 -Compress)"
                    }
                }
                Start-Sleep -Seconds 5
            } finally {
                & sc.exe stop CairnAgent | Out-Null; Start-Sleep -Seconds 5
                $results += Export-VerifierLog 'CairnAgent.exe'
                Disable-Verifier 'CairnAgent.exe'
                & sc.exe start CairnAgent | Out-Null
            }
        }
    }
    'Soak' {
        Enable-Verifier 'CairnAgent.exe'
        try {
            & sc.exe stop CairnAgent | Out-Null; Start-Sleep -Seconds 5
            & sc.exe start CairnAgent | Out-Null; Start-Sleep -Seconds 10
            if (-not (Get-Process CairnAgent -ErrorAction SilentlyContinue)) { throw '服務在 AppVerifier 下無法啟動——這本身就是一筆需調查的記錄' }
            $lt = Join-Path $PSScriptRoot 'Load-Test.ps1'
            & $lt -Profile Office -Hours $Hours -OutputPath (Join-Path $OutputDir 'soak-load.md')
        } finally {
            & sc.exe stop CairnAgent | Out-Null; Start-Sleep -Seconds 10
            $results += Export-VerifierLog 'CairnAgent.exe'
            Disable-Verifier 'CairnAgent.exe'
            & sc.exe start CairnAgent | Out-Null
        }
    }
}

$total = ($results | Where-Object { $null -ne $_.Entries } | Measure-Object -Property Entries -Sum).Sum
if ($null -eq $total) { $total = 0 }
$summary = [ordered]@{ scenario = $Scenario; total_entries = $total; test_failures = $testFailures; logs = $results }
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDir 'summary.json') -Encoding UTF8

Write-Section '結果'
Write-Host "AppVerifier 記錄總數：$total；測試失敗執行檔數：$testFailures；日誌：$OutputDir"
if ($total -gt 0 -or $testFailures -gt 0) {
    Write-Host '未通過（M0-P13 要求 0 筆）。以 WinDbg 開啟對應日誌與 dump 調查。' -ForegroundColor Red
    exit 1
}
Write-Host '通過：0 筆 heap / handle 記錄。' -ForegroundColor Green
exit 0
