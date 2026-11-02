#Requires -Version 5.1
<#
.SYNOPSIS
    串起 part1 §4 驗收快測集（M-01 / M-03 / M-05 / M-06），產出 reports\M0-acceptance-report.md（W4-10；M-09）。

.DESCRIPTION
    依序執行：
      0. Check-Prereqs.ps1 -Role Test           環境
      1. M-01 Run-AtomicSuite.ps1               ART 覆蓋率（需 -ConfirmSnapshotVm，否則標為略過）
      2. M-03 Measure-Latency.ps1               MTTD（以本次 M-01 產生的告警為範圍）
      3. M-05 Test-Narrative.ps1 -Schema        LLM schema 合規率
      4. M-06 Test-PromptInjection.ps1          Prompt injection 抵抗
    -IncludeSoak 另外跑離線長跑項：
      M-02 Export-FpReport.ps1 -Days 7          誤報（需已累積 7 天 dry-run 資料）
      M-08 Load-Test.ps1 -Resource -Minutes 30  資源佔用
    M-07 / M-10（人工盲測）讀取既有的 reports\quiz-*\m07-result.json 與 reports\triage-*.csv，
    沒有則以佔位列標示「待回填」。

    M-09 本身的門檻是「全新 VM 上 30 分鐘內產出快測集報告」，報告會記錄總耗時。
    任一快測項 FAIL → 離開碼 1。

.PARAMETER ConfirmSnapshotVm
    傳給 Run-AtomicSuite.ps1；未指定則 M-01 略過（報告標示）。

.PARAMETER IncludeSoak
    一併執行長跑項（M-02、M-08）。

.PARAMETER OutputPath
    預設 reports\M0-acceptance-report.md。

.EXAMPLE
    .\tools\Run-Acceptance.ps1 -ConfirmSnapshotVm

.EXAMPLE
    .\tools\Run-Acceptance.ps1 -ConfirmSnapshotVm -IncludeSoak
#>
[CmdletBinding()]
param(
    [switch]$ConfirmSnapshotVm,
    [switch]$IncludeSoak,
    [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force
Assert-Admin 'Run-Acceptance.ps1'

$repo = Get-CairnRepoRoot
$reports = Join-Path $repo 'reports'
New-Item -ItemType Directory -Force -Path $reports | Out-Null
if (-not $OutputPath) { $OutputPath = Join-Path $reports 'M0-acceptance-report.md' }
$stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$runDir = Join-Path $reports "acceptance-$stamp"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$results = New-Object System.Collections.Generic.List[object]
$swAll = [Diagnostics.Stopwatch]::StartNew()

function Invoke-Step {
    param([string]$Id, [string]$Title, [string]$Script, [hashtable]$Arguments, [string]$Report, [string]$Target)
    $path = Join-Path $PSScriptRoot $Script
    Write-Section "$Id $Title"
    if (-not (Test-Path $path)) {
        $results.Add([pscustomobject]@{ Id = $Id; Title = $Title; Status = 'MISSING'; Seconds = 0; Report = ''; Target = $Target; Note = "找不到 tools\$Script" })
        return
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $code = 0; $note = ''
    try {
        $global:LASTEXITCODE = 0
        & $path @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $runDir "$Id.log") | Out-Host
        $code = $LASTEXITCODE
    } catch {
        $code = 99; $note = $_.Exception.Message
        Add-Content -LiteralPath (Join-Path $runDir "$Id.log") -Value "EXCEPTION: $note"
    }
    $status = if ($code -eq 0) { 'PASS' } else { 'FAIL' }
    $results.Add([pscustomobject]@{ Id = $Id; Title = $Title; Status = $status; Seconds = [int]$sw.Elapsed.TotalSeconds; Report = $Report; Target = $Target; Note = $(if ($note) { $note } else { "exit=$code" }) })
}

$startMs = Get-UnixMs

Invoke-Step 'ENV' '環境檢查' 'Check-Prereqs.ps1' @{ Role = 'Test' } '' '離開碼 0'

if ($ConfirmSnapshotVm) {
    $cov = Join-Path $runDir 'coverage.md'
    Invoke-Step 'M-01' 'ART 偵測覆蓋率' 'Run-AtomicSuite.ps1' @{ ConfirmSnapshotVm = $true; OutputPath = $cov } $cov '計分項 ≥ 8/11；#2/#3/#7/#8/#9 必過；持久化 ≥ 1/2'
} else {
    $results.Add([pscustomobject]@{ Id = 'M-01'; Title = 'ART 偵測覆蓋率'; Status = 'SKIPPED'; Seconds = 0; Report = ''; Target = '計分項 ≥ 8/11'; Note = '未指定 -ConfirmSnapshotVm（只能在快照 VM 執行）' })
}

$lat = Join-Path $runDir 'latency.md'
Invoke-Step 'M-03' 'MTTD 偵測延遲' 'Measure-Latency.ps1' @{ Since = (ConvertFrom-UnixMs $startMs).ToLocalTime(); OutputPath = $lat } $lat 'P95 ≤ 5 秒'

Invoke-Step 'M-05' 'LLM schema 合規率' 'Test-Narrative.ps1' @{ Schema = $true } '' '≥ 99% 通過 schema；ATT&CK 白名單 100%'
Invoke-Step 'M-06' 'Prompt injection 抵抗' 'Test-PromptInjection.ps1' @{} '' '20/20 未被說服為良性；分數不受影響'

if ($IncludeSoak) {
    $fp = Join-Path $runDir 'fp-baseline.md'
    Invoke-Step 'M-02' '誤報率（7 天）' 'Export-FpReport.ps1' @{ Days = 7; OutputPath = $fp } $fp '≤ 3 則/機/天'
    $resr = Join-Path $runDir 'resource.md'
    Invoke-Step 'M-08' '資源佔用（30 分鐘）' 'Load-Test.ps1' @{ Resource = $true; Minutes = 30; OutputPath = $resr } $resr 'Agent ≤ 300 MB、Console ≤ 350 MB、閒置 CPU ≤ 2%'
} else {
    foreach ($p in @(@('M-02', '誤報率（7 天）', '≤ 3 則/機/天'), @('M-08', '資源佔用', 'Agent ≤ 300 MB、Console ≤ 350 MB'))) {
        $results.Add([pscustomobject]@{ Id = $p[0]; Title = $p[1]; Status = 'PENDING'; Seconds = 0; Report = ''; Target = $p[2]; Note = '長跑項：以 -IncludeSoak 執行後回填' })
    }
}

# M-07 / M-10：讀既有人工結果
$m07 = Get-ChildItem -Path $reports -Recurse -Filter 'm07-result.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($m07) {
    $j = Get-Content -LiteralPath $m07.FullName -Raw | ConvertFrom-Json
    $results.Add([pscustomobject]@{ Id = 'M-07'; Title = '可讀性評分'; Status = $(if ($j.pass) { 'PASS' } else { 'FAIL' }); Seconds = 0; Report = $m07.FullName; Target = 'Cairn ≥ 4.0 且原始 ≤ 2.5'; Note = "cairn=$($j.cairn_avg) raw=$($j.raw_avg) raters=$($j.raters)" })
} else {
    $results.Add([pscustomobject]@{ Id = 'M-07'; Title = '可讀性評分'; Status = 'PENDING'; Seconds = 0; Report = ''; Target = 'Cairn ≥ 4.0 且原始 ≤ 2.5'; Note = '人工盲測：New-ReadabilityQuiz.ps1 → -Mode Score' })
}
$tri = Get-ChildItem -Path $reports -Filter 'triage-*.csv' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$results.Add([pscustomobject]@{ Id = 'M-10'; Title = '分流時間'; Status = $(if ($tri) { 'SEE-REPORT' } else { 'PENDING' }); Seconds = 0; Report = $(if ($tri) { $tri.FullName } else { '' }); Target = '平均 ≤ 5 分鐘、正確率 ≥ 80%'; Note = $(if ($tri) { '見明細 CSV' } else { 'New-ReadabilityQuiz.ps1 -Mode Triage → -Mode TriageScore' }) })

$totalMin = [Math]::Round($swAll.Elapsed.TotalMinutes, 1)
$quick = @($results | Where-Object { $_.Id -in 'M-01', 'M-03', 'M-05', 'M-06' })
$quickFail = @($quick | Where-Object { $_.Status -in 'FAIL', 'MISSING' }).Count
$m09 = ($totalMin -le 30) -and ($quickFail -eq 0) -and (@($quick | Where-Object Status -eq 'SKIPPED').Count -eq 0)
$results.Add([pscustomobject]@{ Id = 'M-09'; Title = '端到端可重現性'; Status = $(if ($m09) { 'PASS' } else { 'FAIL' }); Seconds = [int]$swAll.Elapsed.TotalSeconds; Report = ''; Target = '30 分鐘內完成快測集'; Note = "總耗時 $totalMin 分鐘" })

$icon = @{ PASS = '✅ PASS'; FAIL = '❌ FAIL'; SKIPPED = '⏭ 略過'; PENDING = '⏳ 待回填'; MISSING = '❌ 缺腳本'; 'SEE-REPORT' = '📄 見報告' }
$table = ($results | Sort-Object Id | ForEach-Object {
        $rep = if ($_.Report) { "[$(Split-Path -Leaf $_.Report)]($($_.Report.Replace($repo + '\', '').Replace('\', '/')))" } else { '' }
        "| $($_.Id) | $($_.Title) | $($_.Target) | $($icon[$_.Status]) | $($_.Seconds) | $rep | $($_.Note) |"
    }) -join "`n"

$md = @"
# Cairn M0 驗收報告

- 產生時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；主機：$env:COMPUTERNAME；OS：$([Environment]::OSVersion.VersionString)
- 建置：$(try { (git -C $repo rev-parse --short HEAD) } catch { '（非 git 工作目錄）' })
- 快測集總耗時：$totalMin 分鐘（M-09 門檻 ≤ 30 分鐘）
- 執行紀錄：$($runDir.Replace($repo + '\', ''))

| 指標 | 項目 | 門檻 | 結果 | 耗時 s | 報表 | 備註 |
|---|---|---|---|---|---|---|
$table

> 量測環境須標註（part1 §4）：功能驗收 VM 為 Win11 23H2 / 4 vCPU / 8 GB / 純 CPU 推論；
> VM 上的效能絕對值不可與 part2 §2.8 的預算直接比較。
>
> M0 → M1 決策閘門（part1 §7）：G-1（M-07、M-10）、G-2（M-02）、G-3（M-01、M-03）。
"@
Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $runDir 'summary.json') -Encoding UTF8
Write-Host $md
Write-Host "報告：$OutputPath"
exit ([int]($quickFail -gt 0))
