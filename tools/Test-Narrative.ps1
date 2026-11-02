<#
.SYNOPSIS
    LLM 敘事層驗證：schema 合規率（part1 M-05）與敘事延遲（part1 M-04）。W3 出場條件 3。

.DESCRIPTION
    經 Named Pipe JSON-RPC（tools\Invoke-Rpc.ps1）對既有告警逐一呼叫 narrative.regenerate，
    再以 narrative.get 輪詢至終局狀態，統計：
      -Schema  ：合規率 = ready / (ready + SCHEMA_VIOLATION)，門檻 >= 99%；
                 attack_ids 全數符合 ^T\d{4}(\.\d{3})?$ 且（若提供 -AttackCatalog）全在白名單內，門檻 100%
      -Latency ：provenance.duration_ms（= alerts.ai_latency_ms）的 P95，門檻 <= 20000 ms（CPU；GPU 用 -LatencyBudgetMs 8000）
                 並斷言 ai_state='pending' 期間 alerts.get 已可查得該告警（敘事不阻塞告警呈現）
    兩個開關都未指定時兩者都跑。
    告警數不足 -Count 時循環重跑（M-05 的「20 則歷史告警各重跑 5 次」即 -Count 100 搭配 20 則告警）。

    ★ 本工具只讀寫 ai_* 欄位；另行比對 score_at_trigger / rule_ids 於重跑前後不變（LLM 不參與計分的旁證）。

.PARAMETER Count
    推論次數（預設 100）。

.EXAMPLE
    .\tools\Test-Narrative.ps1 -Count 100
    .\tools\Test-Narrative.ps1 -Latency -Count 20 -LatencyBudgetMs 8000
#>
[CmdletBinding()]
param(
    [int]$Count = 100,
    [switch]$Schema,
    [switch]$Latency,
    [ValidateSet('same', 'reduced_context')][string]$Mode = 'same',
    [int]$PollTimeoutSec = 120,
    [int]$LatencyBudgetMs = 20000,
    [double]$SchemaThreshold = 0.99,
    [string]$AttackCatalog = '',          # attack-techniques.json（陣列或 {techniques:[...]}）；空 = 只檢查格式
    [int]$MaxAlerts = 20,
    [string]$OutDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'reports')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $Schema -and -not $Latency) { $Schema = $true; $Latency = $true }

$InvokeRpc = Join-Path $PSScriptRoot 'Invoke-Rpc.ps1'
if (-not (Test-Path $InvokeRpc)) { throw "找不到 $InvokeRpc（W2-15 交付物）" }

function Invoke-CairnRpc([string]$Method, [hashtable]$Params = @{}) {
    & $InvokeRpc -Method $Method -Params $Params
}

# 依序嘗試多個欄位名（RPC 形狀以 part3 §3.8 為準，此處容忍 snake/camel 差異）
function Get-Field($Obj, [string[]]$Names) {
    if ($null -eq $Obj) { return $null }
    foreach ($n in $Names) {
        $p = $Obj.PSObject.Properties[$n]
        if ($p) { return $p.Value }
    }
    return $null
}

function Get-Percentile([double[]]$Values, [double]$P) {
    if ($Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $idx = [Math]::Ceiling($P / 100.0 * $sorted.Count) - 1
    if ($idx -lt 0) { $idx = 0 }
    return [double]$sorted[[int]$idx]
}

# ---- ATT&CK 白名單 ----
$attackPattern = '^T\d{4}(\.\d{3})?$'
$catalog = $null
if ($AttackCatalog) {
    $raw = Get-Content -Raw -Encoding UTF8 $AttackCatalog | ConvertFrom-Json
    $ids = if ($raw -is [array]) { $raw } else { $raw.techniques }
    $catalog = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($i in $ids) { [void]$catalog.Add([string]$i) }
    Write-Host "已載入 ATT&CK 白名單 $($catalog.Count) 項"
}

# ---- 前置：LLM 必須可用 ----
$health = Invoke-CairnRpc 'health.get'
$llm = Get-Field $health @('llm')
$llmState = Get-Field $llm @('state')
Write-Host "LLM 狀態：$llmState  模型：$(Get-Field $llm @('model_id'))"
if ($llmState -eq 'unavailable') {
    Write-Warning '本機 AI 不可用（模型未下載或已達重啟上限）。此結果不代表 schema 合規率，結束為 inconclusive。'
    exit 2
}

# ---- 取得告警清單 ----
$alerts = @()
$cursor = $null
do {
    $p = @{ limit = 50; sort = 'time_desc' }
    if ($cursor) { $p.cursor = $cursor }
    $page = Invoke-CairnRpc 'alerts.list' $p
    $items = Get-Field $page @('items', 'alerts')
    if ($items) { $alerts += @($items) }
    $cursor = Get-Field $page @('next_cursor', 'nextCursor')
} while ($cursor -and $alerts.Count -lt $MaxAlerts)
$alerts = @($alerts | Select-Object -First $MaxAlerts)
if ($alerts.Count -eq 0) {
    Write-Warning '沒有任何歷史告警可供重跑。請先執行 Run-AtomicSuite.ps1 或 W2 出場條件 2 產生告警。'
    exit 2
}
Write-Host "使用 $($alerts.Count) 則告警，共 $Count 次推論（模式 $Mode）"

# ---- 逐次推論 ----
$results = New-Object System.Collections.Generic.List[object]
for ($n = 0; $n -lt $Count; $n++) {
    $a = $alerts[$n % $alerts.Count]
    $alertId = Get-Field $a @('alert_id', 'id')
    $before = Invoke-CairnRpc 'alerts.get' @{ alert_id = $alertId }
    $scoreBefore = Get-Field $before @('risk_score', 'score_at_trigger')

    $null = Invoke-CairnRpc 'narrative.regenerate' @{ alert_id = $alertId; mode = $Mode }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $state = 'pending'
    $nar = $null
    $visibleWhilePending = $null
    while ($sw.Elapsed.TotalSeconds -lt $PollTimeoutSec) {
        Start-Sleep -Milliseconds 1000
        $nar = Invoke-CairnRpc 'narrative.get' @{ alert_id = $alertId }
        $state = Get-Field $nar @('state')
        if ($state -eq 'pending') {
            if ($null -eq $visibleWhilePending) {
                try { $null = Invoke-CairnRpc 'alerts.get' @{ alert_id = $alertId }; $visibleWhilePending = $true }
                catch { $visibleWhilePending = $false }
            }
            continue
        }
        break
    }
    $sw.Stop()

    $err = Get-Field $nar @('error')
    $errCode = Get-Field $err @('code')
    $prov = Get-Field $nar @('provenance')
    $durMs = Get-Field $prov @('duration_ms')
    if ($null -eq $durMs) { $durMs = [int]$sw.Elapsed.TotalMilliseconds }
    $mapping = @(Get-Field $nar @('attack_mapping'))
    $attackIds = @($mapping | Where-Object { $_ } | ForEach-Object { Get-Field $_ @('id') })
    $badFormat = @($attackIds | Where-Object { $_ -notmatch $attackPattern })
    $notInCatalog = if ($catalog) { @($attackIds | Where-Object { -not $catalog.Contains([string]$_) }) } else { @() }

    $after = Invoke-CairnRpc 'alerts.get' @{ alert_id = $alertId }
    $scoreAfter = Get-Field $after @('risk_score', 'score_at_trigger')

    $r = [pscustomobject]@{
        run = $n + 1; alert_id = $alertId; state = $state; error_code = $errCode
        duration_ms = [int]$durMs; attack_ids = ($attackIds -join ',')
        bad_format = $badFormat.Count; not_in_catalog = $notInCatalog.Count
        visible_while_pending = $visibleWhilePending
        score_unchanged = ("$scoreBefore" -eq "$scoreAfter")
    }
    $results.Add($r)
    Write-Host ("[{0,3}/{1}] alert {2,-24} {3,-8} {4,-18} {5,6} ms  {6}" -f ($n + 1), $Count, $alertId, $state, $errCode, $r.duration_ms, $r.attack_ids)
}

# ---- 統計 ----
$ready = @($results | Where-Object { $_.state -eq 'ready' })
$schemaFail = @($results | Where-Object { $_.error_code -eq 'SCHEMA_VIOLATION' })
$timeouts = @($results | Where-Object { $_.state -eq 'timeout' -or $_.state -eq 'pending' })
$unavail = @($results | Where-Object { $_.error_code -eq 'LLM_UNAVAILABLE' })
$queueFull = @($results | Where-Object { $_.error_code -eq 'QUEUE_FULL' })
$scoreChanged = @($results | Where-Object { -not $_.score_unchanged })

$pass = $true
$summary = [ordered]@{
    generated_at = (Get-Date).ToString('o'); count = $Count; alerts_used = $alerts.Count; mode = $Mode
    ready = $ready.Count; schema_violation = $schemaFail.Count; timeout = $timeouts.Count
    unavailable = $unavail.Count; queue_full = $queueFull.Count
    score_changed_after_regenerate = $scoreChanged.Count
}

if ($scoreChanged.Count -gt 0) {
    Write-Host "✗ 架構紅線：$($scoreChanged.Count) 次重跑敘事後 risk_score 改變（LLM 不得影響分數）" -ForegroundColor Red
    $pass = $false
}

if ($Schema) {
    $den = $ready.Count + $schemaFail.Count
    $rate = if ($den -gt 0) { $ready.Count / $den } else { 0 }
    $badIds = 0
    foreach ($x in $ready) { $badIds += [int]$x.bad_format + [int]$x.not_in_catalog }
    $summary.schema_compliance = [Math]::Round($rate, 4)
    $summary.attack_id_whitelist_violations = $badIds
    $ok = ($den -gt 0) -and ($rate -ge $SchemaThreshold) -and ($badIds -eq 0)
    Write-Host ("M-05 schema 合規率 {0:P2}（門檻 {1:P0}，分母 {2}）；ATT&CK 白名單違規 {3}  → {4}" -f $rate, $SchemaThreshold, $den, $badIds, $(if ($ok) { 'PASS' } else { 'FAIL' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if ($unavail.Count -gt 0) { Write-Warning "$($unavail.Count) 次為 LLM_UNAVAILABLE（不計入分母，但代表子程序不穩定）" }
    if (-not $ok) { $pass = $false }
}

if ($Latency) {
    $lat = [double[]]@($ready | ForEach-Object { [double]$_.duration_ms })
    $p50 = Get-Percentile $lat 50
    $p95 = Get-Percentile $lat 95
    $notVisible = @($results | Where-Object { $_.visible_while_pending -eq $false })
    $summary.latency_p50_ms = $p50
    $summary.latency_p95_ms = $p95
    $summary.alert_not_visible_while_pending = $notVisible.Count
    $ok = ($null -ne $p95) -and ($p95 -le $LatencyBudgetMs) -and ($notVisible.Count -eq 0)
    Write-Host ("M-04 敘事延遲 P50 {0} ms / P95 {1} ms（門檻 {2} ms）；pending 期間告警不可見 {3} 次 → {4}" -f $p50, $p95, $LatencyBudgetMs, $notVisible.Count, $(if ($ok) { 'PASS' } else { 'FAIL' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    if (-not $ok) { $pass = $false }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$outFile = Join-Path $OutDir ("narrative-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
[ordered]@{ summary = $summary; runs = $results } | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $outFile
Write-Host "報告：$outFile"

if ($pass) { exit 0 } else { exit 1 }
