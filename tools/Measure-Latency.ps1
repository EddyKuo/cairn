#Requires -Version 5.1
<#
.SYNOPSIS
    量測偵測延遲 MTTD（part1 M-03）、回應延遲 MTTR（part2 M0-P7）與 AI 敘事延遲（M-04 參考）。

.DESCRIPTION
    以唯讀方式查 cairn.db，對時窗內每則告警計算：
      MTTD = alerts.ts − 觸發事件時間（alert_events.role='trigger' 的 events.ts；
             無 trigger 列時取該告警所連結事件中最晚的 ts，即「攻擊鏈最後一步」）
      MTTR = 第一個回應動作完成時間（audit_log 中同 alert_id、result in ok/partial 的最早 ts）
             − 觸發事件時間（近似「分數達 80 → 動作完成」）
      AI   = alerts.ai_latency_ms（僅 ai_state='ok'）
    輸出 P50 / P95 / P99。

    門檻：MTTD P95 ≤ 5 秒（M-03 驗收門檻；≤ 3 秒為伸展目標）；MTTR P95 ≤ 5 秒（M0-P7）。
    MTTD 未達 → 離開碼 1。

.PARAMETER Since
    只計算此時間之後的告警（本機時間）。預設最近 24 小時。

.PARAMETER AlertId
    只計算指定告警（例如剛跑完 Run-AtomicSuite 的那幾則）。

.PARAMETER OutputPath
    報表路徑，預設 reports\latency-<時間>.md（同名 .json）。

.EXAMPLE
    .\tools\Measure-Latency.ps1 -Since (Get-Date).AddHours(-2)

.EXAMPLE
    .\tools\Measure-Latency.ps1 -AlertId 12,13,14
#>
[CmdletBinding()]
param(
    [datetime]$Since = (Get-Date).AddHours(-24),
    [long[]]$AlertId,
    [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

$repo = Get-CairnRepoRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repo ("reports\latency-{0:yyyyMMdd-HHmmss}.md" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null
$fromMs = Get-UnixMs -At $Since

$where = "a.ts >= $fromMs"
if ($AlertId) { $where = "a.id IN ($($AlertId -join ','))" }
$q = @"
SELECT a.id AS alert_id, a.ts AS alert_ts, a.score_at_trigger, a.ai_state, a.ai_latency_ms,
  (SELECT MAX(e.ts) FROM alert_events ae JOIN events e ON e.id = ae.event_id
     WHERE ae.alert_id = a.id AND ae.role = 'trigger') AS trigger_ts,
  (SELECT MAX(e.ts) FROM alert_events ae JOIN events e ON e.id = ae.event_id
     WHERE ae.alert_id = a.id) AS last_event_ts,
  (SELECT MIN(l.ts) FROM audit_log l
     WHERE l.alert_id = a.id AND l.result IN ('ok','partial')
       AND l.action IN ('suspend_process','terminate_process_tree','quarantine_file','firewall_block')) AS first_action_ts
FROM alerts a WHERE $where ORDER BY a.ts
"@
$rows = @(Invoke-CairnSql -Query $q)
if ($rows.Count -eq 0) { Write-Warning '時窗內沒有告警。'; exit 1 }

$items = foreach ($r in $rows) {
    $evTs = if ($null -ne $r.trigger_ts) { [long]$r.trigger_ts } elseif ($null -ne $r.last_event_ts) { [long]$r.last_event_ts } else { $null }
    [pscustomobject]@{
        AlertId  = $r.alert_id
        Score    = [double]$r.score_at_trigger / 1000
        MttdSec  = $(if ($null -ne $evTs) { ([long]$r.alert_ts - $evTs) / 1000.0 } else { $null })
        MttrSec  = $(if ($null -ne $evTs -and $null -ne $r.first_action_ts) { ([long]$r.first_action_ts - $evTs) / 1000.0 } else { $null })
        AiSec    = $(if ($r.ai_state -eq 'ok' -and $null -ne $r.ai_latency_ms) { [double]$r.ai_latency_ms / 1000 } else { $null })
        AiState  = $r.ai_state
    }
}
$items = @($items)

function Stat($vals) {
    $v = @($vals | Where-Object { $null -ne $_ } | ForEach-Object { [double]$_ })
    [pscustomobject]@{ N = $v.Count; P50 = (Get-Percentile $v 50); P95 = (Get-Percentile $v 95); P99 = (Get-Percentile $v 99) }
}
$mttd = Stat ($items | ForEach-Object MttdSec)
$mttr = Stat ($items | ForEach-Object MttrSec)
$ai   = Stat ($items | ForEach-Object AiSec)
$negative = @($items | Where-Object { $null -ne $_.MttdSec -and $_.MttdSec -lt 0 }).Count

$mttdPass = ($mttd.N -gt 0 -and $mttd.P95 -le 5)
$mttrPass = if ($mttr.N -gt 0) { $mttr.P95 -le 5 } else { $null }

function F($v) { if ($null -eq $v) { '—' } else { '{0:N2}' -f $v } }
$detail = ($items | ForEach-Object { "| $($_.AlertId) | $(F $_.Score) | $(F $_.MttdSec) | $(F $_.MttrSec) | $(F $_.AiSec) | $($_.AiState) |" }) -join "`n"
$md = @"
# Cairn 延遲量測（M-03 / M0-P7 / M-04）

- 時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；告警數：$($items.Count)；起點：$(if ($AlertId) { "指定 $($AlertId -join ',')" } else { $Since })

| 指標 | N | P50 (s) | P95 (s) | P99 (s) | 門檻 | 結果 |
|---|---|---|---|---|---|---|
| MTTD（觸發事件 → 告警） | $($mttd.N) | $(F $mttd.P50) | $(F $mttd.P95) | $(F $mttd.P99) | P95 ≤ 5（伸展 ≤ 3） | $(if ($mttdPass) { '✅' } else { '❌' }) |
| MTTR（觸發事件 → 首個動作完成） | $($mttr.N) | $(F $mttr.P50) | $(F $mttr.P95) | $(F $mttr.P99) | P95 ≤ 5 | $(if ($null -eq $mttrPass) { '—（無動作）' } elseif ($mttrPass) { '✅' } else { '❌' }) |
| AI 敘事延遲（ai_state=ok） | $($ai.N) | $(F $ai.P50) | $(F $ai.P95) | $(F $ai.P99) | P95 ≤ 20（CPU） | 參考 |

$(if ($negative -gt 0) { "> ⚠ $negative 則告警的 MTTD 為負值：events.ts（Sysmon UtcTime）與 alerts.ts（服務牆鐘）的時鐘來源不同或事件時間被竄改，請檢查。" })

## 明細

| alert | 分數 | MTTD s | MTTR s | AI s | ai_state |
|---|---|---|---|---|---|
$detail
"@
Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
[ordered]@{ mttd = $mttd; mttr = $mttr; ai = $ai; mttd_pass = $mttdPass; mttr_pass = $mttrPass; items = $items } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($OutputPath, '.json')) -Encoding UTF8
Write-Host $md
exit ([int](-not $mttdPass))
