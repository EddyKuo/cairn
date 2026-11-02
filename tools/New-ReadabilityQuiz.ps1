#Requires -Version 5.1
<#
.SYNOPSIS
    產生可讀性盲測問卷（part1 M-07）與分流計時問卷（M-10），並計算結果。

.DESCRIPTION
    -Mode Generate（預設）：從 cairn.db 取 10 則告警，輸出到 -OutDir：
        raw-sysmon.txt    對照組：同一批告警的原始 Sysmon 事件（優先從事件記錄取原始 XML，
                          取不到時以 DB 欄位重建成「事件檢視器一般頁籤」格式）
        cairn-alerts.md   實驗組：Cairn 告警（標題、摘要、分數、程序鏈、AI 敘事＋免責標示）
        scores.csv        評分表範本（rater,item,format,score；score 為 1–5，題目：「這則告警讓我知道該做什麼」）
        answer-key.json   題號 ↔ alert_id 對照（只給主持人，勿給受測者）
      兩份檔案的題號各自隨機排序，避免受測者對照。
    -Mode Score：讀回填好的 scores.csv，計算平均。門檻：cairn ≥ 4.0 且 raw ≤ 2.5（≥ 5 位受測者）。
    -Mode Triage：產生 M-10 分流計時表 triage-sheet.csv（rater,item,start,end,verdict）。
    -Mode TriageScore：讀回 triage-sheet.csv，計算平均分流時間與判定正確率
        （標準答案取 alerts.analyst_verdict，或以 -AnswerKey 指定 CSV：item,verdict）。
        門檻：平均 ≤ 5 分鐘、正確率 ≥ 80%。結果寫入 reports\triage-<日期>.csv。

.PARAMETER Mode
    Generate / Score / Triage / TriageScore。

.PARAMETER AlertId
    指定告警 id；省略時取最近 -Count 則分數 ≥ 80 的告警。

.PARAMETER Count
    題數，預設 10。

.PARAMETER OutDir
    問卷輸出目錄，預設 reports\quiz-<日期>。

.PARAMETER AnswerKey
    TriageScore 用的標準答案 CSV（item,verdict）。

.EXAMPLE
    .\tools\New-ReadabilityQuiz.ps1

.EXAMPLE
    .\tools\New-ReadabilityQuiz.ps1 -Mode Score -OutDir .\reports\quiz-20261102

.EXAMPLE
    .\tools\New-ReadabilityQuiz.ps1 -Mode Triage
#>
[CmdletBinding()]
param(
    [ValidateSet('Generate', 'Score', 'Triage', 'TriageScore')][string]$Mode = 'Generate',
    [long[]]$AlertId,
    [int]$Count = 10,
    [string]$OutDir,
    [string]$AnswerKey
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

$repo = Get-CairnRepoRoot
if (-not $OutDir) { $OutDir = Join-Path $repo ("reports\quiz-{0:yyyyMMdd}" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-QuizAlerts {
    if ($AlertId) { $w = "id IN ($($AlertId -join ','))" } else { $w = 'score_at_trigger >= 80000' }
    return @(Invoke-CairnSql -Query "SELECT id, ts, severity, score_at_trigger, rule_ids, attack_ids, title, summary, root_process_guid, ai_state, ai_narrative, ai_recommendation, ai_model_id, analyst_verdict FROM alerts WHERE $w ORDER BY ts DESC LIMIT $Count")
}

function Get-AlertEvents([long]$Id) {
    return @(Invoke-CairnSql -Query @"
SELECT e.ts, e.source_event_id, e.event_type, e.process_guid, e.pid, e.image, e.command_line, e.parent_image,
       e.user_name, e.target_image, e.target_filename, e.registry_path, e.registry_details, e.dest_ip, e.dest_port,
       e.query_name, e.script_block, e.raw_json
FROM alert_events ae JOIN events e ON e.id = ae.event_id WHERE ae.alert_id = $Id ORDER BY e.ts
"@)
}

function Get-RawSysmonText($ev) {
    # 1) 嘗試從 Sysmon 事件記錄取回原始 XML（時間 ±1 秒、同 EventID）
    $t = ConvertFrom-UnixMs ([long]$ev.ts)
    try {
        $log = if ([int]$ev.source_event_id -eq 4104) { 'Microsoft-Windows-PowerShell/Operational' } else { 'Microsoft-Windows-Sysmon/Operational' }
        $cands = Get-WinEvent -FilterHashtable @{ LogName = $log; Id = [int]$ev.source_event_id; StartTime = $t.ToLocalTime().AddSeconds(-1); EndTime = $t.ToLocalTime().AddSeconds(1) } -ErrorAction Stop
        foreach ($c in $cands) {
            $x = $c.ToXml()
            if (-not $ev.process_guid -or $x -match [regex]::Escape($ev.process_guid.Trim('{}'))) { return $x }
        }
    } catch { }
    # 2) 退回：raw_json 或 DB 欄位重建
    if ($ev.raw_json) { return $ev.raw_json }
    $lines = @("Event ID: $($ev.source_event_id)", "UtcTime: $($t.ToString('yyyy-MM-dd HH:mm:ss.fff'))")
    foreach ($f in 'process_guid', 'pid', 'image', 'command_line', 'parent_image', 'user_name', 'target_image', 'target_filename', 'registry_path', 'registry_details', 'dest_ip', 'dest_port', 'query_name', 'script_block') {
        if ($null -ne $ev.$f -and "$($ev.$f)" -ne '') { $lines += "$($f): $($ev.$f)" }
    }
    return ($lines -join "`r`n")
}

function Get-Chain([string]$Root) {
    $r = ConvertTo-SqlString $Root
    return @(Invoke-CairnSql -Query "SELECT depth, image, command_line, signature_signer, signature_valid FROM process_tree WHERE root_process_guid = $r ORDER BY depth, start_ts LIMIT 12")
}

switch ($Mode) {
    'Generate' {
        $alerts = Get-QuizAlerts
        if ($alerts.Count -eq 0) { throw '找不到符合條件的告警（需要分數 ≥ 80 的告警，或以 -AlertId 指定）' }
        $rawOrder   = $alerts | Sort-Object { Get-Random }
        $cairnOrder = $alerts | Sort-Object { Get-Random }
        $key = [ordered]@{ raw = [ordered]@{}; cairn = [ordered]@{} }

        $raw = New-Object System.Text.StringBuilder
        [void]$raw.AppendLine('# 對照組：原始 Sysmon 事件。每一題請回答「這則告警讓我知道該做什麼」1（完全不知道）～ 5（非常清楚）。')
        $i = 0
        foreach ($a in $rawOrder) {
            $i++; $code = 'R{0:D2}' -f $i; $key.raw[$code] = $a.id
            [void]$raw.AppendLine(''); [void]$raw.AppendLine("================ 題 $code ================")
            foreach ($ev in Get-AlertEvents $a.id) { [void]$raw.AppendLine((Get-RawSysmonText $ev)); [void]$raw.AppendLine('---') }
        }
        Set-Content -LiteralPath (Join-Path $OutDir 'raw-sysmon.txt') -Value $raw.ToString() -Encoding UTF8

        $md = New-Object System.Text.StringBuilder
        [void]$md.AppendLine('# 實驗組：Cairn 告警'); [void]$md.AppendLine('每一題請回答「這則告警讓我知道該做什麼」1～5 分。')
        $i = 0
        foreach ($a in $cairnOrder) {
            $i++; $code = 'C{0:D2}' -f $i; $key.cairn[$code] = $a.id
            [void]$md.AppendLine(''); [void]$md.AppendLine("## 題 $code — $($a.title)")
            [void]$md.AppendLine("- 嚴重度：$($a.severity)　風險分數：$([Math]::Round([double]$a.score_at_trigger / 1000))")
            [void]$md.AppendLine("- 命中規則：$(@($a.rule_ids | ConvertFrom-Json) -join ', ')　ATT&CK：$(if ($a.attack_ids) { @($a.attack_ids | ConvertFrom-Json) -join ', ' })")
            [void]$md.AppendLine("- 摘要：$($a.summary)")
            [void]$md.AppendLine(''); [void]$md.AppendLine('**程序鏈**'); [void]$md.AppendLine('')
            foreach ($n in Get-Chain $a.root_process_guid) {
                $sig = if ($n.signature_valid -eq 1) { "已簽章：$($n.signature_signer)" } else { '未簽章／簽章無效' }
                [void]$md.AppendLine(("{0}- ``{1}``（{2}）" -f ('  ' * [int]$n.depth), $n.image, $sig))
            }
            [void]$md.AppendLine('')
            if ($a.ai_state -eq 'ok' -and $a.ai_narrative) {
                [void]$md.AppendLine("> ⚠ AI 生成，僅供參考 · 模型 $($a.ai_model_id)")
                [void]$md.AppendLine(''); [void]$md.AppendLine("**AI 敘事**：$($a.ai_narrative)")
                [void]$md.AppendLine(''); [void]$md.AppendLine("**處置建議**：$($a.ai_recommendation)")
            } else {
                [void]$md.AppendLine("> AI 敘事狀態：$($a.ai_state)（僅規則摘要）")
            }
        }
        Set-Content -LiteralPath (Join-Path $OutDir 'cairn-alerts.md') -Value $md.ToString() -Encoding UTF8

        $csv = @('rater,item,format,score')
        foreach ($k in $key.raw.Keys) { $csv += "rater1,$k,raw," }
        foreach ($k in $key.cairn.Keys) { $csv += "rater1,$k,cairn," }
        Set-Content -LiteralPath (Join-Path $OutDir 'scores.csv') -Value $csv -Encoding UTF8
        $key | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'answer-key.json') -Encoding UTF8
        Write-Host "問卷已輸出到 $OutDir（answer-key.json 僅限主持人）"
        Write-Host '每位受測者複製 scores.csv 中的列並把 rater1 改成自己的代號；回收後執行 -Mode Score。'
        exit 0
    }
    'Score' {
        $rows = @(Import-Csv -LiteralPath (Join-Path $OutDir 'scores.csv') | Where-Object { $_.score -match '^\d' })
        if ($rows.Count -eq 0) { throw 'scores.csv 沒有已填分數的列' }
        $raters = @($rows | ForEach-Object rater | Select-Object -Unique).Count
        $rawAvg   = ($rows | Where-Object format -eq 'raw'   | ForEach-Object { [double]$_.score } | Measure-Object -Average).Average
        $cairnAvg = ($rows | Where-Object format -eq 'cairn' | ForEach-Object { [double]$_.score } | Measure-Object -Average).Average
        $pass = ($raters -ge 5) -and ($cairnAvg -ge 4.0) -and ($rawAvg -le 2.5)
        $out = "M-07 可讀性：受測者 $raters 位；Cairn 平均 $('{0:N2}' -f $cairnAvg)（門檻 ≥ 4.0）；原始 Sysmon 平均 $('{0:N2}' -f $rawAvg)（門檻 ≤ 2.5）；判定 $(if ($pass) { 'PASS' } else { 'FAIL' })"
        Write-Host $out
        Set-Content -LiteralPath (Join-Path $OutDir 'm07-result.txt') -Value $out -Encoding UTF8
        [ordered]@{ raters = $raters; cairn_avg = $cairnAvg; raw_avg = $rawAvg; pass = $pass } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutDir 'm07-result.json') -Encoding UTF8
        exit ([int](-not $pass))
    }
    'Triage' {
        $alerts = Get-QuizAlerts
        $key = [ordered]@{}
        $sheet = @('rater,item,start,end,verdict')
        $i = 0
        foreach ($a in ($alerts | Sort-Object { Get-Random })) {
            $i++; $code = 'T{0:D2}' -f $i; $key[$code] = $a.id
            $sheet += "rater1,$code,,,"
        }
        Set-Content -LiteralPath (Join-Path $OutDir 'triage-sheet.csv') -Value $sheet -Encoding UTF8
        $key | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutDir 'triage-key.json') -Encoding UTF8
        Write-Host "分流表：$(Join-Path $OutDir 'triage-sheet.csv')。start/end 填 HH:mm:ss，verdict 填 true_positive / false_positive / benign。"
        Write-Host '題號對應的告警請以 CairnConsole 開啟（triage-key.json 僅限主持人）。'
        exit 0
    }
    'TriageScore' {
        $key = Get-Content -LiteralPath (Join-Path $OutDir 'triage-key.json') -Raw | ConvertFrom-Json
        $truth = @{}
        if ($AnswerKey) {
            foreach ($r in Import-Csv -LiteralPath $AnswerKey) { $truth[$r.item] = $r.verdict }
        } else {
            foreach ($p in $key.PSObject.Properties) {
                $v = Get-CairnScalar -Query "SELECT analyst_verdict FROM alerts WHERE id = $([long]$p.Value)"
                if ($v) { $truth[$p.Name] = $v }
            }
        }
        $rows = @(Import-Csv -LiteralPath (Join-Path $OutDir 'triage-sheet.csv') | Where-Object { $_.start -and $_.end -and $_.verdict })
        if ($rows.Count -eq 0) { throw 'triage-sheet.csv 沒有已填寫的列' }
        $res = foreach ($r in $rows) {
            $mins = ([datetime]::ParseExact($r.end, 'HH:mm:ss', $null) - [datetime]::ParseExact($r.start, 'HH:mm:ss', $null)).TotalMinutes
            [pscustomobject]@{ rater = $r.rater; item = $r.item; minutes = [Math]::Round($mins, 2); verdict = $r.verdict; truth = $truth[$r.item]; correct = ($truth.ContainsKey($r.item) -and $truth[$r.item] -eq $r.verdict) }
        }
        $res = @($res)
        $avg = ($res | Measure-Object minutes -Average).Average
        $judged = @($res | Where-Object { $null -ne $_.truth })
        $acc = if ($judged.Count) { @($judged | Where-Object correct).Count / $judged.Count } else { 0 }
        $raters = @($res | ForEach-Object rater | Select-Object -Unique).Count
        $pass = ($raters -ge 5) -and ($avg -le 5) -and ($acc -ge 0.8)
        $outCsv = Join-Path $repo ("reports\triage-{0:yyyyMMdd}.csv" -f (Get-Date))
        $res | Export-Csv -LiteralPath $outCsv -NoTypeInformation -Encoding UTF8
        Write-Host ("M-10 分流：受測者 {0} 位；平均 {1:N2} 分鐘（≤ 5）；正確率 {2:P0}（≥ 80%，有標準答案 {3} 題）；判定 {4}" -f $raters, $avg, $acc, $judged.Count, $(if ($pass) { 'PASS' } else { 'FAIL' }))
        Write-Host "明細：$outCsv"
        exit ([int](-not $pass))
    }
}
