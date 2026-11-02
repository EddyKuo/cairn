#Requires -Version 5.1
<#
.SYNOPSIS
    dry-run 誤報基準報表 → 建議排除清單（part4 §4.5.3、W4-4；part1 M-02）。

.DESCRIPTION
    讀取一或多台機器的 cairn.db（唯讀），彙整時窗內：
      - 每條規則的觸發次數排行（前 10 名即誤報主要來源），含 dry-run／抑制分項
      - 每次觸發的程序名、路徑、簽章者、命令列摘要（-Anonymize 時去識別化，R-13）
      - 分數 ≥ 80（score_at_trigger >= 80000）且非 true_positive 的告警數／機／天（M-02）
      - dry-run 影子告警（scores.shadow_score >= 80000）——「若啟用會產生幾則告警」
      - 依「簽章者」與「路徑前綴」聚類的建議排除清單（YAML，輸出到同目錄 *-exclusions.yaml）
      - 套用建議後的預估誤報率
      - 單一規則貢獻 > 30% 告警者標為「必須重寫或降分，不得靠排除清單硬壓」

    安全防呆：不對 Microsoft 簽章者產生全域排除（會讓 PowerShell 等 LOLBin 全部失明），
    此類一律限縮到單一規則並標示「高風險」；也不對 System32 / SysWOW64 路徑產生 path_glob。

    通過門檻：套用建議後 ≤ 3 則／機／天，且無任何規則貢獻 > 30% → 離開碼 0，否則 1。

.PARAMETER Days
    時窗天數，預設 7。

.PARAMETER DbPath
    一或多個 cairn.db 路徑（多台機器時從各機複製出來）。預設本機 %ProgramData%\Cairn\cairn.db。

.PARAMETER OutputPath
    報表路徑，預設 reports\fp-baseline.md。

.PARAMETER MinCluster
    聚類成為建議的最少命中數，預設 3。

.PARAMETER Anonymize
    報表中的使用者名稱與使用者目錄改為雜湊（對外分享前必加，R-13 ②）。

.EXAMPLE
    .\tools\Export-FpReport.ps1 -Days 7 -OutputPath .\reports\fp-baseline.md

.EXAMPLE
    .\tools\Export-FpReport.ps1 -DbPath .\dev.db, .\office.db, .\it.db -Anonymize
#>
[CmdletBinding()]
param(
    [int]$Days = 7,
    [string[]]$DbPath,
    [string]$OutputPath,
    [int]$MinCluster = 3,
    [switch]$Anonymize
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

$repo = Get-CairnRepoRoot
if (-not $DbPath) { $DbPath = @(Get-CairnDbPath) }
if (-not $OutputPath) { $OutputPath = Join-Path $repo 'reports\fp-baseline.md' }
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null
$fromMs = Get-UnixMs -At ([datetime]::UtcNow.AddDays(-$Days))
$machines = $DbPath.Count

function Hide-Pii([string]$s) {
    if (-not $Anonymize -or [string]::IsNullOrEmpty($s)) { return $s }
    $sha = [Security.Cryptography.SHA256]::Create()
    $s = [regex]::Replace($s, '(?i)(\\Users\\)([^\\]+)', {
            param($m)
            $h = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($m.Groups[2].Value.ToLower())) | Select-Object -First 4 | ForEach-Object { $_.ToString('x2') })
            "$($m.Groups[1].Value)user-$h"
        })
    return $s
}

function Get-Dir([string]$image) {
    if ([string]::IsNullOrEmpty($image)) { return $null }
    $i = $image.LastIndexOf('\')
    if ($i -le 0) { return $null }
    return $image.Substring(0, $i).ToLower()
}

function Convert-ToGlob([string]$dir) {
    # 把使用者名稱泛化：c:\users\alice\appdata\local\foo → c:\users\*\appdata\local\foo\*
    return ([regex]::Replace($dir, '(?i)^([a-z]:\\users\\)[^\\]+', '$1*')) + '\*'
}

$hitRank = @{}
$details = New-Object System.Collections.Generic.List[object]
$alertsFp = New-Object System.Collections.Generic.List[object]
$shadowAlerts = 0
$ruleAlertCount = @{}

foreach ($db in $DbPath) {
    Write-Host "讀取 $db"
    foreach ($r in Invoke-CairnSql -DbPath $db -Query "SELECT rule_id, COUNT(*) AS n, SUM(dryrun) AS dry, SUM(suppressed) AS sup FROM rule_hits WHERE ts >= $fromMs GROUP BY rule_id") {
        if (-not $hitRank.ContainsKey($r.rule_id)) { $hitRank[$r.rule_id] = [pscustomobject]@{ Rule = $r.rule_id; Hits = 0; DryRun = 0; Suppressed = 0 } }
        $hitRank[$r.rule_id].Hits += [int]$r.n; $hitRank[$r.rule_id].DryRun += [int]$r.dry; $hitRank[$r.rule_id].Suppressed += [int]$r.sup
    }
    $q = @"
SELECT h.rule_id, h.ts, h.dryrun,
       COALESCE(e.image, p.image) AS image,
       COALESCE(e.signature_signer, p.signature_signer) AS signer,
       COALESCE(e.signature_valid, p.signature_valid) AS sig_valid,
       substr(COALESCE(e.command_line, p.command_line), 1, 160) AS cmd,
       COALESCE(e.user_name, p.user_name) AS user_name
FROM rule_hits h
LEFT JOIN events e ON e.id = h.event_id
LEFT JOIN process_tree p ON p.process_guid = COALESCE(e.process_guid, h.root_process_guid)
WHERE h.ts >= $fromMs AND h.suppressed = 0
"@
    foreach ($d in Invoke-CairnSql -DbPath $db -Query $q) { $d | Add-Member -NotePropertyName Machine -NotePropertyValue $db; $details.Add($d) }

    $qa = @"
SELECT a.id, a.ts, a.score_at_trigger, a.rule_ids, a.analyst_verdict,
       COALESCE(p.image, r.image) AS image, COALESCE(p.signature_signer, r.signature_signer) AS signer
FROM alerts a
LEFT JOIN process_tree p ON p.process_guid = a.trigger_process_guid
LEFT JOIN process_tree r ON r.process_guid = a.root_process_guid
WHERE a.ts >= $fromMs AND a.score_at_trigger >= 80000
  AND (a.analyst_verdict IS NULL OR a.analyst_verdict != 'true_positive')
"@
    foreach ($a in Invoke-CairnSql -DbPath $db -Query $qa) {
        $alertsFp.Add($a)
        foreach ($rid in @($a.rule_ids | ConvertFrom-Json)) {
            if (-not $ruleAlertCount.ContainsKey($rid)) { $ruleAlertCount[$rid] = 0 }
            $ruleAlertCount[$rid]++
        }
    }
    $shadowAlerts += [int](Get-CairnScalar -DbPath $db -Query "SELECT COUNT(*) FROM scores WHERE last_update_ts >= $fromMs AND shadow_score >= 80000 AND score < 80000")
}

# ------------------------------------------------------------
# 聚類 → 建議排除
# ------------------------------------------------------------
$suggestions = New-Object System.Collections.Generic.List[object]
$bySigner = $details | Where-Object { $_.sig_valid -eq 1 -and $_.signer } | Group-Object signer
foreach ($g in $bySigner) {
    if ($g.Count -lt $MinCluster) { continue }
    $rules = @($g.Group | ForEach-Object rule_id | Select-Object -Unique)
    $isMs = $g.Name -match '(?i)^Microsoft'
    if ($isMs) {
        foreach ($rid in $rules) {
            $n = @($g.Group | Where-Object rule_id -eq $rid).Count
            if ($n -lt $MinCluster) { continue }
            $suggestions.Add([pscustomobject]@{ Kind = 'signer'; Value = $g.Name; Scope = $rid; Hits = $n; Risk = 'HIGH'; Rationale = "Microsoft 簽章者僅限縮至 $rid（全域排除會讓 LOLBin 偵測失明）" })
        }
    } else {
        $scope = if ($rules.Count -eq 1) { $rules[0] } else { '' }
        $suggestions.Add([pscustomobject]@{ Kind = 'signer'; Value = $g.Name; Scope = $scope; Hits = $g.Count; Risk = 'normal'; Rationale = "有效簽章者 $($g.Name) 觸發 $($g.Count) 次，涉及規則：$($rules -join ', ')" })
    }
}
$signedCovered = @($suggestions | ForEach-Object Value)
$byDir = $details | Where-Object { $_.image -and -not ($_.sig_valid -eq 1 -and $signedCovered -contains $_.signer) } |
    Group-Object { Convert-ToGlob (Get-Dir $_.image) }
foreach ($g in $byDir) {
    if ($g.Count -lt $MinCluster -or -not $g.Name -or $g.Name -eq '\*') { continue }
    if ($g.Name -match '(?i)\\windows\\(system32|syswow64)') { continue }
    $rules = @($g.Group | ForEach-Object rule_id | Select-Object -Unique)
    $scope = if ($rules.Count -eq 1) { $rules[0] } else { '' }
    $suggestions.Add([pscustomobject]@{ Kind = 'path_glob'; Value = $g.Name; Scope = $scope; Hits = $g.Count; Risk = $(if ($g.Name -match '(?i)\\(temp|downloads|appdata\\local\\temp)\\') { 'HIGH' } else { 'normal' }); Rationale = "路徑前綴觸發 $($g.Count) 次（未簽章或簽章無效），涉及規則：$($rules -join ', ')" })
}

function Test-Suppressed($image, $signer, $rules) {
    foreach ($s in $suggestions) {
        if ($s.Scope -and -not ($rules -contains $s.Scope)) { continue }
        if ($s.Kind -eq 'signer' -and $signer -and $signer -eq $s.Value) { return $true }
        if ($s.Kind -eq 'path_glob' -and $image -and ($image.ToLower() -like $s.Value)) { return $true }
    }
    return $false
}

$fpBefore = $alertsFp.Count
$fpAfter = @($alertsFp | Where-Object { -not (Test-Suppressed $_.image $_.signer @($_.rule_ids | ConvertFrom-Json)) }).Count
$perDayBefore = [Math]::Round($fpBefore / [Math]::Max(1, $Days) / [Math]::Max(1, $machines), 2)
$perDayAfter  = [Math]::Round($fpAfter  / [Math]::Max(1, $Days) / [Math]::Max(1, $machines), 2)
$dominant = @($ruleAlertCount.GetEnumerator() | Where-Object { $fpBefore -gt 0 -and ($_.Value / $fpBefore) -gt 0.30 } | ForEach-Object { [pscustomobject]@{ Rule = $_.Key; Share = $_.Value / $fpBefore } })
$pass = ($perDayAfter -le 3) -and ($dominant.Count -eq 0)

# ------------------------------------------------------------
# 輸出
# ------------------------------------------------------------
$yamlPath = [IO.Path]::ChangeExtension($OutputPath, $null).TrimEnd('.') + '-exclusions.yaml'
$yaml = New-Object System.Text.StringBuilder
[void]$yaml.AppendLine("# Export-FpReport.ps1 產生的建議排除清單（$(Get-Date -Format 'yyyy-MM-dd')；時窗 $Days 天；$machines 台）")
[void]$yaml.AppendLine('# ⚠ 套用前逐條審閱；Risk=HIGH 者預設不建議套用。格式需對齊 rules/exclusions.default.yaml。')
[void]$yaml.AppendLine('exclusions:')
foreach ($s in ($suggestions | Sort-Object Hits -Descending)) {
    [void]$yaml.AppendLine("  - kind: $($s.Kind)")
    [void]$yaml.AppendLine("    value: '$($s.Value.Replace("'", "''"))'")
    [void]$yaml.AppendLine("    scope_rule_id: '$($s.Scope)'")
    [void]$yaml.AppendLine("    reason: '$(($s.Rationale).Replace("'", "''")) [hits=$($s.Hits) risk=$($s.Risk)]'")
    [void]$yaml.AppendLine('    created_by: learning_mode')
}
Set-Content -LiteralPath $yamlPath -Value $yaml.ToString() -Encoding UTF8

$top = $hitRank.Values | Sort-Object Hits -Descending | Select-Object -First 10
$topTable = ($top | ForEach-Object { "| $($_.Rule) | $($_.Hits) | $($_.DryRun) | $($_.Suppressed) | $(if ($ruleAlertCount.ContainsKey($_.Rule)) { $ruleAlertCount[$_.Rule] } else { 0 }) |" }) -join "`n"
$sampleTable = ($details | Sort-Object ts -Descending | Select-Object -First 50 | ForEach-Object {
        "| $($_.rule_id) | $(ConvertFrom-UnixMs ([long]$_.ts)) | $(Hide-Pii (Split-Path -Leaf ([string]$_.image))) | $(Hide-Pii ([string]$_.image)) | $($_.signer) | $((Hide-Pii ([string]$_.cmd)) -replace '\|','\|') |"
    }) -join "`n"
$sugTable = ($suggestions | Sort-Object Hits -Descending | ForEach-Object { "| $($_.Kind) | ``$(Hide-Pii $_.Value)`` | $(if ($_.Scope) { $_.Scope } else { '（全域）' }) | $($_.Hits) | $($_.Risk) |" }) -join "`n"
$domText = if ($dominant.Count) { ($dominant | ForEach-Object { "- **$($_.Rule)** 佔 $('{0:P0}' -f $_.Share) → 必須重寫或降分，不得靠排除清單硬壓" }) -join "`n" } else { '- 無' }

$md = @"
# Cairn 誤報基準報表（M-02）

- 產生時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；時窗：$Days 天；機器數：$machines；去識別化：$([bool]$Anonymize)
- 判定：**$(if ($pass) { 'PASS' } else { 'FAIL' })**（門檻：套用建議後 ≤ 3 則／機／天，且無單一規則 > 30%）

## 摘要

| 指標 | 值 |
|---|---|
| 分數 ≥ 80 且非真陽性告警（套用前） | $fpBefore（$perDayBefore 則／機／天） |
| 套用建議排除後（預估） | $fpAfter（$perDayAfter 則／機／天） |
| dry-run 影子告警（shadow ≥ 80 而 score < 80） | $shadowAlerts |

## 規則觸發排行（前 10）

| 規則 | 命中 | 其中 dry-run | 其中被抑制 | 構成誤報告警數 |
|---|---|---|---|---|
$topTable

## 主導規則（> 30% 告警）

$domText

## 建議排除（完整 YAML：$(Split-Path -Leaf $yamlPath)）

| kind | value | scope | 命中 | 風險 |
|---|---|---|---|---|
$sugTable

## 觸發樣本（最近 50 筆）

| 規則 | 時間 (UTC) | 程序 | 路徑 | 簽章者 | 命令列摘要 |
|---|---|---|---|---|---|
$sampleTable
"@
Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
[ordered]@{ days = $Days; machines = $machines; fp_before = $fpBefore; fp_after = $fpAfter; per_machine_day_before = $perDayBefore; per_machine_day_after = $perDayAfter; shadow_alerts = $shadowAlerts; dominant_rules = $dominant; suggestions = $suggestions; pass = $pass } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($OutputPath, '.json')) -Encoding UTF8
Write-Host "報表：$OutputPath"
Write-Host "建議排除：$yamlPath"
Write-Host ("誤報：{0} → {1} 則／機／天；判定 {2}" -f $perDayBefore, $perDayAfter, $(if ($pass) { 'PASS' } else { 'FAIL' }))
exit ([int](-not $pass))
