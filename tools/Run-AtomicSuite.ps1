#Requires -Version 5.1
<#
.SYNOPSIS
    自動執行 part4 §4.5.2 的 Atomic Red Team 驗證矩陣並產出覆蓋率報表與 Go/No-Go 判定（W4-1；part1 M-01）。

.DESCRIPTION
    ⚠⚠ 本腳本會真的執行攻擊技術。只能在「可還原快照的隔離 VM」中執行，
       絕不可在開發機或生產機執行（part4 §4.5.2）。必須加 -ConfirmSnapshotVm 才會執行。

    對矩陣每一項：
      記錄起始時間 → 以獨立程序（預設經 WMI 建立，使其不屬於本 PowerShell 的程序樹，
      避免各測試的分數在同一棵樹上累加）執行 Invoke-AtomicTest → 等待 -WaitSeconds →
      以唯讀模式查 cairn.db 的 rule_hits / alerts / scores / audit_log → 比對預期 → -Cleanup。

    通過定義（part4 §4.5.2）：偵測到（預期規則有非 dry-run、非抑制的命中）＋ 分數落在預期 ±15
    ＋ 動作等級不低於預期。⚠ 首發為 dryrun 的規則命中不算通過。

    M0 門檻（單一定義）：11 個計分項中 ≥ 8 項通過；#2/#3/#7/#8/#9 必過；持久化 #4/#5 ≥ 1/2。
    #12 不列入計數。全部達成 → 離開碼 0（Go），否則 1（No-Go）。

    動作等級：0=僅記錄（有命中）＜ 1=觀察（分數 ≥ 40）＜ 2=告警（alerts 有列）
              ＜ 3=suspend_process ＜ 4=terminate_process_tree。
    ⚠ 自動回應取決於 %ProgramData%\Cairn\policy.json；demo 用的「自動回應關閉」設定會讓
      預期動作 ≥ 3 的項目失敗。跑本套件前請確認自動回應為開啟。

.PARAMETER ConfirmSnapshotVm
    確認目前在可還原快照的隔離 VM 中。未指定則拒絕執行。

.PARAMETER GetPrereqs
    只下載各測試的前置相依（需網路），完成後請照快照再斷網執行本套件。

.PARAMETER Only
    只跑指定編號（例如 -Only 2,3,7）。

.PARAMETER IncludeExtended
    一併執行 §4.5.2 延伸矩陣（7 項，不列入門檻計數）。

.PARAMETER WaitSeconds
    每個測試執行後等待偵測的秒數，預設 10。

.PARAMETER Isolation
    Wmi（預設）：經 Win32_Process.Create 啟動測試程序；Direct：直接在子 PowerShell 執行。

.PARAMETER RestartAgentBetweenTests
    每項測試前重啟 CairnAgent（清空記憶體中的分數狀態；較慢但最乾淨）。

.PARAMETER AtomicsPath
    atomics 目錄，預設 C:\AtomicRedTeam\atomics。

.PARAMETER SinkPort
    #6 的遠端 payload 改由本機 sink 提供的埠，預設 8081。

.PARAMETER OutputPath
    報表 Markdown 路徑，預設 reports\coverage-<yyyyMMdd>.md；同目錄輸出 coverage.json。

.EXAMPLE
    .\tools\Run-AtomicSuite.ps1 -GetPrereqs -ConfirmSnapshotVm

.EXAMPLE
    .\tools\Run-AtomicSuite.ps1 -ConfirmSnapshotVm -OutputPath .\reports\coverage-$(Get-Date -f yyyyMMdd).md
#>
[CmdletBinding()]
param(
    [switch]$ConfirmSnapshotVm,
    [switch]$GetPrereqs,
    [int[]]$Only,
    [switch]$IncludeExtended,
    [int]$WaitSeconds = 10,
    [ValidateSet('Wmi', 'Direct')][string]$Isolation = 'Wmi',
    [switch]$RestartAgentBetweenTests,
    [string]$AtomicsPath = 'C:\AtomicRedTeam\atomics',
    [int]$SinkPort = 8081,
    [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force
Assert-Admin 'Run-AtomicSuite.ps1（ART 測試需要系統管理員）'

if (-not $ConfirmSnapshotVm) {
    throw '拒絕執行：本腳本會執行真實攻擊技術。請在可還原快照的隔離 VM 中，加上 -ConfirmSnapshotVm 後重試（part4 §4.5.2）。'
}
$repo = Get-CairnRepoRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repo ("reports\coverage-{0:yyyyMMdd}.md" -f (Get-Date)) }
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
    throw "未安裝 invoke-atomicredteam。依 part4 §4.5.2：IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force"
}

# ------------------------------------------------------------
# 矩陣（part4 §4.5.2，權威來源；變更時兩處必須同步）
#   Match：多個 TestNumbers 時，All = 每個載體都須命中（#8），Any = 任一命中即可
# ------------------------------------------------------------
$matrix = @(
    [pscustomobject]@{ No = 1;  Tech = 'T1059.001'; Tests = @(1);       Rule = 'R-T1059-001'; Score = 70;   Level = 1; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = 'Mimikatz cradle，可能同時觸發 R-T1003-*' }
    [pscustomobject]@{ No = 2;  Tech = 'T1055.002'; Tests = @(1);       Rule = 'R-T1055-002'; Score = 60;   Level = 3; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = '必過' }
    [pscustomobject]@{ No = 3;  Tech = 'T1055.001'; Tests = @(1);       Rule = 'R-T1055-002'; Score = 60;   Level = 3; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = '必過；mavinject → notepad' }
    [pscustomobject]@{ No = 4;  Tech = 'T1547.001'; Tests = @(1);       Rule = 'R-T1547-001'; Score = 55;   Level = 0; Match = 'Any'; Scored = $true;  Prereq = $false; Note = '持久化' }
    [pscustomobject]@{ No = 5;  Tech = 'T1053.005'; Tests = @(2);       Rule = 'R-T1053-001'; Score = 50;   Level = 1; Match = 'Any'; Scored = $true;  Prereq = $false; Note = '持久化' }
    [pscustomobject]@{ No = 6;  Tech = 'T1218.011'; Tests = @(1);       Rule = 'R-T1218-001'; Score = 65;   Level = 0; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = 'payload 經本機 sink' }
    [pscustomobject]@{ No = 7;  Tech = 'T1486';     Tests = @(8, 10);   Rule = 'R-T1486-001'; Score = 95;   Level = 4; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = '必過；#1 為 Linux 專用' }
    [pscustomobject]@{ No = 8;  Tech = 'T1490';     Tests = @(1, 2, 5); Rule = 'R-T1490-001'; Score = 80;   Level = 3; Match = 'All'; Scored = $true;  Prereq = $false; Note = '必過；三種載體皆須命中' }
    [pscustomobject]@{ No = 9;  Tech = 'T1003.001'; Tests = @(1);       Rule = 'R-T1003-001'; Score = 85;   Level = 3; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = '必過' }
    [pscustomobject]@{ No = 10; Tech = 'T1562.001'; Tests = @(1);       Rule = 'R-T1562-001'; Score = 85;   Level = 3; Match = 'Any'; Scored = $true;  Prereq = $false; Note = '' }
    [pscustomobject]@{ No = 11; Tech = 'T1105';     Tests = @(7, 9, 10);Rule = 'R-T1105-001'; Score = 65;   Level = 0; Match = 'Any'; Scored = $true;  Prereq = $true;  Note = '#6 為 Linux/macOS 專用' }
    [pscustomobject]@{ No = 12; Tech = 'T1071.001'; Tests = @(1);       Rule = 'R-T1071-001'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $false; Note = '不列入計數（dryrun 規則）' }
)
$extended = @(
    [pscustomobject]@{ No = 101; Tech = 'T1055.012'; Tests = @(1); Rule = 'R-T1055-003'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $true;  Note = '延伸' }
    [pscustomobject]@{ No = 102; Tech = 'T1574.002'; Tests = @(1); Rule = 'R-T1574-001'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $true;  Note = '延伸' }
    [pscustomobject]@{ No = 103; Tech = 'T1003.001'; Tests = @(2); Rule = 'R-T1003-002'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $true;  Note = '延伸' }
    [pscustomobject]@{ No = 104; Tech = 'T1003.002'; Tests = @(1); Rule = 'R-T1003-003'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $false; Note = '延伸' }
    [pscustomobject]@{ No = 105; Tech = 'T1543.003'; Tests = @(1); Rule = 'R-T1543-001'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $false; Note = '延伸' }
    [pscustomobject]@{ No = 106; Tech = 'T1546.012'; Tests = @(1); Rule = 'R-T1546-001'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $false; Note = '延伸' }
    [pscustomobject]@{ No = 107; Tech = 'T1112';     Tests = @(8); Rule = 'R-T1112-001'; Score = $null; Level = 0; Match = 'Any'; Scored = $false; Prereq = $false; Note = '延伸（M1）' }
)
$plan = @($matrix)
if ($IncludeExtended) { $plan += $extended }
if ($Only) { $plan = @($plan | Where-Object { $Only -contains $_.No }) }

function Get-InputArgs($row) {
    if ($row.No -eq 6) { return @{ file_url = "http://127.0.0.1:$SinkPort/T1218.011.sct" } }
    return $null
}

# ------------------------------------------------------------
# -GetPrereqs：只下載前置
# ------------------------------------------------------------
Import-Module invoke-atomicredteam -Force
if ($GetPrereqs) {
    foreach ($row in $plan) {
        foreach ($t in $row.Tests) {
            Write-Host "GetPrereqs #$($row.No) $($row.Tech) -TestNumbers $t"
            $ia = Get-InputArgs $row
            if ($ia) { Invoke-AtomicTest $row.Tech -TestNumbers $t -GetPrereqs -InputArgs $ia -PathToAtomicsFolder $AtomicsPath }
            else { Invoke-AtomicTest $row.Tech -TestNumbers $t -GetPrereqs -PathToAtomicsFolder $AtomicsPath }
        }
    }
    Write-Host '前置下載完成。請照 VM 快照、斷網後再執行本套件（不加 -GetPrereqs）。' -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------
# 前置檢查
# ------------------------------------------------------------
if (-not (Get-Process -Name CairnAgent -ErrorAction SilentlyContinue)) { throw 'CairnAgent 未執行' }
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.RealTimeProtectionEnabled) {
        Write-Warning 'Defender 即時保護為開啟——Defender 可能先攔截導致 Cairn 觀測不到（R-14 ④）。建議在已關閉即時保護的快照上執行。'
    }
} catch { }

$ruleStatus = @{}
try {
    $rl = Invoke-CairnRpc -Method 'rules.list'
    foreach ($r in @($rl.items)) { $ruleStatus[$r.rule_id] = $r.status }
} catch { Write-Warning "rules.list 失敗，改以 rule_hits.dryrun 判斷規則狀態：$($_.Exception.Message)" }

$sinkJob = $null
if (@($plan | Where-Object No -eq 6).Count -gt 0) {
    $sinkRoot = Join-Path $AtomicsPath 'T1218.011\src'
    $lt = Join-Path $PSScriptRoot 'Load-Test.ps1'
    & $lt -StartSink -Port $SinkPort -SinkRoot $sinkRoot
}

# ------------------------------------------------------------
# 執行
# ------------------------------------------------------------
function Invoke-IsolatedAtomic {
    param([string]$Tech, [int]$TestNo, [hashtable]$InputArgs, [switch]$Cleanup)
    $ia = ''
    if ($InputArgs) {
        $pairs = ($InputArgs.GetEnumerator() | ForEach-Object { "'$($_.Key)'='$($_.Value)'" }) -join ';'
        $ia = " -InputArgs @{$pairs}"
    }
    $cl = if ($Cleanup) { ' -Cleanup' } else { '' }
    $cmd = "Import-Module invoke-atomicredteam -Force; Invoke-AtomicTest '$Tech' -TestNumbers $TestNo -PathToAtomicsFolder '$AtomicsPath'$ia$cl"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $cmdline = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"
    if ($Isolation -eq 'Direct' -or $Cleanup) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc | Out-Host
        return
    }
    # 經 WMI 建立：父程序為 WmiPrvSE.exe，與本腳本的程序樹分離
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmdline }
    if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create 失敗：$($r.ReturnValue)" }
    $pid0 = [int]$r.ProcessId
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Process -Id $pid0 -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Get-Process -Id $pid0 -ErrorAction SilentlyContinue) { Write-Warning "測試程序 $pid0 超過 5 分鐘未結束（可能已被 Cairn 暫停）" }
}

function Get-Observation {
    param([string]$Rule, [long]$FromMs)
    $r = ConvertTo-SqlString $Rule
    $hits = @(Invoke-CairnSql -Query "SELECT rule_id, ts, root_process_guid, dryrun, suppressed, score_delta FROM rule_hits WHERE ts >= $FromMs ORDER BY ts")
    $mine = @($hits | Where-Object { $_.rule_id -eq $Rule })
    $live = @($mine | Where-Object { $_.dryrun -eq 0 -and $_.suppressed -eq 0 })
    $roots = @($mine | ForEach-Object root_process_guid | Select-Object -Unique)
    $alerts = @(Invoke-CairnSql -Query "SELECT id, ts, score_at_trigger, rule_ids, actions_taken, root_process_guid FROM alerts WHERE ts >= $FromMs AND rule_ids LIKE '%' || $r || '%' ORDER BY ts")
    $peak = $null
    if ($roots.Count) {
        $in = ($roots | ForEach-Object { ConvertTo-SqlString $_ }) -join ','
        $peak = Get-CairnScalar -Query "SELECT MAX(peak_score) FROM scores WHERE root_process_guid IN ($in)"
    }
    $score = $null
    if ($alerts.Count) { $score = ([double]($alerts | Measure-Object score_at_trigger -Maximum).Maximum) / 1000 }
    elseif ($null -ne $peak) { $score = [double]$peak / 1000 }
    $acts = @(Invoke-CairnSql -Query "SELECT action, result FROM audit_log WHERE ts >= $FromMs AND result IN ('ok','partial')") | ForEach-Object action
    $level = -1
    if ($live.Count) { $level = 0 }
    if ($null -ne $score -and $score -ge 40) { $level = [Math]::Max($level, 1) }
    if ($alerts.Count) { $level = [Math]::Max($level, 2) }
    if ($acts -contains 'suspend_process') { $level = [Math]::Max($level, 3) }
    if ($acts -contains 'terminate_process_tree') { $level = [Math]::Max($level, 4) }
    $latency = $null
    if ($live.Count) { $latency = ([long]$live[0].ts - $FromMs) / 1000.0 }
    return [pscustomobject]@{
        Detected     = ($live.Count -gt 0)
        DryRunOnly   = ($mine.Count -gt 0 -and $live.Count -eq 0)
        AllRules     = @($hits | Where-Object { $_.suppressed -eq 0 } | ForEach-Object rule_id | Select-Object -Unique)
        Score        = $score
        Level        = $level
        Actions      = @($acts | Select-Object -Unique)
        AlertIds     = @($alerts | ForEach-Object id)
        LatencySec   = $latency
    }
}

$levelName = @{ -1 = '未偵測'; 0 = '僅記錄'; 1 = '觀察'; 2 = '告警'; 3 = 'suspend'; 4 = 'terminate' }
$rows = New-Object System.Collections.Generic.List[object]

foreach ($row in $plan) {
    Write-Section ("#{0} {1} -TestNumbers {2}（預期 {3}）" -f $row.No, $row.Tech, ($row.Tests -join ','), $row.Rule)
    $subs = @()
    foreach ($t in $row.Tests) {
        if ($RestartAgentBetweenTests) {
            & sc.exe stop CairnAgent | Out-Null; Start-Sleep -Seconds 5
            & sc.exe start CairnAgent | Out-Null; Start-Sleep -Seconds 15
        }
        $from = Get-UnixMs
        try {
            Invoke-IsolatedAtomic -Tech $row.Tech -TestNo $t -InputArgs (Get-InputArgs $row)
        } catch { Write-Warning "執行失敗：$($_.Exception.Message)" }
        Start-Sleep -Seconds $WaitSeconds
        $obs = Get-Observation -Rule $row.Rule -FromMs $from
        $subs += [pscustomobject]@{ Test = $t; Obs = $obs }
        try { Invoke-IsolatedAtomic -Tech $row.Tech -TestNo $t -InputArgs (Get-InputArgs $row) -Cleanup } catch { Write-Warning "Cleanup 失敗：$($_.Exception.Message)" }
        Write-Host ("  test {0}: detected={1} score={2} level={3} rules={4}" -f $t, $obs.Detected, $obs.Score, $levelName[$obs.Level], ($obs.AllRules -join ','))
    }
    $detected = if ($row.Match -eq 'All') { @($subs | Where-Object { -not $_.Obs.Detected }).Count -eq 0 } else { @($subs | Where-Object { $_.Obs.Detected }).Count -gt 0 }
    $best = $subs | Sort-Object { if ($null -eq $_.Obs.Score) { -1 } else { $_.Obs.Score } } -Descending | Select-Object -First 1
    $score = $best.Obs.Score
    $level = ($subs | ForEach-Object { $_.Obs.Level } | Measure-Object -Maximum).Maximum
    $scoreOk = ($null -eq $row.Score) -or ($null -ne $score -and [Math]::Abs($score - $row.Score) -le 15)
    $levelOk = $level -ge $row.Level
    $statusDry = ($ruleStatus.ContainsKey($row.Rule) -and $ruleStatus[$row.Rule] -ne 'enabled') -or (@($subs | Where-Object { $_.Obs.DryRunOnly }).Count -gt 0)
    $pass = $detected -and $scoreOk -and $levelOk -and -not $statusDry
    $reason = @()
    if (-not $detected) { $reason += '未偵測' }
    if ($statusDry) { $reason += '規則非 enabled（dryrun 不得列為通過）' }
    if (-not $scoreOk) { $reason += "分數 $score 超出 $($row.Score)±15" }
    if (-not $levelOk) { $reason += "動作 $($levelName[[int]$level]) 低於預期 $($levelName[$row.Level])" }
    $rows.Add([pscustomobject]@{
            No = $row.No; Tech = $row.Tech; Tests = ($row.Tests -join ','); ExpectedRule = $row.Rule
            ExpectedScore = $row.Score; ExpectedLevel = $levelName[$row.Level]; Scored = $row.Scored
            Detected = $detected; ActualRules = (@($subs | ForEach-Object { $_.Obs.AllRules }) | Select-Object -Unique) -join ','
            ActualScore = $score; ActualLevel = $levelName[[int]$level]
            Actions = (@($subs | ForEach-Object { $_.Obs.Actions }) | Select-Object -Unique) -join ','
            LatencySec = ($subs | ForEach-Object { $_.Obs.LatencySec } | Where-Object { $null -ne $_ } | Measure-Object -Minimum).Minimum
            AlertIds = (@($subs | ForEach-Object { $_.Obs.AlertIds }) -join ',')
            Pass = $pass; Reason = ($reason -join '；'); Note = $row.Note
        })
}

# ------------------------------------------------------------
# 門檻判定
# ------------------------------------------------------------
$scored = @($rows | Where-Object { $_.Scored })
$passCount = @($scored | Where-Object Pass).Count
$mustNos = 2, 3, 7, 8, 9
$mustPassed = @($rows | Where-Object { $mustNos -contains $_.No -and $_.Pass }).Count
$mustRan = @($rows | Where-Object { $mustNos -contains $_.No }).Count
$persist = @($rows | Where-Object { (4, 5) -contains $_.No -and $_.Pass }).Count
$fullRun = ($scored.Count -eq 11)
$go = $fullRun -and ($passCount -ge 8) -and ($mustPassed -eq 5) -and ($persist -ge 1)

$coverage = [ordered]@{
    generated_at = (Get-Date).ToString('o'); host = $env:COMPUTERNAME
    scored_total = $scored.Count; scored_passed = $passCount
    must_pass = [ordered]@{ required = $mustNos; passed = $mustPassed; ran = $mustRan }
    persistence_passed = $persist; full_run = $fullRun; go = $go
    rows = $rows
}
$jsonPath = Join-Path (Split-Path $OutputPath) 'coverage.json'
$coverage | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$table = ($rows | ForEach-Object {
        "| $($_.No) | $($_.Tech) #$($_.Tests) | $($_.ExpectedRule) | $(if ($_.Detected) {'✅'} else {'❌'}) | $($_.ActualRules) | $($_.ActualScore) / $($_.ExpectedScore) | $($_.ActualLevel) / $($_.ExpectedLevel) | $($_.LatencySec) | $(if ($_.Pass) {'✅ PASS'} elseif (-not $_.Scored) {'—（不計）'} else {'❌ FAIL'}) | $($_.Reason) |"
    }) -join "`n"
$md = @"
# Cairn M0 ART 覆蓋率報表（M-01）

- 時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；主機：$env:COMPUTERNAME；隔離方式：$Isolation
- 判定：**$(if ($go) { 'GO' } else { 'NO-GO' })** —— 計分項通過 $passCount / $($scored.Count)（門檻 ≥ 8/11）；必過項 $mustPassed / 5；持久化 $persist / 2（門檻 ≥ 1）$(if (-not $fullRun) { '；⚠ 非完整執行（-Only），不得作為 Go/No-Go 依據' })

| # | 測試 | 預期規則 | 偵測 | 實際命中規則 | 分數（實際/預期） | 動作（實際/預期） | 延遲 s | 結果 | 原因 |
|---|---|---|---|---|---|---|---|---|---|
$table

通過定義：偵測到 + 分數落在預期 ±15 + 動作等級不低於預期；dryrun 規則不得列為通過（part4 §4.5.2）。
"@
Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
Write-Host $md
Write-Host "報表：$OutputPath；JSON：$jsonPath"
if ($sinkJob) { Stop-Job $sinkJob -ErrorAction SilentlyContinue }
Get-Job -Name "CairnSink-$SinkPort" -ErrorAction SilentlyContinue | Stop-Job -PassThru | Remove-Job -Force -ErrorAction SilentlyContinue
exit ([int](-not $go))
