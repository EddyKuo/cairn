#Requires -Version 5.1
<#
.SYNOPSIS
    Cairn 事件率壓測與資源量測（part4 §4.5.4、W1-12；part1 M-08）。

.DESCRIPTION
    三種用法：

    1) 壓測（預設）：以合成負載產生真實 Sysmon 事件（不跑惡意程式），同時量測：
         - 實際產生的 Sysmon 事件率（以 Sysmon/Operational 的 RecordId 差值計，閉迴路調整負載）
         - CairnAgent 丟包率（agent_health.events_dropped / events_ingested）
         - CairnAgent CPU P95（已除以邏輯核心數，對齊 part4 §4.5.4 的歸一化定義）
         - Private Bytes 線性回歸斜率（MB/hr）與 Handle Count 趨勢
         - queue_depth P95（佔 ring buffer 容量百分比）
         - 結束後佇列排空時間（峰值測試門檻 < 60 秒）
       負載組成：
         預設     ：大量短命程序 cmd.exe /c exit（EID 1/5）
         -Mixed   ：再加檔案建立/刪除（EID 11/23 或 26）與對本機 sink 的 TCP 連線（EID 3）
       ⚠ 每種操作實際產生幾個事件取決於 config\sysmon.xml 的過濾規則，
         因此本腳本以 Sysmon 實際記錄數為準做閉迴路調速，報表同時列出目標與實際事件率。

    2) -Resource：不產生負載，取樣 CairnAgent 與 CairnConsole（含 msedgewebview2 子程序）的
       CPU / 記憶體，輸出 P95（M-08；預設 30 分鐘）。

    3) -StartSink：在 127.0.0.1:<Port> 啟動簡單 HTTP sink（背景 Job），供 W2 出場條件 2 的
       `iwr http://127.0.0.1:8099/payload.txt` 與 ART #6 使用。只給 -StartSink 時啟動後即返回，
       sink 會持續到 PowerShell 關閉或 `Get-Job CairnSink* | Stop-Job`。

.PARAMETER Rate
    目標 Sysmon 事件率（事件/秒）。壓測預設 2000。

.PARAMETER Minutes
    壓測時長（分鐘），預設 10；-Resource 時為取樣時長，預設 30。

.PARAMETER Hours
    以小時指定時長（常駐測試：-Profile Office -Hours 4），優先於 -Minutes。

.PARAMETER Mixed
    混合負載（程序 + 檔案 + 網路）。

.PARAMETER Profile
    Burst（預設，維持 -Rate）、Office（模擬日常辦公：約 50 事件/秒混合負載，可長跑）、
    Idle（不產生負載，只量測——對應 M0-P1 閒置 CPU）。

.PARAMETER Resource
    只量測資源（M-08），不產生負載。

.PARAMETER StartSink
    啟動本機 HTTP sink。

.PARAMETER Port
    sink 埠，預設 8099。⚠ 不可用 8080（llama-server）。

.PARAMETER SinkRoot
    sink 的檔案根目錄；請求的路徑若對應到此目錄下的檔案則回傳檔案內容，否則回傳固定的無害文字。

.PARAMETER Workers
    產生負載的平行 runspace 數，預設 2 × 邏輯核心數。

.PARAMETER QueueCapacity
    ring buffer 容量（計算 queue_depth 百分比），預設 65536（CONVENTIONS C-5）。

.PARAMETER OutputPath
    報表 Markdown 路徑；同名 .json 一併輸出。預設 reports\load-<時間>.md。

.EXAMPLE
    .\tools\Load-Test.ps1 -Rate 2000 -Minutes 10
    # W1 出場條件 6：丟包率 < 0.5%、CPU P95 < 8%、Private Bytes 無單調成長

.EXAMPLE
    .\tools\Load-Test.ps1 -Rate 5000 -Minutes 10 -Mixed

.EXAMPLE
    .\tools\Load-Test.ps1 -Rate 10000 -Minutes 2

.EXAMPLE
    .\tools\Load-Test.ps1 -Profile Office -Hours 4

.EXAMPLE
    .\tools\Load-Test.ps1 -Resource -Minutes 30

.EXAMPLE
    .\tools\Load-Test.ps1 -StartSink -Port 8099
#>
[CmdletBinding()]
param(
    [int]$Rate = 0,
    [double]$Minutes = 0,
    [double]$Hours = 0,
    [switch]$Mixed,
    [ValidateSet('Burst', 'Office', 'Idle')][string]$Profile = 'Burst',
    [switch]$Resource,
    [switch]$StartSink,
    [ValidateRange(1, 65535)][int]$Port = 8099,
    [string]$SinkRoot,
    [int]$Workers = 0,
    [int]$QueueCapacity = 65536,
    [int]$SampleSeconds = 5,
    [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

if ($Port -eq 8080) { throw '8080 是 llama-server 的埠，sink 請用其他埠（例如 8099）' }
$repo = Get-CairnRepoRoot
$cores = [Environment]::ProcessorCount

# ============================================================
# HTTP sink（TcpListener，不需 urlacl/管理員；只綁 127.0.0.1）
# ============================================================
function Start-CairnSink {
    param([int]$Port, [string]$Root)
    $name = "CairnSink-$Port"
    $existing = Get-Job -Name $name -ErrorAction SilentlyContinue | Where-Object State -eq 'Running'
    if ($existing) { Write-Host "sink 已在 127.0.0.1:$Port 執行（Job $name）"; return $existing }
    $job = Start-Job -Name $name -ArgumentList $Port, $Root -ScriptBlock {
        param($Port, $Root)
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $default = [Text.Encoding]::ASCII.GetBytes("Write-Output 'cairn-sink: benign payload'`r`n")
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $client.ReceiveTimeout = 2000
                $stream = $client.GetStream()
                $buf = New-Object byte[] 4096
                $n = 0
                try { $n = $stream.Read($buf, 0, $buf.Length) } catch { }
                $reqLine = ([Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n, 0)) -split "`r`n")[0]
                $path = '/'
                if ($reqLine -match '^[A-Z]+\s+(\S+)') { $path = $Matches[1] }
                $body = $default
                $ctype = 'text/plain'
                if ($Root) {
                    $rel = [Uri]::UnescapeDataString(($path.Split('?')[0]).TrimStart('/')) -replace '/', '\'
                    $full = [IO.Path]::GetFullPath((Join-Path $Root $rel))
                    if ($full.StartsWith([IO.Path]::GetFullPath($Root)) -and (Test-Path -LiteralPath $full -PathType Leaf)) {
                        $body = [IO.File]::ReadAllBytes($full)
                        $ctype = 'application/octet-stream'
                    }
                }
                $hdr = [Text.Encoding]::ASCII.GetBytes("HTTP/1.0 200 OK`r`nContent-Type: $ctype`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
                $stream.Write($hdr, 0, $hdr.Length)
                $stream.Write($body, 0, $body.Length)
            } catch { } finally { $client.Close() }
        }
    }
    Start-Sleep -Milliseconds 800
    if ($job.State -ne 'Running') {
        $err = Receive-Job $job -ErrorAction SilentlyContinue 2>&1 | Out-String
        throw "sink 啟動失敗（埠 $Port 是否被占用？）：$err"
    }
    Write-Host "sink 已啟動：http://127.0.0.1:$Port/（Job $name；停止：Stop-Job -Name $name）" -ForegroundColor Green
    return $job
}

# ============================================================
# 量測工具
# ============================================================
function Get-SysmonLastRecordId {
    $e = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { return [long]$e.RecordId }
    return $null
}

$script:prevCpu = $null
function Get-AgentSample {
    # CPU% 以 Process.TotalProcessorTime 的差值計算（不用 Get-Counter：效能計數器名稱會依
    # Windows 顯示語言在地化，英文路徑在繁中系統上會失敗）。結果已除以邏輯核心數（part4 §4.5.4）。
    $p = Get-Process -Name CairnAgent -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) { $script:prevCpu = $null; return $null }
    $now = [Diagnostics.Stopwatch]::GetTimestamp()
    $cpuTime = $p.TotalProcessorTime.TotalSeconds
    $cpu = $null
    if ($script:prevCpu -and $script:prevCpu.Pid -eq $p.Id) {
        $wall = ($now - $script:prevCpu.Ts) / [double][Diagnostics.Stopwatch]::Frequency
        if ($wall -gt 0) { $cpu = 100.0 * ($cpuTime - $script:prevCpu.Cpu) / $wall / $cores }
    }
    $script:prevCpu = @{ Pid = $p.Id; Ts = $now; Cpu = $cpuTime }
    return [pscustomobject]@{
        T            = (Get-Date)
        CpuPct       = $cpu
        PrivateMB    = [double]$p.PrivateMemorySize64 / 1MB
        Handles      = [int]$p.HandleCount
        Threads      = [int]$p.Threads.Count
    }
}

function Get-ConsoleTreeMemoryMB {
    # CairnConsole + 其所有 msedgewebview2 子孫程序的 Private Bytes 合計（M0-P3b）
    $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name)
    $roots = @($all | Where-Object Name -eq 'CairnConsole.exe')
    if ($roots.Count -eq 0) { return $null }
    $ids = New-Object System.Collections.Generic.HashSet[int]
    $queue = New-Object System.Collections.Generic.Queue[int]
    foreach ($r in $roots) { [void]$ids.Add([int]$r.ProcessId); $queue.Enqueue([int]$r.ProcessId) }
    while ($queue.Count) {
        $pid0 = $queue.Dequeue()
        foreach ($c in ($all | Where-Object ParentProcessId -eq $pid0)) {
            if ($ids.Add([int]$c.ProcessId)) { $queue.Enqueue([int]$c.ProcessId) }
        }
    }
    $sum = 0.0
    foreach ($id in $ids) {
        $p = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($p) { $sum += $p.PrivateMemorySize64 }
    }
    return $sum / 1MB
}

function Get-HealthRows {
    param([long]$FromMs)
    try {
        return @(Invoke-CairnSql -Query "SELECT ts, events_ingested, events_dropped, events_filtered, queue_depth, cpu_percent, private_bytes_mb FROM agent_health WHERE ts >= $FromMs ORDER BY ts")
    } catch {
        Write-Warning "讀取 agent_health 失敗：$($_.Exception.Message)"
        return @()
    }
}

function Get-CounterDelta {
    # agent_health 的計數欄位可能是「累計值」或「區間值」（設計文件未明定）。
    # 單調不減 → 視為累計，取 末-首；否則視為區間值，取總和。
    param([object[]]$Rows, [string]$Field)
    if ($Rows.Count -eq 0) { return $null }
    $vals = @($Rows | ForEach-Object { [double]$_.$Field })
    $mono = $true
    for ($i = 1; $i -lt $vals.Count; $i++) { if ($vals[$i] -lt $vals[$i - 1]) { $mono = $false; break } }
    if ($mono -and $vals.Count -ge 2) { return [pscustomobject]@{ Value = $vals[-1] - $vals[0]; Mode = 'cumulative' } }
    return [pscustomobject]@{ Value = ($vals | Measure-Object -Sum).Sum; Mode = 'interval' }
}

# ============================================================
# 只啟動 sink
# ============================================================
$doLoad = (-not $Resource) -and ($Rate -gt 0 -or $Minutes -gt 0 -or $Hours -gt 0 -or $Profile -ne 'Burst' -or $Mixed)
if ($StartSink) {
    [void](Start-CairnSink -Port $Port -Root $SinkRoot)
    if (-not $doLoad -and -not $Resource) { exit 0 }
}

$durationMin = if ($Hours -gt 0) { $Hours * 60 } elseif ($Minutes -gt 0) { $Minutes } elseif ($Resource) { 30 } else { 10 }
if (-not $OutputPath) {
    $kind = if ($Resource) { 'resource' } else { "load-$Profile" }
    $OutputPath = Join-Path $repo ("reports\{0}-{1:yyyyMMdd-HHmmss}.md" -f $kind, (Get-Date))
}
New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath) | Out-Null

# 讀取 LocalSystem 服務程序的 CPU 時間需要系統管理員權限
Assert-Admin 'Load-Test.ps1 的壓測／資源量測（讀取 CairnAgent 程序的 CPU 時間）'
if (-not (Get-Process -Name CairnAgent -ErrorAction SilentlyContinue)) {
    throw 'CairnAgent 未在執行。請先 sc.exe start CairnAgent（或 .\tools\Install-Dev.ps1）'
}

# ============================================================
# -Resource：只量測（M-08）
# ============================================================
if ($Resource) {
    Write-Section "資源取樣 $durationMin 分鐘（每 $SampleSeconds 秒）"
    $samples = New-Object System.Collections.Generic.List[object]
    $end = (Get-Date).AddMinutes($durationMin)
    while ((Get-Date) -lt $end) {
        $a = Get-AgentSample
        $consoleMb = Get-ConsoleTreeMemoryMB
        if ($a) { $samples.Add([pscustomobject]@{ T = $a.T; AgentCpu = $a.CpuPct; AgentMB = $a.PrivateMB; ConsoleMB = $consoleMb; Handles = $a.Handles }) }
        Start-Sleep -Seconds $SampleSeconds
    }
    $cpuP95 = Get-Percentile -Values @($samples | Where-Object { $null -ne $_.AgentCpu } | ForEach-Object AgentCpu) -P 95
    $memP95 = Get-Percentile -Values @($samples | ForEach-Object AgentMB) -P 95
    $conVals = @($samples | Where-Object { $null -ne $_.ConsoleMB } | ForEach-Object ConsoleMB)
    $conP95 = Get-Percentile -Values $conVals -P 95
    $res = [ordered]@{
        kind = 'resource'; minutes = $durationMin; samples = $samples.Count
        agent_cpu_p95_pct = $cpuP95; agent_private_mb_p95 = $memP95; console_tree_mb_p95 = $conP95
        pass = [ordered]@{
            agent_cpu_idle_le_2pct  = ($null -ne $cpuP95 -and $cpuP95 -le 2)
            agent_mem_le_300mb      = ($null -ne $memP95 -and $memP95 -le 300)
            console_mem_le_350mb    = ($(if ($conVals.Count) { $conP95 -le 350 } else { $null }))
        }
    }
    $md = @"
# Cairn 資源量測（M-08）

- 時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；主機：$env:COMPUTERNAME；邏輯核心：$cores
- 取樣：$durationMin 分鐘 / $($samples.Count) 點

| 指標 | P95 | 門檻 | 結果 |
|---|---|---|---|
| CairnAgent CPU（歸一化） | $('{0:N2}' -f $cpuP95) % | ≤ 2%（閒置） | $($res.pass.agent_cpu_idle_le_2pct) |
| CairnAgent Private Bytes | $('{0:N1}' -f $memP95) MB | ≤ 300 MB | $($res.pass.agent_mem_le_300mb) |
| CairnConsole + WebView2 | $(if ($conVals.Count) { '{0:N1} MB' -f $conP95 } else { '（Console 未開）' }) | ≤ 350 MB | $($res.pass.console_mem_le_350mb) |
"@
    Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
    $res | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($OutputPath, '.json')) -Encoding UTF8
    Write-Host $md
    $failed = @($res.pass.Values | Where-Object { $_ -eq $false }).Count
    exit ([int]($failed -gt 0))
}

# ============================================================
# 壓測
# ============================================================
switch ($Profile) {
    'Office' { if ($Rate -le 0) { $Rate = 50 }; $Mixed = $true }
    'Idle'   { $Rate = 0 }
    default  { if ($Rate -le 0) { $Rate = 2000 } }
}
if ($Workers -le 0) { $Workers = [Math]::Max(2, 2 * $cores) }

$sinkJob = $null
if ($Mixed -and $Rate -gt 0) { $sinkJob = Start-CairnSink -Port $Port -Root $SinkRoot }

$workDir = Join-Path $env:TEMP 'cairn-load'
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

# 共享狀態：控制迴路寫 OpsPerSec，worker 讀取；Stop 為停止旗標
$state = [hashtable]::Synchronized(@{ OpsPerSec = [double]([Math]::Max($Rate, 0) / 2.0); Stop = $false; Ops = [long]0; Errors = [long]0 })

$workerScript = {
    param($State, $Index, $Workers, $Mixed, $Port, $WorkDir)
    $rnd = New-Object System.Random($Index * 7919 + [Environment]::TickCount)
    $psi = New-Object System.Diagnostics.ProcessStartInfo('cmd.exe', '/c exit')
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $done = 0.0
    while (-not $State.Stop) {
        $perWorker = [double]$State.OpsPerSec / $Workers
        if ($perWorker -le 0) { Start-Sleep -Milliseconds 200; $sw.Restart(); $done = 0; continue }
        $due = $sw.Elapsed.TotalSeconds * $perWorker
        if ($done -ge $due) { Start-Sleep -Milliseconds 2; continue }
        try {
            $op = 0
            if ($Mixed) { $op = $rnd.Next(0, 3) }
            switch ($op) {
                0 {   # 程序建立／結束：EID 1 + EID 5
                    $p = [Diagnostics.Process]::Start($psi)
                    [void]$p.WaitForExit(5000); $p.Dispose()
                }
                1 {   # 檔案建立／刪除：EID 11 + EID 23/26（取決於 sysmon.xml 過濾）
                    $f = Join-Path $WorkDir ("w{0}-{1}.dat" -f $Index, $rnd.Next())
                    [IO.File]::WriteAllBytes($f, [byte[]](1..64))
                    [IO.File]::Delete($f)
                }
                2 {   # 本機 TCP 連線：EID 3（sysmon.xml 可能排除 loopback）
                    $c = New-Object System.Net.Sockets.TcpClient
                    try {
                        $c.Connect('127.0.0.1', $Port)
                        $s = $c.GetStream()
                        $b = [Text.Encoding]::ASCII.GetBytes("GET /load HTTP/1.0`r`n`r`n")
                        $s.Write($b, 0, $b.Length)
                    } finally { $c.Close() }
                }
            }
            $State.Ops++
        } catch { $State.Errors++ }
        $done += 1
    }
}

$pool = [RunspaceFactory]::CreateRunspacePool(1, $Workers)
$pool.Open()
$handles = @()
if ($Rate -gt 0) {
    for ($i = 0; $i -lt $Workers; $i++) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($workerScript).AddArgument($state).AddArgument($i).AddArgument($Workers).AddArgument([bool]$Mixed).AddArgument($Port).AddArgument($workDir)
        $handles += [pscustomobject]@{ PS = $ps; H = $ps.BeginInvoke() }
    }
}

Write-Section ("壓測：Profile={0} 目標 {1} 事件/秒，{2} 分鐘，Mixed={3}，Workers={4}" -f $Profile, $Rate, $durationMin, [bool]$Mixed, $Workers)
$startMs = Get-UnixMs
$startRec = Get-SysmonLastRecordId
$samples = New-Object System.Collections.Generic.List[object]
$rateLog = New-Object System.Collections.Generic.List[double]
$end = (Get-Date).AddMinutes($durationMin)
$lastRec = $startRec; $lastT = Get-Date
$agentDied = $false
try {
    while ((Get-Date) -lt $end) {
        Start-Sleep -Seconds $SampleSeconds
        $a = Get-AgentSample
        if (-not $a) { $agentDied = $true; Write-Warning 'CairnAgent 程序消失（崩潰？）'; break }
        $samples.Add($a)
        $rec = Get-SysmonLastRecordId
        $now = Get-Date
        if ($null -ne $rec -and $null -ne $lastRec) {
            $actual = ($rec - $lastRec) / [Math]::Max(0.001, ($now - $lastT).TotalSeconds)
            $rateLog.Add($actual)
            # 閉迴路調速：依實際 / 目標比例修正操作率（每步限制 0.5x–2x）
            if ($Rate -gt 0 -and $actual -gt 0) {
                $ratio = [Math]::Min(2.0, [Math]::Max(0.5, $Rate / $actual))
                $state.OpsPerSec = [Math]::Min([double]$state.OpsPerSec * $ratio, [double]$Rate * 4)
            }
            Write-Host ("  {0:HH:mm:ss}  Sysmon {1,7:N0} 事件/秒  Agent CPU {2,5:N2}%  Private {3,7:N1} MB  Handles {4,6}" -f $now, $actual, $a.CpuPct, $a.PrivateMB, $a.Handles)
        }
        $lastRec = $rec; $lastT = $now
    }
} finally {
    $state.Stop = $true
    foreach ($h in $handles) { try { [void]$h.PS.EndInvoke($h.H) } catch { }; $h.PS.Dispose() }
    $pool.Close(); $pool.Dispose()
    if ($sinkJob -and -not $StartSink) { Stop-Job $sinkJob -ErrorAction SilentlyContinue; Remove-Job $sinkJob -Force -ErrorAction SilentlyContinue }
}
$loadEndMs = Get-UnixMs
$endRec = Get-SysmonLastRecordId

# 佇列排空時間：負載停止後 queue_depth 降到 1% 容量以下所需時間（上限 120 秒）
$drainSec = $null
if (-not $agentDied) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 120) {
        $q = $null
        try { $q = Get-CairnScalar -Query 'SELECT queue_depth FROM agent_health ORDER BY ts DESC LIMIT 1' } catch { }
        if ($null -ne $q -and [double]$q -le $QueueCapacity * 0.01) { $drainSec = [Math]::Round($sw.Elapsed.TotalSeconds, 1); break }
        Start-Sleep -Seconds 2
    }
}

# --- 彙整 ---
$health = Get-HealthRows -FromMs $startMs
$ing = Get-CounterDelta -Rows $health -Field 'events_ingested'
$drp = Get-CounterDelta -Rows $health -Field 'events_dropped'
$dropRate = $null
if ($ing -and $drp -and $ing.Value -gt 0) { $dropRate = $drp.Value / $ing.Value }
$sysmonTotal = if ($null -ne $startRec -and $null -ne $endRec) { $endRec - $startRec } else { $null }
$e2eLoss = $null
if ($sysmonTotal -and $ing -and $sysmonTotal -gt 0) { $e2eLoss = [Math]::Max(0, 1 - ($ing.Value / $sysmonTotal)) }

$cpuP95 = Get-Percentile -Values @($samples | Where-Object { $null -ne $_.CpuPct } | ForEach-Object CpuPct) -P 95
$t0 = if ($samples.Count) { $samples[0].T } else { Get-Date }
$xs = @($samples | ForEach-Object { ($_.T - $t0).TotalHours })
$slopeMem = Get-LinearSlope -X $xs -Y @($samples | ForEach-Object PrivateMB)
$slopeHnd = Get-LinearSlope -X $xs -Y @($samples | ForEach-Object { [double]$_.Handles })
$qP95 = Get-Percentile -Values @($health | ForEach-Object { [double]$_.queue_depth }) -P 95
$qP95Pct = if ($null -ne $qP95) { 100.0 * $qP95 / $QueueCapacity } else { $null }
$achieved = Get-Percentile -Values $rateLog.ToArray() -P 50

$rpcHealth = $null
try { $rpcHealth = Invoke-CairnRpc -Method 'health.get' } catch { Write-Warning "health.get 失敗：$($_.Exception.Message)" }

# 門檻（part4 §4.5.4）
$dropLimit = if ($Rate -le 2000) { 0.005 } elseif ($Rate -le 5000) { 0.01 } else { $null }
$checks = [ordered]@{}
$checks['agent_alive']    = (-not $agentDied)
if ($null -ne $dropLimit) { $checks['drop_rate']  = ($null -ne $dropRate -and $dropRate -lt $dropLimit) }
if ($Profile -ne 'Idle')  { $checks['cpu_p95_lt_8'] = ($null -ne $cpuP95 -and $cpuP95 -lt 8) } else { $checks['cpu_p95_le_2'] = ($null -ne $cpuP95 -and $cpuP95 -le 2) }
if ($Rate -gt 2000 -and $Rate -le 5000) { $checks['queue_p95_lt_50pct'] = ($null -ne $qP95Pct -and $qP95Pct -lt 50) }
if ($Rate -ge 10000) { $checks['drain_lt_60s'] = ($null -ne $drainSec -and $drainSec -lt 60) }
if ($durationMin -ge 60) { $checks['private_slope_lt_0.5mb_hr'] = ($null -ne $slopeMem -and $slopeMem -lt 0.5) }
$checks['achieved_rate_ge_80pct'] = ($Rate -le 0) -or ($null -ne $achieved -and $achieved -ge 0.8 * $Rate)

$result = [ordered]@{
    kind = 'load'; profile = $Profile; target_rate = $Rate; achieved_rate_p50 = $achieved; mixed = [bool]$Mixed
    minutes = $durationMin; workers = $Workers; generator_ops = $state.Ops; generator_errors = $state.Errors
    sysmon_records = $sysmonTotal; agent_ingested = $(if ($ing) { $ing.Value }); agent_dropped = $(if ($drp) { $drp.Value })
    health_counter_mode = $(if ($ing) { $ing.Mode }); drop_rate = $dropRate; end_to_end_loss = $e2eLoss
    cpu_p95_pct = $cpuP95; private_mb_slope_per_hr = $slopeMem; handle_slope_per_hr = $slopeHnd
    queue_depth_p95 = $qP95; queue_depth_p95_pct = $qP95Pct; drain_seconds = $drainSec
    checks = $checks; health_get = $rpcHealth
    environment = [ordered]@{ host = $env:COMPUTERNAME; cores = $cores; os = [Environment]::OSVersion.VersionString; started_ms = $startMs; load_end_ms = $loadEndMs }
}

function Fmt {
    param($v, [string]$f = 'N2')
    if ($null -eq $v) { '—' } else { "{0:$f}" -f $v }
}
$rows = ($checks.GetEnumerator() | ForEach-Object { "| $($_.Key) | $(if ($_.Value) { '✅ PASS' } else { '❌ FAIL' }) |" }) -join "`n"
$md = @"
# Cairn 壓測報告

- 時間：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')；主機：$env:COMPUTERNAME（$cores 邏輯核心）
- ⚠ 量測環境須標註（part4 §4.5.4）：基準硬體 i5-12400 / 16 GB / NVMe / Win11 23H2；本機規格請於下方補記
- Profile：$Profile；目標 $Rate 事件/秒；實際中位數 $(Fmt $achieved 'N0') 事件/秒；$durationMin 分鐘；Mixed=$([bool]$Mixed)

| 指標 | 值 |
|---|---|
| Sysmon 實際記錄數 | $(Fmt $sysmonTotal 'N0') |
| Agent ingested / dropped | $(Fmt $result.agent_ingested 'N0') / $(Fmt $result.agent_dropped 'N0')（agent_health 計數模式：$($result.health_counter_mode)） |
| 丟包率（dropped / ingested） | $(if ($null -ne $dropRate) { '{0:P3}' -f $dropRate } else { '—' }) |
| 端到端遺失（1 − ingested / Sysmon 記錄數） | $(if ($null -ne $e2eLoss) { '{0:P3}' -f $e2eLoss } else { '—' }) |
| CairnAgent CPU P95（歸一化） | $(Fmt $cpuP95) % |
| Private Bytes 斜率 | $(Fmt $slopeMem) MB/hr |
| Handle Count 斜率 | $(Fmt $slopeHnd) /hr |
| queue_depth P95 | $(Fmt $qP95 'N0')（$(Fmt $qP95Pct) % of $QueueCapacity） |
| 佇列排空時間 | $(Fmt $drainSec 'N1') s |
| 產生器操作數 / 錯誤 | $($state.Ops) / $($state.Errors) |

## 門檻判定

| 檢查 | 結果 |
|---|---|
$rows

> 高價值事件（EID 1/8/10）丟包率須為 0%：請檢視 JSON 報表中 health_get 的分優先級丟包分項。
"@
Set-Content -LiteralPath $OutputPath -Value $md -Encoding UTF8
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath ([IO.Path]::ChangeExtension($OutputPath, '.json')) -Encoding UTF8
Write-Host $md
Write-Host "報表：$OutputPath"
Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
$failedChecks = @($checks.Values | Where-Object { -not $_ }).Count
exit ([int]($failedChecks -gt 0))
