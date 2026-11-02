#Requires -Version 5.1
<#
.SYNOPSIS
    Cairn 工具腳本共用函式庫（tools\*.ps1 以 Import-Module 載入）。

.DESCRIPTION
    集中以下各腳本都需要的能力，避免每支腳本各寫一份而分歧：
      - 路徑：資料目錄 %ProgramData%\Cairn、DB 路徑、repo 根目錄
      - 權限：系統管理員檢查
      - SQLite：以 sqlite3 CLI 唯讀查詢 cairn.db，回傳 PSObject（需 sqlite3 >= 3.33 的 -json）
      - JSON-RPC：Named Pipe \\.\pipe\Cairn\rpc 客戶端（4-byte LE 長度前綴，SDD-03 §9.4.2）
      - 統計：百分位數、線性回歸斜率

    單位約定（CONVENTIONS / part2 §2.3.2）：
      - DB 時間欄位 ts 為 Unix epoch 毫秒（UTC）
      - 分數欄位為 milli-point（80 分 = 80000）
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# 路徑
# ------------------------------------------------------------
function Get-CairnRepoRoot {
    <# .SYNOPSIS 回傳 repo 根目錄（tools 的上一層）。 #>
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Get-CairnDataDir {
    <# .SYNOPSIS 回傳 %ProgramData%\Cairn（CONVENTIONS C-2.2 資料目錄）。 #>
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    return (Join-Path $base 'Cairn')
}

function Get-CairnDbPath {
    <# .SYNOPSIS 回傳 %ProgramData%\Cairn\cairn.db。 #>
    return (Join-Path (Get-CairnDataDir) 'cairn.db')
}

function Get-UnixMs {
    <# .SYNOPSIS 目前時間（或指定時間）的 Unix epoch 毫秒。 #>
    param([datetime]$At = [datetime]::UtcNow)
    return [DateTimeOffset]::new($At.ToUniversalTime()).ToUnixTimeMilliseconds()
}

function ConvertFrom-UnixMs {
    param([Parameter(Mandatory)][long]$Ms)
    return [DateTimeOffset]::FromUnixTimeMilliseconds($Ms).UtcDateTime
}

# ------------------------------------------------------------
# 權限
# ------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    <# .SYNOPSIS 非系統管理員時以明確訊息終止。 #>
    param([string]$Why = '此腳本')
    if (-not (Test-IsAdmin)) {
        throw "$Why 需要系統管理員權限。請以「以系統管理員身分執行」開啟 PowerShell 後重試。"
    }
}

# ------------------------------------------------------------
# SQLite（唯讀）
# ------------------------------------------------------------
function Get-Sqlite3Path {
    $cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command sqlite3 -ErrorAction SilentlyContinue }
    if (-not $cmd) {
        throw '找不到 sqlite3 CLI。修復：winget install --id SQLite.SQLite -e，然後重開 PowerShell。'
    }
    return $cmd.Source
}

function Invoke-CairnSql {
    <#
    .SYNOPSIS
        以唯讀方式對 cairn.db 執行一條 SELECT，回傳 PSObject 陣列（空結果回傳空陣列）。
    .PARAMETER Query
        SQL。僅允許查詢；本函式以 -readonly 開啟，任何寫入都會被 SQLite 拒絕。
    .PARAMETER DbPath
        預設 %ProgramData%\Cairn\cairn.db。
    .NOTES
        part1 M-01：「以唯讀模式直接開啟 cairn.db」。WAL 模式下唯讀連線仍需能讀寫 -shm，
        因此以系統管理員執行最穩（%ProgramData%\Cairn 的 ACL 排除一般使用者寫入）。
    #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$DbPath = (Get-CairnDbPath)
    )
    if (-not (Test-Path -LiteralPath $DbPath)) {
        throw "找不到資料庫：$DbPath（服務是否已安裝並啟動過？）"
    }
    $sqlite = Get-Sqlite3Path
    # sqlite3 以 UTF-8 輸出；PowerShell 依 [Console]::OutputEncoding 解碼原生程式輸出，
    # 繁中 Windows 預設為 CP950，不切換會讓中文與非 ASCII 路徑變亂碼。
    # stderr 不合併（PS 5.1 在 $ErrorActionPreference='Stop' 下合併 stderr 會變成終止錯誤），
    # 失敗以離開碼判斷，錯誤訊息直接顯示在主控台。
    $prevEnc = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $out = & $sqlite -readonly -json -cmd '.timeout 5000' $DbPath $Query
        $code = $LASTEXITCODE
    } finally {
        [Console]::OutputEncoding = $prevEnc
    }
    if ($code -ne 0) {
        throw "sqlite3 查詢失敗（exit=$code）。SQL: $Query"
    }
    $text = ($out | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }
    $rows = $text | ConvertFrom-Json
    return @($rows)
}

function Get-CairnScalar {
    param([Parameter(Mandatory)][string]$Query, [string]$DbPath = (Get-CairnDbPath))
    $r = @(Invoke-CairnSql -Query $Query -DbPath $DbPath)
    if ($r.Count -eq 0) { return $null }
    $first = $r[0]
    $prop = @($first.PSObject.Properties)[0]
    return $prop.Value
}

function ConvertTo-SqlString {
    <# .SYNOPSIS SQL 字串常值跳脫（單引號加倍）。僅供工具腳本組查詢使用。 #>
    param([AllowEmptyString()][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

# ------------------------------------------------------------
# JSON-RPC over Named Pipe（SDD-03 §9.4）
# ------------------------------------------------------------
$script:RpcNextId = 1
$script:RpcMaxMessage = 1MB

function Read-PipeExact {
    param([System.IO.Stream]$Stream, [int]$Count, [int]$TimeoutMs)
    $buf = New-Object byte[] $Count
    $off = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($off -lt $Count) {
        $remain = [Math]::Max(1, $TimeoutMs - [int]$sw.ElapsedMilliseconds)
        $task = $Stream.ReadAsync($buf, $off, $Count - $off)
        if (-not $task.Wait($remain)) {
            throw "RPC 讀取逾時（$TimeoutMs ms）"
        }
        $n = $task.Result
        if ($n -le 0) { throw 'RPC 連線被服務端關閉（讀到 EOF）' }
        $off += $n
    }
    return ,$buf
}

function Invoke-CairnRpcCall {
    <#
    .SYNOPSIS
        送出一則 JSON-RPC 2.0 請求並回傳完整回應物件（含 result 或 error）。
    .PARAMETER Method
        例如 health.get、alerts.list（SDD-03 §9.3.2）。
    .PARAMETER Params
        hashtable 或 PSObject，序列化為 params。
    #>
    param(
        [Parameter(Mandatory)][string]$Method,
        $Params = $null,
        [int]$TimeoutMs = 5000,
        [string]$PipeName = 'Cairn\rpc'
    )
    $id = $script:RpcNextId
    $script:RpcNextId++

    $req = [ordered]@{ jsonrpc = '2.0'; id = $id; method = $Method }
    if ($null -ne $Params) { $req.params = $Params } else { $req.params = @{} }
    $json  = $req | ConvertTo-Json -Depth 20 -Compress
    $body  = [Text.Encoding]::UTF8.GetBytes($json)
    if ($body.Length -gt $script:RpcMaxMessage) { throw "請求超過 1 MiB 上限（$($body.Length) bytes）" }
    $hdr   = [BitConverter]::GetBytes([uint32]$body.Length)
    if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($hdr) }

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        try {
            $pipe.Connect([Math]::Min($TimeoutMs, 5000))
        } catch [TimeoutException] {
            throw "無法連上 \\.\pipe\$PipeName（服務未啟動？請檢查 sc.exe query CairnAgent）"
        }
        $pipe.Write($hdr, 0, 4)
        $pipe.Write($body, 0, $body.Length)
        $pipe.Flush()

        $lenBytes = Read-PipeExact -Stream $pipe -Count 4 -TimeoutMs $TimeoutMs
        if (-not [BitConverter]::IsLittleEndian) { [Array]::Reverse($lenBytes) }
        $len = [BitConverter]::ToUInt32($lenBytes, 0)
        if ($len -gt $script:RpcMaxMessage) { throw "回應長度 $len 超過 1 MiB 上限，拒絕讀取" }
        if ($len -eq 0) { throw 'RPC 回應長度為 0' }
        $respBytes = Read-PipeExact -Stream $pipe -Count ([int]$len) -TimeoutMs $TimeoutMs
        $respText  = [Text.Encoding]::UTF8.GetString($respBytes)
        $resp = $respText | ConvertFrom-Json
        if ($resp.PSObject.Properties.Name -contains 'id' -and $resp.id -ne $id) {
            throw "JSON-RPC id 不符：送出 $id，收到 $($resp.id)"
        }
        return $resp
    } finally {
        $pipe.Dispose()
    }
}

function Invoke-CairnRpc {
    <#
    .SYNOPSIS
        呼叫 RPC 並只回傳 result；服務回傳 error 時拋出例外（訊息含 code 與 message）。
    #>
    param(
        [Parameter(Mandatory)][string]$Method,
        $Params = $null,
        [int]$TimeoutMs = 5000
    )
    $resp = Invoke-CairnRpcCall -Method $Method -Params $Params -TimeoutMs $TimeoutMs
    if ($resp.PSObject.Properties.Name -contains 'error' -and $null -ne $resp.error) {
        $e = $resp.error
        $data = ''
        if ($e.PSObject.Properties.Name -contains 'data' -and $null -ne $e.data) {
            $data = ' data=' + ($e.data | ConvertTo-Json -Depth 10 -Compress)
        }
        throw "RPC $Method 失敗：code=$($e.code) message=$($e.message)$data"
    }
    return $resp.result
}

# ------------------------------------------------------------
# 統計
# ------------------------------------------------------------
function Get-Percentile {
    <# .SYNOPSIS 最近秩（nearest-rank）百分位數。空集合回傳 $null。 #>
    param([double[]]$Values, [double]$P)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $rank = [Math]::Ceiling(($P / 100.0) * $sorted.Count)
    $idx = [Math]::Min([Math]::Max([int]$rank - 1, 0), $sorted.Count - 1)
    return [double]$sorted[$idx]
}

function Get-LinearSlope {
    <# .SYNOPSIS 最小平方法斜率（y 對 x）。點數 < 2 回傳 $null。 #>
    param([double[]]$X, [double[]]$Y)
    $n = $X.Count
    if ($n -lt 2 -or $Y.Count -ne $n) { return $null }
    $mx = ($X | Measure-Object -Average).Average
    $my = ($Y | Measure-Object -Average).Average
    $num = 0.0; $den = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $num += ($X[$i] - $mx) * ($Y[$i] - $my)
        $den += ($X[$i] - $mx) * ($X[$i] - $mx)
    }
    if ($den -eq 0) { return $null }
    return $num / $den
}

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host "== $Text ==" -ForegroundColor Cyan
}

Export-ModuleMember -Function `
    Get-CairnRepoRoot, Get-CairnDataDir, Get-CairnDbPath, Get-UnixMs, ConvertFrom-UnixMs, `
    Test-IsAdmin, Assert-Admin, Get-Sqlite3Path, Invoke-CairnSql, Get-CairnScalar, ConvertTo-SqlString, `
    Invoke-CairnRpcCall, Invoke-CairnRpc, Get-Percentile, Get-LinearSlope, Write-Section
