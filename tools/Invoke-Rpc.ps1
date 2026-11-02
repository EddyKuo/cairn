#Requires -Version 5.1
<#
.SYNOPSIS
    Cairn 的 Named Pipe JSON-RPC 命令列客戶端（W2-15；W2 起所有出場條件的驗證入口）。

.DESCRIPTION
    連線 \\.\pipe\Cairn\rpc，以 4-byte little-endian 長度前綴 + UTF-8 JSON-RPC 2.0 封包
    （SDD-03 §9.4.2）送出一則請求，回傳 result 物件（PSObject）。
    服務回傳 error 時預設拋出例外；加 -Raw 則回傳完整回應（含 error），不拋例外。

    可用方法見 SDD-03 §9.3.2（M0 註冊 27 條），例如：
      health.get / alerts.list / alerts.get / narrative.get / narrative.regenerate /
      alerts.setVerdict / response.prepare / response.execute / response.revert /
      events.query / exclusions.list|add|remove|preview|suggestions|dismissSuggestion /
      rules.list / rules.setStatus / rules.explain / audit.list / quarantine.list / undo.apply /
      protection.pause|resume / learning.finish / narrative.feedback / export.create

.PARAMETER Method
    JSON-RPC 方法名。

.PARAMETER Params
    參數（hashtable）。省略時送出空物件 {}。

.PARAMETER TimeoutMs
    連線與讀取逾時，預設 5000 ms（對齊 part3 §3.8.0 的 pipe 逾時 5 秒）。

.PARAMETER Raw
    回傳完整 JSON-RPC 回應而非只取 result；error 不拋例外。

.PARAMETER Json
    以 JSON 字串輸出（方便貼進報告或交給 jq）。

.EXAMPLE
    .\tools\Invoke-Rpc.ps1 -Method health
    # 「health」是 health.get 的簡寫；回傳合法 JSON-RPC 2.0 回應的 result（W2 出場條件 3）

.EXAMPLE
    .\tools\Invoke-Rpc.ps1 -Method alerts.list -Params @{ limit = 10; sort = 'risk_desc' }

.EXAMPLE
    .\tools\Invoke-Rpc.ps1 -Method alerts.get -Params @{ id = 42 } -Json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Method,
    [Parameter(Position = 1)][hashtable]$Params = @{},
    [int]$TimeoutMs = 5000,
    [switch]$Raw,
    [switch]$Json
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

# 簡寫：沒有 '.' 的方法名一律補上 '.get'（health → health.get），對齊 part4 W2 出場條件的寫法。
if ($Method -notmatch '\.') { $Method = "$Method.get" }

if ($Raw) {
    $out = Invoke-CairnRpcCall -Method $Method -Params $Params -TimeoutMs $TimeoutMs
} else {
    $out = Invoke-CairnRpc -Method $Method -Params $Params -TimeoutMs $TimeoutMs
}

if ($Json) {
    $out | ConvertTo-Json -Depth 30
} else {
    $out
}
