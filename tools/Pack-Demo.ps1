#Requires -Version 5.1
<#
.SYNOPSIS
    打包 demo 交付物：cairn-m0.zip（約 40 MB）與 cairn-m0-model.zip（約 2 GB）（W4-8）。

.DESCRIPTION
    cairn-m0.zip
      build\src\svc\CairnAgent.exe、build\src\ui\CairnConsole.exe（Release 建置）
      build\src\...\*.dll         建置輸出內的 DLL
      redist\                     MFC + VC++ 執行期（app-local DLL 與 vc_redist.x64.exe；M0 採 /MD 動態連結，part4 §4.1.2）
      MicrosoftEdgeWebview2Setup.exe   WebView2 Evergreen Bootstrapper
      rules\  config\  tools\（Install-Dev / Check-Prereqs / Invoke-Rpc / 驗收腳本 / lib）
      demo\                       demo 素材（ransom-sim.ps1、README）
      PREREQ.md  DEMO-SCRIPT.md  SHA256SUMS.txt
    cairn-m0-model.zip
      llama.cpp\llama-server.exe 與其 DLL、llama.cpp\models\<gguf>、SHA256SUMS.txt
      （解壓後把 cairn-m0-model\llama.cpp 整個目錄移到 C:\Tools\llama.cpp）

    ⚠ Sysmon 依授權限制「不打包散佈」（part4 §4.5），由測試方依 PREREQ.md 自行安裝。
    ⚠ 安裝目錄解壓後執行：.\tools\Install-Dev.ps1 -BuildDir .\build

    -DemoAssets 另在本機建立 C:\DemoData（300 個 .docx/.jpg 假檔，供 demo 攻擊鏈 B）。
    demo-macro.docm 與 stage2.exe 不由本腳本產生，見 docs\DEMO-SCRIPT.md「素材準備」。

.PARAMETER BuildDir
    預設 <repo>\build\x64-release。

.PARAMETER OutDir
    預設 <repo>\dist。

.PARAMETER LlamaDir
    llama.cpp 目錄，預設 C:\Tools\llama.cpp。

.PARAMETER ModelPath
    預設 <LlamaDir>\models\qwen2.5-3b-instruct-q4_k_m.gguf。

.PARAMETER WebView2Bootstrapper
    本機的 MicrosoftEdgeWebview2Setup.exe；省略時從 Microsoft 官方連結下載。

.PARAMETER SkipModel
    不產生 cairn-m0-model.zip。

.PARAMETER DemoAssets
    在本機建立 C:\DemoData 測試檔案。

.EXAMPLE
    .\tools\Pack-Demo.ps1

.EXAMPLE
    .\tools\Pack-Demo.ps1 -SkipModel -WebView2Bootstrapper D:\MicrosoftEdgeWebview2Setup.exe
#>
[CmdletBinding()]
param(
    [string]$BuildDir,
    [string]$OutDir,
    [string]$LlamaDir = 'C:\Tools\llama.cpp',
    [string]$ModelPath,
    [string]$WebView2Bootstrapper,
    [switch]$SkipModel,
    [switch]$DemoAssets
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repo = Get-CairnRepoRoot
if (-not $BuildDir) { $BuildDir = Join-Path $repo 'build\x64-release' }
if (-not $OutDir) { $OutDir = Join-Path $repo 'dist' }
if (-not $ModelPath) { $ModelPath = Join-Path $LlamaDir 'models\qwen2.5-3b-instruct-q4_k_m.gguf' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# entries：List of [pscustomobject]@{ Src = 檔案完整路徑; Dst = zip 內相對路徑 }
function Add-Entry($list, [string]$Src, [string]$Dst) {
    if (-not (Test-Path -LiteralPath $Src -PathType Leaf)) { throw "缺少檔案：$Src" }
    $list.Add([pscustomobject]@{ Src = (Resolve-Path -LiteralPath $Src).Path; Dst = $Dst.Replace('\', '/') })
}
function Add-Tree($list, [string]$SrcDir, [string]$DstPrefix, [string[]]$Include = @('*')) {
    if (-not (Test-Path -LiteralPath $SrcDir)) { throw "缺少目錄：$SrcDir" }
    $base = (Resolve-Path -LiteralPath $SrcDir).Path.TrimEnd('\')
    Get-ChildItem -LiteralPath $base -Recurse -File -Include $Include | ForEach-Object {
        Add-Entry $list $_.FullName (Join-Path $DstPrefix $_.FullName.Substring($base.Length + 1))
    }
}

function New-Zip([string]$ZipPath, $Entries, [string]$Root) {
    # 直接串流寫入 ZipArchive（不建暫存目錄；>2 GB 由 .NET 4.5+ 的 Zip64 處理，PS 5.1 的 Compress-Archive 有 2 GB 限制）
    if (Test-Path $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    $sums = New-Object System.Text.StringBuilder
    $fs = [IO.File]::Open($ZipPath, [IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($e in $Entries) {
                $level = if ($e.Src -match '\.(gguf|zip|exe)$' -and (Get-Item -LiteralPath $e.Src).Length -gt 100MB) { [System.IO.Compression.CompressionLevel]::NoCompression } else { [System.IO.Compression.CompressionLevel]::Optimal }
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $e.Src, "$Root/$($e.Dst)", $level)
                $h = (Get-FileHash -LiteralPath $e.Src -Algorithm SHA256).Hash
                [void]$sums.AppendLine("$h  $($e.Dst)")
                Write-Host "  + $($e.Dst)"
            }
            $sumEntry = $zip.CreateEntry("$Root/SHA256SUMS.txt")
            $w = New-Object System.IO.StreamWriter($sumEntry.Open(), (New-Object System.Text.UTF8Encoding($false)))
            try { $w.Write($sums.ToString()) } finally { $w.Dispose() }
        } finally { $zip.Dispose() }
    } finally { $fs.Dispose() }
    $mb = (Get-Item -LiteralPath $ZipPath).Length / 1MB
    Write-Host ("已產生 {0}（{1:N1} MB）" -f $ZipPath, $mb) -ForegroundColor Green
    return $mb
}

# ============================================================
# cairn-m0.zip
# ============================================================
Write-Section 'cairn-m0.zip'
$app = New-Object System.Collections.Generic.List[object]
$agent = Join-Path $BuildDir 'src\svc\CairnAgent.exe'
$console = Join-Path $BuildDir 'src\ui\CairnConsole.exe'
if (-not (Test-Path $agent)) { throw "找不到 $agent。請先建置 Release：cmake --preset x64-release; cmake --build --preset x64-release" }
Add-Entry $app $agent 'build\src\svc\CairnAgent.exe'
Add-Entry $app $console 'build\src\ui\CairnConsole.exe'
foreach ($d in @('src\svc', 'src\ui')) {
    Get-ChildItem -LiteralPath (Join-Path $BuildDir $d) -Filter *.dll -File -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Entry $app $_.FullName "build\$d\$($_.Name)" }
}

# MFC + VC++ 執行期（/MD）：VCToolsRedistDir 只在 VS Developer 環境中存在
$redist = $env:VCToolsRedistDir
if (-not $redist) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products * -property installationPath
    $cand = @(Get-ChildItem (Join-Path $vs 'VC\Redist\MSVC') -Directory -ErrorAction SilentlyContinue | Where-Object Name -match '^14\.' | Sort-Object Name -Descending)
    if ($cand.Count) { $redist = $cand[0].FullName }
}
if (-not $redist) { throw '找不到 VC++ Redist 目錄。請在 VS Developer PowerShell（Enter-VsDevShell）中執行本腳本。' }
foreach ($sub in @('x64\Microsoft.VC143.CRT', 'x64\Microsoft.VC143.MFC')) {
    $p = Join-Path $redist $sub
    if (Test-Path $p) { Get-ChildItem -LiteralPath $p -Filter *.dll -File | ForEach-Object { Add-Entry $app $_.FullName "redist\$($_.Name)" } }
    else { Write-Warning "找不到 $p（未安裝 MFC 元件？）" }
}
$vcr = Join-Path $redist 'vc_redist.x64.exe'
if (Test-Path $vcr) { Add-Entry $app $vcr 'redist\vc_redist.x64.exe' }

# WebView2 Bootstrapper
if (-not $WebView2Bootstrapper) {
    $WebView2Bootstrapper = Join-Path $OutDir 'MicrosoftEdgeWebview2Setup.exe'
    if (-not (Test-Path $WebView2Bootstrapper)) {
        Write-Host '下載 WebView2 Evergreen Bootstrapper ...'
        Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $WebView2Bootstrapper -UseBasicParsing
    }
}
$sig = Get-AuthenticodeSignature -FilePath $WebView2Bootstrapper
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') { throw "WebView2 Bootstrapper 簽章無效：$($sig.Status)" }
Add-Entry $app $WebView2Bootstrapper 'MicrosoftEdgeWebview2Setup.exe'

Add-Tree $app (Join-Path $repo 'rules') 'rules' @('*.yaml', '*.json')
Add-Entry $app (Join-Path $repo 'config\sysmon.xml') 'config\sysmon.xml'
Add-Entry $app (Join-Path $repo 'config\policy.default.json') 'config\policy.default.json'
foreach ($t in 'Install-Dev.ps1', 'Check-Prereqs.ps1', 'Invoke-Rpc.ps1', 'Run-Acceptance.ps1', 'Run-AtomicSuite.ps1', 'Measure-Latency.ps1',
               'Export-FpReport.ps1', 'Load-Test.ps1', 'New-ReadabilityQuiz.ps1', 'Test-Narrative.ps1', 'Test-PromptInjection.ps1') {
    $p = Join-Path $PSScriptRoot $t
    if (Test-Path $p) { Add-Entry $app $p "tools\$t" } else { Write-Warning "略過不存在的 tools\$t" }
}
Add-Tree $app (Join-Path $PSScriptRoot 'lib') 'tools\lib'
$fixtures = Join-Path $repo 'tests\fixtures\prompt-injection'
if (Test-Path $fixtures) { Add-Tree $app $fixtures 'tests\fixtures\prompt-injection' }
Add-Entry $app (Join-Path $repo 'docs\PREREQ.md') 'PREREQ.md'
Add-Entry $app (Join-Path $repo 'docs\DEMO-SCRIPT.md') 'DEMO-SCRIPT.md'

# demo 素材：勒索模擬腳本（只作用於 C:\DemoData）
$demoDir = Join-Path $OutDir 'demo-staging'
New-Item -ItemType Directory -Force -Path $demoDir | Out-Null
$ransom = @'
#Requires -Version 5.1
<#
.SYNOPSIS  Cairn demo 攻擊鏈 B 的勒索模擬（無害：只改寫 C:\DemoData 內的假檔）。
.DESCRIPTION
  對 C:\DemoData 下的檔案逐一寫出 <名稱>.locked（內容為原檔 XOR 後的位元組）並刪除原檔，
  觸發 R-T1486-001（高速改寫 + 刪原檔）。-WithVss 另執行 vssadmin delete shadows（R-T1490-001），
  ⚠ 會真的刪除本機陰影複製，只能在快照 VM 使用。
#>
param([switch]$WithVss, [int]$DelayMs = 50)
$ErrorActionPreference = 'Stop'
$root = 'C:\DemoData'
if (-not (Test-Path $root)) { throw "找不到 $root（先執行 Pack-Demo.ps1 -DemoAssets）" }
Get-ChildItem -LiteralPath $root -File | Where-Object Extension -ne '.locked' | ForEach-Object {
    $b = [IO.File]::ReadAllBytes($_.FullName)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor 0x5A }
    [IO.File]::WriteAllBytes($_.FullName + '.locked', $b)
    Remove-Item -LiteralPath $_.FullName -Force
    Start-Sleep -Milliseconds $DelayMs
}
Set-Content -LiteralPath (Join-Path $root 'README-RESTORE.txt') -Value 'Cairn demo：這是勒索信的模擬檔。'
if ($WithVss) { & vssadmin.exe delete shadows /all /quiet }
'@
Set-Content -LiteralPath (Join-Path $demoDir 'ransom-sim.ps1') -Value $ransom -Encoding UTF8
Add-Entry $app (Join-Path $demoDir 'ransom-sim.ps1') 'demo\ransom-sim.ps1'

$appMb = New-Zip (Join-Path $OutDir 'cairn-m0.zip') $app 'cairn-m0'
if ($appMb -gt 150) { Write-Warning ("cairn-m0.zip {0:N0} MB 超過 M0-P9「Agent 安裝 ≤ 150 MB」" -f $appMb) }

# ============================================================
# cairn-m0-model.zip
# ============================================================
if (-not $SkipModel) {
    Write-Section 'cairn-m0-model.zip'
    $mod = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path $ModelPath)) { throw "找不到模型 $ModelPath（-SkipModel 可略過）" }
    Add-Entry $mod $ModelPath ("llama.cpp\models\" + (Split-Path -Leaf $ModelPath))
    $srv = Join-Path $LlamaDir 'llama-server.exe'
    if (-not (Test-Path $srv)) { throw "找不到 $srv" }
    Add-Entry $mod $srv 'llama.cpp\llama-server.exe'
    Get-ChildItem -LiteralPath $LlamaDir -Filter *.dll -File | ForEach-Object { Add-Entry $mod $_.FullName "llama.cpp\$($_.Name)" }
    $lic = Join-Path $LlamaDir 'LICENSE'
    if (Test-Path $lic) { Add-Entry $mod $lic 'llama.cpp\LICENSE' }
    [void](New-Zip (Join-Path $OutDir 'cairn-m0-model.zip') $mod 'cairn-m0-model')
}

# ============================================================
# demo 測試資料（本機）
# ============================================================
if ($DemoAssets) {
    Write-Section '建立 C:\DemoData（300 個假檔）'
    $root = 'C:\DemoData'
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $rnd = New-Object Random 42
    for ($i = 1; $i -le 300; $i++) {
        $ext = if ($i % 2) { 'docx' } else { 'jpg' }
        $buf = New-Object byte[] (4096 + $rnd.Next(0, 8192))
        $rnd.NextBytes($buf)
        [IO.File]::WriteAllBytes((Join-Path $root ("document-{0:D3}.{1}" -f $i, $ext)), $buf)
    }
    Write-Host "已建立 $root（300 檔）。攻擊鏈 B：powershell -ExecutionPolicy Bypass -File demo\ransom-sim.ps1 [-WithVss]"
}
Remove-Item -LiteralPath $demoDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host '完成。Sysmon 不在包內，請依 PREREQ.md 安裝。'
exit 0
