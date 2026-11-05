#Requires -Version 5.1
<#
.SYNOPSIS
    一鍵驗證 Cairn M0 開發／測試環境（part4 §4.1.3；每位開發者與每台測試機的第一道關卡）。

.DESCRIPTION
    逐項檢查 part4 §4.1.3 的清單，每項輸出 [OK] / [WARN] / [FAIL] 與修復指令。
    任一 FAIL → 離開碼 1；只有 WARN → 離開碼 0（但請讀完警告）。

    -Role Dev（預設）：檢查完整建置工具鏈（MSVC + MFC、Windows SDK、CMake、vcpkg、Node）。
    -Role Test       ：只檢查執行期需求（Sysmon、WebView2 Runtime、llama-server、模型、sqlite3）。

.PARAMETER Role
    Dev 或 Test。

.PARAMETER LlamaDir
    llama.cpp 解壓目錄，預設 C:\Tools\llama.cpp（part4 §4.1.2 Step 5）。

.PARAMETER ModelPath
    .gguf 模型路徑。預設 <LlamaDir>\models\qwen2.5-3b-instruct-q4_k_m.gguf；
    無 GPU 時亦接受 qwen2.5-1.5b-instruct-q4_k_m.gguf（R-12）。

.PARAMETER SysmonConfig
    預期套用的 Sysmon 組態，預設 <repo>\config\sysmon.xml。

.EXAMPLE
    .\tools\Check-Prereqs.ps1
    # 離開碼 0 = W1 出場條件 1 通過

.EXAMPLE
    .\tools\Check-Prereqs.ps1 -Role Test -LlamaDir D:\llama
#>
[CmdletBinding()]
param(
    [ValidateSet('Dev', 'Test')][string]$Role = 'Dev',
    [string]$LlamaDir = 'C:\Tools\llama.cpp',
    [string]$ModelPath,
    [string]$SysmonConfig
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'lib\CairnTools.psm1') -Force

$repo = Get-CairnRepoRoot
if (-not $SysmonConfig) { $SysmonConfig = Join-Path $repo 'config\sysmon.xml' }
if (-not $ModelPath)    { $ModelPath    = Join-Path $LlamaDir 'models\qwen2.5-3b-instruct-q4_k_m.gguf' }

$script:results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Name, [ValidateSet('OK', 'WARN', 'FAIL')][string]$Status, [string]$Detail = '', [string]$Fix = '')
    $script:results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail; Fix = $Fix })
    $color = @{ OK = 'Green'; WARN = 'Yellow'; FAIL = 'Red' }[$Status]
    Write-Host ("[{0,-4}] {1}" -f $Status, $Name) -ForegroundColor $color -NoNewline
    if ($Detail) { Write-Host " — $Detail" } else { Write-Host '' }
    if ($Status -ne 'OK' -and $Fix) { Write-Host "         修復：$Fix" -ForegroundColor DarkGray }
}

function Invoke-Check {
    # 單項檢查失敗（例外）不得中斷整張清單。
    param([string]$Name, [scriptblock]$Body, [string]$Fix = '')
    try { & $Body } catch { Add-Result $Name 'FAIL' "檢查時發生例外：$($_.Exception.Message)" $Fix }
}

function Get-ChannelMaxBytes {
    param([string]$LogName)
    $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    return [long]$log.MaximumSizeInBytes
}

Write-Section "Cairn M0 前置檢查（Role=$Role）"

# 1. 系統管理員
Invoke-Check '目前為系統管理員' {
    if (Test-IsAdmin) { Add-Result '目前為系統管理員' 'OK' }
    else { Add-Result '目前為系統管理員' 'FAIL' '目前為一般權限' '以「以系統管理員身分執行」開啟 PowerShell 後重跑本腳本' }
}

if ($Role -eq 'Dev') {
    # 2. MSVC v143 + MFC
    Invoke-Check 'MSVC v143 工具鏈與 MFC 標頭' {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (-not (Test-Path $vswhere)) {
            Add-Result 'MSVC v143 工具鏈與 MFC 標頭' 'FAIL' '找不到 vswhere.exe（未安裝 Visual Studio 2022）' '依 part4 §4.1.2 Step 1 以 winget 安裝 VS2022（含 VC.ATLMFC 元件）'
            return
        }
        $vs = & $vswhere -latest -products * -version '[17.8,18.0)' `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if (-not $vs) {
            Add-Result 'MSVC v143 工具鏈與 MFC 標頭' 'FAIL' '找不到 VS2022 17.8+ 且含 VC.Tools.x86.x64' 'VS Installer → 修改 → 勾選「使用 C++ 的桌面開發」'
            return
        }
        $msvcRoot = Join-Path $vs 'VC\Tools\MSVC'
        $toolsets = @(Get-ChildItem $msvcRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^14\.(3|4)\d' } | Sort-Object Name -Descending)
        if ($toolsets.Count -eq 0) {
            Add-Result 'MSVC v143 工具鏈與 MFC 標頭' 'FAIL' "在 $msvcRoot 找不到 14.3x/14.4x（v143）" '安裝 MSVC v143 build tools'
            return
        }
        $afx = Join-Path $toolsets[0].FullName 'atlmfc\include\afxwin.h'
        if (Test-Path $afx) {
            Add-Result 'MSVC v143 工具鏈與 MFC 標頭' 'OK' "toolset $($toolsets[0].Name)"
        } else {
            Add-Result 'MSVC v143 工具鏈與 MFC 標頭' 'FAIL' "缺少 $afx（MFC 預設不安裝）" 'VS Installer → 個別元件 → 勾選「C++ MFC for latest v143 build tools (x86 & x64)」（Microsoft.VisualStudio.Component.VC.ATLMFC）'
        }
    } 'VS Installer 修復安裝'

    # 2b. MSVC ASan 元件（W1 出場條件 2 需要 x64-asan）
    Invoke-Check 'MSVC AddressSanitizer 元件' {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.ASAN -property installationPath
        if ($vs) { Add-Result 'MSVC AddressSanitizer 元件' 'OK' }
        else { Add-Result 'MSVC AddressSanitizer 元件' 'FAIL' '未安裝 VC.ASAN' 'VS Installer → 個別元件 → 「C++ AddressSanitizer」（Microsoft.VisualStudio.Component.VC.ASAN）' }
    }

    # 3. Windows SDK >= 10.0.22621.0
    Invoke-Check 'Windows SDK >= 10.0.22621.0' {
        $inc = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
        $vers = @(Get-ChildItem $inc -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^10\.0\.\d+\.\d+$' } | ForEach-Object { [version]$_.Name } | Sort-Object -Descending)
        if ($vers.Count -gt 0 -and $vers[0] -ge [version]'10.0.22621.0') {
            $sdk = $vers[0].ToString()
            # EvtSubscribe 的標頭是 winevt.h（wevtapi 只是匯入程式庫名，SDK 中沒有 wevtapi.h）
            $need = @('um\winevt.h', 'um\netfw.h', 'shared\bcrypt.h')
            $missing = @($need | Where-Object {
                    -not (Test-Path (Join-Path $inc "$sdk\$_")) -and -not (Test-Path (Join-Path $inc "$sdk\$($_ -replace '^shared','um')"))
                })
            if ($missing.Count -eq 0) { Add-Result 'Windows SDK >= 10.0.22621.0' 'OK' $sdk }
            else { Add-Result 'Windows SDK >= 10.0.22621.0' 'FAIL' "SDK $sdk 缺標頭：$($missing -join ', ')" '以 VS Installer 重新安裝 Windows 11 SDK (10.0.22621)' }
        } else {
            $have = 'none'
            if ($vers.Count -gt 0) { $have = $vers[0].ToString() }
            Add-Result 'Windows SDK >= 10.0.22621.0' 'FAIL' "目前最高：$have" 'VS Installer → 個別元件 → Windows 11 SDK (10.0.22621.0)'
        }
    }

    # 4. CMake >= 3.25 + VCPKG_ROOT
    Invoke-Check 'CMake >= 3.25 且 VCPKG_ROOT 已設定' {
        $cmake = Get-Command cmake -ErrorAction SilentlyContinue
        if (-not $cmake) {
            Add-Result 'CMake >= 3.25 且 VCPKG_ROOT 已設定' 'FAIL' 'PATH 中沒有 cmake' '在 VS Developer PowerShell 中執行（Enter-VsDevShell），或 winget install Kitware.CMake'
            return
        }
        $line = (& $cmake.Source --version | Select-Object -First 1)
        $ver = [version](($line -replace '^cmake version\s+', '') -replace '-.*$', '')
        $vcpkg = [Environment]::GetEnvironmentVariable('VCPKG_ROOT')
        if (-not $vcpkg) { $vcpkg = [Environment]::GetEnvironmentVariable('VCPKG_ROOT', 'Machine') }
        if ($ver -lt [version]'3.25') {
            Add-Result 'CMake >= 3.25 且 VCPKG_ROOT 已設定' 'FAIL' "cmake $ver" '升級 CMake 至 3.25+'
        } elseif (-not $vcpkg -or -not (Test-Path (Join-Path $vcpkg 'scripts\buildsystems\vcpkg.cmake'))) {
            Add-Result 'CMake >= 3.25 且 VCPKG_ROOT 已設定' 'FAIL' "cmake $ver；VCPKG_ROOT='$vcpkg' 無效" 'git clone https://github.com/microsoft/vcpkg C:\Tools\vcpkg; C:\Tools\vcpkg\bootstrap-vcpkg.bat; [Environment]::SetEnvironmentVariable("VCPKG_ROOT","C:\Tools\vcpkg","Machine")；重開 PowerShell'
        } else {
            Add-Result 'CMake >= 3.25 且 VCPKG_ROOT 已設定' 'OK' "cmake $ver；VCPKG_ROOT=$vcpkg"
        }
    }

    # 4b. Ninja（CMakePresets 使用 Ninja 產生器）
    Invoke-Check 'Ninja 產生器' {
        if (Get-Command ninja -ErrorAction SilentlyContinue) { Add-Result 'Ninja 產生器' 'OK' }
        else { Add-Result 'Ninja 產生器' 'FAIL' 'PATH 中沒有 ninja（CMakePresets 指定 Ninja）' '在 VS Developer PowerShell 中執行（VS 隨附 ninja），或 winget install Ninja-build.Ninja' }
    }

    # 6. Node 20
    Invoke-Check 'Node.js 20' {
        $node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $node) { Add-Result 'Node.js 20' 'FAIL' 'PATH 中沒有 node' 'winget install --id OpenJS.NodeJS.LTS -e'; return }
        $v = (& $node.Source --version).Trim()
        $major = [int](($v -replace '^v', '').Split('.')[0])
        if ($major -ge 20) { Add-Result 'Node.js 20' 'OK' $v }
        else { Add-Result 'Node.js 20' 'FAIL' $v 'winget install --id OpenJS.NodeJS.LTS -e' }
    }
}

# 5. WebView2 Runtime
Invoke-Check 'WebView2 Runtime 已安裝' {
    $guid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    $keys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$guid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid",
        "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$guid")
    $pv = $null
    foreach ($k in $keys) {
        $p = Get-ItemProperty -Path $k -Name pv -ErrorAction SilentlyContinue
        if ($p -and $p.pv -and $p.pv -ne '0.0.0.0') { $pv = $p.pv; break }
    }
    if ($pv) { Add-Result 'WebView2 Runtime 已安裝' 'OK' $pv }
    else { Add-Result 'WebView2 Runtime 已安裝' 'FAIL' '登錄檔中找不到 Evergreen Runtime' '下載並執行 https://go.microsoft.com/fwlink/p/?LinkId=2124703（Evergreen Bootstrapper）' }
}

# 7. Sysmon64 服務 Running
Invoke-Check 'Sysmon64 服務為 Running' {
    $svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-Result 'Sysmon64 服務為 Running' 'FAIL' '未安裝' "依 docs\PREREQ.md 安裝：Sysmon64.exe -accepteula -i `"$SysmonConfig`""
    } elseif ($svc.Status -ne 'Running') {
        Add-Result 'Sysmon64 服務為 Running' 'FAIL' "狀態 $($svc.Status)" 'Start-Service Sysmon64'
    } else {
        $ver = ''
        $drv = Get-Command Sysmon64.exe -ErrorAction SilentlyContinue
        $path = (Get-CimInstance Win32_Service -Filter "Name='Sysmon64'").PathName.Trim('"')
        if (Test-Path $path) { $ver = (Get-Item $path).VersionInfo.FileVersion }
        if ($ver -and ([version]($ver -replace '[^\d\.].*$', '')) -lt [version]'15.15') {
            Add-Result 'Sysmon64 服務為 Running' 'FAIL' "版本 $ver < 15.15（需 FileBlockExecutable / ProcessTampering）" '下載最新 Sysmon 並以 Sysmon64.exe -u 後重新 -i 安裝'
        } else {
            Add-Result 'Sysmon64 服務為 Running' 'OK' "版本 $ver"
        }
    }
}

# 8. Sysmon 通道 >= 1GB
Invoke-Check 'Sysmon 事件通道 maxSize >= 1GB' {
    $max = Get-ChannelMaxBytes 'Microsoft-Windows-Sysmon/Operational'
    if ($max -ge 1GB) { Add-Result 'Sysmon 事件通道 maxSize >= 1GB' 'OK' ("{0:N0} MB" -f ($max / 1MB)) }
    else { Add-Result 'Sysmon 事件通道 maxSize >= 1GB' 'FAIL' ("目前 {0:N0} MB" -f ($max / 1MB)) 'wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824' }
} '先安裝 Sysmon'

# 9. Sysmon 組態雜湊 == config\sysmon.xml（防組態漂移，R-07）
Invoke-Check 'Sysmon 組態與 config\sysmon.xml 一致' {
    if (-not (Test-Path $SysmonConfig)) {
        Add-Result 'Sysmon 組態與 config\sysmon.xml 一致' 'FAIL' "找不到 $SysmonConfig" '確認 repo 完整（config\sysmon.xml）'
        return
    }
    $fileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SysmonConfig).Hash
    # Sysmon 將目前套用組態的雜湊記在驅動參數的 ConfigHash（格式 "SHA256=XXXX"）。
    # 已在 Windows 驗證（Sysmon 15.21，2026-11-05）：ConfigHash 即 XML 原檔的 SHA256。
    $param = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters' -ErrorAction SilentlyContinue
    $applied = $null
    if ($param -and ($param.PSObject.Properties.Name -contains 'ConfigHash')) { $applied = [string]$param.ConfigHash }
    if (-not $applied) {
        Add-Result 'Sysmon 組態與 config\sysmon.xml 一致' 'WARN' '讀不到 SysmonDrv\Parameters\ConfigHash' "Sysmon64.exe -c `"$SysmonConfig`""
    } elseif ($applied -match $fileHash) {
        Add-Result 'Sysmon 組態與 config\sysmon.xml 一致' 'OK' "SHA256=$($fileHash.Substring(0,16))…"
    } else {
        Add-Result 'Sysmon 組態與 config\sysmon.xml 一致' 'FAIL' "已套用 $applied ≠ 檔案 SHA256=$fileHash" "Sysmon64.exe -c `"$SysmonConfig`""
    }
}

# 10. llama-server 與模型
Invoke-Check 'llama-server 可執行檔與 .gguf 模型存在' {
    $exe = Join-Path $LlamaDir 'llama-server.exe'
    $alt = Join-Path (Split-Path $ModelPath) 'qwen2.5-1.5b-instruct-q4_k_m.gguf'
    if (-not (Test-Path $exe)) {
        Add-Result 'llama-server 可執行檔與 .gguf 模型存在' 'FAIL' "找不到 $exe" '依 docs\PREREQ.md §4 下載 llama.cpp release 並解壓至 C:\Tools\llama.cpp'
    } elseif (Test-Path $ModelPath) {
        Add-Result 'llama-server 可執行檔與 .gguf 模型存在' 'OK' (Split-Path $ModelPath -Leaf)
    } elseif (Test-Path $alt) {
        Add-Result 'llama-server 可執行檔與 .gguf 模型存在' 'WARN' '僅有 1.5B 降級模型（R-12）' '有獨顯時建議改用 3B 模型'
    } else {
        Add-Result 'llama-server 可執行檔與 .gguf 模型存在' 'FAIL' "找不到 $ModelPath" 'hf download Qwen/Qwen2.5-3B-Instruct-GGUF qwen2.5-3b-instruct-q4_k_m.gguf --local-dir C:\Tools\llama.cpp\models'
    }
}

# 11. ScriptBlockLogging + PowerShell 通道 >= 256MB
Invoke-Check 'ScriptBlockLogging 已啟用且通道 >= 256MB' {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $v = Get-ItemProperty -Path $k -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    $max = Get-ChannelMaxBytes 'Microsoft-Windows-PowerShell/Operational'
    $fix = "New-Item -Path '$k' -Force | Out-Null; Set-ItemProperty -Path '$k' -Name EnableScriptBlockLogging -Value 1 -Type DWord; wevtutil sl `"Microsoft-Windows-PowerShell/Operational`" /ms:268435456"
    if (-not $v -or $v.EnableScriptBlockLogging -ne 1) {
        Add-Result 'ScriptBlockLogging 已啟用且通道 >= 256MB' 'FAIL' '未啟用（R-T1059-001 依賴 EID 4104）' $fix
    } elseif ($max -lt 256MB) {
        Add-Result 'ScriptBlockLogging 已啟用且通道 >= 256MB' 'FAIL' ("通道 {0:N0} MB" -f ($max / 1MB)) $fix
    } else {
        Add-Result 'ScriptBlockLogging 已啟用且通道 >= 256MB' 'OK'
    }
}

# 12. sqlite3 CLI
Invoke-Check 'sqlite3.exe 在 PATH 中（需支援 -json）' {
    $p = Get-Sqlite3Path
    $v = (& $p -version).Split(' ')[0]
    if ([version]$v -ge [version]'3.33.0') { Add-Result 'sqlite3.exe 在 PATH 中（需支援 -json）' 'OK' $v }
    else { Add-Result 'sqlite3.exe 在 PATH 中（需支援 -json）' 'FAIL' "版本 $v < 3.33（無 -json）" 'winget upgrade --id SQLite.SQLite -e' }
} 'winget install --id SQLite.SQLite -e'

# 13. Python 3.12（僅模型下載用 → WARN 等級）
Invoke-Check 'Python 3.12（僅下載模型用）' {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
    if (-not $py) { Add-Result 'Python 3.12（僅下載模型用）' 'WARN' '未安裝；若模型已下載可忽略' 'winget install --id Python.Python.3.12 -e'; return }
    $v = (& $py.Source --version 2>&1 | Out-String).Trim()
    if ($v -match '3\.12') { Add-Result 'Python 3.12（僅下載模型用）' 'OK' $v }
    else { Add-Result 'Python 3.12（僅下載模型用）' 'WARN' $v 'winget install --id Python.Python.3.12 -e' }
}

# 14. 可用 VRAM（決定 -ngl 99 / -ngl 0；R-12）
Invoke-Check '可用 VRAM' {
    $smi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if ($smi) {
        $mb = [int]((& $smi.Source --query-gpu=memory.total --format=csv,noheader,nounits | Select-Object -First 1).Trim())
        if ($mb -ge 6144) { Add-Result '可用 VRAM' 'OK' "$mb MB → llama-server 用 -ngl 99，模型 3B" }
        else { Add-Result '可用 VRAM' 'WARN' "$mb MB < 6 GB → 建議 -ngl 0 或 1.5B 模型" '' }
    } else {
        Add-Result '可用 VRAM' 'WARN' '無 NVIDIA GPU（或無 nvidia-smi）→ CPU 模式：-ngl 0，模型降級 1.5B（R-12）' ''
    }
}

# 15. %ProgramData%\Cairn 可寫入
Invoke-Check '%ProgramData%\Cairn 可寫入' {
    $dir = Get-CairnDataDir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $probe = Join-Path $dir (".prereq-probe-{0}.tmp" -f [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath $probe -Value 'ok' -Encoding ASCII
    Remove-Item -LiteralPath $probe -Force
    Add-Result '%ProgramData%\Cairn 可寫入' 'OK' $dir
} '以系統管理員身分執行；檢查 %ProgramData%\Cairn 的 ACL'

# ------------------------------------------------------------
$fails = @($script:results | Where-Object Status -eq 'FAIL')
$warns = @($script:results | Where-Object Status -eq 'WARN')
Write-Section '結果'
Write-Host ("OK={0}  WARN={1}  FAIL={2}" -f (@($script:results | Where-Object Status -eq 'OK').Count), $warns.Count, $fails.Count)
if ($fails.Count -gt 0) {
    Write-Host '環境未通過。請依上方「修復」指令處理後重跑。' -ForegroundColor Red
    exit 1
}
Write-Host '環境檢查通過。' -ForegroundColor Green
exit 0
