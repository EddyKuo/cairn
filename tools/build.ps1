<#
.SYNOPSIS
    一鍵 configure / build / test（自動載入 vcvars64，不需先開開發者命令列）。

.DESCRIPTION
    以 vswhere 找出含 C++ 工具的 Visual Studio 安裝並套用 vcvars64 環境，再依 CMakePresets.json 執行
    configure → build → ctest。build 目錄沒有 CMakeCache.txt 時自動 configure。
    ninja 不在 PATH 時會嘗試 winget 安裝位置。

.PARAMETER Preset
    CMake preset 名稱（x64-debug | x64-release | x64-asan）。預設 x64-debug。

.PARAMETER NoTest
    只建置，不跑 ctest。

.PARAMETER Reconfigure
    以 cmake --fresh 重新 configure（捨棄既有 CMakeCache）。CMakeLists / vcpkg.json 改動後使用。

.PARAMETER WebUi
    先建置 ui-web（npm ci + npm run build）。CairnConsole.exe 內嵌 ui-web/dist，改前端後需加此參數。

.EXAMPLE
    pwsh tools\build.ps1
.EXAMPLE
    pwsh tools\build.ps1 -Preset x64-asan -Reconfigure
.EXAMPLE
    pwsh tools\build.ps1 -WebUi -NoTest
#>
param(
    [ValidateSet('x64-debug', 'x64-release', 'x64-asan')]
    [string]$Preset = 'x64-debug',
    [switch]$NoTest,
    [switch]$Reconfigure,
    [switch]$WebUi
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

# --- MSVC 環境 ---
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "找不到 vswhere.exe：$vswhere" }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { throw '找不到含 C++ 工具的 Visual Studio 安裝' }
$vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "找不到 vcvars64.bat：$vcvars" }
cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
}

# --- ninja（vcvars 不一定帶入；winget 安裝的 ninja 不在預設 PATH）---
if (-not (Get-Command ninja -ErrorAction SilentlyContinue)) {
    $wingetNinja = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter ninja.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($wingetNinja) { $env:PATH = "$($wingetNinja.DirectoryName);$env:PATH" }
    else { throw '找不到 ninja：請安裝（winget install Ninja-build.Ninja）或加入 PATH' }
}

function Invoke-Step([string]$Title, [scriptblock]$Body) {
    Write-Host "== $Title" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE) { throw "$Title 失敗（exit $LASTEXITCODE）" }
}

Push-Location $repo
try {
    if ($WebUi) {
        Push-Location ui-web
        try {
            Invoke-Step 'ui-web: npm ci' { npm ci --no-audit --no-fund }
            Invoke-Step 'ui-web: npm run build' { npm run build }
        } finally { Pop-Location }
    }

    if ($Reconfigure) {
        Invoke-Step "configure $Preset (--fresh)" { cmake --preset $Preset --fresh }
    } elseif (-not (Test-Path "build\$Preset\CMakeCache.txt")) {
        Invoke-Step "configure $Preset" { cmake --preset $Preset }
    }

    Invoke-Step "build $Preset" { cmake --build --preset $Preset }

    if (-not $NoTest) {
        Invoke-Step "test $Preset" { ctest --preset $Preset --output-on-failure }
    }
} finally {
    Pop-Location
}
