# Cairn M0 — 執行前置需求（PREREQ）

> 版本：v0.1 · 2026-11-02 · 對應 part4 §4.1、§4.5
> 適用對象：拿到 `cairn-m0.zip` / `cairn-m0-model.zip` 的**測試方**（乾淨 Windows 11 VM）。
> 開發機的完整工具鏈（VS2022 + MFC、vcpkg、Node）見 [part4 §4.1.2](part4_plan.md) 與 [WINDOWS-FIRST-RUN.md](WINDOWS-FIRST-RUN.md)。

⚠ **M0 只能跑在隔離測試機上，嚴禁部署到有真實資料的環境**（part1 §6：SQLite 未加密、命令列未遮罩、無自我保護）。

以下所有指令都在**系統管理員 PowerShell** 中執行。

---

## 0. 環境

| 項目 | 需求 |
|---|---|
| OS | Windows 11 23H2 x64（或 Windows 10 22H2 19045+） |
| 功能驗收 VM | 4 vCPU / 8 GB RAM，**必須可還原快照** |
| GPU（選配） | NVIDIA ≥ 6 GB VRAM；無 GPU 時模型改用 1.5B（R-12） |
| Office | 任一含 Word 的版本（demo 攻擊鏈 A 與 W2 出場條件需要 `winword.exe`） |
| sqlite3 CLI | `winget install --id SQLite.SQLite -e`（驗收查詢與 `tools\*.ps1` 需要，版本 ≥ 3.33） |

---

## 1. Sysmon（不隨 Cairn 散佈，需自行安裝）

Sysinternals 散佈條款限制，Cairn 套件**不包含 Sysmon**。需要 **v15.15 以上**（FileBlockExecutable、ProcessTampering 事件）。

```powershell
$dst = 'C:\Tools\Sysmon'
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$dst\Sysmon.zip" -UseBasicParsing
Expand-Archive -Path "$dst\Sysmon.zip" -DestinationPath $dst -Force

# 確認簽章（必須是 Microsoft 簽署）
Get-AuthenticodeSignature "$dst\Sysmon64.exe" | Format-List Status, SignerCertificate

# 以 Cairn 調校過的組態安裝（路徑換成 cairn-m0 解壓位置）
& "$dst\Sysmon64.exe" -accepteula -i C:\cairn-m0\config\sysmon.xml

# 驗證
Get-Service Sysmon64
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 | Format-Table TimeCreated, Id
```

**已經裝有 Sysmon（例如 SOC 既有組態）**：Sysmon 組態是全域單一份，直接 `-c` 會覆蓋既有組態（R-07）。
請先與 IT 確認；M0 測試機建議使用專屬 VM。

日後更新組態（不需重裝）：

```powershell
& C:\Tools\Sysmon\Sysmon64.exe -c C:\cairn-m0\config\sysmon.xml
```

---

## 2. 事件通道容量

避免高負載時事件被輪替掉（R-02）：

```powershell
wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:1073741824      # 1 GB
wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456   # 256 MB
wevtutil gl 'Microsoft-Windows-Sysmon/Operational' | Select-String maxSize
```

---

## 3. PowerShell Script Block Logging（EID 4104）

`R-T1059-001`（M0 必備規則、ART 矩陣 #1）完全依賴 EID 4104，而它**預設關閉**：

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord
```

---

## 4. WebView2 Runtime

Windows 11 內建 Evergreen Runtime；Windows 10 或被移除時，執行套件內附的 Bootstrapper：

```powershell
C:\cairn-m0\MicrosoftEdgeWebview2Setup.exe /silent /install
```

驗證：`Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' pv`

---

## 5. VC++ 與 MFC 執行期

M0 採 `/MD` 動態連結（part4 §4.1.2）。套件 `redist\` 內附：

- `vc_redist.x64.exe`：系統層安裝（建議）
  ```powershell
  C:\cairn-m0\redist\vc_redist.x64.exe /install /quiet /norestart
  ```
- `mfc140u.dll` 等 app-local DLL：`Install-Dev.ps1` 會與執行檔放在同一目錄。若 `CairnConsole.exe` 啟動時報「找不到 mfc140u.dll」，
  將 `redist\*.dll` 複製到 `%ProgramFiles%\Cairn\`。

---

## 6. llama.cpp 與模型（AI 敘事，選配但 demo 需要）

`cairn-m0-model.zip` 內含 `llama.cpp\llama-server.exe`（與其 DLL）及 `llama.cpp\models\qwen2.5-3b-instruct-q4_k_m.gguf`（約 2 GB）。

```powershell
Expand-Archive C:\Downloads\cairn-m0-model.zip -DestinationPath C:\Temp -Force    # → C:\Temp\cairn-m0-model
# 先驗證完整性（套件內 SHA256SUMS.txt，路徑相對於 cairn-m0-model\）
$root = 'C:\Temp\cairn-m0-model'
Get-Content "$root\SHA256SUMS.txt" | ForEach-Object {
    $h, $f = $_ -split '\s+', 2
    $ok = (Get-FileHash (Join-Path $root $f) -Algorithm SHA256).Hash -eq $h
    '{0}  {1}' -f $(if ($ok) { 'OK  ' } else { 'FAIL' }), $f
}
# 全部 OK 後搬到預設位置
New-Item -ItemType Directory -Force -Path C:\Tools | Out-Null
Move-Item "$root\llama.cpp" C:\Tools\llama.cpp
```

最終結構：`C:\Tools\llama.cpp\llama-server.exe`、`C:\Tools\llama.cpp\models\qwen2.5-3b-instruct-q4_k_m.gguf`。

**自行下載模型**（不使用套件時）：

```powershell
winget install --id Python.Python.3.12 -e
pip install -U "huggingface_hub[cli]"
hf download Qwen/Qwen2.5-3B-Instruct-GGUF qwen2.5-3b-instruct-q4_k_m.gguf --local-dir C:\Tools\llama.cpp\models
Get-FileHash C:\Tools\llama.cpp\models\qwen2.5-3b-instruct-q4_k_m.gguf -Algorithm SHA256
```

把算出的 SHA256 與 Hugging Face 檔案頁面上的 SHA256（LFS 欄位）比對，一致才使用。
Cairn 會把模型 SHA256 前 16 碼記為 `alerts.ai_model_id`，供稽核「這段敘事是哪個模型產生的」。

**無獨顯**：改下載 `Qwen/Qwen2.5-1.5B-Instruct-GGUF` 的 `qwen2.5-1.5b-instruct-q4_k_m.gguf`（R-12），
並在 `%ProgramData%\Cairn\policy.json` 的 LLM 區段把模型路徑與 GPU layers 改為 CPU 模式
（欄位名以 `config\policy.default.json` 為準）。

> llama-server 由 `CairnAgent` 以 Job Object 管理（啟動、閒置 300 秒卸載、崩潰重啟），**不需要手動常駐**。

---

## 7. 安裝 Cairn

```powershell
Expand-Archive C:\Downloads\cairn-m0.zip -DestinationPath C:\ -Force   # → C:\cairn-m0
cd C:\cairn-m0
Set-ExecutionPolicy -Scope Process Bypass
.\tools\Check-Prereqs.ps1 -Role Test        # 全部 OK 才繼續
.\tools\Install-Dev.ps1 -BuildDir .\build   # 安裝服務、複製規則與組態到 %ProgramData%\Cairn
.\tools\Invoke-Rpc.ps1 -Method health       # 應回傳健康度 JSON
& "$env:ProgramFiles\Cairn\CairnConsole.exe"
```

---

## 8. Demo／ART 測試機的額外設定

| 項目 | 為什麼 | 指令 |
|---|---|---|
| 關閉 Tamper Protection | demo C3 的 `reg add` 停用 Defender 會被拒（part1 §5） | Windows 安全性 → 病毒與威脅防護設定 → 竄改防護：關閉（只能手動） |
| 關閉 Defender 即時保護（ART 快照） | Defender 先攔截會讓 Cairn 觀測不到（R-14 ④） | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Defender 排除 Cairn | 避免 `CairnAgent.exe` 被隔離（R-14 ①） | `.\tools\Install-Dev.ps1 -BuildDir .\build -AddDefenderExclusion` |
| WER 本機 dump | 崩潰可分析（part2 §2.8.1） | `Install-Dev.ps1` 已自動設定 |

---

## 9. 移除

```powershell
.\tools\Install-Dev.ps1 -Uninstall              # 保留 %ProgramData%\Cairn
.\tools\Install-Dev.ps1 -Uninstall -PurgeData   # 一併刪除 DB、隔離區、Cairn 防火牆規則
& C:\Tools\Sysmon\Sysmon64.exe -u               # 如需移除 Sysmon
```
