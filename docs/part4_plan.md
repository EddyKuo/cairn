# 第四部分：實作計畫與驗證（Cairn M0）

| 項目 | 內容 |
|---|---|
| 版本 | v0.1 · 2026-08-19 |
| 權威 | 技術約定以 [CONVENTIONS.md](CONVENTIONS.md) 為準 |

> **範圍界定**：本部分僅涵蓋 **M0 MVP**（4 週）。M0 的唯一目的是產出一套 **可在乾淨 Windows VM 上安裝、可被紅隊測試、可對客戶 demo** 的單機 EDR。
>
> **刻意不做**（依 v2 spec 2.12.6 的 A 路徑）：核心驅動、EV/WHQL 簽章、ELAM/AM-PPL 自我保護、集中管理主控台、授權與商業模式。這些屬 M1/M2，見 §4.7。
>
> **感測策略**：Sysmon 為 M0 的**主要**感測來源（v2 spec §2.12.6 方案 A+）。理由：其核心驅動由 Microsoft 簽章，我方零簽章成本即可取得 CreateRemoteThread、映像 SHA256、原始磁碟存取等使用者模式 ETW 拿不到的高保真遙測。M0 階段將 Sysmon 視為**硬相依**以換取開發速度；自有 ETW 消費器（去除 Sysmon 相依）延後至 M1。
>
> **授權注意**：Sysinternals 授權對「隨商業產品散佈」有限制。M0 為內部開發與 PoC，採「要求測試環境自行安裝 Sysmon」的方式，不打包散佈，因此不觸及該限制。此假設在進入商業銷售前必須重新檢視。

---

## 4.1 開發環境與前置需求

### 4.1.1 環境矩陣

| 項目 | 版本 / 規格 | 備註 |
|---|---|---|
| 開發機 OS | Windows 11 23H2 x64（或 Windows 10 22H2 19045+） | 需管理員權限 |
| 測試機 OS | Windows 11 23H2 x64，**乾淨快照 VM** | Hyper-V / VMware，**必須可還原快照** |
| **IDE** | **Visual Studio 2022 17.8+**，必要工作負載與元件見下方 Step 1 | MFC 元件**預設不安裝**，必須手動勾選 |
| **編譯器** | MSVC v143（`/std:c++20`） | `CONVENTIONS.md` §C-1 |
| **Windows SDK** | 10.0.22621.0 或更新 | 需含 `wevtapi.lib`、`netfw.h`、`bcrypt.h` |
| **CMake** | 3.25+ | 隨 VS2022 附帶（`C++ CMake tools for Windows`） |
| **vcpkg** | manifest mode（`vcpkg.json`） | 第三方相依一律經此，不手動下載 |
| **WebView2 SDK** | `Microsoft.Web.WebView2` 1.0.2478.35+ | **一律經 vcpkg（`webview2` port），禁止 NuGet**——兩條路徑並存等於不可重現建置 |
| **WebView2 Runtime** | Evergreen（Win11 內建；Win10 需確認） | **執行**時需要，非建置時 |
| Node.js | 20 LTS | 前端建置（產物編入 EXE 資源） |
| Sysmon | v15.15+（需 FileBlockExecutable、ProcessTampering 事件） | 感測來源 |
| llama.cpp | 最新 release 的 `llama-server`（CUDA 或 CPU build） | Tier-3 敘事 |
| 模型 | Qwen2.5-3B-Instruct-GGUF `Q4_K_M` | 約 **1.9–2.1 GB** |
| GPU（選配） | NVIDIA ≥ 6 GB VRAM，CUDA 12.x | 無 GPU 則走 CPU 模式；此時模型降級為 Qwen2.5-1.5B-Instruct Q4_K_M（見 §4.6 R-12） |
| **Microsoft Office** | 任一含 Word 的版本 | W2 出場條件與 §5 demo 腳本需要 `winword.exe` |
| **Python** | 3.12 | 僅用於 Step 5 下載模型 |
| **sqlite3 CLI** | 任一近期版本 | 出場條件與驗收查詢 |

### 4.1.2 一次性環境建置（複製貼上）

**Step 1 — Visual Studio 2022 與 C++ 工具鏈**

⚠ **MFC 不在預設安裝中**。用 GUI 安裝時務必在「個別元件」勾選 `C++ MFC for latest v143 build tools (x86 & x64)`，否則 `#include <afxwin.h>` 會找不到。以下為 winget 一行安裝（含所有必要元件）：

```powershell
# 以「系統管理員」身分開啟 PowerShell
# ⚠ --override 的值必須是單一字串；PowerShell 中行尾的 \ 是字面反斜線而非續行符，
#   直接跨行會讓 VS Installer 收到含反斜線與換行的畸形參數。改以陣列組合：
$vsArgs = @(
  '--quiet','--wait','--norestart',
  '--add','Microsoft.VisualStudio.Workload.NativeDesktop',
  '--add','Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
  '--add','Microsoft.VisualStudio.Component.VC.ATLMFC',
  '--add','Microsoft.VisualStudio.Component.VC.CMake.Project',
  '--add','Microsoft.VisualStudio.Component.VC.ASAN',
  '--add','Microsoft.VisualStudio.Component.Windows11SDK.22621',
  '--includeRecommended'
) -join ' '
winget install --id Microsoft.VisualStudio.2022.Community -e --override $vsArgs

winget install --id OpenJS.NodeJS.LTS -e
winget install --id Python.Python.3.12 -e        # Step 5 下載模型用
winget install --id SQLite.SQLite -e             # 出場條件與驗收查詢用（sqlite3 CLI）
winget install --id Git.Git -e
winget install --id 7zip.7zip -e
```

驗證（在一般 PowerShell 中先載入開發環境，`$env:` 語法在 cmd 下無效）：

```powershell
Import-Module "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "$env:ProgramFiles\Microsoft Visual Studio\2022\Community" -DevCmdArguments '-arch=x64'

cl                  # 期望 Microsoft (R) C/C++ Optimizing Compiler Version 19.3x
cmake --version     # 期望 3.25+
node --version      # 期望 v20.x
# 確認 MFC 標頭存在（此路徑不存在 = Step 1 的 VC.ATLMFC 元件沒裝上）
dir "$env:VCToolsInstallDir\atlmfc\include\afxwin.h"
```

**Step 2 — vcpkg（manifest mode）**

```powershell
git clone https://github.com/microsoft/vcpkg C:\Tools\vcpkg
& C:\Tools\vcpkg\bootstrap-vcpkg.bat
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", "C:\Tools\vcpkg", "Machine")
# 重開 PowerShell 使環境變數生效
```

專案根目錄的 `vcpkg.json`（**不需手動 install，CMake configure 時自動還原**）：

```json
{
  "name": "cairn",
  "version": "0.1.0",
  "builtin-baseline": "<執行 git -C %VCPKG_ROOT% rev-parse HEAD 取得，W1-1 定版後填入並禁止隨意更動>",
  "dependencies": [
    "nlohmann-json", "yyjson", "yaml-cpp", "sqlite3",
    "spdlog", "wil", "gtest", "webview2"
  ],
  "overrides": []
}
```

> **triplet 選 `x64-windows-static-md`**：靜態連結第三方函式庫（不散佈一堆 DLL），但動態連結 CRT（`/MD`）。
> ⚠ 這與 part0 §0.3 原先寫的「MFC 靜態連結（`/MT`）」衝突，**以本節為準**（part0 已同步更正）：
> MFC 與 CRT 一律動態連結（`/MD` + `CMAKE_MFC_FLAG 2`），VC++ Redistributable 與 MFC 執行期 DLL 由 `Pack-Demo.ps1` 打包。
> **不用全靜態 `x64-windows-static`**：MFC 與 CRT 混用靜態/動態連結會產生難以診斷的堆積不一致問題——在一個模組 `new`、另一個模組 `delete` 會直接崩潰。統一 `/MD` 是唯一安全的選擇。

**Step 3 — 安裝 Sysmon**

```powershell
# 以「系統管理員」身分執行
$dst = "C:\Tools\Sysmon"
New-Item -ItemType Directory -Force -Path $dst | Out-Null
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$dst\Sysmon.zip"
Expand-Archive -Path "$dst\Sysmon.zip" -DestinationPath $dst -Force

# 使用本專案調校過的組態安裝（config/sysmon.xml，見 §4.2）
& "$dst\Sysmon64.exe" -accepteula -i C:\src\Cairn\config\sysmon.xml

# 驗證：服務存在且事件通道有資料
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
    Format-Table TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}}
```

日後更新組態（**不需重裝服務**）：

```powershell
& "C:\Tools\Sysmon\Sysmon64.exe" -c C:\src\Cairn\config\sysmon.xml
```

**Step 4 — 提高 Sysmon 事件通道容量**（避免高負載時事件被輪替掉，見 §4.6 R-02）

```powershell
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824   # 1 GB
wevtutil gl "Microsoft-Windows-Sysmon/Operational"                   # 確認 maxSize
```

**Step 4b — 啟用 PowerShell Script Block Logging（EID 4104）**

`R-T1059-001`（M0 必備規則、§4.5.2 矩陣 #1）完全依賴 EID 4104，而 Script Block Logging **預設關閉**：

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456   # 256 MB
```

**Step 5 — llama.cpp 與模型**

```powershell
$llama = "C:\Tools\llama.cpp"
New-Item -ItemType Directory -Force -Path "$llama\models" | Out-Null

# 5a. 下載 llama.cpp release（依 GPU 選 cuda 或 cpu build）
#     https://github.com/ggml-org/llama.cpp/releases  → llama-b*-bin-win-cuda-x64.zip
#     解壓到 C:\Tools\llama.cpp

# 5b. 下載模型（約 1.9–2.1 GB）
pip install -U "huggingface_hub[cli]"
hf download Qwen/Qwen2.5-3B-Instruct-GGUF `
    qwen2.5-3b-instruct-q4_k_m.gguf --local-dir "$llama\models"

# 5c. 啟動推論服務（開發期常駐；M0 由 CairnAgent 以 Job Object 管理，見 §4.3 W3-3）
& "$llama\llama-server.exe" `
    -m "$llama\models\qwen2.5-3b-instruct-q4_k_m.gguf" `
    --host 127.0.0.1 --port 8080 `
    -c 8192 -ngl 99 --parallel 1 --no-webui   # 8192：prompt 預算 3400 + n_predict 512 在 4096 下會 overflow（SDD-03 §7.2.2）

# 5d. 驗證（另開一個 PowerShell）
curl.exe http://127.0.0.1:8080/health
```

> `-ngl 99` = 全層卸載至 GPU；**無 GPU 時改為 `-ngl 0`**。M0 不實作 v2 spec 2.9 的五級 VRAM 讓渡，僅實作最基本的「閒置 300 秒關閉 llama-server 子程序」（見 W3-4）。

**Step 6 — 取得原始碼、建置、跑起來**

```powershell
git clone <repo-url> C:\src\Cairn
cd C:\src\Cairn

# 前端先建置（產物 ui-web/dist 會被編入 CairnConsole.exe 的 RCDATA 資源）
cd ui-web; npm ci; npm run build; cd ..

# CMake configure + build（首次會由 vcpkg 還原相依，約 5–15 分鐘）
cmake --preset x64-debug
cmake --build --preset x64-debug

# 產物
#   build\x64-debug\src\svc\CairnAgent.exe
#   build\x64-debug\src\ui\CairnConsole.exe

# 安裝並啟動服務（需系統管理員）
.\build\x64-debug\src\svc\CairnAgent.exe --install
sc.exe start CairnAgent

# 開啟 UI（一般權限即可）
.\build\x64-debug\src\ui\CairnConsole.exe
```

**開發期迭代**（統一採 part3 §3.8 的 `--dev-http` 設計）：
⚠ **不可**讓 WebView2 直接載入 `http://localhost:5173`——一旦導向 Vite，
part3 §3.8.0 的攔截 filter `*://cairn.local/api/v1/*` 就完全失效，
前端的 `fetch('/api/v1/…')` 會打到 Vite 而 404，HMR 迭代拿不到任何資料。
正解是由 `CairnConsole` 開一個**僅開發建置**的本機 HTTP 橋接埠，讓 Vite 的 proxy 指過去。

```powershell
# T1 (管理員): 服務以主控台模式跑，方便看 log 與下中斷點
.\build\x64-debug\src\svc\CairnAgent.exe --console
# T2: cd ui-web; npm run dev          # Vite 於 5173；vite.config.ts 將 /api/v1 proxy 至 127.0.0.1:5080
# T3: .\build\x64-debug\src\ui\CairnConsole.exe --dev-http 5080   # 僅 Debug 建置，Release 以 #ifdef 移除
# 前端在瀏覽器開 http://localhost:5173 除錯；WebView2 宿主本身以 RCDATA 版驗證
```

### 4.1.3 前置檢查腳本

`tools/Check-Prereqs.ps1` — 一鍵驗證環境，**每位開發者與每台測試機的第一道關卡**：

```powershell
# tools\Check-Prereqs.ps1 檢查項目（實作於 W1-1）
#  [x] 目前為系統管理員
#  [x] MSVC v143 工具鏈與 MFC 標頭 (afxwin.h) 存在
#  [x] Windows SDK >= 10.0.22621.0
#  [x] CMake >= 3.25 且 VCPKG_ROOT 已設定
#  [x] WebView2 Runtime 已安裝 (檢查 HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients)
#  [x] node 20 存在
#  [x] Sysmon64 服務為 Running
#  [x] Sysmon 事件通道 maxSize >= 1GB
#  [x] Sysmon 組態雜湊 == config\sysmon.xml 雜湊（防組態漂移）
#  [x] llama-server 可執行檔與 .gguf 模型存在
#  [x] ScriptBlockLogging 已啟用且 PowerShell/Operational 通道 maxSize >= 256MB
#  [x] sqlite3.exe 在 PATH 中（出場條件與驗收查詢需要）
#  [x] Python 3.12 存在（僅用於 Step 5 下載模型）
#  [x] 可用 VRAM（決定 -ngl 99 或 -ngl 0；無獨顯時模型降級為 1.5B）
#  [x] %ProgramData%\Cairn 可寫入
# 任一項失敗 → 非零離開碼 + 明確修復指令
```

---

## 4.2 Repo 結構

> **最重要的一條結構約束**：**所有偵測邏輯放在 `src/core` 靜態庫，且該庫不得 `#include <windows.h>`、不得連結任何 Win32 函式庫。**
> 這是能寫單元測試的前提——規則求值、程序樹重建、分數衰減必須能在不安裝 Sysmon、不開服務、不需管理員權限的情況下，用 gtest 在 CI 上跑完。所有 Win32 相依（`EvtSubscribe`、`OpenProcess`、COM、CNG）一律放在 `src/svc`，並以 `src/core` 定義的介面（`IEventSource`、`IResponder`、`IProcessSnapshot`、`IClock`）注入。測試時以 fake 取代。

```
Cairn/
├─ CMakeLists.txt                        # 頂層：專案、C++20、warning 等級、子目錄
├─ CMakePresets.json                     # x64-debug / x64-release / x64-asan
├─ vcpkg.json                            # manifest：相依與 builtin-baseline pin
├─ .clang-format                         # 統一格式，CI 檢查
├─ README.md
│
├─ src/
│  ├─ core/                              # ★ 靜態庫 cairn_core —— 純邏輯，零 Win32、零 I/O
│  │  ├─ CMakeLists.txt                  #   target_link_libraries 只有 yaml-cpp / yyjson
│  │  ├─ model/
│  │  │  ├─ NormalizedEvent.h            #   §2.1.3 的統一事件模型
│  │  │  ├─ GuidValue.h                  #   std::array<uint8_t,16> + std::hash 特化
│  │  │  ├─ EventType.h
│  │  │  └─ StringInterner.h/.cpp        #   InternId ↔ string，deque 儲存不失效
│  │  ├─ tree/
│  │  │  ├─ ProcessTree.h/.cpp           #   unordered_map + 父子索引，單執行緒擁有
│  │  │  └─ ProcessNode.h
│  │  ├─ rules/
│  │  │  ├─ Ast.h                        #   Condition / ConditionGroup / CompiledRule
│  │  │  ├─ RuleLoader.h/.cpp            #   YAML → RuleDefinition（yaml-cpp）
│  │  │  ├─ RuleCompiler.h/.cpp          #   RuleDefinition → AST + triggerMask 索引
│  │  │  ├─ Evaluator.h/.cpp             #   Tier-1 無狀態求值
│  │  │  ├─ SequenceMatcher.h/.cpp       #   Tier-2 有狀態序列比對
│  │  │  └─ Exclusions.h/.cpp            #   路徑 / 雜湊 / 簽章者 / 規則 ID
│  │  ├─ score/
│  │  │  ├─ Score.h                      #   FixedScore 定點數 + kDecayTable
│  │  │  └─ ScoreEngine.h/.cpp           #   加分 + 衰減 + 40/80/95 門檻判定
│  │  ├─ prompt/
│  │  │  ├─ PromptBuilder.h/.cpp         #   輸入隔離 / 消毒 / 截斷（純字串處理，可測）
│  │  │  └─ VerdictValidator.h/.cpp      #   schema + ATT&CK 白名單（純邏輯，可測）
│  │  └─ base/
│  │     ├─ Result.h                     #   std::expected 風格錯誤通道（CONVENTIONS §C-6）
│  │     ├─ RingBuffer.h                 #   MPSC 無鎖環形佇列（純模板，可測）
│  │     ├─ IClock.h                     #   時間注入介面 —— 衰減測試不能靠真的等
│  │     └─ IEventSource.h               #   感測抽象，M1 換自有 ETW 消費器時下游不動
│  │
│  ├─ svc/                               # 可執行檔 CairnAgent.exe —— 所有 Win32 相依集中於此
│  │  ├─ CMakeLists.txt                  #   每個子目錄各自 add_library STATIC：
│  │  │                                  #     cairn_telemetry / cairn_store / cairn_response
│  │  │                                  #     cairn_llm / cairn_rpc（對齊 CONVENTIONS C-2.2 的 8 庫）
│  │  │                                  #   cairn_core 為 INTERFACE 匯總目標
│  │  │                                  #     = cairn_common + cairn_rules + cairn_store
│  │  │                                  #   link: cairn_core wevtapi.lib bcrypt.lib
│  │  │                                  #         crypt32.lib ole32.lib oleaut32.lib winhttp.lib
│  │  ├─ main.cpp                        #   --install / --uninstall / --console / 服務入口
│  │  ├─ ServiceHost.h/.cpp              #   SCM 對接、8 條執行緒的生命週期與停止順序
│  │  ├─ telemetry/                      #   對應 cairn::telemetry（C-2.2）
│  │  │  ├─ EvtChannelSource.h/.cpp      #   EvtSubscribe push 回呼（§2.2.3）
│  │  │  ├─ SysmonXmlParser.h/.cpp       #   EventXml → NormalizedEvent（每個 EID 一個 mapper）
│  │  │  ├─ BookmarkStore.h/.cpp         #   EvtUpdateBookmark 持久化，重啟續讀
│  │  │  └─ ProcessSnapshot.h/.cpp       #   CreateToolhelp32Snapshot，啟動時重建樹
│  │  ├─ store/
│  │  │  ├─ SqliteDb.h/.cpp              #   RAII 封裝、StatementCache、Transaction
│  │  │  ├─ BatchWriter.h/.cpp           #   T4：唯一寫入連線持有者
│  │  │  ├─ ReadOnlyDb.h/.cpp            #   T7 每執行緒一條唯讀連線
│  │  │  ├─ RetentionJob.h/.cpp          #   分批 DELETE + incremental_vacuum
│  │  │  └─ schema/001_init.sql          #   §2.3.2 的 DDL，以 RCDATA 嵌入
│  │  ├─ response/
│  │  │  ├─ ResponseExecutor.h/.cpp      #   T6：CoInitializeEx + 動作排序
│  │  │  ├─ ProcessResponder.h/.cpp      #   NtSuspendProcess / TerminateProcess / PID 身分驗證
│  │  │  ├─ FirewallResponder.h/.cpp     #   INetFwPolicy2 COM
│  │  │  ├─ QuarantineStore.h/.cpp       #   MoveFileExW + CNG AES-256-GCM
│  │  │  └─ AuditLog.h/.cpp              #   append-only + 雜湊鏈
│  │  ├─ llm/
│  │  │  ├─ LlamaServerSupervisor.h/.cpp       #   Job Object 子程序、閒置卸載、stdout 導流
│  │  │  ├─ WinHttpClient.h/.cpp         #   分階段逾時 + stop_token 取消（§2.6.5）
│  │  │  └─ LlmWorker.h/.cpp       #   T5：有界佇列、schema 驗證、丟最舊
│  │  ├─ rpc/
│  │  │  ├─ PipeServer.h/.cpp            #   Named Pipe + SDDL + FIRST_PIPE_INSTANCE
│  │  │  ├─ JsonRpcDispatcher.h/.cpp     #   JSON-RPC 2.0，method → handler 表
│  │  │  ├─ Framing.h/.cpp               #   4-byte LE 長度前綴讀寫
│  │  │  └─ handlers/                    #   對應 SDD-03 §9.3.2 的 RPC 方法（M0 註冊 27 條）
│  │  └─ health/
│  │     └─ Watchdog.h/.cpp              #   T8：訂閱靜默偵測、子程序監看、重訂閱
│  │
│  └─ ui/                                # 可執行檔 CairnConsole.exe —— MFC 宿主，零偵測邏輯
│     ├─ CMakeLists.txt                  #   set(CMAKE_MFC_FLAG 2) —— 動態連結 MFC
│     ├─ CairnConsole.h/.cpp                  #   CWinAppEx 衍生，InitInstance
│     ├─ MainFrame.h/.cpp                #   CFrameWndEx，OnCreate 建 WebView2、OnSize 填滿
│     ├─ WebViewHost.h/.cpp              #   ICoreWebView2Controller 生命週期
│     ├─ ResourceInterceptor.h/.cpp      #   WebResourceRequested：/api/v1/* → JSON-RPC
│     │                                  #                        其餘 → RCDATA 資源
│     ├─ RpcClient.h/.cpp                #   Named Pipe 客戶端 + 重連
│     ├─ EmbeddedAssets.h/.cpp           #   ui-web/dist → RCDATA 的取出與 MIME 判定
│     ├─ CairnConsole.rc                      #   RCDATA 定義（由 CMake 於建置時產生）
│     └─ resource.h
│
├─ ui-web/                               # React 18 + Vite + TS（建置產物編入 EXE 資源）
│  ├─ package.json
│  ├─ vite.config.ts                     #   base: './'，單檔輸出便於嵌入
│  └─ src/
│     ├─ App.tsx
│     ├─ pages/
│     │  ├─ AlertQueue.tsx               #   告警佇列（主畫面）
│     │  ├─ AlertDetail.tsx              #   程序樹 + 時序 + AI 敘事 + 處置
│     │  └─ Settings.tsx                 #   規則 / 排除清單 / Agent 健康度
│     ├─ components/
│     │  ├─ ProcessTreeView.tsx
│     │  ├─ TimelineView.tsx
│     │  ├─ ScoreBadge.tsx
│     │  └─ NarrativePanel.tsx           #   AI 敘事 + 模型版本標註 + 免責標示
│     └─ lib/api.ts                      #   fetch('/api/v1/...')，不知道 IPC 存在
│
├─ rules/                                # YAML 規則包（§2.4.2 的 DSL）
│  ├─ _schema.json                       # 規則 schema，CI 驗證用
│  ├─ T1055-injection.yaml
│  ├─ T1486-ransomware.yaml
│  ├─ T1547-persistence.yaml
│  ├─ T1059-script-exec.yaml
│  ├─ T1218-lolbin.yaml
│  ├─ T1490-inhibit-recovery.yaml
│  ├─ T1003-credential-access.yaml
│  └─ exclusions.default.yaml            # 開發工具 / 備份 / 遠端桌面預設排除
│
├─ config/
│  ├─ sysmon.xml                         # 調校過的 Sysmon 組態（見下）
│  └─ policy.default.json                # 分數門檻、回應動作、學習期設定
│
├─ tools/
│  ├─ Check-Prereqs.ps1
│  ├─ Install-Dev.ps1                    # 一鍵安裝服務（本機開發）
│  ├─ Run-AtomicSuite.ps1                # 紅隊驗證自動化（§4.5.2）
│  ├─ Load-Test.ps1                      # 事件率壓測（§4.5.4）
│  ├─ Export-FpReport.ps1                # dry-run 誤報報表 → 建議排除清單
│  ├─ Run-AppVerifier.ps1                # §2.8.1 的記憶體正確性驗證
│  ├─ Invoke-Rpc.ps1                     # Named Pipe JSON-RPC 命令列客戶端（W2 起的驗證入口）
│  ├─ Test-Narrative.ps1                 # LLM schema 合規率與延遲（part1 M-04/M-05）
│  ├─ Test-PromptInjection.ps1           # 注入語料集（part1 M-06）
│  ├─ Measure-Latency.ps1                # MTTD（part1 M-03）
│  ├─ New-ReadabilityQuiz.ps1            # 可讀性盲測問卷（part1 M-07）
│  ├─ Run-Acceptance.ps1                 # 串起 part1 §4 的驗收快測集 → reports/
│  ├─ check-mermaid.mjs                  # UML 驗證（CONVENTIONS C-10）
│  ├─ package.json                       # check-mermaid 的相依（jsdom + mermaid）
│  └─ Pack-Demo.ps1                      # 打包 demo zip
│
├─ reports/                              # 驗收與量測產出（不進版控）
│  └─ M0-acceptance-report.md
│
├─ tests/                                # gtest + CTest
│  ├─ CMakeLists.txt
│  ├─ core/                              # ★ 主戰場：純邏輯，不需管理員、不需 Sysmon
│  │  ├─ RuleEvaluatorTests.cpp          #   每個運算子 × 命中/未命中/邊界
│  │  ├─ SequenceMatcherTests.cpp        #   within 邊界、亂序、部分命中、跨樹不誤配
│  │  ├─ ProcessTreeTests.cpp            #   PID 重用、孤兒節點、淘汰、深樹
│  │  ├─ ScoreDecayTests.cpp             #   定點數精確值斷言（EXPECT_EQ 非 EXPECT_NEAR）
│  │  ├─ StringInternerTests.cpp         #   容量上限、deque 不失效
│  │  ├─ RingBufferTests.cpp             #   MPSC 併發、滿佇列丟棄
│  │  ├─ PromptBuilderTests.cpp          #   注入字串消毒、<<< 跳脫、截斷
│  │  └─ VerdictValidatorTests.cpp       #   schema 違規、ATT&CK 白名單、URL 剔除
│  ├─ svc/                               # 需 Win32，部分需管理員（CI 上標記為 skip）
│  │  ├─ SysmonXmlParserTests.cpp        #   以 fixtures 的真實 XML 驗證每個 EID mapper
│  │  ├─ SqliteBatchWriterTests.cpp      #   臨時檔 DB，批次寫入與 retention
│  │  ├─ QuarantineRoundTripTests.cpp    #   隔離 → 還原 → 雜湊比對必須相同
│  │  └─ JsonRpcFramingTests.cpp         #   長度前綴、分段到達、超大訊息拒絕
│  └─ fixtures/
│     ├─ sysmon-samples/                 # 真實錄製的 Sysmon XML（測試不需真的跑攻擊）
│     └─ expected/                       # 黃金檔（golden files）
│
└─ docs/
   ├─ CONVENTIONS.md                     # 全文件唯一權威的技術約定
   ├─ README.md                          # 文件索引
   ├─ part0..part4.md                    # 本 PRD
   ├─ sdd/
   │  ├─ sdd-01-architecture.md
   │  ├─ sdd-02-detection-storage.md
   │  └─ sdd-03-llm-response-ui.md
   ├─ RULE-DSL.md
   └─ DEMO-SCRIPT.md                     # 10 分鐘 demo 腳本（W4 交付）
```

> **產物路徑假設 Ninja 產生器**：`CMakePresets.json` 的三個 preset 一律使用 **Ninja**
> （`"generator": "Ninja"`），故產物路徑不含組態子目錄。改用 Visual Studio 產生器時，
> 本文件所有 `build\x64-debug\src\...` 路徑都要加上 `\Debug\`。

**前端如何進到 EXE**：`ui-web/dist` 由 CMake 的 custom command 在建置時掃描，產生 `CairnConsole.rc` 的 RCDATA 條目（每個檔案一條，含相對路徑字串表）。`EmbeddedAssets` 於執行期以 `FindResource`/`LoadResource` 取出，`ResourceInterceptor` 依副檔名判定 MIME 後回填給 WebView2。**不用 `SetVirtualHostNameToFolderMapping`**，因為那需要 dist 目錄真實存在於磁碟上，等於把前端原始碼散佈出去，且多一個可被竄改的攻擊面。

### `config/sysmon.xml` 設計要點

M0 的組態以 **SwiftOnSecurity / olafhartong 的 modular config 為基礎**再收斂，**必須開啟**下列 Event ID，其餘一律過濾掉以控制事件量：

| Event ID | 內容 | M0 用途 |
|---|---|---|
| 1 | ProcessCreate（含 SHA256、完整命令列、父程序、簽章者） | 程序樹主幹、Tier-1 規則 |
| 3 | NetworkConnect | C2 / 外連偵測 |
| 5 | ProcessTerminate | 程序樹生命週期 |
| 7 | ImageLoad（**僅未簽章 / 非系統路徑**，否則量爆炸） | DLL 側載 |
| 8 | CreateRemoteThread | **注入偵測核心訊號** |
| 10 | ProcessAccess（**僅 lsass.exe 與我方程序為 target**） | 憑證竊取、竄改我方 |
| 11 | FileCreate（**僅高風險副檔名與使用者目錄**） | 勒索、落地檔案 |
| 12/13/14 | Registry（**僅持久化鍵路徑**） | T1547 |
| 22 | DnsQuery | DGA / C2 |
| 23/26 | FileDelete / FileDeleteDetected | 反鑑識、勒索 |
| 25 | ProcessTampering | 空殼行程 / 行程挖空 |
| 27 | FileBlockExecutable | **M0 唯一的檔案層「攔截」點** |

> **Event ID 7 與 11 是事件量爆炸的頭號來源**（見 §4.6 R-01）。組態中必須以 `Image`、`TargetFilename` 的 exclude 規則大量收斂，並在 W1 出場條件中以實測事件率驗證。

---

## 4.3 四週逐週計畫

### 4.3.0-a 排程基準：以驗證量能而非人力估算

> 本專案以 **AI 輔助開發**為前提，**不以人日估算排程**——產出速度不是瓶頸，
> 「產出是否正確」才是。因此四週的可行性不由人力推導，而由**每週能完成多少驗證**決定：
> 沒被測試或紅隊腳本驗證過的程式碼，一律視為未完成，不計入出場條件。

**各週的風險量級**（依「相依鏈長度 × 不確定性」排序，不是工時）：

| 週 | 主要工作 | 風險量級 | 不確定性來源 |
|---|---|---|---|
| W1 | 無鎖 MPSC 環形佇列、`EvtSubscribe` 回呼 + bookmark 狀態機、自寫 Sysmon XML pull parser（17 個 EID mapper + PowerShell 4104）、SQLite RAII 層 + 批次寫入 + retention、SCM 服務宿主（8 條執行緒）、`Watchdog` 訂閱靜默偵測 | **高** | 記憶體序與競態無法靠閱讀發現；Sysmon 實際事件率只能實測 |
| W2 | 規則 DSL 編譯器 + AST 求值 + 有狀態序列比對 + 定點數計分 + Named Pipe JSON-RPC + MFC/WebView2 宿主 + RCDATA 嵌入 + React 主畫面 | **高** | 序列比對的狀態機語意、WebView2 非同步初始化時序 |
| W3 | 回應執行器（四動作 + 還原 + 稽核鏈）、LLM 敘事層、Alert Detail | 中 | 回應動作必須在真實系統上驗證還原路徑 |
| W4 | ART 自動化、規則補齊、長跑與效能驗收、Settings、打包與文件 | 中 | 紅隊矩陣通過率是唯一的外部檢核，結果不可預測 |

**這個前提改變了什麼**：

| 項目 | 傳統人力開發 | AI 輔助開發（本專案） |
|---|---|---|
| 瓶頸 | 寫得出來的量 | **審查與驗證得完的量** |
| 排程單位 | 人日 | 每週的出場條件（§4.3.1–4.3.4） |
| 落後的訊號 | 工作項延遲 | **出場條件未過**，或測試／ART 通過率停滯 |
| 補救方式 | 加人、加班 | **砍範圍**（加不了「AI 產能」也解不了驗證瓶頸） |

W1→W2→W3 的相依鏈是嚴格序列化的（地基不穩不進下一週），這一點與開發方式無關：
偵測管線沒跑通，規則引擎無從驗證；規則引擎沒跑通，回應與敘事都沒有輸入。

**若某週出場條件未過**，唯一的槓桿是砍範圍，砍除順位（依「離核心假設最遠」排序）：

1. `QuarantineStore` 的 CNG 加密 → 降為單純搬移 + ACL 收緊
2. `AuditLog` 雜湊鏈 → 降為純 append（誠實揭露無完整性鏈）
3. `Settings.tsx` → 併入 Alert Detail 的側欄
4. `RetentionJob` 分批刪除 → 降為單次 DELETE

再不夠，就把工期誠實改為 **6–8 週**——這比帶著未達標的地基往上疊誠實得多。

---

### 4.3.0 因改用 C++ 而重新評估的範圍

改用 C++20 + MFC/WebView2 後，**四週總長不變**——但必須誠實承認：同樣的功能，C++ 要自己寫掉一整層 C# 開箱即用的基礎設施。以下是變重的工作項與**多出來的驗證面**（AI 可以很快產出這些程式碼，但每一項都是新增的出錯面，必須被測試覆蓋）：

> 下表「C# 原本的做法」欄為**已作廢的 .NET 方案**，僅供對照，不是可選路徑（見 part0 D-2）。

| 工作項 | C# 原本的做法 | C++ 的做法 | 新增的驗證負擔 |
|---|---|---|---|
| 事件訂閱 | `EventLogWatcher` + `EventRecord.Properties`，開箱即用 | `EvtSubscribe` push 回呼 + `EvtRender` + 手動 bookmark 持久化 + 重訂閱狀態機 | **高**：bookmark 持久化與重訂閱只有斷線／重啟才觸發，需刻意造測試 |
| XML → 事件模型 | `XDocument` + LINQ，一個 mapper 十行 | 自寫 pull parser（不引入 XML 函式庫，`EventData` 結構固定）+ UTF-16 處理 + intern | **高**：17 個 EID mapper × 欄位缺漏／編碼邊界，需 golden-XML 回歸測試 |
| SQLite 存取 | `Microsoft.Data.Sqlite`，`DbCommand` 直接用 | 自建 RAII 封裝、`StatementCache`、`Transaction`、bind 型別對應、錯誤碼處理 | 中：型別綁定與錯誤碼靠單元測試覆蓋 |
| HTTP 客戶端 | `HttpClient` + `CancellationToken`，一行取消 | WinHTTP 分階段逾時 + 跨執行緒 `WinHttpCloseHandle` 取消 + 總時長看門狗 | 中：逾時與跨執行緒取消需故障注入測試 |
| API 層 | ASP.NET Minimal API + SignalR，幾乎零成本 | **自寫 Named Pipe 伺服器 + JSON-RPC 2.0 + 長度前綴框架 + 推播機制** | **高**：長度前綴框架的黏包／截斷是典型漏測點 |
| UI 宿主 | 瀏覽器直接開，零成本 | MFC 宿主 + WebView2 非同步初始化 + `WebResourceRequested` 攔截 + RCDATA 資源嵌入與 MIME | **高**：非同步初始化時序只能手動驗證 |
| 記憶體正確性 | GC 兜底 | ASan / Application Verifier 建置與除錯時間 | **高**：ASan／Application Verifier 建置必須進 CI，否則等於沒有 |
| **合計** | | | **7 項自建基礎設施，全部落在 W1–W2 的地基層** |

**因此砍掉以下範圍以維持四週**（不是「延後再說」，是明確移出 M0 並記錄在 §4.4）：

| 移出 M0 的項目 | 原規劃 | 改為 | 理由 |
|---|---|---|---|
| **首批規則數** | 20 條 | **12 條** | 保留 §4.5.2 紅隊矩陣直接對應的核心規則：注入 2（`R-T1055-001/002`）／憑證 1（`R-T1003-001`）／勒索 2（`R-T1486-001`、`R-T1490-001`）／持久化 2（`R-T1547-001`、`R-T1053-001`）／LOLBin 與防禦規避 3（`R-T1218-001`、`R-T1059-001`、`R-T1562-001`）／C2 2（`R-T1071-001`、`R-T1105-001`）＝ 12 條，與 part2 §2.5 表格的「M0 ✅」欄一致。規則是**資料不是程式碼**，M1 補規則不需改任何 C++ |
| **Live Telemetry 即時事件流畫面** | W2 交付 | **M1** | 分流工作靠 Alert Detail 的時間軸即可完成。⚠ 這是**明確的能力降級**：part3 §3.1.2 把它定位為「M0 規則調校與誤報排查的唯一工具」。M0 期間改以 `Export-FpReport.ps1` 的離線報表 + `sqlite3` 直查取代，代價是誤報排查需離線分析。part3 §3.1.2／§3.8.1 端點 10／§3.9 U-10 已同步標註「M1」 |
| **勒索誘餌檔案（canary）** | 原 W3 規劃項 | **M1** | 需要一整套檔案佈署、監看、白名單機制。M0 的 T1486 偵測改為純規則路徑（高速改寫 + 刪原檔 + 影本清除的序列），紅隊矩陣仍可驗證 |
| **即時推播（SignalR 等價物）** | 原 W2 規劃項 | **UI 輪詢 2 秒** | 自寫 pipe 推播需要處理連線狀態機與重連退避，是額外一整組難測的失敗路徑。M0 用 UI 端 2 秒輪詢，體感差異在單機情境下無感 |
| **規則管理畫面的編輯功能** | 原 W4 規劃項 | **唯讀清單 + dry-run 切換** | 規則以 YAML 檔編輯即可，M0 不做線上編輯器 |

> **為何砍規則數而不砍週數**：四週的價值在於「有一個硬性的驗證時點」。延長到六週會讓範圍繼續膨脹，而 M0 要證明的假設（可解釋告警是否成立）用 12 條規則就足以驗證——紅隊矩陣中列入計分的 11 個 ART 測試每個都有對應規則，覆蓋率門檻不變。

---

**共通規則**
- 每週最後一天為 **出場評審（exit review）**；出場條件未過 → **不進下一週**，先砍範圍再往前，不允許帶著未達標的地基往上疊。
- 所有出場條件必須是**可執行的指令**或**可截圖的畫面**，不接受「大致完成」。
- 每日 build 必須綠燈；`ctest` 失敗即阻擋合併。
- **`src/core` 的每個新檔案都必須同時附上 gtest**——這是 C++ 專案不失控的唯一防線。

---

### W1 — 骨架 + 遙測落地

**目標**：Sysmon 事件能穩定、低延遲、無遺漏地落進 SQLite。這是整個產品的地基，**寧可花滿一週也不能將就**。
⚠ 本週是四週中風險最高的一週：`EvtSubscribe` 的回呼約束、bookmark 復原、無鎖佇列，三者任一做錯都會在 W3/W4 以「事件莫名其妙變少」的形式爆發，且極難回頭定位。

| # | 工作項 | 相依 | 產出 |
|---|---|---|---|
| W1-1 | CMake 骨架 + `CMakePresets.json`（debug/release/asan）+ `vcpkg.json` + `.clang-format` + CI | — | 一行指令可建置 |
| W1-2 | `tools/Check-Prereqs.ps1` + `config/sysmon.xml` 初版 | W1-1 | 環境可重現 |
| W1-3 | `src/core/base`：`Result<T>`、`RingBuffer`（MPSC 無鎖，含 `EventPriority` 分級與滿載時由低到高丟棄、分優先級計數，經 `agent_health.events_dropped`（總計）與 `health.get` 的即時分項回報（part2 §2.3.2 的表只有總計欄））、`IClock`、`IEventSource` | W1-1 | 地基型別 + 測試。**降險路徑**：先以 `std::mutex` + `std::deque` 的 `BoundedQueue` 實作並通過全部介面測試（半天），無鎖版本作為第二實作以相同介面替換，`RingBufferTests` 以 `TYPED_TEST_SUITE` 同時對兩個實作跑。**若 W1 第 3 天無鎖版本未在 ASan + TSan 下穩定通過併發壓測，直接以加鎖版本進 W2**（2,000 事件/秒對加鎖佇列不構成瓶頸），效能不足再回頭優化 |
| W1-4 | `src/core/model`：`NormalizedEvent`、`GuidValue`、`StringInterner` | W1-3 | 事件模型定版 |
| W1-5 | `EvtChannelSource`：`EvtSubscribe` push 回呼 + `EvtRender` + 錯誤處理 | W1-3 | 事件流入 |
| W1-6 | `BookmarkStore`：`EvtUpdateBookmark` 持久化 + 重啟續讀 | W1-5 | 服務重啟不遺漏 |
| W1-7 | `SysmonXmlParser`：EID 1/3/5/7/8/10/11/12-14/15/17-18/22/23/25/26 → `NormalizedEvent`，外加 PowerShell 4104 mapper → `NormalizedEvent` | W1-4, W1-5 | 每個 mapper 一組 fixture 測試 |
| W1-8 | `SqliteDb` RAII 封裝 + `001_init.sql` + `BatchWriter`（1000 筆/200ms） | W1-4 | 落地且不逐筆 INSERT |
| W1-9 | `RetentionJob`：7 天分批 DELETE + `incremental_vacuum` | W1-8 | 磁碟不無限成長 |
| W1-10 | `ServiceHost`：SCM 對接、`--install/--console`、8 條執行緒的建立與停止順序 | W1-5, W1-8 | 可當服務跑 |
| W1-11 | `Watchdog` 初版：訂閱靜默偵測（120 秒無事件即重訂閱）+ `agent_health` 自我遙測 | W1-10 | **無聲失敗可被發現** |
| W1-12 | `tools/Load-Test.ps1`：合成事件產生器（`-Rate` / `-Minutes` / `-Mixed` / `-Profile` / `-Resource` / `-StartSink`） | W1-5 | W1 出場條件的壓測工具 |
| W1-13 | `tools/Run-AppVerifier.ps1` | W1-1 | W3/W4 出場條件需要 |

**出場條件（全部須通過）**

```powershell
# 1. 環境檢查通過
.\tools\Check-Prereqs.ps1                       # 離開碼 0

# 2. 建置與測試綠燈（含 ASan 建置）
cmake --build --preset x64-debug
ctest --preset x64-debug --output-on-failure     # 全綠
cmake --build --preset x64-asan
ctest --preset x64-asan --output-on-failure      # ★ ASan 下也必須全綠

# 3. 事件確實落地（服務跑 10 分鐘一般操作後）
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT event_type, COUNT(*) FROM events GROUP BY event_type;"
#    → 至少出現 PROCESS_CREATE / NETWORK_CONNECT / REGISTRY_SET / DNS_QUERY 四類

# 4. 重啟不遺漏：停服務 → 產生 100 個程序 → 啟服務 → 檢查事件數
$t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
sc.exe stop CairnAgent
1..100 | % { Start-Process cmd.exe "/c exit" -WindowStyle Hidden -Wait }
sc.exe start CairnAgent; Start-Sleep 30
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT COUNT(*) FROM events WHERE event_type='PROCESS_CREATE' AND ts > $t;"
#    → 應接近 100（bookmark 續讀生效），不得為 0
#    ⚠ event_type 依 §2.3.2 DDL 為 TEXT（PROCESS_CREATE / NETWORK_CONNECT / ...），不是整數 EID

# 5. 健康度指標可讀且達標
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT * FROM agent_health ORDER BY ts DESC LIMIT 1;"
#    → events_dropped / events_ingested < 0.001、queue_depth < 20% 容量；
#    渲染失敗數由 health.get 回報（agent_health 表無此欄）

# 6. 壓測通過（見 §4.5.4）
.\tools\Load-Test.ps1 -Rate 2000 -Minutes 10
#    → 丟包率 < 0.5%，CairnAgent CPU P95 < 8%，Private Bytes 無單調成長
```

---

### W2 — 規則引擎 + 程序樹 + RPC/UI 骨架

**目標**：從「一堆事件」變成「少數幾則有意義的告警」，並讓 UI 能看到它們。
本週把 **RPC + MFC/WebView2 宿主**排進來（而非 W3），因為這是 C++ 版本最容易低估的一塊，必須及早暴露風險。

| # | 工作項 | 相依 | 產出 |
|---|---|---|---|
| W2-1 | `ProcessTree`：`ProcessGuid` 主鍵、PID 重用、孤兒節點、`ProcessSnapshot` 啟動重建 | W1-7 | 樹結構正確 |
| W2-2 | `RuleLoader` + `_schema.json`：YAML 載入與 schema 驗證，載入失敗保留舊規則集 | W1-4 | 規則可外部維護 |
| W2-3 | `RuleCompiler` + `Ast`：12 種運算子、`triggerMask` 前置索引、常數 intern | W2-2 | AST 可求值 |
| W2-4 | `Evaluator`（Tier-1 無狀態）| W2-3 | 單事件 signal |
| W2-5 | `SequenceMatcher`（Tier-2 有狀態時序關聯：`sequence`/`within`/`correlate_by`）| W2-3, W2-1 | **偵測主力** |
| W2-6 | `ScoreEngine`：`FixedScore` 定點數加分 + 半衰期衰減 + 40/80/95 三級門檻 | W2-5 | 分數而非布林 |
| W2-7 | `Exclusions` + `exclusions.default.yaml` | W2-3 | 誤報第一道防線 |
| W2-8 | 首批 **12 條規則**（見 §4.3.0 的取捨），對齊 §4.5.2 紅隊矩陣 | W2-3 | 可驗證 |
| W2-9 | `PipeServer` + `Framing` + `JsonRpcDispatcher`：Named Pipe、SDDL、4-byte 長度前綴 | W1-10 | IPC 通道 |
| W2-10 | RPC handlers：`health` / `alerts.list` / `alerts.get` | W2-9, W2-6 | 對應 part3 §3.8 |
| W2-11 | `CairnConsole.exe`：MFC 宿主 + WebView2 初始化 + `OnSize` 填滿 + `RpcClient` | W2-9 | **視窗能開** |
| W2-12 | `ResourceInterceptor` + `EmbeddedAssets`：RCDATA 嵌入、`/api/v1/*` → JSON-RPC 轉接 | W2-11 | 前端不知 IPC |
| W2-13 | `AlertQueue.tsx`（2 秒輪詢版）| W2-12, W2-10 | 主畫面可看 |
| W2-14 | `dry-run` 模式 | W2-6 | 安全上線機制 |
| W2-15 | `tools/Invoke-Rpc.ps1`：Named Pipe JSON-RPC 命令列客戶端 | W2-9 | W2 起所有出場條件的驗證入口 |

**出場條件**

```powershell
# 1. 核心邏輯測試（含黃金檔）
ctest --preset x64-debug -R "core\." --output-on-failure
#    → 全綠，含 within 邊界、亂序事件、PID 重用、衰減精確值

# 2. 真實命中：手動觸發 Office → PowerShell 序列
# ⚠ 需已安裝 Office（環境矩陣已列）；URL 用獨立 sink，不可打 llama-server 的 8080 埠
.\tools\Load-Test.ps1 -StartSink -Port 8099
powershell -c "Start-Process winword; Start-Sleep 2; Start-Process powershell -ArgumentList '-c iwr http://127.0.0.1:8099/payload.txt'"
#    → CairnConsole 的告警佇列 5 秒內出現告警，分數 >= 65

# 3. RPC 通道可用（不經 UI，直接測 pipe）
.\tools\Invoke-Rpc.ps1 -Method health
#    → 回傳合法 JSON-RPC 2.0 回應

# 4. UI 能開、能看、能點
.\build\x64-debug\src\ui\CairnConsole.exe
#    → 視窗開啟 3 秒內顯示告警佇列；調整視窗大小 WebView2 正確填滿；關閉後
#      msedgewebview2.exe 子程序全部退出（工作管理員確認）

# 5. 誤報初篩：一般辦公操作 4 小時
#    → 分數 >= 80 的告警 <= 3 則，且每則可解釋來源規則
```

**UI 驗收標準（W2-13）**：告警佇列必須在**單一畫面**呈現——時間、程序名、分數、命中規則、嚴重度、狀態。依 P1 persona（資安維運工程師）的需求，目標是「**不需登入端點就能判斷告警真偽**」，因此列表必須可直接展開看到程序樹摘要，不可強迫使用者多次跳頁。

---

### W3 — 回應動作 + 告警詳情 + LLM 敘事

**目標**：補上 EDR 的 **R（Response）**，以及本產品真正的差異化——可解釋的告警。

| # | 工作項 | 相依 | 產出 |
|---|---|---|---|
| W3-1 | `ResponseExecutor` 骨架：T6 專屬執行緒 + `CoInitializeEx(APARTMENTTHREADED)` + 動作排序 | W2-6 | 不阻塞管線 |
| W3-2 | `ProcessResponder`：`NtSuspendProcess` / `TerminateProcess` / 程序樹走訪 / **PID 身分驗證** | W3-1, W2-1 | 可止血且不殺錯 |
| W3-3 | `QuarantineStore`：`MoveFileExW` + CNG AES-256-GCM + metadata + **還原** | W3-1 | 可回復（誤報必需） |
| W3-4 | `FirewallResponder`：`INetFwPolicy2` COM 建/刪規則 | W3-1 | 斷 C2 |
| W3-5 | `AuditLog`：append-only + 雜湊鏈 | W3-2~4 | 不可否認 |
| W3-6 | `LlamaServerSupervisor`：`CreateProcess` + Job Object + 閒置 300 秒卸載 + stdout 導流 + 崩潰重啟 | W1-10 | 資源可控 |
| W3-7 | `WinHttpClient`：分階段逾時 + `stop_token` 取消 + 總時長看門狗 | W3-6 | 不會被卡死 |
| W3-8 | `PromptBuilder`：輸入隔離、消毒、`<<<` 跳脫、512 字元截斷 | W1-4 | 抗 prompt injection |
| W3-9 | `VerdictValidator`：JSON schema + ATT&CK 白名單 + URL/Base64 剔除 | W3-8 | 輸出必為合法且安全 |
| W3-10 | `LlmWorker`（T5）：有界佇列 32、滿載踢掉優先度最低者（SDD-03 §7.7.2）、僅處理分數 >= 80 | W3-7, W3-9 | 差異化功能 |
| W3-11 | RPC handlers：`response.prepare` / `response.execute` / `alerts.setVerdict` / `narrative.get` | W2-9, W3-2 | UI 可下指令 |
| W3-12 | `AlertDetail.tsx`：程序樹 + 時間軸 + AI 敘事 + 一鍵處置（二次確認）+ 標記誤報 | W2-13, W3-11 | Demo 主場景 |
| W3-13 | `tools/Test-Narrative.ps1` + `tools/Test-PromptInjection.ps1`（含 30 樣本注入語料，其中 20 例對應 part1 M-06） | W3-9 | W3 出場條件的驗證工具 |

**出場條件**

```powershell
# 1. 隔離 → 還原 往返無損（雜湊必須一致）
ctest --preset x64-debug -R QuarantineRoundTrip --output-on-failure

# 2. 回應動作在 ASan + Application Verifier 下無錯誤
.\tools\Run-AppVerifier.ps1 -Scenario Response
#    → 0 筆 handle / heap 記錄（COM 與 CNG 是 handle 洩漏的高風險區）

# 3. LLM 敘事：schema 違規率 < 1%（跑 100 則歷史告警）
.\tools\Test-Narrative.ps1 -Count 100
#    → 全部通過 VerdictValidator；ATT&CK 編號全在白名單內

# 4. Prompt injection 測試集：30 樣本（含 part1 M-06 的 20 例）
.\tools\Test-PromptInjection.ps1
#    → 0 例改變 attack_ids 或 confidence；**分數完全不受 LLM 影響**（架構保證）

# 5. LLM 完全離線時，偵測與回應能力 100% 不受影響
Stop-Process -Name llama-server -Force
#    → 告警照常產生，narrative 為 null，UI 顯示 ai_state='unavailable'

# 6. 服務停止時不留孤兒程序
sc.exe stop CairnAgent
Get-Process llama-server -ErrorAction SilentlyContinue    # → 必須為空（Job Object 生效）
```

> **架構紅線（W3-10）**：LLM **永遠不參與加分或阻擋決策**，只在事後解釋。此為 v2 spec §2.2 A4／§2.8 的刻意設計取捨（見 CONVENTIONS C-8 原則 1）——LLM 的輸入含攻擊者可控字串，若讓其影響分數，等於把防護決策權交給一個可被注入的元件。此紅線在 code review 中必須明確檢查：`ScoreEngine` 不得 include 任何 `llm/` 標頭。

---

### W4 — 紅隊驗證 + 誤報收斂 + 打包 demo

**目標**：把「能跑」變成「**證明它有效**」。M0 的價值不在功能清單，而在一份可信的驗證報告。

| # | 工作項 | 相依 | 產出 |
|---|---|---|---|
| W4-0 | RPC handlers：`rules.list` / `rules.setStatus` / `exclusions.list\|add\|remove` / `exclusions.preview` / `exclusions.suggestions` / `exclusions.dismissSuggestion` / `audit.list` / `quarantine.list` / `protection.pause\|resume` / `learning.finish` / `export.create`（清單見 SDD-03 §9.3.2） | W2-9, W3-11 | W4-7 的 Settings 頁與 part1 的「標記為誤報即時生效」都需要 |
| W4-1 | `tools/Run-AtomicSuite.ps1`：自動化執行 §4.5.2 全部 ART 測試並產出覆蓋率報表 | W2-8 | 可重複驗證 |
| W4-2 | 依紅隊結果補規則至 **19 條**（12 條首批 + §4.5.2 延伸矩陣的 7 條；其餘 1 條 `R-T1486-002` canary 留 M1）（不是重寫程式，只是加 YAML）並修正誤判。⚠ **W4-2 與 W4-7 僅得改動 YAML 規則與 `ui-web/` 前端，不得改動 `src/svc` 的 C++**，否則長跑量測結果對交付版本失效 | W4-1 | 覆蓋率達標 |
| W4-3 | 7 天 dry-run 誤報基準（**W2 出場評審通過當天啟動**——dry-run 模式是 W2-14、規則包是 W2-8，W1 結束時還沒有任何規則可 dry-run；W3 收集、W4-1 收成）| W2-8, W2-14 | 誤報數據 |
| W4-4 | `Export-FpReport.ps1`：dry-run 資料 → 建議排除清單 | W4-3 | 可交付 |
| W4-5 | **記憶體正確性總驗收**：ASan 全套 + Application Verifier 4 小時實機負載 | 全部 | §2.8 M0-P13 |
| W4-6 | 效能回歸：完整壓測 + 4 小時常駐量測 + 48 小時記憶體曲線 | W1-11 | NFR 驗證 |
| W4-7 | `Settings.tsx`：規則唯讀清單 + dry-run 切換 + 排除清單 + Agent 健康度 | W3-12 | UI 齊備 |
| W4-8 | Release 建置 + `Pack-Demo.ps1`：**兩個 zip** —— `cairn-m0.zip`（約 40 MB，含 EXE／規則／組態／WebView2 bootstrapper／MFC 與 VC++ 執行期）＋ `cairn-m0-model.zip`（約 2 GB）；另附 `PREREQ.md` 列出 Sysmon 安裝步驟 | 全部 | 可交付 |
| W4-9 | `docs/DEMO-SCRIPT.md`：10 分鐘 demo 腳本 + 驗證報告 | W4-1, W4-3 | 對外溝通 |
| W4-10 | `tools/Run-Acceptance.ps1`：串起 part1 §4 的 M-01/M-03/M-05/M-06 快測集，產出 `reports/M0-acceptance-report.md`（`-IncludeSoak` 另跑長跑項） | W4-1 | part1 M-09 的落地 |

**出場條件（= M0 Go/No-Go）**

> **長跑量測的建置**：72 小時連續執行與 48 小時記憶體曲線的量測對象是 **W3 出場評審通過的建置**，
> 於 W3 最後一天啟動、W4 第 4 天判讀，並記錄該 commit SHA。
> W4 之後若有任何觸及 `src/svc` 的變更，須重跑 24 小時縮短版。

| 門檻 | 目標值 | 驗證方式 |
|---|---|---|
| ART 技術覆蓋率 | **見 §4.5.2 的單一門檻定義**（11 項計分中 ≥ 8 項通過；#2/#3/#7/#8/#9 必過；持久化 #4/#5 ≥ 1/2） | `Run-AtomicSuite.ps1` 報表 |
| 誤報率 | **≤ 3 則/機器/天**（分數 ≥ 80），2–3 台連續 7 天 | 7 天 dry-run 統計 |
| MTTD | 分數達 80 至告警出現 **≤ 3 秒**；AI 敘事 P95 **≤ 20 秒**（CPU 模式，對齊 part2 §2.8 M0-P8）| 紅隊演練計時 |
| 常駐 CPU | 閒置 **≤ 2%**、辦公負載 **≤ 6%**（P95，4 小時量測）| `typeperf` |
| 常駐記憶體 | `CairnAgent` 未啟用 LLM **≤ 300 MB**；48 小時 Private Bytes 斜率 **< 0.5 MB/hr** | `typeperf` + 線性回歸 |
| **記憶體正確性** | **ASan 0 錯誤、Application Verifier 0 記錄、Handle Count 無單調成長** | §2.8.1 工具鏈 |
| 穩定性 | 72 小時連續執行 **0 次崩潰**、0 次資料庫損毀、`CrashDumps` 為空 | 長跑測試 |
| 安裝 | 乾淨 VM 快照 →（前置：測試方自行安裝 Sysmon v15.15+ 並套用 `config/sysmon.xml`、安裝 WebView2 Evergreen Bootstrapper、解壓模型包）→ 執行 `Install-Dev.ps1` → **10 分鐘內可看到第一則告警**。⚠ Sysmon 依 §4.5 開宗明義**不打包散佈**（授權限制），模型檔約 2 GB，因此「解壓即可執行」不成立 | 實機演練 2 次 |

---

## 4.4 M0 明確不做的事（避免範圍蔓延）

| 項目 | 為何延後 | 落在 |
|---|---|---|
| 核心驅動、EV/WHQL 簽章 | 前置期以月計，且需求尚未驗證 | M2 |
| ELAM / AM-PPL 自我保護 | 需 ELAM 憑證，M0 誠實揭露此缺口 | M1 |
| 集中管理主控台 | 單機 demo 已足以驗證核心價值 | M1 |
| 自有 ETW 消費器（去除 Sysmon 相依）| Sysmon 讓 M0 快 3–4 週 | M1 |
| 勒索檔案回滾（VSS 協同）| 複雜度高，M0 以規則序列偵測 + 快速終止替代 | M1 |
| 授權、計費、多租戶 | 依使用者明確指示 | 商業化階段 |
| CEF / OCSF 匯出、SIEM 介接 | 無客戶需求驅動前不做 | M1+ |
| **Live Telemetry 即時事件流畫面** | 因改用 C++ 的範圍重估而移出（§4.3.0）；非驗證核心假設所需 | M1 |
| **勒索誘餌檔案（canary）** | 同上；M0 的 T1486 改走純規則序列偵測 | M1 |
| **即時推播（UI 改 2 秒輪詢）** | 同上；單機情境下體感無差異 | M1 |
| **規則線上編輯器** | 同上；M0 規則以 YAML 檔編輯，UI 僅唯讀 + dry-run 切換 | M1 |

---

## 4.5 驗證計畫

### 4.5.1 單元 / 整合測試策略

**原則**：測試針對**純邏輯**與**資料轉換**，不依賴真的執行惡意程式。fixture 使用**真實錄製的 Sysmon XML**（`tests/fixtures/sysmon-samples/`），一次錄製、永久回放。

**C++ 測試策略（gtest + CTest）**

這一節是 C++ 專案能不能維持四週節奏的關鍵。C++ 沒有 GC 兜底、重構成本高，**測試不是品質保險，是開發速度本身**——沒有測試就得每次都手動起服務、裝 Sysmon、跑攻擊才能驗證一行改動，那樣四週絕對做不完。

| 機制 | 做法 |
|---|---|
| **`src/core` 零 Win32** | 規則求值、程序樹、計分、prompt 組裝、輸出驗證全在 `cairn_core` 靜態庫，**不 include `<windows.h>`**。CI 上不需管理員權限、不需安裝 Sysmon 即可跑完全部核心測試 |
| **介面注入取代 Win32 呼叫** | `IEventSource`（事件來源）、`IResponder`（回應動作）、`IProcessSnapshot`（程序列舉）、`IClock`（時間）。測試以 fake 實作取代：`FakeEventSource` 回放 fixture XML、`FakeClock` 讓衰減測試不必真的等 5 分鐘 |
| **`IClock` 是必須的** | 分數半衰期測試若用真實時間，測試會慢且不穩定。`FakeClock::Advance(5min)` 讓 `ScoreDecayTests` 在微秒內驗證精確值——這也是 §2.4.3 堅持定點數的原因之一：可以 `EXPECT_EQ(score, 45'000)` 而非 `EXPECT_NEAR` |
| **黃金檔（golden files）** | `SysmonXmlParser` 的每個 EID mapper：輸入 `fixtures/sysmon-samples/eid_1_*.xml`，輸出與 `fixtures/expected/*.json` 逐欄位比對。新增 EID 支援時只需加一對檔案 |
| **CTest 整合與分層** | `ctest -R "core\."` 為快速回合（< 5 秒，每次存檔跑）；`ctest -R "svc\."` 需 Win32、部分需管理員，CI 上以 `DISABLED_` 或 label 標記；`ctest --preset x64-asan` 為合併前必跑 |
| **ASan 建置是 CI 的一等公民** | 所有 `core` 測試在一般建置與 ASan 建置下各跑一次。ASan 抓到的 use-after-free 在一般建置下往往「剛好能跑」，等到生產環境才隨機崩潰 |

```cmake
# tests/CMakeLists.txt
add_executable(cairn_tests core/RuleEvaluatorTests.cpp core/ScoreDecayTests.cpp ...)
target_link_libraries(cairn_tests PRIVATE cairn_core GTest::gtest_main)
gtest_discover_tests(cairn_tests PROPERTIES LABELS "core")
```

| 模組 | 測試類型 | **必測**案例 | 門檻 |
|---|---|---|---|
| `SysmonXmlParser` | 單元 | 每個 Event ID 一組 fixture；欄位缺漏 / 格式異常 / 截斷的 XML **不可崩潰、不可 UB**（回傳 `Result` 錯誤）| 覆蓋率 ≥ 85% |
| `RuleCompiler` / `Evaluator` | 單元 | 每個運算子（`in`、`has`、`not in`、萬用字元、正則）正負案例 | 覆蓋率 ≥ 90% |
| `SequenceMatcher` | 單元 | ① 順序正確且在 `within` 內 → 命中 ② 順序顛倒 → 不命中 ③ 超出時間窗 → 不命中 ④ 跨程序樹 → 不命中 ⑤ 中間插入無關事件 → 仍命中 | **100% 分支** |
| `ScoreEngine` | 單元 | ① 多規則累加 ② 半衰期衰減數值正確（含時鐘跳動）③ 三級門檻邊界值（39/40/79/80/94/95）④ 分數上限不溢位 | **100% 分支** |
| `ProcessTree` | 單元（`src/core`，無 Win32）| ① 正常父子重建 ② **PID 重用**（同 PID 不同 GUID 不可掛錯父）③ 父程序先結束的孤兒節點 ④ 深度 10 層的樹 ⑤ 1 萬節點的記憶體與查詢效能 | **100% 分支** |
| `QuarantineStore` | 整合 | **隔離 → 還原往返後 SHA256 必須一致**；磁碟滿、檔案被鎖定、路徑含 Unicode 的錯誤處理 | **100% 分支** |
| `BatchWriter` / `RingBuffer` | 整合 | 佇列滿時分級丟棄且計數正確；flush 條件（1000 筆 / 200ms）兩路徑皆測；**`RingBuffer` 需多執行緒併發壓測並在 ASan 下跑** | 覆蓋率 ≥ 80% |
| `VerdictValidator` | 單元 | 非法 ATT&CK 編號、超長 narrative、缺欄位、非 JSON → 一律拒絕 | **100% 分支** |
| `StringInterner` | 單元 | 容量上限後的降級路徑；`deque` 儲存確保既有 `string_view` 不失效（**用 `vector` 會過不了這個測試**）| **100% 分支** |
| RPC handlers | 合約 | 每個 method 的正常 / 找不到 / 參數錯誤；框架層的分段到達與超大訊息拒絕；**確認 pipe SDDL 正確套用** | 全 method |

**CI 閘門**：`ctest --preset x64-debug` 與 `ctest --preset x64-asan` 皆全綠 + 上述覆蓋率門檻 + `clang-format --dry-run --Werror` + MSVC `/analyze` 警告數不得增加 + `rules/*.yaml` 通過 `_schema.json` 驗證，任一失敗即阻擋合併。

### 4.5.2 紅隊驗證（Atomic Red Team）

**環境準備**（**務必在可還原快照的 VM 中執行，絕不可在開發機或生產機執行**）：

```powershell
# VM 內，系統管理員
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
Import-Module invoke-atomicredteam -Force

# 每個測試後務必清理
# Invoke-AtomicTest <T-ID> -Cleanup
```

**M0 驗證矩陣**（12 項）

> **前置**：矩陣所有 payload 一律**先在有網路的狀態下**跑一次 `-GetPrereqs`（#1 Mimikatz 腳本、
> #2 `RedInjection.exe`、#3 `T1055.001.dll`、#6 遠端 payload、#9 ProcDump 都需下載），
> 下載完成後**才照快照**；之後每輪測試在斷網快照上執行。
> #6 的遠端 payload 改以本機 HTTP sink 提供：`-InputArgs file_url=http://127.0.0.1:8081/x.sct`。
>
> **預期分數一律取 part2 §2.5 的規則權重**，通過容差 ±15。

| # | ART 測試 | 執行指令 | 預期命中規則 | 預期分數 | 預期動作 |
|---|---|---|---|---|---|
| 1 | **T1059.001** PowerShell 執行 | `Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs` 後執行 | `R-T1059-001` 可疑編碼命令列（此 test 為 Mimikatz download cradle，會同時觸發 `R-T1003-*`，實際分數可能更高） | 70 | 記錄 + 提升取樣率 |
| 2 | **T1055.002** PE 注入 | `Invoke-AtomicTest T1055.002 -TestNumbers 1 -GetPrereqs` | `R-T1055-002` 遠端執行緒注入（Sysmon EID 8）。⚠ 不是 `R-T1055-001`——後者要求 Office 父程序，而 `RedInjection.exe` 是獨立執行 | 60 | 告警 + `suspend_process` + AI 敘事 |
| 3 | **T1055.001** DLL 注入 | `Invoke-AtomicTest T1055.001 -TestNumbers 1 -GetPrereqs` | `R-T1055-002` 遠端執行緒 + 未簽章模組載入。⚠ mavinject 的目標是 notepad（非系統程序），規則的「系統程序」條件需放寬或另立規則 | 60 | 告警 + `suspend_process` |
| 4 | **T1547.001** Run 鍵持久化 | `Invoke-AtomicTest T1547.001 -TestNumbers 1` | `R-T1547-001` 非安裝程式寫入 Run 鍵（Sysmon EID 13） | 55 | 記錄；若父程序已可疑則累加至 80 → 告警 |
| 5 | **T1053.005** 排程工作 | `Invoke-AtomicTest T1053.005 -TestNumbers 2`（或 #1 加 `-InputArgs` 指定 `%TEMP%` 下的執行體） | `R-T1053-001` schtasks 建立高頻或開機執行的可疑排程。⚠ #1 的執行體是 `calc.exe`（System32），不符「使用者目錄」的描述 | 50 | 記錄 + 觀察 |
| 6 | **T1218.011** Rundll32 代理執行 | `Invoke-AtomicTest T1218.011 -TestNumbers 1 -GetPrereqs` | `R-T1218-001` LOLBin 異常參數 | 65 | 記錄；搭配外連則升至 85 |
| 7 | **T1486** 資料加密（勒索） | `Invoke-AtomicTest T1486 -TestNumbers 8,10 -GetPrereqs` | `R-T1486-001` 高速改寫 + 刪原檔序列。#8 = GPG4Win 批次加密、#10 = Akira 副檔名改名 + 勒索信落地。⚠ **T1486 #1 是 FreeBSD/Linux 專用，Windows 上不會執行**（誘餌檔案 `R-T1486-002` 已移出 M0，見 §4.3.0） | **95** | **立即終止程序樹**（不等 AI） |
| 8 | **T1490** 抑制系統復原 | `Invoke-AtomicTest T1490 -TestNumbers 1,2,5` | `R-T1490-001` 磁碟區陰影複製刪除。三種載體（vssadmin / wmic shadowcopy / PowerShell WMI）**皆須命中**，否則規則等於只綁 `vssadmin` 字串，可被輕易繞過。⚠ **#3 是 wbadmin 刪除備份目錄，不是 vssadmin**；`vssadmin delete shadows` 是 **#1** | 80 | 告警 + `suspend_process`（80–94 級；依 §4.6 R-08 只有 ≥ 95 才自動終止） |
| 9 | **T1003.001** LSASS 記憶體 | `Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs` | `R-T1003-001` 對 lsass.exe 的高權限 handle（Sysmon EID 10） | 85 | 告警 + `suspend_process` + AI 敘事 |
| 10 | **T1562.001** 停用 Defender | `Invoke-AtomicTest T1562.001 -TestNumbers 1` | `R-T1562-001` 停用 Defender / 竄改防護設定。⚠ 原列的 `T1112 #1` 是 `reg add ... HideFileExt`（隱藏副檔名），`R-T1112-001`（Defender/SmartScreen/UAC）不會命中 | 85 | 告警 + `suspend_process` |
| 11 | **T1105** 工具傳輸 | `Invoke-AtomicTest T1105 -TestNumbers 7,9,10` | `R-T1105-001` 腳本直譯器/LOLBin 下載可執行檔並落地（certutil urlcache / BITSAdmin / PowerShell Download）。⚠ **#6 是 sftp，Linux/macOS 專用** | 65 | 記錄；落地後執行則升至 90 |
| 12 | **T1071.001** Web 協定 C2 | `Invoke-AtomicTest T1071.001 -TestNumbers 1` | **M0 無對應可命中的規則**：此 test 是 3 次一次性 `Invoke-WebRequest` 換 User-Agent，沒有週期性；而 `R-T1071-001`（beacon 週期規律）首發狀態為 `dryrun`，dry-run 下不產生告警 | — | **僅記錄，不列入通過計數** |

**自動化與報表**（`tools/Run-AtomicSuite.ps1`）：

```powershell
# 對每個測試：記錄起訖時間 → 執行 → 等待 10 秒 → 以唯讀模式直接查 cairn.db 的 alerts/rule_hits → 比對預期 → 清理
# （M0 不開任何監聽埠，故不經 HTTP；查詢用 file:...?mode=ro）
.\tools\Run-AtomicSuite.ps1 -OutputPath .\reports\coverage-$(Get-Date -f yyyyMMdd).md

# 報表欄位：測試 ID / 是否偵測 / 實際命中規則 / 實際分數 / 實際動作 / 偵測延遲 / 通過與否
# 通過定義：偵測到 + 分數落在預期 ±15 + 動作等級不低於預期
```

**M0 通過門檻**：**11 項中 ≥ 8 項通過**（#12 不列入計數，理由見表）；
其中 **#2、#3、#7、#8、#9 為必過項**（注入與勒索兩大核心情境，未過即 No-Go），
持久化（#4、#5）另需 **≥ 1/2** 通過。此為 Go/No-Go 的**單一門檻定義**，§4.3 出場條件表一律引用本處。
⚠ **首發狀態為 `dryrun` 的規則不得列為通過項**——dry-run 不產生告警。

**延伸矩陣（M1，或 W4 有餘裕時加測）**——part2 §2.5 的 20 條規則中，
有 8 條在 M0 矩陣裡沒有對應驗證項（下表 7 條 + `R-T1486-002` canary，後者已明確移出 M0），但 ART 都有現成測試：

| ART 指令 | 對應規則 |
|---|---|
| `Invoke-AtomicTest T1055.012 -TestNumbers 1` | `R-T1055-003` Process Hollowing |
| `Invoke-AtomicTest T1574.002 -TestNumbers 1` | `R-T1574-001` DLL 側載 |
| `Invoke-AtomicTest T1003.001 -TestNumbers 2` | `R-T1003-002` comsvcs MiniDump |
| `Invoke-AtomicTest T1003.002 -TestNumbers 1` | `R-T1003-003` reg save hive |
| `Invoke-AtomicTest T1543.003 -TestNumbers 1` | `R-T1543-001` 服務持久化 |
| `Invoke-AtomicTest T1546.012 -TestNumbers 1` | `R-T1546-001` IFEO / Winlogon |
| `Invoke-AtomicTest T1112 -TestNumbers 8` | `R-T1112-001` 防護鍵值竄改（M1） |

**原則**：沒有驗證項的規則不得標為 `enabled`。part2 §2.5 的「M0」欄即為此表的另一半。

### 4.5.3 誤報基準（7 天 dry-run）

**這是 M0 最容易被忽略、卻最決定產品生死的驗證。** 誤報是 EDR 被解除安裝的頭號原因。

**方法**

1. **W2 出場評審通過當天啟動**（W1 結束時尚無規則可 dry-run，見 W4-3）（不是等到 W4 才做，否則來不及累積 7 天資料）。
2. 部署到 **2–3 台真實日常使用的機器**，且刻意涵蓋不同工作型態：
   - 一台**開發者機器**（編譯、除錯器、Git、容器 —— 誤報率最高的環境）
   - 一台**一般辦公機器**（Office、瀏覽器、視訊會議）
   - 一台**IT 管理機器**（遠端桌面、腳本、備份軟體）
3. 全部規則設為 `status: dryrun` —— **只記錄、不動作、不彈窗**。使用者完全無感。
4. 排除清單先套用 `exclusions.default.yaml`（開發工具、備份、遠端桌面範本）。

**產出**

```powershell
.\tools\Export-FpReport.ps1 -Days 7 -OutputPath .\reports\fp-baseline.md
```

報表須包含：
- **每條規則的觸發次數排行**（前 10 名即是誤報主要來源）
- **每次觸發的程序名、路徑、簽章者、命令列摘要**
- **依「簽章者」與「路徑前綴」自動聚類**的建議排除清單（YAML 格式，可直接貼入 `rules/exclusions.*.yaml`）
- **調整後的預估誤報率**

**通過門檻**：套用建議排除清單後，分數 ≥ 80 的告警 **≤ 3 則/機器/天**。任何單一規則貢獻超過總告警 30% 者，**該規則必須重寫或降分，不得靠排除清單硬壓**（靠排除清單掩蓋壞規則會在客戶環境失效）。

### 4.5.4 效能驗證

**壓測方法**（`tools/Load-Test.ps1`）：以合成負載產生 Sysmon 事件，而非真的跑惡意程式。

```powershell
# 事件產生器：大量短命程序 + 檔案 I/O + 網路連線 + 登錄檔寫入
.\tools\Load-Test.ps1 -Rate 2000 -Minutes 10 -Mixed
#   內部作法：平行啟動 N 個 cmd /c echo（觸發 EID 1/5）、
#             批次建立/刪除檔案（EID 11/23）、
#             批次 TCP 連線至本機 sink（EID 3）

# 極端峰值測試
.\tools\Load-Test.ps1 -Rate 10000 -Minutes 2

# 常駐測試（4 小時，模擬日常辦公）
.\tools\Load-Test.ps1 -Profile Office -Hours 4
```

**通過門檻**

| 情境 | 指標 | 門檻 |
|---|---|---|
| 持續 2,000 事件/秒 × 10 分鐘 | 丟包率 | < 0.5% |
| **持續 5,000 事件/秒 × 10 分鐘** | 丟包率；`queue_depth` P95 | < 1%；< 50%（對應 part2 §2.8 **M0-P5**，先前完全沒被驗證） |
| | 消費延遲 P95（事件時間 → 落地時間） | < 2 秒 |
| | Agent CPU P95 | < 8% |
| 峰值 10,000 事件/秒 × 2 分鐘 | 不崩潰、不 OOM；佇列排空時間 | < 60 秒 |
| | 丟棄須為**分級丟棄**（先丟低價值事件），高價值事件（EID 1/8/10）丟包率 | **0%** |
| 閒置 4 小時 | CPU P95 | ≤ 2% |
| | 記憶體（未啟用 LLM） | ≤ 300 MB，無單調成長 |
| 72 小時長跑 | 崩潰次數 / DB 損毀 | 0 |
| SQLite 寫入 | 單批 1000 筆耗時 P95 | < 50 ms |

> **量測基準硬體**（與 part2 §2.8、part1 §4 一致）：Intel i5-12400（6C/12T）/ 16 GB / NVMe SSD / Windows 11 23H2；
> 功能驗收 VM 另配 4 vCPU / 8 GB。所有數據須標註量測環境，不標註環境的效能數字視為無效。
> CPU 百分比一律為**單一邏輯處理器歸一化後**的值（`\Process(...)\% Processor Time` ÷ 邏輯核心數）。

---

## 4.6 M0 風險清單

| # | 風險 | 觸發徵兆 | 應變 |
|---|---|---|---|
| **R-01** | **Sysmon 事件量爆炸** — 組態過鬆導致每秒數萬事件，CPU 與磁碟被吃光 | `agent_health` 表（或 UI 健康度面板）事件率持續 > 5,000/s；Sysmon 通道快速輪替；磁碟 I/O 佔滿 | ① `config/sysmon.xml` 對 EID 7（ImageLoad）與 11（FileCreate）套用嚴格 exclude，僅保留未簽章 / 使用者目錄 ② W1 出場條件即以實測事件率把關 ③ 提供 `-Profile Minimal` 降級組態，遇高負載機器可切換 ④ 若仍超標，砍掉 EID 7 只保留 8/10（注入偵測的核心訊號） |
| **R-02** | **EventLog 消費延遲與訂閱靜默失效** — `EvtSubscribe` 為批次投遞，高負載下延遲數秒至數十秒；通道輪替會**直接遺失事件**；且回呼太慢時 OS 會**無聲取消訂閱** | 消費延遲 P95 > 5 秒；bookmark 落後；Sysmon 通道 `LogFileIsFull` / 事件序號跳號 | ① 通道容量提高至 1 GB（§4.1.2 Step 4）② 以 bookmark 續傳，服務重啟不遺漏 ③ 監控事件**序號跳號**主動偵測遺失並上報健康度 ④ **回呼內只做 `EvtRender` + memcpy**（§2.2.3 鐵則），任何解析都推到 T2 ⑤ `Watchdog` 的 120 秒靜默偵測 + 自動重訂閱（W1-11，M0 必做）⑥ 若延遲無法收斂，改用 ETW real-time session 直接訂閱 Sysmon provider（繞過 EventLog，M1 本來就要做） |
| **R-03** | **SQLite 寫入瓶頸** — 高事件率下寫入成為瓶頸，佇列積壓 | 批次寫入 P95 > 100 ms；佇列深度持續 > 50%；`database is locked` | ① WAL 模式 + `synchronous=NORMAL` ② 嚴禁逐筆 INSERT，一律批次交易 ③ 單一 writer 執行緒獨佔寫入連線（§2.3.3），避免 `SQLITE_BUSY` ④ 寫入與查詢分離連線（`SQLITE_THREADSAFE=2`） ⑤ 仍不足則降級：原始事件只留高價值類型，其餘僅存聚合計數 |
| **R-04** | **LLM 太慢或產生幻覺** — CPU 模式下敘事需 20–40 秒；模型捏造不存在的 ATT&CK 編號或錯誤的攻擊敘事 | 敘事 P95 > 60 秒；`VerdictValidator` 拒絕率 > 5%；人工抽查發現敘事與實際行為不符 | ① **架構保證**：LLM 完全非同步，不阻塞偵測與回應（W3 出場條件已驗證 llama-server 掛掉不影響防護）② GBNF 約束解碼 + ATT&CK 白名單驗證，非法輸出直接丟棄 ③ UI 明確標註「AI 生成，僅供參考」並顯示模型版本 ④ 敘事逾時則顯示規則命中摘要作為 fallback ⑤ **人工抽查 30 則敘事的正確率，低於 70% 則 demo 時降級為「規則摘要 + 選配 AI」** |
| **R-05** | **規則誤報淹沒** — 首批規則在真實環境每天產生數十則告警，測試者失去信任 | 7 天 dry-run 顯示 > 10 則/天；單一規則貢獻 > 30% 告警 | ① 全部新規則預設 `dryrun`，**絕不預設啟用阻擋** ② §4.5.3 的 7 天基準必須在 W4 前完成 ③ 高誤報規則**重寫或降分**，不靠排除清單掩蓋 ④ 分數門檻可調，demo 前依實測調校 ⑤ UI 提供「標記為誤報」一鍵回饋 |
| **R-06** | **無自我保護被測試者質疑** — 測試者一行 `taskkill` 即解除防護，質疑產品價值 | W2 起每週自測 `taskkill /F /IM CairnAgent.exe`，Watchdog 未在 10 秒內記錄並在 UI 呈現即視為徵兆 | ① **誠實揭露，寫入文件與 demo 腳本第一頁**：M0 為 A 路徑架構，自我保護是已知缺口，M1 以 ELAM 補上 ② M0 仍實作提高門檻的手段：`Watchdog` 訂閱靜默偵測（W1-11）、SCM 服務失敗自動重啟、關鍵檔案獨佔開啟、**被終止事件記錄並在 UI 顯眼呈現**（⚠ M0 **沒有**雙程序互保，那需要 M1 的 ELAM） ③ Demo 中主動展示「我們偵測得到自己被關掉」，把缺口轉化為透明度 ④ 銷售說明中明確標示適用場景（有實體管控的環境） |
| **R-07** | **Sysmon 相依風險** — 測試環境未裝 Sysmon、版本不符、或組態被覆蓋（Sysmon 組態是全域單一份，可能與客戶既有 SOC 工具衝突） | `Check-Prereqs.ps1` 失敗；事件量突然歸零；組態雜湊不符 | ① 啟動時與**每小時**檢查 Sysmon 服務狀態與組態雜湊，不符則在 UI 明確告警 ② 提供「合併模式」：偵測到既有組態時只**加入**我方所需 EID 而不覆蓋 ③ Sysmon 缺席時降級為純使用者模式 ETW（能力下降但不完全失效），並在 UI 標示「降級運作中」 |
| **R-08** | **回應動作誤傷** — 誤報導致終止關鍵業務程序或隔離重要檔案 | **dry-run 影子計數**：7 天基準中分數 ≥ 95 的規則命中 > 0 次（代表自動終止會在真實環境誤觸發）；或 `analyst_verdict='false_positive'` 且分數 ≥ 80 的比例 > 20% | ① M0 預設**只有分數 ≥ 95 的確定性規則**才自動終止，80–94 僅告警等待人工確認 ② 系統關鍵程序（`services.exe`、`lsass.exe`、`csrss.exe` 等）硬編碼**永不終止**白名單 ③ 隔離必須可還原且往返雜湊一致（已列為 100% 分支覆蓋的必測項）④ **執行前重新驗證 PID 身分**（比對建立時間，§2.7），防止 PID 重用導致殺錯無辜程序 ⑤ 所有回應動作寫入 append-only 稽核日誌 |
| **R-09** | **記憶體錯誤導致服務崩潰，無 GC 兜底** — use-after-free、緩衝區溢位、跨執行緒 double-close handle。C++ 的這類 bug 在測試環境常「剛好能跑」，到客戶機器才隨機崩潰，且事後極難定位 | 服務每隔數小時至數天無預警重啟；`%LOCALAPPDATA%\CrashDumps` 出現 `CairnAgent.exe.*.dmp`；`Handle Count` 或 `Private Bytes` 單調成長 | ① **`src/core` 零 Win32 + 全面 gtest**，把最複雜的邏輯放在可測且無資源管理的地方 ② 一律 RAII（`wil::unique_*`、`unique_ptr`），**禁止裸 `new`/`delete` 與裸 handle** ③ **ASan 建置納入 CI 必跑**（W1 出場條件即包含）—— ⚠ **MSVC 的 ASan 不含 LeakSanitizer**，只抓 UAF／溢位／double-free，記憶體洩漏抓不到 ④ **洩漏與 handle 洩漏一律靠 Application Verifier（Heaps／Handles／Leak）＋ UMDH 快照差異**，4 小時實機負載納入 W4 Go/No-Go（§2.8 M0-P13）⑤ 開啟本機 WER dump，任何崩潰都有 dump 可分析 ⑥ 高風險區（`EvtSubscribe` 回呼的 `thread_local` 緩衝、`WinHttpCloseHandle` 的跨執行緒取消、COM 物件生命週期）明列於 code review 檢查表 |
| **R-10** | **MFC + WebView2 的初始化與 COM 執行緒模型踩雷** — WebView2 建立是**非同步**的（`CreateCoreWebView2Environment` 走回呼），在 `OnCreate` 中同步等待會死鎖；MFC 的 UI 執行緒是 STA，而 `ResponseExecutor` 也需要 STA，兩者若共用 apartment 會互相阻塞；WebView2 子程序未正確釋放會殘留 | 視窗開啟後空白或卡死；`msedgewebview2.exe` 在主程式關閉後仍殘留於工作管理員；`RPC_E_WRONG_THREAD` / `CO_E_NOTINITIALIZED` 錯誤 | ① **W2 就把 UI 宿主做完**（不排到 W3），及早暴露風險 ② WebView2 一律走非同步回呼完成初始化，期間視窗顯示載入狀態，**絕不同步等待** ③ UI 程序與服務程序的 COM apartment 完全隔離（不同程序，天然不互相影響）；服務內 T6 自行 `CoInitializeEx` 且 COM 物件不跨執行緒傳遞 ④ `CMainFrame::OnDestroy` 明確釋放 `ICoreWebView2Controller`（`Close()`），並在 W2 出場條件中以工作管理員驗證子程序全數退出 ⑤ WebView2 Runtime 缺席時給出明確錯誤訊息與安裝連結，而非閃退 |
| **R-11** | **四週工期與驗證量能** — 專案以 AI 輔助開發，瓶頸不在產出速度而在**審查與驗證**：W1–W2 的地基層有 7 項自建基礎設施（§4.3.0 表），每一項都是新增的出錯面；且 W1→W2→W3 的相依鏈嚴格序列化（§4.3.0-a：地基不穩不進下一週），無法靠並行壓縮 | 任一週出場評審有 ≥ 2 項條件未過；或 W1 結束時 `src/core` 測試數 < 40；或 ART 通過率連續兩週停滯 | ① 依 §4.3.0-a 的砍範圍清單依序啟動：`QuarantineStore` 加密降為單純搬移 + ACL、`AuditLog` 雜湊鏈降為純 append、`Settings.tsx` 併入 Alert Detail 側欄、`RetentionJob` 降為單次 DELETE ② W2 結束仍落後即啟動 part0 D-2 退路的第三順位（LLM 敘事層降為佔位）③ 每週一 15 分鐘 slip 檢視，連續兩週 slip 即把工期改為 6 週並對外重新溝通 ④ `EvtSubscribe`／無鎖佇列／WebView2 三個高風險區在 W1 第 2 天前各完成一支 spike，**AI 產出的並行與時序程式碼一律以壓力測試與 ASan 驗證，不以閱讀通過** |
| **R-12** | **推論硬體不足** — 測試機無獨顯或 VRAM 不足，llama-server 啟動失敗或 CUDA OOM | `llama-server` 啟動失敗；CUDA OOM；敘事 P95 > 40 秒 | ① `Check-Prereqs.ps1` 檢查 VRAM 並自動決定 `-ngl 99` / `-ngl 0` ② 無 GPU 時模型降級為 Qwen2.5-**1.5B**-Instruct Q4_K_M ③ M0 不實作 VRAM 讓渡，因此**規定 demo 機不得同時跑其他 GPU 應用** ④ `LlamaServerSupervisor` 連續 3 次啟動失敗即永久停用 Tier-3 並在 UI 標示 |
| **R-13** | **內部部署的同意與隱私** — §4.5.3 要求把 LocalSystem 服務 + 全域 Sysmon 組態部署到 2–3 台同事的日常機器，蒐集命令列與檔案路徑（常含明文密碼與 token） | 受測同事回報效能下降或拒絕安裝；法遵／IT 質疑蒐集範圍 | ① 部署前取得**書面同意**並說明蒐集範圍 ② dry-run 資料僅存本機，報表匯出前對路徑與使用者名去識別化 ③ 提供一鍵移除腳本 ④ Sysmon 組態採 R-07 ② 的合併模式，不覆蓋既有組態 |
| **R-14** | **與 Defender／既有 EDR 互斥** | `CairnAgent.exe` 被 Defender 隔離；`NtSuspendProcess` / `TerminateProcess` 回 `ACCESS_DENIED`；`INetFwPolicy2` 規則被第三方防火牆覆寫 | ① 開發與測試機把 `%ProgramData%\Cairn\` 與建置輸出加入 Defender 排除 ② 回應動作失敗須寫入稽核並在 UI 顯示原因，**不得靜默失敗** ③ demo 環境事前確認未安裝其他 EDR ④ ART 測試在 Defender 即時保護關閉的快照上執行，避免 Defender 先攔截導致我方觀測不到 |

---

## 4.7 M0 之後：M1 概要

M1 目標是把 M0 從「可 demo 的 PoC」推進到「可進企業 PoC 的產品」，對應 v2 spec 2.12.6 的 **B 路徑**（使用者模式 + ELAM 驅動）。

1. **自有 ETW 消費器，解除 Sysmon 硬相依** — 直接訂閱 `Kernel-Process` / `Kernel-File` / `Kernel-Registry` / `Kernel-Network` / **`Kernel-Audit-API-Calls`**（不需 EtwTi 即可偵測注入的關鍵 provider）。同時消除 §4.6 R-07 的相依風險與散佈授權疑慮。
2. **ELAM 驅動 + AM-PPL 自我保護** — 補上 M0 最致命的缺口（R-06），並藉此取得訂閱 **EtwTi** 的資格，大幅提升注入遙測保真度。**憑證與 MVI 申請前置期以月計，須在 M0 期間即平行啟動**。
3. **集中管理主控台** — 端點註冊、政策下發、跨端點關聯查詢、mTLS 雙向認證、RBAC 三級。沒有主控台的產品是單機 HIPS，無法進入企業採購流程。
4. **回應能力補強** — WFP 使用者模式篩選器取代 `INetFwPolicy2`（更精細的網路隔離，且不動使用者的防火牆規則清單）、AMSI Provider 註冊（無檔案攻擊攔截，無驅動架構下 CP 值最高的攔截點）、VSS 協同的勒索回滾。
5. **規則庫擴充至 100+ 條與內容更新機制** — 規則包獨立簽章、獨立版本、可回滾、分階段發布（內部 → 1% canary → 10% → 全量）。
