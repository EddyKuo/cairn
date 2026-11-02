# Cairn M0 — Windows 首次驗證清單（WINDOWS-FIRST-RUN）

> 版本：v0.1 · 2026-11-02

## 0. 先讀：這批程式碼的狀態

**W1–W4 的程式碼是在 macOS 上寫的，從未在 Windows 上編譯或執行過。** 具體來說：

| 區塊 | 在 Mac 上做過的檢查 | 沒做過的 |
|---|---|---|
| `src/core`、`tests/core`（純 C++20，零 Win32） | 用 Apple clang 做 `-fsyntax-only` 語法／型別檢查 | 沒有用 MSVC 編譯過、沒連結過、**沒跑過任何測試** |
| `src/svc`、`src/ui`（Win32 / MFC / WebView2 / COM） | 無（Mac 沒有 Windows SDK） | 全部：編譯、連結、執行 |
| 可攜的 svc 片段（例如 Sysmon XML parser、ConfirmationTokenStore） | 部分以 clang 做過語法檢查 | 沒用 MSVC 編譯、沒跑過 |
| `ui-web`（React + TS） | 可能跑過 `npm run build`（型別檢查） | 沒在 WebView2 裡載入過 |
| `tools\*.ps1`、`.github/workflows/ci.yml` | 無（Mac 無法執行 Windows PowerShell） | 全部 |
| `tests/fixtures/sysmon-samples/` | — | **手寫的合成樣本**，不是真實錄製 |

所以第一次在 Windows 上建置**一定會有編譯錯誤**。這份清單的目的是讓你依「風險由低到高」的順序推進，
每一步都有明確的通過條件，不在地基還沒穩的時候往上疊（part4 §4.3.0-a 的原則）。

**處理原則（每一步都適用）**

1. **只修讓它編譯／通過的最小改動**，不要順手改設計。改動若影響行為（不只是語法），補一個測試。
2. **每修一類錯誤就 commit 一次**，訊息寫清楚錯誤類型，日後回頭查得到。
3. 遇到「設計文件與實作不一致」時，以 `docs/CONVENTIONS.md` → SDD → PRD 的順序判斷誰對，並在 commit 訊息註明。
4. 測試失敗時**先懷疑測試與 fixture**（它們也沒跑過），確認是實作問題才改實作。
5. 不要為了讓測試綠燈而放寬斷言或加 `GTEST_SKIP`——那等於把 bug 帶進 W2。

---

## 1. 環境建置

依 [part4 §4.1.2](part4_plan.md) Step 1–5 安裝 VS2022（**含 MFC 與 ASan 元件**）、vcpkg、Sysmon、llama.cpp 與模型，
或給測試機用 [PREREQ.md](PREREQ.md)。然後：

```powershell
# 系統管理員 PowerShell
cd C:\src\Cairn
Set-ExecutionPolicy -Scope Process Bypass
Get-ChildItem -Recurse -Include *.ps1, *.psm1 .\tools | Unblock-File     # 從 zip / 網路取得時需要

# 載入 MSVC 開發環境（cmake / ninja / cl 都在這裡面）
Import-Module "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "$env:ProgramFiles\Microsoft Visual Studio\2022\Community" -DevCmdArguments '-arch=x64' -SkipAutomaticLocation

.\tools\Check-Prereqs.ps1          # 期望離開碼 0
```

**通過條件**：`Check-Prereqs.ps1` 離開碼 0（= W1 出場條件 1）。

### 1.1 PowerShell 腳本的編碼

Windows PowerShell 5.1 會把**沒有 BOM 的 UTF-8** 腳本當成系統碼頁（繁中 Windows 為 CP950）讀取，
中文字串會變亂碼，甚至造成剖析錯誤。`tools\` 下由本批產生的 `.ps1/.psm1` 已存成 **UTF-8 with BOM**。
若遇到亂碼或莫名的剖析錯誤，先檢查並轉換：

```powershell
Get-ChildItem .\tools -Recurse -Include *.ps1, *.psm1 | ForEach-Object {
    $b = [IO.File]::ReadAllBytes($_.FullName)
    if (-not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)) {
        $t = [Text.Encoding]::UTF8.GetString($b)
        [IO.File]::WriteAllText($_.FullName, $t, (New-Object Text.UTF8Encoding($true)))
        "已加 BOM：$($_.Name)"
    }
}
```

或改用 PowerShell 7（`pwsh`），它預設以 UTF-8 讀取。

---

## 2. 首次 configure / build

### 2.1 前端先建置（`CairnConsole.exe` 需要 `ui-web/dist`）

```powershell
cd ui-web; npm ci; npm run build; cd ..       # 沒有 package-lock.json 時改用 npm install
```

### 2.2 Configure

```powershell
cmake --preset x64-debug          # 首次會由 vcpkg 還原相依，約 5–15 分鐘
```

預期可能遇到的錯誤：

| 錯誤類型 | 典型訊息 | 處理 |
|---|---|---|
| vcpkg baseline | `builtin-baseline ... is not a valid commit` | `vcpkg.json` 的 baseline 是在 Mac 上從 GitHub tag 取得的 SHA。`git -C $env:VCPKG_ROOT fetch` 後重試；仍不行就改成 `git -C $env:VCPKG_ROOT rev-parse HEAD` 的值並 commit |
| CMake 套件名 / target 名 | `Could not find a package configuration file provided by "unofficial-webview2"` 或 `target "WIL::WIL" not found` | vcpkg port 匯出的名稱以 port 安裝完成時印出的 usage 為準（`vcpkg install <port>` 最後幾行）。逐一對照頂層 `CMakeLists.txt` 的 `find_package` 與各子目錄的 `target_link_libraries`，改成正確名稱 |
| 架構紅線檢查 | `架構紅線違反：... include 了 llm/ 或 prompt/ 標頭` | **這是設計約束，不是建置問題**。不可移除檢查，要改的是那個 include（part4 W3 架構紅線） |
| `src/core 不得相依 Win32` | 同上 | 把 Win32 相依移到 `src/svc`，以 core 定義的介面注入 |

### 2.3 依相依順序逐層建置

不要一次 build 全部——錯誤會淹沒畫面。依地基到上層的順序：

```powershell
cmake --build --preset x64-debug --target cairn_common
cmake --build --preset x64-debug --target cairn_rules
cmake --build --preset x64-debug --target cairn_tests_core     # ← 先讓核心測試能編譯
cmake --build --preset x64-debug --target cairn_telemetry
cmake --build --preset x64-debug --target cairn_store
cmake --build --preset x64-debug --target cairn_response
cmake --build --preset x64-debug --target cairn_llm
cmake --build --preset x64-debug --target cairn_rpc
cmake --build --preset x64-debug --target cairn_tests_svc
cmake --build --preset x64-debug --target CairnAgent
cmake --build --preset x64-debug --target CairnConsole
```

預期的錯誤類型（依出現機率排序）與處理原則：

| # | 類型 | 例子 | 處理 |
|---|---|---|---|
| 1 | **缺少 include**（MSVC STL 的傳遞 include 與 libc++ 不同） | `'std::min': is not a member`、`'uint8_t': undeclared` | 補上對應標準標頭（`<algorithm>`、`<cstdint>`、`<string>`…）。最常見、最安全的一類 |
| 2 | **`/W4` + `/sdl` 警告被當錯誤** | C4244 縮窄轉換、C4100 未用參數、C4996 不安全函式 | 以 `static_cast` 明示轉換；未用參數拿掉名稱；不要整批 `#pragma warning(disable)` |
| 3 | **`/permissive-` 一致性** | 相依名稱缺 `typename` / `template`、暫時物件綁非 const 參考 | 依編譯器提示補上 |
| 4 | **Win32 API 簽章錯誤**（svc 從未編譯過） | `EvtSubscribe` 回呼型別、`WinHttpSetTimeouts` 參數、`BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` 欄位、`INetFwRule` 方法名 | 對照 Microsoft Learn 的函式原型逐一修正；**修完務必補跑對應 svc 測試**，Win32 參數錯誤常常編得過但行為錯 |
| 5 | **wil 用法** | `wil::unique_evt_handle` 不存在、`wil::com_ptr` 與 `Microsoft::WRL::ComPtr` 混用 | 以 vcpkg 安裝的 wil 版本的標頭為準（`resource.h`、`com.h`） |
| 6 | **MFC 宿主** | `afxwin.h` 前 include 了 `windows.h`、`UNICODE` 定義衝突、`CMAKE_MFC_FLAG` 未生效 | MFC 標頭必須最先 include；確認 `src/ui/CMakeLists.txt` 的 `set(CMAKE_MFC_FLAG 2)` 在 `add_executable` 之前 |
| 7 | **WebView2 SDK** | `CreateCoreWebView2EnvironmentWithOptions` 未定義、`Callback<>` 找不到 | 確認連結 vcpkg 的 webview2 target，且 `#include <wrl.h>` + `using namespace Microsoft::WRL` |
| 8 | **連結錯誤** | `unresolved external symbol EvtSubscribe` / `WinHttpOpen` / `BCryptOpenAlgorithmProvider` / `NetFwPolicy2` CLSID | 補上 `wevtapi.lib` / `winhttp.lib` / `bcrypt.lib` / `ole32.lib` / `oleaut32.lib` / `crypt32.lib`；CLSID 需 `#include <netfw.h>` 且在一個 .cpp 定義 `INITGUID` 或連結 `uuid.lib` |
| 9 | **CRT 混用** | `LNK2038: mismatch detected for 'RuntimeLibrary'` | 全部必須 `/MD`（`x64-windows-static-md` triplet + `CMAKE_MSVC_RUNTIME_LIBRARY`）；不要改成 `/MT`（part4 §4.1.2 的理由） |
| 10 | **RCDATA 產生** | `ui-web/dist` 不存在、`.rc` 路徑含反斜線跳脫問題 | 先跑 §2.1；`.rc` 中的路徑需用 `/` 或 `\\` |

**通過條件**：`cmake --build --preset x64-debug` 零錯誤；產物
`build\x64-debug\src\svc\CairnAgent.exe`、`build\x64-debug\src\ui\CairnConsole.exe`、
`build\x64-debug\tests\cairn_tests_core.exe`、`build\x64-debug\tests\cairn_tests_svc.exe` 都存在。

---

## 3. 核心測試（不需管理員、不需 Sysmon）

```powershell
ctest --preset x64-debug -R "core\." --output-on-failure
```

- 這是最先該變綠的一批：純邏輯，失敗原因只會是實作或測試本身。
- 失敗時單獨跑一個測試看完整輸出：
  `.\build\x64-debug\tests\cairn_tests_core.exe --gtest_filter=ScoreDecay*`
- 特別注意：`RingBufferTests`（併發，可能偶發失敗——重跑 50 次：`--gtest_repeat=50 --gtest_break_on_failure`）、
  `ScoreDecayTests`（定點數精確值）、`SequenceMatcherTests`（within 邊界）、`RuleLoaderTests`（載入全部 `rules/*.yaml`）。
- 若無鎖 `LockFreeRingBuffer` 在併發測試中不穩定，依 part4 W1-3 的降險路徑**直接改用加鎖的 `BoundedQueue`**（兩者介面相同），不要在 W1 花超過一天調無鎖版本。

然後是 ASan：

```powershell
cmake --preset x64-asan
cmake --build --preset x64-asan
ctest --preset x64-asan -R "core\." --output-on-failure
```

**通過條件**：x64-debug 與 x64-asan 下 `core.*` 全綠（W1 出場條件 2 的一半）。

---

## 4. svc 測試（需 Win32，部分需管理員）

```powershell
# 系統管理員 PowerShell
ctest --preset x64-debug -R "svc\." --output-on-failure
ctest --preset x64-asan  -R "svc\." --output-on-failure
```

### 4.1 用真實 Sysmon 事件取代合成 fixture

`tests/fixtures/sysmon-samples/` 是依 Sysmon schema **手寫**的。在裝好 Sysmon 的機器上錄製真實樣本，
逐一替換並重跑 `SysmonXmlParserTests`：

```powershell
$out = '.\tests\fixtures\sysmon-samples\recorded'
New-Item -ItemType Directory -Force -Path $out | Out-Null
# 產生一些事件
Start-Process cmd.exe '/c exit' -Wait -WindowStyle Hidden
Resolve-DnsName example.com -ErrorAction SilentlyContinue | Out-Null
# 每個 EID 取最新一筆的原始 XML
foreach ($id in 1,3,5,7,8,10,11,12,13,14,15,17,18,22,23,25,26) {
    $e = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = $id } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { [IO.File]::WriteAllText("$out\eid_${id}_recorded.xml", $e.ToXml(), (New-Object Text.UTF8Encoding($false))) }
    else { "EID $id：目前沒有事件（可能被 sysmon.xml 過濾或尚未發生）" }
}
$ps = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 1
[IO.File]::WriteAllText("$out\ps_4104_recorded.xml", $ps.ToXml(), (New-Object Text.UTF8Encoding($false)))
```

⚠ 錄製的樣本可能含使用者名稱與路徑，commit 前去識別化。EID 8/10/25 需要實際觸發（可在快照 VM 用 ART 產生）。

### 4.2 需要特別盯的 svc 測試

| 測試 | 為什麼 |
|---|---|
| `QuarantineRoundTrip*` | W3 出場條件 1：隔離 → 還原 → SHA256 一致；CNG AES-GCM 與 DPAPI 都沒在 Windows 上跑過 |
| `ProcessResponder*` | 暫停／終止／**PID 身分驗證**——絕不能殺錯程序 |
| `SqliteBatchWriter*` / `Retention*` / `AuditChain*` | 批次交易、upsert、雜湊鏈 |
| `JsonRpcFraming*` | 長度前綴的分段到達、超過 1 MiB 拒絕 |

**通過條件**：x64-debug 與 x64-asan 下 `svc.*` 全綠（需管理員的項目在管理員 shell 下也必須綠，不得 skip）。

---

## 5. 安裝服務並做冒煙測試

```powershell
.\tools\Install-Dev.ps1                       # 預設 build\x64-debug
.\tools\Invoke-Rpc.ps1 -Method health -Json   # 合法 JSON-RPC 回應 = W2 出場條件 3
& "$env:ProgramFiles\Cairn\CairnConsole.exe"
```

開不起來時：

- **主控台模式**看即時 log（先停服務）：
  ```powershell
  sc.exe stop CairnAgent
  & "$env:ProgramFiles\Cairn\CairnAgent.exe" --console
  ```
- 日誌：`%ProgramData%\Cairn\logs\`（實際路徑以 `src/svc` 的 spdlog 設定為準）
- 崩潰 dump：`%LOCALAPPDATA%\CrashDumps\CairnAgent.exe.*.dmp`（服務為 LocalSystem 時在
  `C:\Windows\System32\config\systemprofile\AppData\Local\CrashDumps`）——`Install-Dev.ps1` 已開啟 WER LocalDumps
- 事件檢視器 → Windows 記錄 → 應用程式（Event ID 1000/1001）

---

## 6. 依週出場條件逐項驗證

各週出場條件的權威定義在 [part4 §4.3](part4_plan.md)。以下為可直接執行的指令與判讀。
**前一週沒全過，不進下一週。**

### W1 — 骨架 + 遙測落地

```powershell
# 1. 環境
.\tools\Check-Prereqs.ps1                                     # 離開碼 0
# 2. 建置與測試（含 ASan）
cmake --build --preset x64-debug; ctest --preset x64-debug --output-on-failure
cmake --build --preset x64-asan;  ctest --preset x64-asan  --output-on-failure
# 3. 事件確實落地（服務跑 10 分鐘一般操作後）
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT event_type, COUNT(*) FROM events GROUP BY event_type;"
#    → 至少 PROCESS_CREATE / NETWORK_CONNECT / REGISTRY_SET / DNS_QUERY
# 4. 重啟不遺漏（bookmark 續讀）
$t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
sc.exe stop CairnAgent
1..100 | ForEach-Object { Start-Process cmd.exe "/c exit" -WindowStyle Hidden -Wait }
sc.exe start CairnAgent; Start-Sleep 30
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT COUNT(*) FROM events WHERE event_type='PROCESS_CREATE' AND ts > $t;"
#    → 接近 100，不得為 0
# 5. 健康度
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT * FROM agent_health ORDER BY ts DESC LIMIT 1;"
#    → events_dropped / events_ingested < 0.001、queue_depth < 20% 容量
# 6. 壓測
.\tools\Load-Test.ps1 -Rate 2000 -Minutes 10                  # 離開碼 0；報表在 reports\load-Burst-*.md
# 自我遙測：服務被殺能被看見（R-06 自測）
taskkill /F /IM CairnAgent.exe; Start-Sleep 15; Get-Service CairnAgent   # SCM 應已自動重啟
```

> `Load-Test.ps1` 的「實際事件率」取自 Sysmon 記錄數。若遠低於目標（產生器的 cmd.exe 啟動速度有上限，
> 或 `sysmon.xml` 過濾了測試負載），報表的 `achieved_rate_ge_80pct` 會失敗——這時先調 `-Workers` 與 `-Mixed`，
> 不要直接放寬門檻。

### W2 — 規則引擎 + 程序樹 + RPC/UI

```powershell
# 1. 核心邏輯（含黃金檔）
ctest --preset x64-debug -R "core\." --output-on-failure
# 2. 真實命中：Office → PowerShell
.\tools\Load-Test.ps1 -StartSink -Port 8099
powershell -c "Start-Process winword; Start-Sleep 2; Start-Process powershell -ArgumentList '-c iwr http://127.0.0.1:8099/payload.txt'"
#    → CairnConsole 告警佇列 5 秒內出現告警，分數 >= 65
.\tools\Invoke-Rpc.ps1 -Method alerts.list -Params @{ limit = 5; sort = 'time_desc' } -Json
# 3. RPC 通道
.\tools\Invoke-Rpc.ps1 -Method health
# 4. UI：開啟 3 秒內顯示佇列；調整大小 WebView2 填滿；關閉後 msedgewebview2.exe 全部退出
& "$env:ProgramFiles\Cairn\CairnConsole.exe"
Get-Process msedgewebview2 -ErrorAction SilentlyContinue      # 關閉視窗後應為空（或只剩非 Cairn 的）
# 5. 誤報初篩：一般辦公 4 小時後
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT id, score_at_trigger/1000, rule_ids, title FROM alerts WHERE score_at_trigger >= 80000 AND ts > <4 小時前的 ms>;"
#    → <= 3 則且每則可解釋
```

W2 出場當天**啟動 7 天 dry-run 誤報基準**（part4 W4-3），部署到 2–3 台機器。

### W3 — 回應動作 + 告警詳情 + LLM 敘事

```powershell
# 1. 隔離往返
ctest --preset x64-debug -R QuarantineRoundTrip --output-on-failure
# 2. AppVerifier（回應動作）
.\tools\Run-AppVerifier.ps1 -Scenario Response                # 0 筆記錄
# 3. LLM 敘事 schema（tools\Test-Narrative.ps1，見該腳本說明）
.\tools\Test-Narrative.ps1 -Count 100
# 4. Prompt injection
.\tools\Test-PromptInjection.ps1
# 5. LLM 離線不影響偵測與回應
Stop-Process -Name llama-server -Force
#    → 觸發一次 W2 的 Office → PowerShell 序列：告警照常產生，ai_state='unavailable'
sqlite3 "$env:ProgramData\Cairn\cairn.db" "SELECT id, ai_state FROM alerts ORDER BY ts DESC LIMIT 3;"
# 6. 服務停止不留孤兒
sc.exe stop CairnAgent; Start-Sleep 25
Get-Process llama-server -ErrorAction SilentlyContinue        # → 必須為空（Job Object）
sc.exe start CairnAgent
```

W3 最後一天：記錄 commit SHA，啟動 72 小時長跑與 48 小時記憶體曲線（part4 W4 長跑量測說明）：

```powershell
git rev-parse HEAD | Set-Content .\reports\soak-build-sha.txt
typeperf "\Process(CairnAgent)\% Processor Time" "\Process(CairnAgent)\Private Bytes" "\Process(CairnAgent)\Handle Count" "\Process(CairnAgent)\Thread Count" -si 30 -o .\reports\perf-72h.csv
```

> ⚠ `typeperf` 的計數器名稱會依 Windows 顯示語言在地化；繁中系統上英文路徑會回報「找不到計數器」。
> 改用在地化名稱（`typeperf -q Process` 列出），或把顯示語言切成英文後量測。`Load-Test.ps1` 以
> `Process.TotalProcessorTime` 計算 CPU，不受此影響。

### W4 — 紅隊驗證 + 誤報收斂 + 打包

```powershell
# ART（只能在快照 VM！先 -GetPrereqs、照快照、斷網）
.\tools\Run-AtomicSuite.ps1 -GetPrereqs -ConfirmSnapshotVm
.\tools\Run-AtomicSuite.ps1 -ConfirmSnapshotVm                 # 離開碼 0 = Go
# 誤報基準（7 天 dry-run 後；多台時把各機 cairn.db 複製出來）
.\tools\Export-FpReport.ps1 -Days 7 -DbPath .\dev.db, .\office.db, .\it.db -Anonymize
# 延遲
.\tools\Measure-Latency.ps1 -Since (Get-Date).AddDays(-1)
# 記憶體正確性總驗收（4 小時實機負載）
.\tools\Run-AppVerifier.ps1 -Scenario Soak -Hours 4
# 效能回歸
.\tools\Load-Test.ps1 -Rate 5000 -Minutes 10 -Mixed
.\tools\Load-Test.ps1 -Rate 10000 -Minutes 2
.\tools\Load-Test.ps1 -Profile Idle -Hours 4                    # 閒置 CPU ≤ 2%
.\tools\Load-Test.ps1 -Resource -Minutes 30                     # M-08
# 驗收快測集（M-09：全新 VM 上 30 分鐘內）
.\tools\Run-Acceptance.ps1 -ConfirmSnapshotVm
# 打包
cmake --preset x64-release; cmake --build --preset x64-release
.\tools\Pack-Demo.ps1                                           # dist\cairn-m0.zip + dist\cairn-m0-model.zip
```

最後依 [DEMO-SCRIPT.md](DEMO-SCRIPT.md) 在乾淨 VM 上演練 2 次，並回填其驗證報告章節。

---

## 7. 工具腳本中未經驗證的假設（首次執行時優先確認）

這些是工具腳本在 Mac 上撰寫時、無法對照實作確認的介面假設。若不符，修腳本（或修實作，依設計文件判斷）：

| 假設 | 出現在 | 如何確認 |
|---|---|---|
| `agent_health.events_ingested / events_dropped` 是**累計值**還是**區間值** | `Load-Test.ps1` | 腳本會自動判斷（單調不減視為累計），報表會印出判定結果；確認與 `src/svc` 的實作一致 |
| RPC 參數名：`alerts.get` / `response.prepare` 用 `id`；`response.execute` 用 `action`、`confirmation_token`；revert 用 `audit_id` | `Run-AppVerifier.ps1 -AlertId`、`Invoke-Rpc.ps1` 範例 | `.\tools\Invoke-Rpc.ps1 -Method response.prepare -Params @{...} -Raw` 看錯誤訊息，對照 RPC handler 實作 |
| `rules.list` 回傳 `{ items: [{ rule_id, status, ... }] }` | `Run-AtomicSuite.ps1` | 同上；失敗時腳本會退回以 `rule_hits.dryrun` 判斷 |
| Sysmon 的 `SysmonDrv\Parameters\ConfigHash` 是對 XML 原檔計算的 SHA256 | `Check-Prereqs.ps1` | 套用 `config\sysmon.xml` 後比對 `Get-FileHash`；不一致就改成比對 `Sysmon64.exe -c` 的輸出 |
| `appverif.exe -export log -for <image> -with To=<file>` 的語法與 XML 中的 `logEntry` 節點名 | `Run-AppVerifier.ps1` | 先手動對一個測試執行檔跑一次並開啟匯出的 XML |
| ART 測試以 WMI 啟動後，Cairn 會把它視為獨立的程序樹 | `Run-AtomicSuite.ps1` | 跑一項後查 `rule_hits.root_process_guid` 是否與其他測試不同；若仍累加到同一棵樹，改用 `-RestartAgentBetweenTests` |
| `%ProgramData%\Cairn\policy.json` 是服務讀取的政策檔名；規則目錄為 `%ProgramData%\Cairn\rules\` | `Install-Dev.ps1` | 對照 `src/svc` 的設定載入程式碼 |
| `CairnAgent.exe --install / --uninstall / --console` | `Install-Dev.ps1` | 對照 `src/svc/main.cpp` |
| CI 的 `ajv` 規則驗證：規則檔是「一檔一條規則」且符合 `rules/_schema.json` | `.github/workflows/ci.yml` | 本機 `npx -p ajv-cli@5.0.0 -p ajv-formats@2.1.1 ajv validate -s rules/_schema.json -d rules/R-*.yaml` |
| CI 的 `core-only` job 能在 Linux/macOS 以 vcpkg 還原 yaml-cpp / yyjson / nlohmann-json / gtest | `.github/workflows/ci.yml` | 第一次推上 GitHub 後看該 job |
