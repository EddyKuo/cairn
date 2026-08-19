# Cairn M0 — 全文件共用技術約定（C/C++ 版）

> 本檔為 PRD 與 SDD 的**唯一權威**。任何文件與此衝突，以此為準。
> 版本：**v1.0 · 2026-08-19**（取代原 D-2（.NET 8）決策）

## C-1 語言與工具鏈

| 項目 | 決定 |
|---|---|
| 語言 | **C++20**（`/std:c++20`），必要處以 C 介面對外 |
| 編譯器 | MSVC v143（Visual Studio 2022 17.8+），`/W4 /permissive- /GS /guard:cf /sdl` |
| 建置系統 | **CMake 3.25+ + vcpkg（manifest mode，`vcpkg.json`）** |
| 目標平台 | Windows 10 21H2 (19044) 以上 x64；**僅 Windows，不做跨平台抽象層** |
| UI 宿主 | **MFC**（`CWinAppEx` / `CFrameWndEx`）+ **WebView2**（`ICoreWebView2Controller` 填滿客戶區） |
| 前端 | React 18 + Vite + TypeScript，`npm run build` 產物**嵌入 EXE 資源**，以 `SetVirtualHostNameToFolderMapping` 或自訂 `WebResourceRequested` 供應 |

## C-2 產品命名與程序架構

**產品／內部代號：Cairn**（原 MyEDR，2026-08-19 更名）

> *Cairn*（音 /kɛərn/，石堆路標）——荒野中人為堆疊的石塊，用來標示「有人走過這裡、路在這個方向」。
> 這正是本產品在做的事：把單看毫無意義的散落事件堆成一條可辨識、有方向的軌跡。
> 名稱不綁定 "EDR" 類別，也不綁定 AI，未來產品定位調整時不需再改識別碼。
> ⚠ 此為**內部代號**。對外品牌與商標檢索為 M0 驗證通過、確定商品化後的獨立決策。

### C-2.1 二進位命名

| 二進位 | 角色 | 身分 | 職責 |
|---|---|---|---|
| `CairnAgent.exe` | 端點代理 | Windows Service，LocalSystem，Session 0 | 事件消費、正規化、規則引擎、計分、SQLite、回應執行、LLM 客戶端、RPC 伺服器 |
| `CairnConsole.exe` | 分析主控台 | 使用者 Session，一般權限 | MFC 宿主 + WebView2；**無任何偵測邏輯**，一切經 RPC 取得 |
| `llama-server.exe` | 推論後端 | 由 `CairnAgent` 以 Job Object `Cairn.Inference` 管理的子程序 | 本機推論，HTTP `127.0.0.1:8080`，以 `--api-key`（啟動時隨機產生，寫入 `%ProgramData%\Cairn\`，ACL 排除 Users）保護；隨服務生死 |

**命名原則**：`Cairn` 前綴 ＋ **直白的角色名**，不給各二進位取主題式代號。
理由：安全產品的程序會出現在使用者的工作管理員、服務清單與 IT 的資產盤點中，
名字必須讓人一眼看出「這是誰、在做什麼」。可愛或隱晦的程序名在端點上看起來像惡意軟體。
（業界同慣例：`CSFalconService.exe`、`SentinelAgent.exe`、`MsMpEng.exe`。）

### C-2.2 系統層識別碼

| 項目 | 值 |
|---|---|
| SCM 服務名稱 | `CairnAgent` |
| 服務顯示名稱 | `Cairn Endpoint Agent` |
| 服務描述 | `Cairn 端點偵測與回應代理程式。停止此服務將關閉所有防護。` |
| 安裝目錄 | `%ProgramFiles%\Cairn\` |
| 資料目錄 | `%ProgramData%\Cairn\` |
| WebView2 虛擬主機名 | `cairn.local`（`https://cairn.local/…`，攔截 filter `*://cairn.local/api/v1/*`） |
| 事件資料庫 | `%ProgramData%\Cairn\cairn.db` |
| Named Pipe | `\\.\pipe\Cairn\rpc` |
| 單一實例互斥鎖 | `Global\CairnConsole.SingleInstance` |
| UI 設定登錄機碼 | `HKCU\Software\Cairn\UI`（視窗幾何，走 `CWinAppEx::SaveState`）；其餘 UI 偏好存 `%LOCALAPPDATA%\Cairn\ui.json` |
| 防火牆規則前綴 | `Cairn - Block `（含尾端空格；完整規則名 `Cairn - Block {alertId} ({ip})`） |
| C++ 命名空間 | `cairn::`（子命名空間 `cairn::telemetry` / `rules` / `store` / `llm` / `response` / `rpc` / `model` / `score` / `svc` / `util`；跨模組資料型別一律置於 `cairn::model`，見 SDD-01 §2.4 的 L-2） |
| 靜態庫 | `cairn_telemetry` / `cairn_rules` / `cairn_store` / `cairn_llm` / `cairn_response` / `cairn_rpc` / `cairn_common` / `cairn_tests`；另有 `cairn_core`（CMake **INTERFACE** 匯總目標 ＝ `cairn_common` + `cairn_rules` + `cairn_store`，供 `cairn_tests` 與 `svc.host` 一次連結，不產生獨立 `.lib`） |
| 遙測指標前綴 | `cairn.` |

### C-2.3 程序間通訊

**IPC**：Named Pipe `\\.\pipe\Cairn\rpc`，**JSON-RPC 2.0**，訊息框架為 4-byte little-endian 長度前綴。
SDDL：`D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)`（M0 允許互動使用者讀寫；危險指令另需二次確認 token）。
防搶佔：`FILE_FLAG_FIRST_PIPE_INSTANCE`。

> **UI 的 REST 契約（part3 §3.8）不變**：`CairnConsole` 內建一層極薄的轉接，把 WebView2 的 `fetch('/api/v1/...')` 經 `WebResourceRequested` 攔截後轉為 JSON-RPC 呼叫。前端程式碼不需知道 IPC 的存在。

## C-3 第三方相依（全部經 vcpkg）

| 用途 | 選用 | 授權備註（M0 內部自用，不處理） |
|---|---|---|
| JSON | `nlohmann-json`（可讀性）+ 熱路徑用 `yyjson` | MIT |
| YAML（規則） | `yaml-cpp` | MIT |
| 儲存 | `sqlite3`（WAL 模式） | Public Domain |
| HTTP 客戶端 | **WinHTTP**（系統內建，零相依） | — |
| 日誌 | `spdlog` | MIT |
| 測試 | `gtest` | BSD-3 |
| Windows RAII | `wil`（Windows Implementation Library） | MIT |
| 靜態規則 | `yara`（M0 可延後） | BSD-3 |
| WebView2 | `Microsoft.Web.WebView2` SDK | — |

**不使用**：Boost、Qt、任何 GC 執行期。

## C-4 事件來源（不變，仍為無驅動）

| 來源 | 機制 |
|---|---|
| Sysmon | `EvtSubscribe`（`wevtapi.lib`）訂閱 `Microsoft-Windows-Sysmon/Operational`，push 模式回呼 |
| PowerShell 4104 | `EvtSubscribe` 訂閱 `Microsoft-Windows-PowerShell/Operational` |
| Security 4688 | 備援，Sysmon 缺席時啟用 |

## C-5 執行緒模型（詳見 SDD-01 §2.5）

```
[EvtSubscribe callback (OS thread)] --push--> [MPSC LockFreeRingBuffer<RawEvent, 65536>]
        |                                                    |
        v                                                    v
   (只做 memcpy，零解析)                          [NormalizerThread] 解析 XML -> NormalizedEvent
                                                             |
                                                             v
                                              [AnalysisThread] 單執行緒持有 ProcessTree 與 ScoreBoard
                                                 |            |               |
                                                 v            v               v
                                        [WriterThread]  [LlmWorker]   [ResponseExecutor]
                                        批次 SQLite      逾時可取消      同步執行 + 稽核
                                                             ^
                                        [RpcServerThreadPool] <- CairnConsole
```
**鐵則**：`AnalysisThread` 為單一執行緒且獨佔擁有程序樹與分數，避免鎖；所有跨執行緒溝通一律經佇列傳值，不共享可變狀態。

## C-6 命名與程式碼風格

| 項目 | 約定 | 範例 |
|---|---|---|
| 命名空間 | `cairn::<subsystem>` | `cairn::rules` |
| 類別 / 結構 | PascalCase | `RuleEngine` |
| 介面 | `I` 前綴，純虛擬 + 虛擬解構子 | `IEventSource` |
| 成員變數 | `m_` 前綴 | `m_processTree` |
| 常數 / enum class | PascalCase | `Verdict::Malicious` |
| 檔案 | 類別同名 | `RuleEngine.h/.cpp` |
| 錯誤處理 | **不用例外跨模組邊界**；以 `Result<T>`（`std::expected` 風格）回傳；建構失敗用工廠函式 | `Result<RuleSet> LoadRules(...)` |
| 資源管理 | 一律 RAII，Win32 handle 用 `wil::unique_handle` | — |
| 指標 | 擁有權用 `unique_ptr`；非擁有觀察用裸指標或 `std::span` | — |

## C-7 UML 約定

所有 UML 一律以 **Mermaid** 撰寫（`classDiagram` / `sequenceDiagram` / `stateDiagram-v2` / `erDiagram` / `flowchart`），
理由：可直接在 GitHub、VS Code、Artifact 中渲染，且為純文字可進版控 diff。

## C-8 沿用不變的原則

| # | 原則 |
|---|---|
| 1 | LLM 不參與加分與阻擋決策，僅事後解釋（v2 §2.8） |
| 2 | 分數閾值 40 / 80 / 95 = 深度觀察 / 告警+回應 / 立即阻擋 |
| 3 | 規則 ID 格式 `R-T<ATT&CK>-<序號>` |
| 4 | 回應動作僅四種 user-mode（見 C-9），其中三種可還原；`terminate_process_tree` 不可逆，人工觸發時強制打字確認（part3 §3.3.3 的 L3），自動觸發僅限分數 ≥ 95 或規則標記 `deterministic: true` |
| 5 | M0 不處理 driver、簽章、授權法務 |

## C-9 跨文件識別碼正規名（合併稽核後定案）

| 類別 | 正規名 | 曾用過的別名（已全面汰除） |
|---|---|---|
| 回應動作 | `suspend_process` / `terminate_process_tree` / `quarantine_file` / `firewall_block` | `kill_tree`、`quarantine`、`quarantine_image`、`block_ip` |
| 規則 ID | `R-T<ATT&CK>-<序號>` | `MYEDR-T…`、`RULE-T…` |
| API 前綴 | `/api/v1/…`（前端寫法；實際走 Named Pipe JSON-RPC） | `/api/…` |
| 產品／識別碼 | `Cairn` / `CairnAgent` / `CairnConsole` / `cairn::` | `MyEDR`、`MyEdrSvc`、`MyEdrUI`、`myedr::` |

**DB schema 版本 v2**：相對初版新增 `rule_hits` / `alert_events` / `audit_log` 三表，
`scores.score`、`peak_score`、`alerts.score_at_trigger` 改為 INTEGER milli-point 並新增 `shadow_score`，
`agent_health` 新增 `events_filtered` 且主鍵改為獨立 `id`，
`exclusions.scope_rule_id` 改為 `NOT NULL DEFAULT ''`（`''` = 全域；NULL 會讓 UNIQUE 失效），
移除 `events.rule_hits` JSON 欄位與依賴它的索引 `ix_events_hit`、移除 `scores.hit_rules`。
權威 DDL 在 PRD part2 §2.3.2，完整差異表在 SDD-02 §6.1.1（S-1 ~ S-13），ER 圖在 SDD-02 §6.1。

**shadow_score 的語意**：dry-run 規則的命中**只累加 `shadow_score`，絕不進 `score`**。
若讓 dryrun 分數進入真實分數（只是不做狀態轉移），觀察中的規則會替後續的 enabled 命中墊高分數，
使它跨過 80／95 而真的告警與回應——等於 dryrun 規則間接參與了阻擋決策。

**衰減半衰期**：程序樹取該樹上所有命中規則的**最長**半衰期（分數退得慢＝保守）。
初稿曾誤寫為「最短」，已更正。

## C-10 UML 驗證

32 張 Mermaid 圖已全數以 `mermaid@11` 的 `parse()` 驗證通過（2026-08-19）。
新增或修改圖表後請重跑驗證，避免 render 失敗：

```bash
# 抽出所有 mermaid 區塊 → mermaid.parse() 逐一檢查
node tools/check-mermaid.mjs docs/*.md docs/sdd/*.md
```
