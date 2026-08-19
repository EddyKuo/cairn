# Cairn M0 — PRD 與設計文件索引

> 最小可驗證 EDR（4 週）。上游規格：`../NextGen_AI_EDR_Specification_v2.docx` §2.12.6 方案 A+ 的落地版。
> **M0 明確不處理**：kernel driver、driver signing / EV / WHQL / MVI / ELAM、授權與法務。感測改用 Sysmon。
> 版本：**v0.1 · 2026-08-19**（全文件一致）

| # | 文件 | 內容 |
|---|---|---|
| 0 | [part0_overview.md](part0_overview.md) | 總綱、砍掉什麼與為什麼、3 個關鍵技術決策與退路 |
| 1 | [part1_product.md](part1_product.md) | 產品定義、In/Out of Scope、成功指標、10 分鐘 Demo 腳本、誠實揭露 |
| 2 | [part2_arch.md](part2_arch.md) | 架構圖、Sysmon 組態、SQLite DDL、計分引擎、規則池 20 條（M0 交付 12 條）、LLM 敘事層 |
| 3 | [part3_uiux.md](part3_uiux.md) | 4 畫面線框、分流流程、程序樹規格、Design tokens、REST API 契約 |
| 4 | [part4_plan.md](part4_plan.md) | 環境建置、Repo 結構、W1–W4 計畫、ART 驗證矩陣、風險 |

## 設計文件 (SDD)

| # | 文件 | 內容 |
|---|---|---|
| — | [CONVENTIONS.md](CONVENTIONS.md) | **全文件唯一權威**：C++20 / MFC+WebView2 / 三程序架構 / 執行緒模型 / 命名風格 / UML 約定 |
| 1 | [sdd/sdd-01-architecture.md](sdd/sdd-01-architecture.md) | 導論與術語、系統架構、模組分解、執行緒模型、啟動與關機時序、感測層與事件管線 |
| 2 | [sdd/sdd-02-detection-storage.md](sdd/sdd-02-detection-storage.md) | 程序樹與計分、規則引擎（AST / sequence 比對）、儲存層（ER、批次寫入、崩潰復原） |
| 3 | [sdd/sdd-03-llm-response-ui.md](sdd/sdd-03-llm-response-ui.md) | LLM 敘事層、回應執行器、MFC+WebView2 宿主與 JSON-RPC、橫切關注、需求追溯矩陣 |

> UML 一律以 Mermaid 撰寫，可直接在 GitHub / VS Code 渲染。

## 名稱

專案代號 **Cairn**（石堆路標）。二進位為 `CairnAgent.exe`（服務）與 `CairnConsole.exe`（MFC + WebView2 主控台）。
命名體系與系統層識別碼見 [CONVENTIONS.md](CONVENTIONS.md) §C-2。

## 全文件一致的約定

| 項目 | 約定 |
|---|---|
| 規則 ID | `R-T<ATT&CK>-<序號>`，如 `R-T1055-001` |
| 規則數 | part2 §2.5 定義 **20 條設計池**，**M0 交付其中 12 條**（part4 §4.3.0），W4 依紅隊結果補至 18 條 |
| 分數閾值 | 40 = 深度觀察／80 = 告警 + 回應／95 = 立即阻擋（不等 LLM） |
| API Base | 前端仍寫 `fetch('/api/v1/...')`；由 `CairnConsole` 攔截後轉為 Named Pipe JSON-RPC，**不開任何監聽埠**。契約以 part3 §3.8 為準 |
| 不可讓步原則 | LLM 不參與加分與阻擋決策，僅事後解釋（沿用 v2 §2.8） |
| 回應動作 | 四種 user-mode：`suspend_process` / `terminate_process_tree` / `quarantine_file` / `firewall_block`。除終止程序樹外皆可還原 |

## 起手式

```powershell
# 1. 環境檢查（實作於 W1-1）
.\tools\Check-Prereqs.ps1
# 2. 安裝調校過的 Sysmon 組態
Sysmon64.exe -accepteula -i config\sysmon.xml
# 3. 啟動本地推論（僅開發期手動；正式運行由 CairnAgent 以 Job Object `Cairn.Inference` 管理，見 CONVENTIONS C-2.1）
& "C:\Tools\llama.cpp\llama-server.exe" -m "C:\Tools\llama.cpp\models\qwen2.5-3b-instruct-q4_k_m.gguf" `
    --host 127.0.0.1 --port 8080 -c 8192 -ngl 99 --parallel 1 --no-webui
# 4. 三個終端機：Agent（--console，需管理員）/ npm run dev（前端 HMR）/ CairnConsole（--dev-http 5080）
#    ⚠ 沒有獨立的 API 程序 —— API 由 Agent 內的 Named Pipe JSON-RPC 提供
```
詳見 part4 §4.1。
