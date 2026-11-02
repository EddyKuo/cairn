# tools — 開發、驗證與打包腳本

> 版本：v0.2 · 2026-11-02
> ⚠ 所有 `.ps1` 都是在 macOS 上撰寫、**尚未在 Windows 上執行過**。首次使用前請讀 [docs/WINDOWS-FIRST-RUN.md](../docs/WINDOWS-FIRST-RUN.md) §7 的「未經驗證的假設」。

PowerShell 腳本相容 Windows PowerShell 5.1 與 PowerShell 7，檔案以 UTF-8 with BOM 儲存。
每支腳本都有 comment-based help：`Get-Help .\tools\<腳本>.ps1 -Full`。共用函式在 `lib\CairnTools.psm1`
（DB 唯讀查詢、Named Pipe JSON-RPC 客戶端、百分位數與線性回歸）。

| 腳本 | 用途 | 對應 | 需管理員 |
|---|---|---|---|
| `Check-Prereqs.ps1` | 環境前置檢查，任一 FAIL → 離開碼 1 | part4 §4.1.3、W1 出場 1 | 建議 |
| `Install-Dev.ps1` | 建置產物安裝為 `CairnAgent` 服務；`-Uninstall [-PurgeData]` | W1-10 | ✅ |
| `Invoke-Rpc.ps1` | `\\.\pipe\Cairn\rpc` 的 JSON-RPC 2.0 命令列客戶端 | W2-15 | — |
| `Load-Test.ps1` | 壓測（`-Rate -Minutes -Mixed -Profile`）、資源量測（`-Resource`）、本機 HTTP sink（`-StartSink -Port`） | §4.5.4、W1-12、M-08 | 建議 |
| `Run-AppVerifier.ps1` | Application Verifier（`-Scenario Tests\|Response\|Soak`） | §2.8.1、W1-13、W3/W4 | ✅ |
| `Run-AtomicSuite.ps1` | ART 驗證矩陣 + 覆蓋率報表 + Go/No-Go（**僅限快照 VM**，需 `-ConfirmSnapshotVm`） | §4.5.2、W4-1、M-01 | ✅ |
| `Export-FpReport.ps1` | dry-run 誤報報表 → 建議排除清單 YAML | §4.5.3、W4-4、M-02 | 建議 |
| `Measure-Latency.ps1` | MTTD / MTTR / AI 敘事延遲 P50/P95/P99 | M-03 | 建議 |
| `New-ReadabilityQuiz.ps1` | 可讀性盲測問卷（M-07）與分流計時（M-10，`-Mode Triage`） | M-07、M-10 | — |
| `Run-Acceptance.ps1` | 串起驗收快測集 → `reports\M0-acceptance-report.md`；`-IncludeSoak` 加長跑項 | W4-10、M-09 | ✅ |
| `Pack-Demo.ps1` | `dist\cairn-m0.zip` + `dist\cairn-m0-model.zip`；`-DemoAssets` 建 `C:\DemoData` | W4-8 | — |
| `Test-Narrative.ps1` | LLM 敘事 schema 合規率與延遲 | W3、M-04/M-05 | — |
| `Test-PromptInjection.ps1` | Prompt injection 語料測試 | W3、M-06 | — |
| `check-mermaid.mjs` | 驗證文件內的 Mermaid UML | CONVENTIONS C-10 | — |

報表一律輸出到 `reports\`（不進版控）。DB 查詢一律以 `sqlite3 -readonly` 開啟 `%ProgramData%\Cairn\cairn.db`，需 sqlite3 ≥ 3.33（`-json`）。

## check-mermaid.mjs — 驗證 SDD 內的 UML 圖

文件集的 32 張 UML（目前全部在 `docs/sdd/`） 全部以 Mermaid 撰寫。改圖後跑這支，避免推上去才發現 render 失敗。

```bash
cd tools
npm i          # 首次執行需安裝（jsdom + mermaid，約 166MB，僅開發用）
npm run check:uml
```

輸出 `mermaid: ok=32 fail=0` 即全數通過；失敗會印出檔名、行號與語法錯誤位置。
