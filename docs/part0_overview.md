# Cairn M0 — 最小可驗證 EDR · 產品需求規格書 (PRD)

| 項目 | 內容 |
|---|---|
| 代號 | **Cairn M0**（Minimum Verifiable EDR） |
| 版本 | v0.1 · 2026-08-19 |
| 上游文件 | `NextGen_AI_EDR_Specification_v2.docx`（本文件為其 §2.12.6 方案 **A+** 的可執行落地版） |
| 目標工期 | 4 週（W1–W4），期末必須有可 demo、可被紅隊腳本驗證的單機成品 |
| 核心賭注 | 「Sysmon 高保真遙測 ＋ 有狀態時序計分 ＋ 本地 LLM 敘事」能把原始 log 變成 5 分鐘可分流的告警 |

## 0.1 為什麼是 M0 而不是直接做 v2

v2 spec 是完整商品規格（30 週、含 kernel driver、EV 憑證、WHQL、MVI、中央主控台、合規 track）。
它的問題不是寫錯，而是**第一個可被驗證的時間點太晚**——在花掉數月的憑證前置期之前，沒有任何證據證明產品的差異化主張（可解釋告警）成立。

M0 的唯一任務是**用最短路徑驗證這個主張**，因此刻意砍掉所有「已知可行但耗時」的工程：

| 刻意不做 | 理由 | 何時做 |
|---|---|---|
| 自有 kernel driver | 開發 + 穩定性測試 ≥ 10 週，且與核心假設無關 | M2（v2 路徑 C） |
| Driver signing / EV / WHQL / MVI / ELAM | 前置期以「月」計，純外部等待 | M1 啟動申請（v2 路徑 B） |
| 授權與法務（GPL / Sysinternals 散佈條款 / 模型授權） | M0 為**內部自用驗證**，不散佈、不銷售 | 進入商品化前 |
| 自我保護 (Tamper Protection) | 必須有 ELAM 驅動才成立 | M1 |
| 中央管理主控台 / 多端點 | 單機即可驗證核心假設 | M1 |
| 靜態掃描引擎 | 與差異化主張無關，市場已飽和 | 視客戶需求 |

## 0.2 M0 的三個關鍵技術決策

| # | 決策 | 選擇 | 理由 | 退路 |
|---|---|---|---|---|
| D-1 | 感測器來源 | **Sysmon**（Microsoft 已簽章的核心驅動）+ PowerShell 4104 + Security 4688 | 零簽章成本即取得 CreateRemoteThread（EID 8）、檔案雜湊（EID 1）、映像簽章者與簽章狀態（EID 7）等純 user-mode ETW 拿不到的高保真事件 | 自建 ETW 消費器（`Kernel-Audit-API-Calls`），M1 補上作為 Sysmon 缺席時的降級路徑 |
| D-2 | 實作語言與程序架構 | **C++20 + MFC/WebView2 三程序**（`CairnAgent.exe` 服務 ／ `CairnConsole.exe` MFC 宿主 ／ `llama-server.exe` 子程序，見 [CONVENTIONS.md](CONVENTIONS.md) C-1、C-2） | ① 使用者明確要求以 C/C++ 實作 ② 目標平台**僅 Windows**，不需跨平台抽象層，可直接使用 Win32／`wevtapi`／COM 原生 API ③ UI 面積全數在 WebView2 內渲染，MFC 僅作宿主，其重量不會隨功能成長 ④ 無 GC 執行期，常駐記憶體與延遲皆為可控的 native 行為，NFR 才有意義 ⑤ 與 M1／M2 的 driver track 同語言同工具鏈，屆時服務可直接與驅動共用結構定義與 IOCTL 介面——C# 沒有這條路徑 | **不改語言**。退路已依序使用：① 首批規則 20 → 12（**已於 part4 §4.3.0 執行**）② UI 畫面 4 → 3，Live Telemetry 移出（**已執行**）③ **尚未使用**：UI 再砍至 2（僅 Alerts 與 Alert Detail）④ **尚未使用**：LLM 敘事層降為佔位。語言與程序架構為不可退讓項 |
| D-3 | LLM 整合方式 | **本機 `llama-server` HTTP** + Qwen2.5-3B-Instruct GGUF + JSON schema 約束 | 免去 llama.cpp C API 綁定與 VRAM 生命週期管理；**C++ 端以系統內建的 WinHTTP 呼叫，零額外相依**（不需引入 libcurl／OpenSSL）；程序隔離讓 LLM 崩潰或耗盡 VRAM 都不會拖垮偵測服務，且可用 Job Object 統一回收 | M1 改為 in-process llama.cpp，取回 VRAM 讓渡控制權 |

> **沿用 v2 的不可讓步原則**：LLM 永不參與加分與阻擋決策，只在事後解釋。理由見 v2 §2.2 A4 / §2.8——LLM 輸入含攻擊者可控字串，讓它影響決策等於把防護決策權交給可被注入的元件。

## 0.3 為什麼 MFC 是可接受的選擇

v2 spec §2.6.3 曾建議「以 Win32 直接宿主 WebView2、移除 MFC 依賴」，理由是 MFC 的文件／檢視架構、控制項與訊息映射在本產品中幾乎全未使用。**這個論點本身是對的**——但它衡量的是「MFC 提供的功能有多少被用到」，而 M0 該衡量的是「達成同樣結果要寫多少樣板碼、要冒多少風險」。在 M0 的取捨下，MFC 仍然成立：

| # | 理由 | 說明 |
|---|---|---|
| 1 | **團隊熟悉度** | 這是 4 週工期下唯一真正稀缺的資源。宿主層若用不熟的框架，省下的 2MB 會用除錯的天數償還 |
| 2 | **省下的是樣板碼，不是功能** | `CWinAppEx` / `CFrameWndEx` 直接給了訊息迴圈、單一實例（`CMutex` + 啟用既有視窗）、系統匣圖示（`CTrayIcon` 慣用法）、視窗位置與大小記憶（`CWinAppEx::SaveState/LoadState` 走登錄檔）、以及 `OnIdle` 掛載。純 Win32 要自己寫這些，約 400–600 行且每一行都可能有錯 |
| 3 | **MFC 的重量不會擴大** | 因為 UI 面積本來就全在 WebView2 內。宿主層的功能清單是**封閉**的（見 part3 §3.10：視窗、系統匣、Toast、WebView2 初始化與錯誤畫面、RPC 轉接），不會隨產品功能成長而增加。這正是「MFC 用不到的部分很多」之所以不構成成本的原因 |

**誠實列出代價**（接受，但要知道自己在付什麼）：

| 代價 | 量級 | 處置 |
|---|---|---|
| 需散佈 MFC 執行期 DLL 與 VC++ Redistributable | 打包後約 **+3 MB** | M0 採**動態連結**（`/MD` + `CMAKE_MFC_FLAG 2`，vcpkg triplet `x64-windows-static-md`，見 part4 §4.1.2）。⚠ 不用 `/MT` 全靜態：MFC 與 CRT 混用靜態／動態連結會產生堆積不一致（在一個模組 `new`、另一個模組 `delete` 直接崩潰）。執行期 DLL 由 `Pack-Demo.ps1` 一併打包。NFR M0-P9「Agent 安裝 ≤ 150 MB」有充裕餘裕 |
| MFC 的文件／檢視架構完全用不到 | 認知負擔，非執行期成本 | 專案以「對話方塊型」或單一 `CFrameWndEx` 建立，**不產生** Document/View 骨架 |
| MFC 為舊技術棧，新人招募面較窄 | 中長期 | 宿主層程式碼刻意保持在 1 個框架類別（`CMainFrame`）+ 5 個輔助類別（`CairnConsoleApp` / `WebViewHost` / `ResourceInterceptor` / `RpcClient` / `EmbeddedAssets`，見 part4 §4.2）以內，將來要換成純 Win32 是一天的工作，非架構性風險 |

> **界線**：MFC 的使用**僅限 `CairnConsole.exe` 的宿主層**。`CairnAgent.exe`（服務、偵測、儲存、回應）不得引入任何 MFC 標頭或型別，其對外介面一律為標準 C++ 與 Win32 SDK。此界線確保偵測核心可被單元測試、可被 M1 的驅動 track 直接沿用。

## 0.4 文件結構

| 章節 | 內容 |
|---|---|
| **[CONVENTIONS.md](CONVENTIONS.md)** | **全文件唯一權威**的技術約定（語言、工具鏈、命名、識別碼、執行緒模型、UML）。任何文件與此衝突，以此為準 |
| 第 1 部分 | 產品定義、範圍、成功指標、驗收 Demo 腳本、誠實揭露 |
| 第 2 部分 | 技術架構、Sysmon 組態、SQLite Schema、計分引擎與規則、LLM 敘事層 |
| 第 3 部分 | UI/UX 規格：資訊架構、線框圖、互動流程、Design tokens、API 契約 |
| 第 4 部分 | 4 週實作計畫、Repo 結構、測試與紅隊驗證計畫、風險清單 |

設計文件（SDD-01～03：架構／偵測與儲存／LLM、回應與 UI）見 [README.md](README.md#設計文件-sdd)。
