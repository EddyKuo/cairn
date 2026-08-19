# Cairn M0 — 最小可驗證 EDR

單機 Windows EDR 的四週最小可驗證版本（Minimum Verifiable EDR）。
核心賭注：**Sysmon 高保真遙測 ＋ 有狀態時序計分 ＋ 本地 LLM 敘事**，把原始 log 變成 5 分鐘可分流的告警。

> 目前為**文件階段**，尚無原始碼。

- 技術約定唯一權威：[docs/CONVENTIONS.md](docs/CONVENTIONS.md)
- 文件索引：[docs/README.md](docs/README.md)

| 文件 | 內容 |
|---|---|
| [part0_overview.md](docs/part0_overview.md) | 總綱、砍掉什麼與為什麼、三個關鍵技術決策 |
| [part1_product.md](docs/part1_product.md) | 產品定義、範圍、成功指標、Demo 腳本、誠實揭露 |
| [part2_arch.md](docs/part2_arch.md) | 架構、Sysmon 組態、SQLite DDL、計分引擎、規則池、LLM 敘事層 |
| [part3_uiux.md](docs/part3_uiux.md) | 線框、分流流程、Design tokens、API 契約 |
| [part4_plan.md](docs/part4_plan.md) | 環境、Repo 結構、W1–W4 計畫、ART 驗證矩陣、風險 |
| [sdd/](docs/sdd/) | 設計文件：架構／偵測與儲存／LLM、回應與 UI |

## 不可讓步原則

LLM **不參與**加分與阻擋決策，僅事後解釋。

## 文件驗證

```bash
npm --prefix tools install
npm --prefix tools run check:uml   # 應輸出 mermaid: ok=32 fail=0
```
