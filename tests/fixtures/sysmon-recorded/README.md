# 實機錄製的 Sysmon 樣本

> 與隔壁 `sysmon-samples/`（手寫合成）不同，這裡的事件**原樣取自實機通道**（ADR_002 第 5 條）。

| 檔案 | 來源 |
|---|---|
| `idle_workstation_sample.xml` | Windows 11 閒置工作站，Sysmon 15.21（schema 4.91）＋ `config/sysmon.xml`，2026-08-23 錄製。每個 EID 一筆（1/3/4/5/7/8/11/12/13/16/17/18/22/23/25；4 與 16 為解析器不支援的 EID） |

**格式不得修改**：`EvtRender(EvtRenderEventXml)` 的原樣輸出——單引號屬性、每筆單行、每筆皆含
`<Data Name='RuleName'>`。`RecordedSysmonTests.FixtureKeepsEvtRenderShape` 會擋下改成雙引號或多行的修改。

**已去識別化**（只換值，不動結構）：

| 原始 | 替換為 |
|---|---|
| 主機名 | `WORKSTATION-01` |
| 使用者名稱（含 `C:\Users\<name>`） | `analyst` |
| 使用者 SID | `S-1-5-21-1000000001-1000000002-1000000003-1001` |
| ProcessGuid 前 4 bytes（由 machine ID 推導） | `0c0ffee0`（全檔一致，程序間關聯保留） |
| 本機 / 對外 IP | `2001:db8::/32`、`192.168.1.10` |
| 對外主機名、本機路徑、個人化軟體 | `example.net`、`C:\Cairn\…`、`ExampleVendor` |

新增樣本時沿用同樣的替換，並避開 PTR 反查（`*.in-addr.arpa`、`*.ip6.arpa`）事件——它們以反轉形式內嵌本機 IP。
