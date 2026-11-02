# Sysmon / PowerShell / Security 事件 XML 樣本

> ⚠ **這些是合成樣本，不是真實錄製。** 它們在 Mac 開發機上依 Sysmon v15（schema 4.90）官方欄位定義、
> 以 `EvtRender(EvtRenderEventXml)` 的輸出格式手寫（單行、單引號屬性、`xmlns='http://schemas.microsoft.com/win/2004/08/events/event'`）。
>
> **到 Windows 上必須以真實錄製替換或補充**（part4 §4.5.1「一次錄製、永久回放」）：
>
> ```powershell
> # 以管理員執行：每個 EID 匯出最近一筆真實事件
> foreach ($id in 1,3,5,7,8,10,11,12,13,14,15,17,18,22,23,25,26) {
>   wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[EventID=$id]]" /c:1 /rd:true /f:xml `
>     | Out-File -Encoding utf8 "tests\fixtures\sysmon-samples\real_eid$('{0:d2}' -f $id).xml"
> }
> wevtutil qe Microsoft-Windows-PowerShell/Operational /q:"*[System[EventID=4104]]" /c:1 /rd:true /f:xml `
>   | Out-File -Encoding utf8 tests\fixtures\sysmon-samples\real_ps4104.xml
> ```
>
> 錄製後檢查兩件事：① `wevtutil` 的輸出與 `EvtRender` 是否一致（屬性引號、命名空間、空白）；
> ② 實際欄位名稱大小寫（例如 EID 10 是 `SourceProcessGUID`，解析器以不分大小寫比對）。
> 真實樣本含主機名與使用者名稱，進版控前先去識別化。

## 檔案

| 檔案 | 用途 |
|---|---|
| `eidNN_*.xml` | 每個 Sysmon EID mapper 一組（1/3/5/7/8/10/11/12/13/14/15/17/18/22/23/25/26） |
| `ps4104_script_block.xml` | PowerShell 4104（含 `&apos;` `&amp;` `&quot;` 與 `&#x4E2D;&#25991;` 數字參照） |
| `sec4688_process_create.xml` | Security 4688 降級路徑（合成 ProcessGuid、`TargetUserName='-'` 退回 Subject*） |
| `edge_entities_cmdline.xml` | 攻擊者可控命令列含 `<<<END_UNTRUSTED_DATA>>>`、引號、`&`、`>`；`<Data Name='X'/>` 自閉合 |
| `edge_missing_guid.xml` | 缺 ProcessGuid → 必須解析失敗（MalformedEventXml），不得產生 GUID 全零的事件 |
| `edge_unsupported_eid6.xml` | M0 不啟用的 EID 6 → 必須回報不支援 |
| `manifest.json` | 樣本清單與是否預期解析成功 |

黃金檔在 `../expected/<name>.json`：只列出非空欄位；`image` / `parent_image` / `user` / `signer` / `target_image`
為小寫（`InternLower` 正規化），GUID 為大寫含大括號，`time_ms` 為 Unix epoch 毫秒。
4688 的黃金檔以 `"synthetic_guid": true` 表示 ProcessGuid 應為 `SysmonXmlParser::SyntheticGuid(pid, time_ms)`。

樣本與黃金檔由 `../make_sysmon_fixtures.py` 產生（`python3 tests/fixtures/make_sysmon_fixtures.py tests/fixtures`）；修改樣本請改產生器後重新產生，兩者一起進版控。
