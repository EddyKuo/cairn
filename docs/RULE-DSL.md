# Cairn 規則 DSL — 規則作者指南（M0）

> 權威來源：SDD-02 §5.2.0（schema）、§5.3（運算子）、§5.4（sequence / threshold / booster）、§5.5（三態與排除）。
> 機器可讀 schema：[`rules/_schema.json`](../rules/_schema.json)。實作：`src/core/rules/RuleCompiler.cpp`。
> 規則是**資料不是程式碼**：新增或調整規則不需改任何 C++，存檔後 2 秒內熱重載。

## 1. 檔案與載入

- 位置：`C:\ProgramData\Cairn\rules\*.yaml`（開發時為 repo 的 `rules/`）。
- 一個檔案可放多條規則，以 `---` 分隔。以 `_` 或 `exclusions` 開頭的檔案不會當成規則載入。
- **絕不因規則錯誤停擺**：
  - YAML 語法錯誤 → 該**檔案**整個略過，其他檔案照常載入。
  - schema / 語意錯誤 → 只有該**條規則**失敗，在 Settings 的規則清單標紅（`loadError`）。
  - 全部規則都失敗 → 服務保留**舊的**規則集繼續運作，並把健康度轉為降級。
- 熱重載時，內容雜湊（`ContentHash`，註解不影響）**相同**的規則保留進行中的部分比對；**不同**的規則丟棄進行中比對——每則告警都必須能追溯到一份確定的規則文字。

## 2. 頂層欄位

| 鍵 | 必填 | 型別／值域 | 預設 | 說明 |
|---|---|---|---|---|
| `id` | ✅ | `R-T<ATT&CK>-<三位序號>` | — | 例 `R-T1055-001`（CONVENTIONS C-8 原則 3） |
| `title` | ✅ | ≤ 120 字 | — | 告警標題的來源（不依賴 LLM） |
| `description` | | 字串 | | |
| `severity` | ✅ | `low` \| `medium` \| `high` \| `critical` | — | 告警嚴重度（分數 ≥ 95 時一律 critical） |
| `status` | | `enabled` \| `dryrun` \| `disabled` | **`dryrun`** | 新規則一律先觀察 |
| `score` | ✅ | 1–100 | — | 載入時 ×1000 轉 milli-point |
| `decay` | ✅ | `\d+[sm]`，30s–3600s | — | 半衰期；整棵樹取命中規則中**最長**者 |
| `deterministic` | | bool | `false` | 命中即跳 Blocked（只用於 IOC 雜湊這類零誤報條件） |
| `requires_events` | ✅ | EID 陣列 | — | 依賴的 Sysmon EID / 4104；用於健康度與「因缺少 EID 而停用」 |
| `attack` | | ATT&CK 技術編號陣列 | | 寫入 `alerts.attack_ids` |
| `sequence` | 二擇一 | 見 §4 | | 多步序列（Tier-2） |
| `event` + `where` | 二擇一 | 見 §3 | | 單事件規則（Tier-1）簡寫 |
| `threshold` / `within` / `correlate_by` | | | `within: 300s`、`process_tree_root` | 單事件規則可用 |
| `boosters` | | 見 §5 | | |
| `response` | | 見 §6 | `[alert]`、需確認 | |
| `exceptions` | | 見 §7 | | 規則自帶排除 |

## 3. 條件（`where`）

`where` 是條件陣列，彼此為 **AND**。需要 OR 時用 `any_of`，巢狀 AND 用 `all_of`：

```yaml
where:
  - field: image
    op: ends_with_any
    value: ['\powershell.exe', '\pwsh.exe']
  - any_of:
      - field: command_line
        op: contains
        value: 'downloadstring'
      - field: script_block
        op: contains
        value: 'invoke-mimikatz'
```

### 3.1 運算子

| 運算子 | value | 說明 |
|---|---|---|
| `equals` / `not_equals` | 單值 | 字串、整數、布林、GUID |
| `contains` / `not_contains` | 單一字串 | 子字串 |
| `starts_with` / `ends_with`（及 `not_`） | 單一字串 | |
| `in` / `not_in` | 清單 | 完全相等（字串或整數） |
| `contains_any` / `ends_with_any` / `starts_with_any`（及 `not_`） | 清單 | 任一符合 |
| `matches` / `not_matches` | 正則字串 | ECMAScript，**一律不分大小寫**（開頭的 `(?i)` 會被移除）。可加 `prefilter: [字面量...]`：任何命中都必須含其中之一，否則直接跳過正則。未寫時會自動抽取群組與字元類別以外最長的必要字面量 |
| `gt` / `lt` | 整數 | |
| `has_any` | 整數或 `0x` 遮罩，可為清單（OR） | `(值 & 遮罩) != 0`，用於 `granted_access` |
| `equals_ref` / `not_equals_ref` | `<步驟id>.<欄位>` | 只能引用**前序**步驟；步驟 0 與 booster 不可用 |

**大小寫**：所有字串比對都不分大小寫（ASCII）。常數請照文件習慣寫，載入時會自動小寫化。

**反斜線**：路徑請用**單引號**（`'\winword.exe'`）。YAML 單引號內反斜線是字面值；雙引號內是跳脫字元。

**三值約定**：欄位缺值時，任何述詞（**包含 `not_*`**）一律為 false。缺值代表「不知道」，不知道不得構成命中。

### 3.2 欄位

| 欄位 | 型別 | 來源 |
|---|---|---|
| `image` / `parent_image` | 字串 | 行為者／父程序完整路徑（父程序缺值時改由程序樹補） |
| `command_line` / `parent_command_line` | 字串 ⚠ 攻擊者可控 | EID 1；非 EID 1 事件取程序樹節點上的命令列 |
| `user` / `integrity_level` / `sha256` / `signer` | 字串 | |
| `signature_valid` | 布林 | EID 1 不含簽章資訊，通常缺值 |
| `process_guid` / `parent_process_guid` / `root_process_guid` / `target_process_guid` | GUID | |
| `pid` / `parent_pid` / `granted_access` / `dest_port` / `event_id` | 整數 | |
| `target_image` / `target_filename` | 字串 | EID 8/10；EID 11/15/23/26（EID 7 的 ImageLoaded 亦放這裡） |
| `registry_event_type` / `registry_path` / `registry_details` | 字串 | EID 12/13/14（`registry_path` 即 TargetObject，含值名稱） |
| `dest_ip` / `dest_hostname` / `query_name` / `query_results` / `pipe_name` | 字串 | EID 3 / 22 / 17-18 |
| `script_block` | 字串 ⚠ | 4104 |
| `tamper_type` | 字串 | EID 25 |
| `tree_depth` / `tree_score` | 整數（衍生） | 程序樹深度、該樹當前分數（整數分） |
| `image_is_signed` / `image_in_user_writable_dir` / `parent_is_office` | 布林（衍生） | |

### 3.3 事件型別（`event`）

可為單一字串或清單：`PROCESS_CREATE`(1)、`NETWORK_CONNECT`(3)、`PROCESS_TERMINATE`(5)、`IMAGE_LOAD`(7)、`REMOTE_THREAD`(8)、`PROCESS_ACCESS`(10)、`FILE_CREATE`(11)、`REGISTRY_ADD`(12)、`REGISTRY_SET`(13)、`REGISTRY_RENAME`(14)、`FILE_STREAM_HASH`(15)、`PIPE_CREATE`/`PIPE_CONNECT`(17/18)、`WMI_EVENT`(19-21)、`DNS_QUERY`(22)、`FILE_DELETE`(23/26)、`PROCESS_TAMPERING`(25)、`SCRIPT_BLOCK`(4104)。別名：`REG_SET`、`REGISTRY_EVENT`（= 12+13+14）、`CREATE_REMOTE_THREAD`。

## 4. 序列（Tier-2）

```yaml
sequence:
  within: 120s                 # 30s–600s；從步驟 0 命中起算，含邊界
  correlate_by: process_tree_root   # 或 process_guid
  steps:                       # 1–4 步，依序命中
    - id: office_spawn
      event: PROCESS_CREATE
      where: [...]
    - id: remote_inject
      event: REMOTE_THREAD
      where:
        - field: process_guid
          op: equals_ref
          value: office_spawn.process_guid
```

- **單獨的步驟 0 不計分**，只建立部分比對。完整命中才計一次分。
- 同一 `(規則, 樹)` 最多 8 個並行部分比對，超過丟最舊；全域上限 20,000。`seq_state_evicted` 持續 > 0 代表步驟 0 太寬鬆。
- 綁定相同的步驟 0 重複出現不會重開比對。
- 程序樹以 Sysmon `ProcessGuid` 建立；`explorer.exe`、`services.exe`、`svchost.exe` 等工作階段骨幹程序的子程序**各自成一棵樹**（見 `EnginePolicy::treeBoundaryImages`），否則整個桌面工作階段會落在同一棵樹上。

### 4.1 `threshold`

```yaml
threshold: {count: 30, within: 30s, distinct_field: target_filename}
```

步驟的條件在**滾動視窗**內成立 `count` 次（或 `distinct_field` 相異值達 `count` 個，上限 4,096）才算該步命中。成立後計數歸零。`threshold.within` 不得大於 `sequence.within`。

## 5. Boosters

```yaml
boosters:
  - id: shadow_delete
    event: PROCESS_CREATE
    score: 40
    where: [...]
```

- 在同一 `correlate_by` 鍵、`within` 視窗內，主規則已完整命中後，booster 條件成立即 `+score`。
- booster 早於主命中發生時先暫存，主命中成立時若仍在視窗內一併生效。
- 同一 booster 每個視窗只加一次；加分同樣飽和於 100。

## 6. 回應

```yaml
response:
  on_score_ge: 80           # 40 | 80 | 95
  actions: [suspend_process, alert]
  require_confirmation: false
```

- 動作只能是 CONVENTIONS C-9 的四個正規名：`suspend_process`、`terminate_process_tree`、`quarantine_file`、`firewall_block`（另可寫 `alert`，告警本來就會產生）。
- `require_confirmation: true`（預設）的規則**不自動執行**任何動作，只產生告警。
- **C-8 原則 4**：`terminate_process_tree` 只在分數 ≥ 95 或規則 `deterministic: true` 時自動執行；80–94 一律降為 `suspend_process`。
- 分數 ≥ 95（Blocked）時引擎另加 `terminate_process_tree` + `quarantine_file` + `firewall_block`（part2 §2.4.3）。
- `quarantine_file` 只作用於「位於使用者可寫目錄、且非有效簽章」的觸發程序映像；`firewall_block` 以該樹最近一次外連 IP 為目標；`EnginePolicy::neverTargetImages`（lsass、csrss、explorer、Cairn 自身…）永不作為目標。
- 學習期、暫停防護、或 `auto_response_enabled = false` 時：照常計分與告警，但不送出任何自動回應。
- **LLM 永遠不參與加分或阻擋**（CONVENTIONS C-8 原則 1）。

## 7. 三態與排除

| 狀態 | 載入 | 計分 | 轉移狀態 | 回應 | `rule_hits` |
|---|---|---|---|---|---|
| `disabled` | 編譯但不建索引 | ✗ | ✗ | ✗ | ✗ |
| `dryrun` | ✅ | 只進 `shadow_score` | ✗ | ✗ | ✅ `dryrun=1` |
| `enabled` | ✅ | ✅ | ✅ | ✅ | ✅ |

**排除在規則完整命中之後才評估**。被排除的命中仍寫入 `rule_hits(suppressed=1)` 並累加 `exclusions.hit_count`，因此可以回答「這條排除擋掉了多少偵測」。

規則自帶排除（`exceptions`）的 `kind` 與 DB `exclusions.kind` 相同：

| kind | 比對對象（觸發事件的行為者程序） |
|---|---|
| `path` | 映像完整路徑（完全相等） |
| `path_glob` | 映像路徑（`*` `?` 萬用字元） |
| `sha256` | 映像雜湊 |
| `signer` | 簽章者 |
| `rule_id` | 規則 ID（全域停用某條規則） |
| `cmdline_glob` | 命令列 |

⚠ 不要排除 `Microsoft Windows` 簽章者：powershell.exe、rundll32.exe 等 LOLBin 都由它簽署。

## 8. 檢查清單（提交新規則前）

1. `status: dryrun` 起步；**沒有紅隊驗證項的規則不得標為 `enabled`**（part4 §4.5.2）。
2. 高頻事件（EID 1/3/7/11）上的 `matches` 一定要搭配便宜的前置條件（同一 `where` 內的 `ends_with` / `contains`，或 `prefilter`）。AND 會依成本自動排序，但 `any_of` 內的正則每次都會跑。
3. `not_*` 條件不會在缺值時成立——若要排除某程序，請同時確保欄位必定存在。
4. 在 `tests/core/` 為新規則補一個正例與一個反例（`RuleLoaderTests` 會檢查整包規則都能載入）。
5. 跑 `python3 tools/check-rules.py`（CI 也會跑）：除 schema 外，還檢查 RuleCompiler 語意、`requires_events` 是否涵蓋用到的事件型別、`config/sysmon.xml` 是否真的會記錄這些事件、ATT&CK ID 是否在白名單、`prefilter` 是否涵蓋正則的所有匹配路徑。
   ⚠ 規則依賴的事件若在 `sysmon.xml` 是 `onmatch="include"`（EID 10/11/12/13/23），**Sysmon 只記錄符合 include 條件的事件**——檢查器會列出這些規則，請確認 include 條件涵蓋規則要看的值，否則規則在實機上永遠不會命中。
6. 跑 `tools/Export-FpReport.ps1` 看 7 天 dry-run 的觸發排行；單一規則貢獻超過總告警 30% 者必須重寫，不得靠排除清單硬壓。
