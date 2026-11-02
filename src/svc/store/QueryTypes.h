// src/svc/store/QueryTypes.h                  namespace cairn::store
// 唯讀查詢的值型別。RPC 層（part3 §3.8 / SDD-03 §9.3.2）負責轉成 JSON：
//   - 分數一律為 milli-point（RPC 邊界除以 1000 四捨五入成 0–100 顯示分）
//   - 時間一律為 Unix ms（RPC 邊界轉 RFC3339）
//   - GUID 為大寫含大括號字串（與 DB 一致）
// 本檔刻意不含任何 JSON 相依：查詢層只回傳資料，呈現交給 RPC。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cairn::store {

// ---------------------------------------------------------------- alerts.list
enum class AlertSort : uint8_t { TimeDesc, RiskDesc };

struct AlertListFilter {
    std::vector<std::string> severities;     // low | medium | high | critical；空 = 不限
    // 工作流狀態（由 DB 欄位推導，見 AlertSummary::status）：pending | auto_blocked | resolved
    std::vector<std::string> statuses;
    std::optional<int64_t>   since, until;   // ts 範圍（含）
    std::string              q;              // 標題 / 映像路徑 / 規則 ID 子字串（不分大小寫）
    std::optional<bool>      hasNarrative;   // ai_state = 'ok'
    bool                     blockedOnly = false;
    AlertSort                sort  = AlertSort::TimeDesc;
    int                      limit = 20;     // 上限 200
    std::optional<std::string> cursor;       // 上一頁回傳的 nextCursor（opaque）
};

// 列表列的程序鏈摘要（樹根 → 觸發程序，最多 8 層）
struct ChainItem {
    std::string name;              // 映像檔名
    uint32_t    pid = 0;
    int64_t     scoreDeltaMilli = 0;   // 此程序事件累計貢獻的分數（enabled 且未抑制）
    int32_t     depth = 0;
};

struct AlertSummary {
    int64_t     id = 0;
    int64_t     ts = 0;
    std::string severity;
    int64_t     scoreAtTriggerMilli = 0;
    std::string title;
    std::string rootProcessGuid;
    std::optional<std::string> triggerProcessGuid;
    // 列表雙行列所需（part3 §3.8.5：不需 N+1 查詢）
    std::string processName;                 // 觸發程序（無則樹根）的映像檔名
    std::string parentName;
    std::string imagePath;
    std::vector<std::string> ruleIds;
    std::string aiState;                     // pending | ok | timeout | schema_violation | unavailable | skipped
    std::optional<std::string> analystVerdict;
    std::string scoreState;                  // scores.state（無列則 'normal'）
    int         actionsCount = 0;
    // 推導：analyst_verdict 非空 → resolved；scores.state = blocked → auto_blocked；其餘 pending
    std::string status;
    std::vector<ChainItem> processChain;
    std::optional<std::string> narrativePreview;   // ai_state = ok 時敘事的前 120 字元（UTF-8 安全截斷）
    bool exclusionCreated = false;                 // audit_log 有此告警的 exclusion_add 紀錄
};

struct AlertListStats {
    int64_t pending = 0;          // 未判定
    int64_t observing = 0;        // scores.state = watching 的樹數
    int64_t critical = 0;         // 未判定且 severity = critical
    int64_t today = 0;            // 近 24 小時告警數
    int64_t totalMatched = 0;     // 符合篩選的總數
    double  falsePositiveRate = 0;// 30 天內 false_positive / 已判定
};

struct AlertListResult {
    std::vector<AlertSummary>  items;
    std::optional<std::string> nextCursor;
    AlertListStats             stats;
};

// ---------------------------------------------------------------- alerts.get
struct AlertRecord {
    int64_t     id = 0;
    int64_t     ts = 0;
    std::string rootProcessGuid;
    std::optional<std::string> triggerProcessGuid;
    std::string severity;
    int64_t     scoreAtTriggerMilli = 0;
    std::vector<std::string> ruleIds;
    std::vector<std::string> attackIds;
    std::string title;
    std::optional<std::string> summary;
    std::string aiState;
    std::optional<std::string> aiNarrative;
    std::optional<std::string> aiRecommendation;
    std::optional<double>      aiConfidence;
    std::vector<std::string>   aiAttackIds;
    std::optional<std::string> aiModelId;
    std::optional<int64_t>     aiLatencyMs;
    std::string actionsTakenJson = "[]";     // 原樣 JSON 陣列（ResponseExecutor 寫入的物件）
    std::optional<std::string> analystVerdict;
    std::optional<std::string> analystNote;
    std::optional<int64_t>     verdictTs;
};

struct ScoreRecord {
    std::string rootProcessGuid;
    int64_t     scoreMilli = 0, peakMilli = 0, shadowMilli = 0;
    int64_t     lastUpdateTs = 0, firstHitTs = 0;
    std::string state;
};

struct ProcessNodeRecord {
    std::string processGuid;
    std::optional<std::string> parentProcessGuid;
    std::string rootProcessGuid;
    int32_t     depth = 0;                   // 相對告警樹根的深度（遞迴 CTE 計算）
    uint32_t    pid = 0;
    std::optional<std::string> image;
    std::optional<std::string> commandLine;
    std::optional<std::string> userName;
    std::optional<std::string> integrityLevel;
    std::optional<std::string> sha256;
    std::optional<std::string> signer;
    std::optional<bool>        signatureValid;
    int64_t     startTs = 0;
    std::optional<int64_t> endTs;
    int64_t     eventCount = 0;
    bool        terminatedByUs = false;
    bool        placeholder = false;         // pid = 0：FK 佔位節點（EID 1 未收到）
    int64_t     childCount = 0;
    std::vector<std::string> ruleIds;        // 命中此程序事件的規則（去重）
    int64_t     scoreDeltaMilli = 0;         // 此程序事件累計貢獻的分數
};

struct HitBrief {
    std::string ruleId;
    int64_t     scoreDeltaMilli = 0;
    bool        dryrun = false;
    bool        suppressed = false;
};

struct EventRecord {
    int64_t     id = 0;
    int64_t     ts = 0;
    std::string source;
    int32_t     sourceEventId = 0;
    std::string eventType;
    int32_t     priority = 2;
    std::optional<std::string> processGuid, parentProcessGuid, rootProcessGuid;
    uint32_t    pid = 0;
    std::optional<std::string> image, parentImage, commandLine, parentCommandLine, userName, integrityLevel, sha256;
    std::optional<std::string> signer;
    std::optional<bool>        signatureValid;
    std::optional<std::string> targetProcessGuid, targetImage;
    std::optional<int64_t>     grantedAccess;
    std::optional<std::string> targetFilename, registryPath, registryDetails;
    std::optional<std::string> destIp;
    std::optional<int64_t>     destPort;
    std::optional<std::string> destHostname, queryName, queryResults, pipeName, scriptBlock;
    int64_t     scoreDeltaMilli = 0;
};

struct TimelineEntry {
    EventRecord event;
    std::optional<int32_t> stepIndex;        // alert_events.step_index
    std::string role;                        // trigger | evidence | context
    std::vector<HitBrief> hits;              // 此事件觸發的規則命中
};

struct RuleHitRecord {
    int64_t     id = 0;
    int64_t     ts = 0;
    std::string ruleId;
    std::string rootProcessGuid;
    std::optional<int64_t> eventId, alertId;
    int64_t     scoreDeltaMilli = 0;
    bool        dryrun = false, suppressed = false;
    std::optional<int64_t> suppressedBy;
    std::string ruleHash;
};

struct AuditRecord {
    int64_t     id = 0;
    int64_t     ts = 0;
    std::string actor, action, eventKind;
    std::optional<int64_t>     alertId;
    std::optional<std::string> target;
    std::string paramsJson;
    std::string result;
    std::optional<std::string> error;
    std::string prevHash, rowHash;
};

// 回應動作可選的目標（Alert Detail 的處置面板）
struct AvailableTargets {
    struct File { std::string path; };
    struct Ip   { std::string ip; std::optional<int64_t> port; };
    std::vector<File> files;   // 樹中程序的映像（非佔位）＋ FILE_CREATE / FILE_STREAM_HASH 的落地檔
    std::vector<Ip>   ips;     // 樹中 NETWORK_CONNECT 的目的端（去重，上限 50）
};

struct AlertDetail {
    AlertRecord                    alert;
    std::optional<ScoreRecord>     score;
    std::vector<ProcessNodeRecord> processTree;   // 依 start_ts 排序；深度上限 64
    std::vector<TimelineEntry>     timeline;      // alert_events 的事件，最舊在前（上限 500）
    std::vector<RuleHitRecord>     hits;          // 告警的命中（含 dryrun / suppressed，供 GET /alerts/{id}/hits）
    AvailableTargets               availableTargets;
    // 此告警的稽核列（alert_id 相符，id 遞增）：RPC 以此為 actions_taken 補 audit_id / reverted
    //（event_kind = action_reverted 且 params.reverts_audit_id 指向原動作）
    std::vector<AuditRecord>       audits;
};

// ---------------------------------------------------------------- events.query
struct EventQuery {
    std::optional<int64_t>     from, to;
    std::optional<std::string> processGuid;      // 程序或其樹（rootProcessGuid 任一相符）
    std::optional<std::string> eventType;        // PROCESS_CREATE ...
    std::optional<std::string> textContains;     // image / command_line / target_filename / query_name 子字串
    int                        limit = 100;      // 上限 1000
    std::optional<int64_t>     beforeId;         // cursor：取 id < beforeId（依 id 遞減）
};

struct EventPage {
    std::vector<EventRecord> items;
    std::optional<int64_t>   nextBeforeId;
};

// ---------------------------------------------------------------- exclusions
struct ExclusionRecord {
    int64_t     id = 0;
    std::string kind, value, scopeRuleId;
    std::optional<std::string> reason;
    std::string createdBy;
    int64_t     createdTs = 0;
    std::optional<int64_t> expiresTs;
    bool        enabled = true;
    int64_t     hitCount = 0;
    std::optional<int64_t> lastHitTs;
    int64_t     suppressedCount30d = 0;   // rule_hits.suppressed_by = id 且 30 天內
};

struct ExclusionPreview {
    int64_t              wouldSuppressCount = 0;          // 30 天內會被抑制的告警數
    int64_t              previouslyTruePositiveCount = 0; // 其中曾被判為真陽性者（高風險排除的警訊）
    std::vector<int64_t> sampleAlertIds;                  // 最多 5 筆
};

struct ExclusionSuggestion {
    std::string          suggestionId;   // 穩定 id：sha256(kind|value|scope) 前 16 碼
    std::string          kind = "path";
    std::string          value;          // 觸發程序映像（小寫）
    std::string          scopeRuleId;
    std::string          source;         // false_positive | dryrun
    int64_t              triggeredCount = 0;
    std::vector<std::string> affectedRuleIds;
    std::vector<int64_t> sampleAlertIds;
};

// ---------------------------------------------------------------- rules.list 統計
struct RuleStats {
    std::string ruleId;
    int64_t hits30d = 0;            // enabled 且未抑制的命中
    int64_t dryrunHits30d = 0;
    int64_t suppressed30d = 0;
    int64_t alerts30d = 0;          // 含此規則的告警數
    int64_t fpAlerts30d = 0;        // 其中被判為 false_positive 者
    int64_t shadowAlerts30d = 0;    // dryrun 命中的樹中 shadow >= 80 但實分 < 80 者（「若啟用會多幾則告警」）
    int64_t shadowFpAlerts30d = 0;  // 上述樹中後來被判為誤報者
};

// ---------------------------------------------------------------- audit
struct AuditQuery {
    std::optional<int64_t>   from, to;
    std::vector<std::string> actions;
    std::optional<std::string> actor;
    std::optional<std::string> q;          // target / params 子字串
    int                      limit = 100;  // 上限 1000
    std::optional<int64_t>   beforeId;
};


struct AuditPage {
    std::vector<AuditRecord> items;
    std::optional<int64_t>   nextBeforeId;
};

// ---------------------------------------------------------------- health
struct HealthRecord {
    int64_t id = 0, ts = 0;
    int64_t eventsIngested = 0, eventsDropped = 0, eventsFiltered = 0, queueDepth = 0;
    double  cpuPercent = 0, privateBytesMb = 0, dbSizeMb = 0;
    std::string sysmonState, llmState;
    std::optional<double> tier2P95Ms, llmP95Ms;
};

// ---------------------------------------------------------------- 啟動用
struct MaxIds {
    int64_t nextEventId = 1;   // SELECT IFNULL(MAX(id),0)+1 FROM events（含 sqlite_sequence，避免重用）
    int64_t nextAlertId = 1;
};

} // namespace cairn::store
