// src/core/model/WriteOp.h                    namespace cairn::model
// 所有寫入 SQLite 的請求都以 WriteOp 傳值進 WriterThread（T4）的佇列 —— T4 是唯一持有寫入連線者
// （part2 §2.3.3「單一 writer 原則」）。T3/T5/T6/T7 一律不得自行開寫入連線。
//
// ID 配發（SDD-02 §5.4 的「events.id 從哪裡來」）：
//   events.id 與 alerts.id 由 AnalysisThread 顯式指定（啟動時以 MAX(id)+1 初始化），
//   因此 rule_hits.event_id / alert_events.event_id / rule_hits.alert_id 在投遞當下就已知。
//
// 時間一律為 Unix epoch 毫秒（UnixMs）。interned 欄位在列中已解析為字串，store 不需認識 StringInterner。
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "base/Result.h"
#include "model/Domain.h"
#include "model/GuidValue.h"
#include "model/NormalizedEvent.h"

namespace cairn::model {

using UnixMs = int64_t;

// ---- events ----
struct EventRow {
    int64_t         id = 0;                 // 由 AnalysisThread 顯式指定
    NormalizedEvent ev;                     // interned 欄位由 WriterThread 以 interner 解析
    GuidValue       rootProcessGuid{};
    int64_t         scoreDeltaMilli = 0;
};

// ---- process_tree（upsert；禁止 INSERT OR REPLACE，SDD-02 §6.3.1）----
struct ProcessRow {
    GuidValue   processGuid{};
    GuidValue   parentProcessGuid{};
    GuidValue   rootProcessGuid{};
    int32_t     depth = 0;
    uint32_t    pid   = 0;
    std::string image;
    std::string commandLine;
    std::string userName;
    std::string integrityLevel;
    std::string sha256;
    std::string signatureSigner;
    std::optional<bool> signatureValid;
    UnixMs      startTs = 0;
    std::optional<UnixMs> endTs;
    uint32_t    eventCount = 0;
};

struct ProcessEndUpdate {          // EID 5 回填 end_ts
    GuidValue processGuid{};
    UnixMs    endTs = 0;
};

struct ProcessTerminatedByUs {     // 回應動作終止的標記
    GuidValue processGuid{};
};

// ---- scores（upsert）----
struct ScoreRow {
    GuidValue rootProcessGuid{};
    int64_t   scoreMilli  = 0;
    int64_t   peakMilli   = 0;
    int64_t   shadowMilli = 0;
    UnixMs    lastUpdateTs = 0;
    UnixMs    firstHitTs   = 0;
    TreeState state = TreeState::Benign;
};

// ---- rule_hits ----
struct RuleHitRow {
    UnixMs      ts = 0;
    std::string ruleId;
    GuidValue   rootProcessGuid{};
    std::optional<int64_t> eventId;
    std::optional<int64_t> alertId;
    int64_t     scoreDeltaMilli = 0;
    bool        dryrun     = false;
    bool        suppressed = false;
    std::optional<int64_t> suppressedBy;    // exclusions.id
    std::string ruleHash;
};

// ---- alerts（Urgent：獨立 Safe 交易立即提交，SDD-02 §6.3.3）----
struct AlertEventLink {
    int64_t                eventId = 0;
    std::optional<int32_t> stepIndex;       // sequence 第幾步；nullopt = 非序列證據
    std::string            role = "evidence";   // trigger | evidence | context
};

struct AlertRow {
    int64_t     id = 0;                     // 由 AnalysisThread 顯式指定
    UnixMs      ts = 0;
    GuidValue   rootProcessGuid{};
    std::optional<GuidValue> triggerProcessGuid;
    Severity    severity = Severity::High;
    int64_t     scoreAtTriggerMilli = 0;
    std::vector<std::string> ruleIds;
    std::vector<std::string> attackIds;
    std::string title;                      // 規則模板產生，不依賴 LLM
    std::string summary;                    // 規則模板產生，不依賴 LLM
    AiState     aiState = AiState::Pending;
    std::vector<AlertEventLink> events;     // 與告警同交易寫入 alert_events
    std::vector<RuleHitRow>     hits;       // 構成此告警的命中（alert_id 已填），同交易寫入
};

// ---- alerts 欄位回填 ----
struct AlertNarrativeUpdate {               // T5 LlmWorker 回填
    int64_t     alertId = 0;
    AiState     aiState = AiState::Ok;
    std::optional<std::string> narrative;
    std::optional<std::string> recommendation;
    std::optional<double>      confidence;
    std::vector<std::string>   aiAttackIds;
    std::optional<std::string> modelId;     // 模型檔 SHA256 前 16 碼
    std::optional<int64_t>     latencyMs;
};

struct AlertVerdictUpdate {                 // RPC alerts.setVerdict
    int64_t     alertId = 0;
    Verdict     verdict = Verdict::TruePositive;
    std::string note;
    UnixMs      ts = 0;
};

struct AlertActionAppend {                  // T6 回應執行結果附加到 alerts.actions_taken（JSON 陣列）
    int64_t     alertId = 0;
    std::string actionJson;                 // {"action":..,"target":..,"result":..,"ts":..,"audit_id":..}
};

// ---- audit_log（Urgent；row_hash 由 WriterThread 依雜湊鏈計算，呼叫端不填）----
struct AuditRow {
    UnixMs      ts = 0;
    std::string actor;                      // system | analyst | rule_engine
    std::string action;                     // C-9 動作名 / exclusion_add / verdict / db_rebuilt ...
    std::optional<int64_t> alertId;
    std::string target;
    std::string paramsJson = "{}";
    std::string result;                     // ok | failed | partial
    std::optional<std::string> error;
};

// ---- exclusions ----
struct ExclusionInsert {
    ExclusionKind kind = ExclusionKind::Path;
    std::string   value;
    std::string   scopeRuleId;              // '' = 全域
    std::string   reason;
    std::string   createdBy = "user";       // user | learning_mode | builtin
    UnixMs        createdTs = 0;
    std::optional<UnixMs> expiresTs;
};
struct ExclusionRemove { int64_t id = 0; };
struct ExclusionSetEnabled { int64_t id = 0; bool enabled = true; };
struct ExclusionHitIncrement { int64_t id = 0; uint32_t count = 1; UnixMs ts = 0; };

// ---- agent_health ----
struct HealthRow {
    UnixMs  ts = 0;
    int64_t eventsIngested = 0;
    int64_t eventsDropped  = 0;
    int64_t eventsFiltered = 0;
    int64_t queueDepth     = 0;
    double  cpuPercent     = 0;
    double  privateBytesMb = 0;
    double  dbSizeMb       = 0;
    std::string sysmonState = "ok";         // ok | outdated | missing
    std::string llmState    = "unavailable";// ok | unavailable | degraded
    std::optional<double> tier2P95Ms;
    std::optional<double> llmP95Ms;
};

// ---- 完成回呼（RPC 需要新列的 id 時用；在 WriterThread 上呼叫，實作不得阻塞）----
using WriteCompletion = std::function<void(Result<int64_t>)>;

using WritePayload = std::variant<
    EventRow, ProcessRow, ProcessEndUpdate, ProcessTerminatedByUs, ScoreRow, RuleHitRow,
    AlertRow, AlertNarrativeUpdate, AlertVerdictUpdate, AlertActionAppend, AuditRow,
    ExclusionInsert, ExclusionRemove, ExclusionSetEnabled, ExclusionHitIncrement, HealthRow>;

struct WriteOp {
    WritePayload    payload;
    WriteCompletion onDone;                 // 可為空

    // Urgent = alerts / audit_log / verdict：WriterThread 優先取出、獨立 Safe 交易（synchronous=FULL）。
    [[nodiscard]] bool IsUrgent() const noexcept
    {
        return std::holds_alternative<AlertRow>(payload) || std::holds_alternative<AuditRow>(payload) ||
               std::holds_alternative<AlertVerdictUpdate>(payload) ||
               std::holds_alternative<ExclusionInsert>(payload) ||
               std::holds_alternative<ExclusionRemove>(payload) ||
               std::holds_alternative<ExclusionSetEnabled>(payload);
    }
};

// 寫入佇列的抽象，讓 core（AnalysisEngine）可在測試中注入 fake。
class IWriteSink {
public:
    virtual ~IWriteSink() = default;
    // 非阻塞。false = 佇列滿（呼叫端計入 events_dropped）；Urgent 項目不受容量限制。
    [[nodiscard]] virtual bool Post(WriteOp&& op) = 0;
};

} // namespace cairn::model
