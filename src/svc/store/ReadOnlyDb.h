// src/svc/store/ReadOnlyDb.h                  namespace cairn::store
// 唯讀查詢層（SDD-02 §6.5）。每個 RPC worker / LlmWorker 執行緒各自 Open 一個實例（不得跨執行緒共用）。
//   - 連線以 SQLITE_OPEN_READONLY + query_only=1 開啟：編譯期就杜絕 UI 路徑不小心寫入
//   - 禁止顯式交易（長交易會阻止 checkpoint 使 -wal 無限成長）；每個查詢一個隱式交易
//   - 每個公開方法設 2 秒查詢上限（sqlite3_progress_handler），逾時回 ErrorCode::Timeout（RPC 映射 504）
//   - 分頁一律 keyset cursor + LIMIT 一次讀完，不做「開著 cursor 慢慢讀」
//
// 也實作 model::IAlertContextProvider：LlmWorker（T5）以此組出 PromptInput。
//
// ★ 可攜程式碼。
#pragma once
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/Result.h"
#include "model/NarrativeTypes.h"
#include "store/AuditChain.h"
#include "store/QueryTypes.h"
#include "store/SqliteDb.h"

namespace cairn::store {

class ReadOnlyDb final : public model::IAlertContextProvider {
public:
    [[nodiscard]] static Result<std::unique_ptr<ReadOnlyDb>> Open(const std::filesystem::path& dbPath);

    // ---- alerts ----
    [[nodiscard]] Result<AlertListResult> ListAlerts(const AlertListFilter& f, int64_t nowMs);
    // 不存在回 nullopt（RPC 映射 404）
    [[nodiscard]] Result<std::optional<AlertDetail>> GetAlert(int64_t alertId);
    [[nodiscard]] Result<std::optional<AlertRecord>> GetAlertRecord(int64_t alertId);
    // 告警 id 對應的樹根（response.prepare / verdict 用）
    [[nodiscard]] Result<std::optional<std::string>> AlertRoot(int64_t alertId);
    // 以樹根為起點的整棵子樹（遞迴 CTE，深度上限 64）
    [[nodiscard]] Result<std::vector<ProcessNodeRecord>> GetProcessSubtree(const std::string& rootGuid);
    // 同一棵樹上的其他告警（verdict 的 affected_alerts）
    [[nodiscard]] Result<std::vector<int64_t>> AlertsForRoot(const std::string& rootGuid);

    // ---- events ----
    [[nodiscard]] Result<EventPage> QueryEvents(const EventQuery& q);

    // ---- exclusions ----
    [[nodiscard]] Result<std::vector<ExclusionRecord>> ListExclusions(int64_t nowMs, bool includeDisabled = true);
    [[nodiscard]] Result<ExclusionPreview> PreviewExclusion(const std::string& kind, const std::string& value,
                                                            const std::string& scopeRuleId, int64_t nowMs);
    // minDryrunHits：dryrun 命中達此次數才建議（誤報判定一次即建議）
    [[nodiscard]] Result<std::vector<ExclusionSuggestion>> ExclusionSuggestions(int64_t nowMs, int64_t minDryrunHits = 3);

    // ---- rules ----
    [[nodiscard]] Result<std::vector<RuleStats>> RuleStatsAll(int64_t nowMs);
    [[nodiscard]] Result<std::vector<RuleHitRecord>> HitsForAlert(int64_t alertId);

    // ---- audit ----
    [[nodiscard]] Result<AuditPage> ListAudit(const AuditQuery& q);
    [[nodiscard]] Result<std::optional<AuditRecord>> GetAudit(int64_t auditId);
    [[nodiscard]] Result<ChainReport> VerifyAudit(int64_t fromId = 1, int64_t toId = 0);
    // 啟動時驗證最近 N 列（SDD-03 §10.3 audit_chain_valid）
    [[nodiscard]] Result<ChainReport> VerifyRecentAudit(int64_t lastN = 1000);

    // ---- health ----
    [[nodiscard]] Result<std::optional<HealthRecord>> LatestHealth();
    [[nodiscard]] Result<std::vector<HealthRecord>> HealthSince(int64_t sinceMs, int limit = 2880);
    [[nodiscard]] Result<int64_t> DatabaseBytes();

    // ---- 啟動 ----
    [[nodiscard]] Result<MaxIds> QueryMaxIds();

    // ---- IAlertContextProvider ----
    [[nodiscard]] Result<model::PromptInput> LoadPromptInput(int64_t alertId) override;

    [[nodiscard]] SqliteDb& Db() noexcept { return *m_db; }

private:
    explicit ReadOnlyDb(std::unique_ptr<SqliteDb> db) noexcept : m_db(std::move(db)) {}
    [[nodiscard]] Result<std::vector<TimelineEntry>> LoadTimeline(int64_t alertId, int limit);
    // 由 fromGuid 沿 parent 往上走到 rootGuid（含），回傳根在前的鏈
    [[nodiscard]] Result<std::vector<ProcessNodeRecord>> LoadChain(const std::string& fromGuid,
                                                                   const std::string& rootGuid, size_t maxDepth);
    [[nodiscard]] Result<int64_t> ProcessScore(const std::string& processGuid);

    std::unique_ptr<SqliteDb> m_db;
};

// 時間軸事件的一行摘要（不可信字串；PromptBuilder / UI 端負責消毒與跳脫）
[[nodiscard]] std::string SummarizeEvent(const EventRecord& e);
// 路徑的檔名部分（"C:\\a\\b.exe" → "b.exe"）
[[nodiscard]] std::string BaseName(std::string_view path);

} // namespace cairn::store
