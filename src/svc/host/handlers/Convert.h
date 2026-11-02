// src/svc/host/handlers/Convert.h             namespace cairn::host::conv
// store / response / rules 的值型別 → UI 契約 JSON（ui-web/src/lib/types.ts，part3 §3.8）。
// 純函式、可攜、可單元測試（tests/svc/RpcHandlersTests.cpp）。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "host/HandlerContext.h"
#include "response/ResponseTypes.h"
#include "rules/RuleLoader.h"
#include "rpc/JsonRpcDispatcher.h"
#include "store/QueryTypes.h"

namespace cairn::host::conv {

using Json = nlohmann::json;

// ---- 基本換算 ----
[[nodiscard]] std::string Iso(int64_t unixMs);                       // 2026-08-19T06:26:09.331Z
[[nodiscard]] Json IsoOrNull(const std::optional<int64_t>& unixMs);
[[nodiscard]] std::optional<int64_t> ParseIso(std::string_view s);   // RFC3339（Z 或 ±hh:mm），秒以下可省略
[[nodiscard]] std::optional<int64_t> ParseTime(const Json& v);       // ISO 字串或 Unix ms 數字
[[nodiscard]] int ScoreDisplay(int64_t milli) noexcept;              // milli-point → 0–100（四捨五入、夾限）
[[nodiscard]] std::string NarrativeStateOf(std::string_view aiState);// ok→ready、schema_violation→failed，其餘同名
[[nodiscard]] std::string BaseName(std::string_view path);
[[nodiscard]] Json StrOrNull(const std::optional<std::string>& s);
[[nodiscard]] Json StrOrNull(const std::string& s);                  // 空字串 → null

// ---- 參數 ----
// UI 的 query 參數：單值為字串、多值為陣列；兩者都接受。
[[nodiscard]] std::vector<std::string> StringList(const Json& params, const char* key);
// ID 以字串傳入（也接受數字）；UI 用 alert_id，腳本用 id —— 兩者皆可。
[[nodiscard]] std::optional<int64_t> IdParam(const Json& params, std::initializer_list<const char*> keys);

// ---- 錯誤（data = {code, http?, details?}）----
[[nodiscard]] rpc::RpcError Err(std::string code, int http, std::string message, Json details = Json::object());
[[nodiscard]] rpc::RpcError FromError(const Error& e);               // ErrorCode → 業務碼 / HTTP

// ---- 告警 ----
[[nodiscard]] std::string WorkflowStatusOf(const std::optional<std::string>& verdict, std::string_view scoreState);
[[nodiscard]] Json AlertSummaryJson(const store::AlertSummary& a);
[[nodiscard]] Json AlertListJson(const store::AlertListResult& r);

// 回應動作的摘要（alerts.get 的 actions_taken）。優先來自 ResponseExecutor::ListActions。
[[nodiscard]] Json ActionTakenJson(const response::ActionRecord& r);
// 退路：alerts.actions_taken 的 JSON 陣列（ResponseExecutor 寫入的原樣物件）
[[nodiscard]] Json ActionsTakenFromDbJson(std::string_view actionsTakenJson, const std::vector<store::AuditRecord>& audits);

[[nodiscard]] std::string SignatureStatusOf(const std::optional<bool>& valid, const std::optional<std::string>& signer);
[[nodiscard]] Json ProcessNodeJson(const store::ProcessNodeRecord& n, const std::string& focusGuid);
[[nodiscard]] Json TimelineJson(const std::vector<store::TimelineEntry>& t);
[[nodiscard]] Json InjectionEdgesJson(const std::vector<store::TimelineEntry>& t);
[[nodiscard]] Json MatchedRulesJson(const store::AlertDetail& d, const std::vector<rules::RuleInfo>& infos);
[[nodiscard]] Json AlertDetailJson(const store::AlertDetail& d, const std::string& hostname,
                                   const std::vector<rules::RuleInfo>& infos, const Json& actionsTaken);

// narrative.get（part3 §3.8.3）
[[nodiscard]] Json NarrativeJson(const store::AlertRecord& a, int64_t nowMs, const std::string& llmDetail);
[[nodiscard]] std::string AttackUrl(std::string_view techniqueId);   // T1055.001 → https://attack.mitre.org/techniques/T1055/001/

// ---- 排除清單 ----
[[nodiscard]] Json ExclusionJson(const store::ExclusionRecord& e);
[[nodiscard]] Json ExclusionPreviewJson(const store::ExclusionPreview& p, const std::vector<store::AlertSummary>& samples);
[[nodiscard]] Json SuggestionJson(const store::ExclusionSuggestion& s);
// ExclusionRecord（DB）→ 引擎的 ExclusionEntry
[[nodiscard]] std::optional<rules::ExclusionEntry> ToEngineExclusion(const store::ExclusionRecord& e);

// ---- 規則 ----
[[nodiscard]] Json RuleInfoJson(const rules::RuleInfo& r, const store::RuleStats* stats);

// ---- 稽核 / 隔離 ----
[[nodiscard]] Json AuditEntryJson(const store::AuditRecord& a);
[[nodiscard]] Json QuarantineItemJson(const response::QuarantineEntry& q, bool restored, std::optional<int64_t> auditId);

// ---- 回應動作 ----
[[nodiscard]] Json PrepareJson(const response::PrepareResponse& r);
[[nodiscard]] Json ExecuteJson(const response::ExecuteResponse& r, const std::optional<std::string>& undoToken);
[[nodiscard]] Json RevertJson(const response::RevertResponse& r, int64_t nowMs);

// ---- 健康度 ----
struct HealthExtras {
    std::string protectionState = "protecting";   // protecting | learning | paused
    std::optional<int64_t> pausedUntil;           // INT64_MAX = 直到重開機
    bool learningActive = false;
    int  learningDay = 1;
    int  learningTotalDays = 3;
    int64_t alertsToday = 0;
    int64_t unreadHigh  = 0;
};
[[nodiscard]] Json HealthJson(const LiveHealth& h, const HealthExtras& x, int64_t nowMs);

} // namespace cairn::host::conv
