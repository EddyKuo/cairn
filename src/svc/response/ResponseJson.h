// src/svc/response/ResponseJson.h             namespace cairn::response
// 回應執行器的序列化、impactHash、執行順序與狀態彙總。可攜程式碼（nlohmann::json）。
#pragma once
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "base/Errors.h"
#include "response/ResponseTypes.h"

namespace cairn::response {

// ---- 狀態 ----
[[nodiscard]] std::string_view ActionStatusToString(ActionStatus s) noexcept;   // succeeded | partially_succeeded | failed | rejected
[[nodiscard]] std::string_view OverallResultOf(ActionStatus s) noexcept;        // part3 §3.8.4：success | partial_success | failed | rejected
[[nodiscard]] std::string_view AuditResultOf(ActionStatus s) noexcept;          // audit_log.result：ok | partial | failed
[[nodiscard]] int HttpStatusOf(ActionStatus s) noexcept;                        // 200 / 207 / 502 / 409

// 逐目標結果 → 整體狀態（SDD-03 §8.4）。空集合視為 Failed。
[[nodiscard]] ActionStatus ComputeStatus(const std::vector<TargetOutcome>& outcomes) noexcept;

// ---- 拒絕（前置驗證未過）的對外碼 ----
// ConfirmationTokenStore / ResponseExecutor 以 Error{code, context=API 碼} 回傳拒絕，
// context 固定為以下字串之一，RPC 層據此組 HTTP 狀態：
//   CONFIRMATION_REQUIRED(403) TOKEN_INVALID(403) TOKEN_EXPIRED(410) TOKEN_BINDING_MISMATCH(403)
//   IMPACT_CHANGED(409) TYPED_CONFIRMATION_MISMATCH(400) TOKEN_LIMIT(429) ACTION_NOT_ALLOWED(403)
//   NOT_REVERSIBLE(409) ALREADY_REVERTED(409) ACTION_NOT_FOUND(404) INVALID_TARGET(400) SERVICE_STOPPING(503)
struct RejectInfo {
    int         httpStatus = 500;
    std::string code;           // API 碼
    std::string message;        // 人話
};
[[nodiscard]] Error MakeReject(ErrorCode code, std::string_view apiCode, std::string_view message = {});
[[nodiscard]] RejectInfo RejectInfoOf(const Error& e);

// ---- 執行順序約束（SDD-03 §8.5.1）：suspend → quarantine → firewall → terminate ----
[[nodiscard]] int ActionOrderRank(model::ActionKind a) noexcept;

// ---- impactHash：正規化 JSON（nlohmann 的 object 以 key 排序、dump 無空白）的 SHA-256 ----
// 只納入「身分」欄位（不含 label / warning 等顯示字串），使顯示文案修改不致讓 token 失效。
[[nodiscard]] std::string ComputeImpactHash(int64_t alertId, model::ActionKind action, const ActionImpact& impact);

// ---- 字串工具 ----
[[nodiscard]] std::string BaseNameLower(std::string_view path);
[[nodiscard]] std::string ToLower(std::string_view s);
[[nodiscard]] bool ConstantTimeEquals(std::string_view a, std::string_view b) noexcept;
[[nodiscard]] std::string Base64Encode(const void* data, size_t len);
[[nodiscard]] bool Base64Decode(std::string_view in, std::vector<uint8_t>& out);
[[nodiscard]] std::string FormatIsoUtc(UnixMs ms);                              // 2026-08-19T06:26:09.331Z

// ---- JSON ----
[[nodiscard]] nlohmann::json ToJson(const model::ProcessRef& p);
[[nodiscard]] bool FromJson(const nlohmann::json& j, model::ProcessRef& p);
[[nodiscard]] nlohmann::json ToJson(const TargetOutcome& t);
[[nodiscard]] nlohmann::json ToJson(const ActionImpact& impact, model::ActionKind action);
[[nodiscard]] nlohmann::json ToJson(const PrepareResponse& r);               // part3 §3.8.4 Step 1 形狀
[[nodiscard]] nlohmann::json ToJson(const ExecuteResponse& r);               // part3 §3.8.4 Step 2 形狀
[[nodiscard]] nlohmann::json ToJson(const RevertResponse& r);
[[nodiscard]] nlohmann::json ToJson(const ActionRecord& r);
[[nodiscard]] bool FromJson(const nlohmann::json& j, ActionRecord& r);
[[nodiscard]] nlohmann::json ToJson(const QuarantineEntry& q);
[[nodiscard]] bool FromJson(const nlohmann::json& j, QuarantineEntry& q);

// alerts.actions_taken 的單一元素：{action, target, result, ts, action_id, automatic, ...}
[[nodiscard]] std::string ActionTakenJson(const ActionRecord& r);
// 稽核列的 params（SDD-03 §8.6.1 的 event_kind / targets / reason / impact_hash 皆收進 params JSON，
// 因 part2 §2.3.2 的 audit_log 權威 DDL 無這些欄位）
[[nodiscard]] std::string AuditParamsJson(std::string_view eventKind, const ActionRecord& r,
                                          std::string_view tokenSha256 = {});

} // namespace cairn::response
