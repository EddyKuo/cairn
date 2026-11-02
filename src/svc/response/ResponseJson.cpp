#include "response/ResponseJson.h"

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <optional>

#include "response/Sha256.h"

namespace cairn::response {

using nlohmann::json;

// ------------------------------------------------------------
// 狀態
// ------------------------------------------------------------
std::string_view ActionStatusToString(ActionStatus s) noexcept
{
    switch (s) {
    case ActionStatus::Succeeded: return "succeeded";
    case ActionStatus::PartiallySucceeded: return "partially_succeeded";
    case ActionStatus::Failed: return "failed";
    case ActionStatus::Rejected: return "rejected";
    }
    return "failed";
}

std::string_view OverallResultOf(ActionStatus s) noexcept
{
    switch (s) {
    case ActionStatus::Succeeded: return "success";
    case ActionStatus::PartiallySucceeded: return "partial_success";
    case ActionStatus::Failed: return "failed";
    case ActionStatus::Rejected: return "rejected";
    }
    return "failed";
}

std::string_view AuditResultOf(ActionStatus s) noexcept
{
    switch (s) {
    case ActionStatus::Succeeded: return "ok";
    case ActionStatus::PartiallySucceeded: return "partial";
    default: return "failed";
    }
}

int HttpStatusOf(ActionStatus s) noexcept
{
    switch (s) {
    case ActionStatus::Succeeded: return 200;
    case ActionStatus::PartiallySucceeded: return 207;
    case ActionStatus::Failed: return 502;
    case ActionStatus::Rejected: return 409;
    }
    return 500;
}

ActionStatus ComputeStatus(const std::vector<TargetOutcome>& outcomes) noexcept
{
    size_t ok = 0;
    for (const auto& o : outcomes)
        if (o.ok) ++ok;
    if (outcomes.empty() || ok == 0) return ActionStatus::Failed;
    if (ok == outcomes.size()) return ActionStatus::Succeeded;
    return ActionStatus::PartiallySucceeded;
}

// ------------------------------------------------------------
// 拒絕碼
// ------------------------------------------------------------
Error MakeReject(ErrorCode code, std::string_view apiCode, std::string_view message)
{
    std::string ctx(apiCode);
    if (!message.empty()) ctx.append(": ").append(message);
    return MakeError(code, ctx);
}

RejectInfo RejectInfoOf(const Error& e)
{
    RejectInfo r;
    const auto colon = e.context.find(':');
    r.code    = e.context.substr(0, colon);
    r.message = colon == std::string::npos ? std::string{} : e.context.substr(colon + 2 <= e.context.size() ? colon + 2 : colon + 1);

    struct Map { std::string_view code; int http; };
    static constexpr Map kMap[] = {
        {"CONFIRMATION_REQUIRED", 403}, {"TOKEN_INVALID", 403},       {"TOKEN_EXPIRED", 410},
        {"TOKEN_BINDING_MISMATCH", 403}, {"IMPACT_CHANGED", 409},     {"TYPED_CONFIRMATION_MISMATCH", 400},
        {"TOKEN_LIMIT", 429},            {"ACTION_NOT_ALLOWED", 403}, {"NOT_REVERSIBLE", 409},
        {"ALREADY_REVERTED", 409},       {"ACTION_NOT_FOUND", 404},   {"INVALID_TARGET", 400},
        {"SERVICE_STOPPING", 503},
    };
    for (const auto& m : kMap) {
        if (m.code == r.code) {
            r.httpStatus = m.http;
            return r;
        }
    }
    // 非拒絕類錯誤：依 ErrorCode 粗分
    r.code = std::string(ErrorCodeName(e.code));
    r.message = e.context;
    switch (e.code) {
    case ErrorCode::InvalidArgument: r.httpStatus = 400; break;
    case ErrorCode::NotFound: r.httpStatus = 404; break;
    case ErrorCode::AccessDenied: r.httpStatus = 403; break;
    case ErrorCode::Timeout: r.httpStatus = 504; break;
    default: r.httpStatus = 500; break;
    }
    return r;
}

int ActionOrderRank(model::ActionKind a) noexcept
{
    switch (a) {
    case model::ActionKind::SuspendProcess: return 0;
    case model::ActionKind::QuarantineFile: return 1;
    case model::ActionKind::FirewallBlock: return 2;
    case model::ActionKind::TerminateProcessTree: return 3;   // 不可逆永遠最後
    }
    return 4;
}

// ------------------------------------------------------------
// 字串工具
// ------------------------------------------------------------
std::string ToLower(std::string_view s)
{
    std::string out(s);
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

std::string BaseNameLower(std::string_view path)
{
    const auto pos = path.find_last_of("\\/");
    return ToLower(pos == std::string_view::npos ? path : path.substr(pos + 1));
}

bool ConstantTimeEquals(std::string_view a, std::string_view b) noexcept
{
    // 長度不同仍走完整個迴圈，避免以耗時推測長度
    const size_t n = std::max(a.size(), b.size());
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<unsigned>(ca ^ cb);
    }
    return diff == 0;
}

std::string Base64Encode(const void* data, size_t len)
{
    static constexpr char kTbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const auto* p = static_cast<const uint8_t*>(data);
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 2 < len; i += 3) {
        const uint32_t v = (uint32_t{p[i]} << 16) | (uint32_t{p[i + 1]} << 8) | p[i + 2];
        out.push_back(kTbl[(v >> 18) & 63]);
        out.push_back(kTbl[(v >> 12) & 63]);
        out.push_back(kTbl[(v >> 6) & 63]);
        out.push_back(kTbl[v & 63]);
    }
    if (i < len) {
        uint32_t v = uint32_t{p[i]} << 16;
        if (i + 1 < len) v |= uint32_t{p[i + 1]} << 8;
        out.push_back(kTbl[(v >> 18) & 63]);
        out.push_back(kTbl[(v >> 12) & 63]);
        out.push_back(i + 1 < len ? kTbl[(v >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

bool Base64Decode(std::string_view in, std::vector<uint8_t>& out)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    if (in.size() % 4 != 0) return false;
    for (size_t i = 0; i < in.size(); i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = in[i + static_cast<size_t>(k)];
            if (c == '=') {
                v[k] = 0;
                ++pad;
            } else {
                if (pad) return false;
                v[k] = val(c);
                if (v[k] < 0) return false;
            }
        }
        const uint32_t x = (static_cast<uint32_t>(v[0]) << 18) | (static_cast<uint32_t>(v[1]) << 12) |
                           (static_cast<uint32_t>(v[2]) << 6) | static_cast<uint32_t>(v[3]);
        out.push_back(static_cast<uint8_t>(x >> 16));
        if (pad < 2) out.push_back(static_cast<uint8_t>(x >> 8));
        if (pad < 1) out.push_back(static_cast<uint8_t>(x));
    }
    return true;
}

std::string FormatIsoUtc(UnixMs ms)
{
    const std::time_t secs = static_cast<std::time_t>(ms / 1000);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &secs);
#else
    gmtime_r(&secs, &tm);
#endif
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1,
                  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms % 1000));
    return buf;
}

// ------------------------------------------------------------
// impactHash
// ------------------------------------------------------------
std::string ComputeImpactHash(int64_t alertId, model::ActionKind action, const ActionImpact& impact)
{
    json items = json::array();
    for (const auto& it : impact.items) {
        json j;
        j["key"] = it.key;
        j["reachable"] = it.reachable;
        if (it.process) {
            j["pid"]   = it.process->pid;
            j["start"] = it.process->startTsMs;
            j["guid"]  = it.process->processGuid.ToString();
            j["image"] = ToLower(it.process->image);
        }
        if (it.filePath) j["file"] = ToLower(*it.filePath);
        if (it.fileSha256) j["sha256"] = *it.fileSha256;
        if (it.ip) j["ip"] = *it.ip;
        items.push_back(std::move(j));
    }
    // 以 key 排序，消除列舉順序造成的差異
    std::sort(items.begin(), items.end(),
              [](const json& a, const json& b) { return a.at("key").get<std::string>() < b.at("key").get<std::string>(); });
    json root;
    root["alert_id"] = alertId;
    root["action"]   = std::string(model::ActionKindToString(action));
    root["items"]    = std::move(items);
    root["typed"]    = ToLower(impact.typedExpected);
    return Sha256::HexOf(root.dump());
}

// ------------------------------------------------------------
// JSON
// ------------------------------------------------------------
json ToJson(const model::ProcessRef& p)
{
    return json{{"process_guid", p.processGuid.ToString()},
                {"pid", p.pid},
                {"start_ts", p.startTsMs},
                {"image", p.image},
                {"depth", p.depth}};
}

bool FromJson(const json& j, model::ProcessRef& p)
{
    if (!j.is_object()) return false;
    if (auto g = model::GuidValue::Parse(j.value("process_guid", std::string{}))) p.processGuid = *g;
    p.pid       = j.value("pid", 0u);
    p.startTsMs = j.value("start_ts", int64_t{0});
    p.image     = j.value("image", std::string{});
    p.depth     = j.value("depth", 0);
    return true;
}

json ToJson(const TargetOutcome& t)
{
    json j{{"key", t.key}, {"label", t.label}, {"result", t.ok ? "success" : "failed"}, {"reason", t.reason}};
    if (t.win32Error != 0) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "0x%X", static_cast<unsigned>(t.win32Error));
        j["error_code"] = buf;
        j["error_message"] = t.reason;
    }
    return j;
}

static bool OutcomeFromJson(const json& j, TargetOutcome& t)
{
    if (!j.is_object()) return false;
    t.key    = j.value("key", std::string{});
    t.label  = j.value("label", std::string{});
    t.ok     = j.value("result", std::string{}) == "success";
    t.reason = j.value("reason", std::string{});
    const auto code = j.value("error_code", std::string{});
    t.win32Error = code.empty() ? 0u : static_cast<uint32_t>(std::strtoul(code.c_str(), nullptr, 16));
    return true;
}

json ToJson(const ActionImpact& impact, model::ActionKind action)
{
    json j;
    json procs = json::array();
    json files = json::array();
    json ips   = json::array();
    for (const auto& it : impact.items) {
        if (it.process) {
            json p{{"process_guid", it.process->processGuid.ToString()},
                   {"pid", it.process->pid},
                   {"name", BaseNameLower(it.process->image)},
                   {"image_path", it.process->image},
                   {"reachable", it.reachable},
                   {"protected", it.protectedTarget},
                   {"warning", it.warning.empty() ? json(nullptr) : json(it.warning)}};
            if (!it.warningLevel.empty()) p["warning_level"] = it.warningLevel;
            procs.push_back(std::move(p));
        } else if (it.filePath) {
            json f{{"path", *it.filePath},
                   {"exists", it.reachable},
                   {"warning", it.warning.empty() ? json(nullptr) : json(it.warning)}};
            if (it.fileSize) f["size_bytes"] = *it.fileSize;
            if (it.fileSha256) f["sha256"] = *it.fileSha256;
            files.push_back(std::move(f));
        } else if (it.ip) {
            ips.push_back(json{{"ip", *it.ip},
                               {"warning", it.warning.empty() ? json(nullptr) : json(it.warning)}});
        }
    }
    switch (action) {
    case model::ActionKind::SuspendProcess:
    case model::ActionKind::TerminateProcessTree: j["processes"] = std::move(procs); break;
    case model::ActionKind::QuarantineFile: j["files"] = std::move(files); break;
    case model::ActionKind::FirewallBlock: j["addresses"] = std::move(ips); break;
    }
    j["total_count"] = impact.totalCount;
    j["protected_process_count"] = impact.protectedCount;
    j["warnings"] = impact.warnings;
    return j;
}

json ToJson(const PrepareResponse& r)
{
    json j{{"confirmation_token", r.confirmationToken.empty() ? json(nullptr) : json(r.confirmationToken)},
           {"expires_at", r.expiresAt ? json(FormatIsoUtc(r.expiresAt)) : json(nullptr)},
           {"action", std::string(model::ActionKindToString(r.action))},
           {"risk_level", "L" + std::to_string(r.riskLevel)},
           {"reversible", r.reversible},
           {"require_token", r.requireToken},
           {"require_typed_confirmation", r.requireTypedConfirmation},
           {"typed_confirmation_expected",
            r.requireTypedConfirmation ? json(r.typedConfirmationExpected) : json(nullptr)},
           {"impact", ToJson(r.impact, r.action)}};
    return j;
}

json ToJson(const ExecuteResponse& r)
{
    json results = json::array();
    for (const auto& t : r.results) results.push_back(ToJson(t));
    return json{{"action_id", r.actionId},
                {"action", std::string(model::ActionKindToString(r.action))},
                {"overall_result", std::string(OverallResultOf(r.status))},
                {"http_status", HttpStatusOf(r.status)},
                {"executed_at", FormatIsoUtc(r.executedAt)},
                {"initiator", r.actor},
                {"reason", r.reason},
                {"results", std::move(results)},
                {"audit_entry_id", r.auditId ? json(*r.auditId) : json(nullptr)},
                {"reversible", r.reversible},
                {"error_summary", r.errorSummary}};
}

json ToJson(const RevertResponse& r)
{
    json results = json::array();
    for (const auto& t : r.results) results.push_back(ToJson(t));
    return json{{"action_id", r.actionId},
                {"overall_result", std::string(OverallResultOf(r.status))},
                {"http_status", HttpStatusOf(r.status)},
                {"results", std::move(results)},
                {"audit_entry_id", r.auditId ? json(*r.auditId) : json(nullptr)}};
}

json ToJson(const ActionRecord& r)
{
    json results = json::array();
    for (const auto& t : r.results) results.push_back(ToJson(t));
    json suspended = json::array();
    for (const auto& p : r.suspended) suspended.push_back(ToJson(p));
    return json{{"schema_version", r.schemaVersion},
                {"action_id", r.actionId},
                {"alert_id", r.alertId},
                {"action", std::string(model::ActionKindToString(r.action))},
                {"status", std::string(ActionStatusToString(r.status))},
                {"executed_at", r.executedAt},
                {"actor", r.actor},
                {"reason", r.reason},
                {"automatic", r.automatic},
                {"impact_hash", r.impactHash},
                {"results", std::move(results)},
                {"suspended", std::move(suspended)},
                {"quarantine_ids", r.quarantineIds},
                {"firewall_rule_name", r.firewallRuleName},
                {"ip", r.ip},
                {"audit_id", r.auditId ? json(*r.auditId) : json(nullptr)},
                {"reverted", r.reverted},
                {"reverted_at", r.revertedAt ? json(*r.revertedAt) : json(nullptr)},
                {"revert_audit_id", r.revertAuditId ? json(*r.revertAuditId) : json(nullptr)}};
}

static std::optional<ActionStatus> ActionStatusFromString(std::string_view s)
{
    for (auto st : {ActionStatus::Succeeded, ActionStatus::PartiallySucceeded, ActionStatus::Failed,
                    ActionStatus::Rejected})
        if (ActionStatusToString(st) == s) return st;
    return std::nullopt;
}

bool FromJson(const json& j, ActionRecord& r)
{
    try {
        if (!j.is_object()) return false;
        r.schemaVersion = j.value("schema_version", 1);
        r.actionId      = j.at("action_id").get<std::string>();
        r.alertId       = j.value("alert_id", int64_t{0});
        const auto act  = model::ActionKindFromString(j.at("action").get<std::string>());
        if (!act) return false;
        r.action = *act;
        r.status = ActionStatusFromString(j.value("status", std::string{"failed"})).value_or(ActionStatus::Failed);
        r.executedAt = j.value("executed_at", int64_t{0});
        r.actor      = j.value("actor", std::string{});
        r.reason     = j.value("reason", std::string{});
        r.automatic  = j.value("automatic", false);
        r.impactHash = j.value("impact_hash", std::string{});
        r.results.clear();
        if (j.contains("results"))
            for (const auto& t : j.at("results")) {
                TargetOutcome o;
                if (OutcomeFromJson(t, o)) r.results.push_back(std::move(o));
            }
        r.suspended.clear();
        if (j.contains("suspended"))
            for (const auto& p : j.at("suspended")) {
                model::ProcessRef ref;
                if (FromJson(p, ref)) r.suspended.push_back(std::move(ref));
            }
        r.quarantineIds    = j.value("quarantine_ids", std::vector<std::string>{});
        r.firewallRuleName = j.value("firewall_rule_name", std::string{});
        r.ip               = j.value("ip", std::string{});
        r.auditId.reset();
        if (j.contains("audit_id") && j.at("audit_id").is_number_integer()) r.auditId = j.at("audit_id").get<int64_t>();
        r.reverted = j.value("reverted", false);
        r.revertedAt.reset();
        if (j.contains("reverted_at") && j.at("reverted_at").is_number_integer())
            r.revertedAt = j.at("reverted_at").get<int64_t>();
        r.revertAuditId.reset();
        if (j.contains("revert_audit_id") && j.at("revert_audit_id").is_number_integer())
            r.revertAuditId = j.at("revert_audit_id").get<int64_t>();
        return true;
    } catch (const json::exception&) {
        return false;   // P-2：模組內例外不得跨出
    }
}

json ToJson(const QuarantineEntry& q)
{
    return json{{"schema_version", q.schemaVersion},
                {"quarantine_id", q.quarantineId},
                {"original_path", q.originalPath},
                {"original_sddl", q.originalSddl},
                {"sha256", q.sha256},
                {"size_bytes", q.sizeBytes},
                {"quarantined_ts", q.quarantinedTs},
                {"alert_id", q.alertId},
                {"rule_ids", q.ruleIds},
                {"actor", q.actor},
                {"encryption", json{{"algo", q.algo}, {"nonce", q.nonceB64}, {"tag", q.tagB64}}},
                {"action_id", q.actionId ? json(*q.actionId) : json(nullptr)}};
}

bool FromJson(const json& j, QuarantineEntry& q)
{
    try {
        if (!j.is_object()) return false;
        q.schemaVersion = j.value("schema_version", 1);
        q.quarantineId  = j.at("quarantine_id").get<std::string>();
        q.originalPath  = j.at("original_path").get<std::string>();
        q.originalSddl  = j.value("original_sddl", std::string{});
        q.sha256        = j.at("sha256").get<std::string>();
        q.sizeBytes     = j.value("size_bytes", uint64_t{0});
        q.quarantinedTs = j.value("quarantined_ts", int64_t{0});
        q.alertId       = j.value("alert_id", int64_t{0});
        q.ruleIds       = j.value("rule_ids", std::vector<std::string>{});
        q.actor         = j.value("actor", std::string{});
        const auto& enc = j.at("encryption");
        q.algo     = enc.value("algo", std::string{"AES-256-GCM"});
        q.nonceB64 = enc.at("nonce").get<std::string>();
        q.tagB64   = enc.at("tag").get<std::string>();
        q.actionId.reset();
        if (j.contains("action_id") && j.at("action_id").is_string()) q.actionId = j.at("action_id").get<std::string>();
        return true;
    } catch (const json::exception&) {
        return false;
    }
}

std::string ActionTakenJson(const ActionRecord& r)
{
    std::string target;
    if (!r.ip.empty()) {
        target = r.ip;
    } else if (!r.results.empty()) {
        target = r.results.front().label;
        if (r.results.size() > 1) target += " (+" + std::to_string(r.results.size() - 1) + ")";
    }
    json j{{"action", std::string(model::ActionKindToString(r.action))},
           {"target", target},
           {"result", std::string(OverallResultOf(r.status))},
           {"ts", r.executedAt},
           {"action_id", r.actionId},
           {"automatic", r.automatic},
           {"actor", r.actor},
           {"reversible", model::IsReversible(r.action)},
           {"reverted", r.reverted}};
    json failed = json::array();
    for (const auto& t : r.results)
        if (!t.ok) failed.push_back(ToJson(t));
    if (!failed.empty()) j["failures"] = std::move(failed);
    return j.dump();
}

std::string AuditParamsJson(std::string_view eventKind, const ActionRecord& r, std::string_view tokenSha256)
{
    json targets = json::array();
    for (const auto& t : r.results) targets.push_back(ToJson(t));
    json j{{"event_kind", std::string(eventKind)},
           {"action_id", r.actionId},
           {"status", std::string(ActionStatusToString(r.status))},
           {"automatic", r.automatic},
           {"reason", r.reason},
           {"impact_hash", r.impactHash},
           {"targets", std::move(targets)}};
    if (!tokenSha256.empty()) j["confirmation_token_sha256"] = std::string(tokenSha256);
    return j.dump();
}

} // namespace cairn::response
