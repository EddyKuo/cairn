#include "host/handlers/Convert.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <limits>
#include <set>

#include "store/ReadOnlyDb.h"

namespace cairn::host::conv {

// ============================================================ 基本換算

namespace {
// 公曆日期 → 自 1970-01-01 起的天數（Howard Hinnant 的 days_from_civil，避免依賴 timegm / _mkgmtime）
int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) noexcept
{
    y -= m <= 2;
    const int64_t  era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void CivilFromDays(int64_t z, int64_t& y, unsigned& m, unsigned& d) noexcept
{
    z += 719468;
    const int64_t  era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y                  = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp  = (5 * doy + 2) / 153;
    d                  = doy - (153 * mp + 2) / 5 + 1;
    m                  = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
}

bool Digits(std::string_view s, size_t pos, size_t n, int& out) noexcept
{
    if (pos + n > s.size()) return false;
    int v = 0;
    for (size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}
} // namespace

std::string Iso(int64_t unixMs)
{
    int64_t days = unixMs / 86'400'000;
    int64_t rem  = unixMs % 86'400'000;
    if (rem < 0) {
        rem += 86'400'000;
        --days;
    }
    int64_t  y = 0;
    unsigned m = 0, d = 0;
    CivilFromDays(days, y, m, d);
    const int64_t hh = rem / 3'600'000, mm = (rem / 60'000) % 60, ss = (rem / 1000) % 60, ms = rem % 1000;
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%04lld-%02u-%02uT%02lld:%02lld:%02lld.%03lldZ", static_cast<long long>(y), m, d,
                  static_cast<long long>(hh), static_cast<long long>(mm), static_cast<long long>(ss),
                  static_cast<long long>(ms));
    return buf;
}

Json IsoOrNull(const std::optional<int64_t>& unixMs)
{
    return unixMs ? Json(Iso(*unixMs)) : Json(nullptr);
}

std::optional<int64_t> ParseIso(std::string_view s)
{
    // YYYY-MM-DDTHH:MM:SS[.fff][Z|±hh:mm]，也接受只有日期（YYYY-MM-DD，視為 UTC 午夜）
    int Y = 0, M = 0, D = 0, h = 0, mi = 0, se = 0;
    if (!Digits(s, 0, 4, Y) || s.size() < 10 || s[4] != '-' || !Digits(s, 5, 2, M) || s[7] != '-' ||
        !Digits(s, 8, 2, D))
        return std::nullopt;
    if (M < 1 || M > 12 || D < 1 || D > 31) return std::nullopt;
    size_t  pos = 10;
    int64_t frac = 0;
    int64_t offsetMin = 0;
    if (pos < s.size()) {
        if (s[pos] != 'T' && s[pos] != 't' && s[pos] != ' ') return std::nullopt;
        if (!Digits(s, pos + 1, 2, h) || s.size() < pos + 9 || s[pos + 3] != ':' || !Digits(s, pos + 4, 2, mi) ||
            s[pos + 6] != ':' || !Digits(s, pos + 7, 2, se))
            return std::nullopt;
        pos += 9;
        if (pos < s.size() && s[pos] == '.') {
            ++pos;
            int64_t scale = 100;
            while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
                if (scale > 0) frac += (s[pos] - '0') * scale;
                scale /= 10;
                ++pos;
            }
        }
        if (pos < s.size()) {
            if (s[pos] == 'Z' || s[pos] == 'z') {
                ++pos;
            } else if (s[pos] == '+' || s[pos] == '-') {
                int oh = 0, om = 0;
                if (!Digits(s, pos + 1, 2, oh)) return std::nullopt;
                size_t mpos = pos + 3;
                if (mpos < s.size() && s[mpos] == ':') ++mpos;
                if (!Digits(s, mpos, 2, om)) return std::nullopt;
                offsetMin = (oh * 60 + om) * (s[pos] == '-' ? -1 : 1);
                pos       = mpos + 2;
            }
        }
        if (pos != s.size()) return std::nullopt;
        if (h > 23 || mi > 59 || se > 60) return std::nullopt;
    }
    const int64_t days = DaysFromCivil(Y, static_cast<unsigned>(M), static_cast<unsigned>(D));
    return ((days * 24 + h) * 60 + mi - offsetMin) * 60'000 + static_cast<int64_t>(se) * 1000 + frac;
}

std::optional<int64_t> ParseTime(const Json& v)
{
    if (v.is_number_integer()) return v.get<int64_t>();
    if (v.is_number()) return static_cast<int64_t>(v.get<double>());
    if (v.is_string()) {
        const auto& s = v.get_ref<const std::string&>();
        if (auto t = ParseIso(s)) return t;
        // 純數字字串視為 Unix ms
        if (!s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            try {
                return std::stoll(s);
            } catch (...) {
            }
        }
    }
    return std::nullopt;
}

int ScoreDisplay(int64_t milli) noexcept
{
    const int64_t v = (milli + (milli >= 0 ? 500 : -500)) / 1000;
    return static_cast<int>(std::clamp<int64_t>(v, 0, 100));
}

std::string NarrativeStateOf(std::string_view aiState)
{
    if (aiState == "ok") return "ready";
    if (aiState == "schema_violation") return "failed";
    if (aiState.empty()) return "pending";
    return std::string(aiState);   // pending | timeout | unavailable | skipped
}

std::string BaseName(std::string_view path)
{
    const auto p = path.find_last_of("\\/");
    return std::string(p == std::string_view::npos ? path : path.substr(p + 1));
}

Json StrOrNull(const std::optional<std::string>& s)
{
    return s && !s->empty() ? Json(*s) : Json(nullptr);
}

Json StrOrNull(const std::string& s)
{
    return s.empty() ? Json(nullptr) : Json(s);
}

std::vector<std::string> StringList(const Json& params, const char* key)
{
    std::vector<std::string> out;
    if (!params.is_object()) return out;
    auto it = params.find(key);
    if (it == params.end()) return out;
    auto add = [&](const Json& v) {
        if (!v.is_string()) return;
        // 也接受逗號分隔
        std::string s = v.get<std::string>();
        size_t      start = 0;
        while (start <= s.size()) {
            const size_t comma = s.find(',', start);
            std::string  part  = s.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
            if (!part.empty()) out.push_back(part);
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    };
    if (it->is_array()) {
        for (const auto& v : *it) add(v);
    } else {
        add(*it);
    }
    return out;
}

std::optional<int64_t> IdParam(const Json& params, std::initializer_list<const char*> keys)
{
    for (const char* k : keys) {
        if (auto v = rpc::GetInt(params, k)) return v;
        // "A-4821" 之類帶前綴的顯示 ID：取最後一段數字
        if (auto s = rpc::GetString(params, k)) {
            const auto p = s->find_last_not_of("0123456789");
            const std::string digits = p == std::string::npos ? *s : s->substr(p + 1);
            if (!digits.empty()) {
                try {
                    return std::stoll(digits);
                } catch (...) {
                }
            }
        }
    }
    return std::nullopt;
}

// ============================================================ 錯誤

rpc::RpcError Err(std::string code, int http, std::string message, Json details)
{
    Json data = Json::object();
    data["http"] = http;
    if (!details.is_null() && !(details.is_object() && details.empty())) data["details"] = std::move(details);
    const int rpcCode = code == "INVALID_PARAMS" ? rpc::kInvalidParams : rpc::kAppError;
    return rpc::RpcError{rpcCode, std::move(code), std::move(message), std::move(data)};
}

rpc::RpcError FromError(const Error& e)
{
    switch (e.code) {
    case ErrorCode::NotFound: return Err("NOT_FOUND", 404, e.context);
    case ErrorCode::InvalidArgument: return Err("INVALID_PARAMS", 400, e.context);
    case ErrorCode::Timeout: return Err("TIMEOUT", 504, e.context);
    case ErrorCode::ServiceUnavailable: return Err("SERVICE_UNAVAILABLE", 503, e.context);
    case ErrorCode::ConfirmationRequired: return Err("CONFIRMATION_REQUIRED", 403, e.context);
    case ErrorCode::ConfirmationExpired: return Err("TOKEN_EXPIRED", 410, e.context);
    case ErrorCode::TokenInvalid: return Err("TOKEN_INVALID", 401, e.context);
    case ErrorCode::ImpactChanged: return Err("IMPACT_CHANGED", 409, e.context);
    case ErrorCode::TypedConfirmationMismatch: return Err("TYPED_CONFIRMATION_MISMATCH", 400, e.context);
    case ErrorCode::NotReversible: return Err("NOT_REVERSIBLE", 409, e.context);
    case ErrorCode::DbBusy: return Err("TIMEOUT", 504, e.context);
    default: return Err("INTERNAL", 500, e.ToString());
    }
}

// ============================================================ 告警

std::string WorkflowStatusOf(const std::optional<std::string>& verdict, std::string_view scoreState)
{
    if (verdict) return *verdict == "false_positive" ? "false_positive" : "resolved";
    if (scoreState == "blocked") return "auto_blocked";
    if (scoreState == "watching") return "observing";
    return "pending";
}

Json AlertSummaryJson(const store::AlertSummary& a)
{
    Json chain = Json::array();
    for (const auto& c : a.processChain) {
        chain.push_back(Json{{"name", c.name}, {"pid", c.pid}, {"risk_score", ScoreDisplay(c.scoreDeltaMilli)},
                             {"depth", c.depth}});
    }
    std::string status = a.status.empty() ? WorkflowStatusOf(a.analystVerdict, a.scoreState) : a.status;
    if (a.analystVerdict && *a.analystVerdict == "false_positive") status = "false_positive";
    return Json{{"alert_id", std::to_string(a.id)},
                {"severity", a.severity},
                {"risk_score", ScoreDisplay(a.scoreAtTriggerMilli)},
                {"title", a.title},
                {"time", Iso(a.ts)},
                {"process_name", a.processName},
                {"parent_name", StrOrNull(a.parentName)},
                {"image_path", a.imagePath},
                {"rule_hits", a.ruleIds},
                {"status", status},
                {"narrative_state", NarrativeStateOf(a.aiState)},
                {"narrative_preview", StrOrNull(a.narrativePreview)},
                {"analyst_verdict", StrOrNull(a.analystVerdict)},
                {"exclusion_created", a.exclusionCreated},
                {"process_chain", std::move(chain)},
                {"root_process_guid", a.rootProcessGuid},
                {"actions_count", a.actionsCount}};
}

Json AlertListJson(const store::AlertListResult& r)
{
    Json items = Json::array();
    for (const auto& a : r.items) items.push_back(AlertSummaryJson(a));
    return Json{{"items", std::move(items)},
                {"next_cursor", StrOrNull(r.nextCursor)},
                {"stats",
                 Json{{"pending", r.stats.pending},
                      {"observing", r.stats.observing},
                      {"critical", r.stats.critical},
                      {"today", r.stats.today},
                      {"total_matched", r.stats.totalMatched},
                      {"false_positive_rate", r.stats.falsePositiveRate}}}};
}

Json ActionTakenJson(const response::ActionRecord& r)
{
    std::string target = r.ip;
    if (target.empty() && !r.results.empty()) {
        target = r.results.front().label;
        if (r.results.size() > 1) target += " (+" + std::to_string(r.results.size() - 1) + ")";
    }
    std::string result;
    switch (r.status) {
    case response::ActionStatus::Succeeded: result = "success"; break;
    case response::ActionStatus::PartiallySucceeded: result = "partial_success"; break;
    case response::ActionStatus::Failed: result = "failed"; break;
    case response::ActionStatus::Rejected: result = "rejected"; break;
    }
    if (r.reverted) result = "reverted";
    Json j{{"action_id", r.actionId},
           {"audit_id", r.auditId ? Json(*r.auditId) : Json(nullptr)},
           {"time", Iso(r.executedAt)},
           {"action", std::string(model::ActionKindToString(r.action))},
           {"target", target},
           {"initiator", r.automatic ? std::string("rule_engine") : r.actor},
           {"result", result},
           {"reversible", model::IsReversible(r.action)},
           {"reverted", r.reverted}};
    if (!r.quarantineIds.empty()) j["quarantine_id"] = r.quarantineIds.front();
    return j;
}

Json ActionsTakenFromDbJson(std::string_view actionsTakenJson, const std::vector<store::AuditRecord>& audits)
{
    Json out = Json::array();
    const Json arr = Json::parse(actionsTakenJson.begin(), actionsTakenJson.end(), nullptr, false);
    if (!arr.is_array()) return out;

    // 由稽核列推導 audit_id 與 reverted：action_completed / action_reverted 的 params.action_id
    auto findAudit = [&](const std::string& actionId, std::string_view kind) -> std::optional<int64_t> {
        for (const auto& a : audits) {
            if (a.eventKind != kind) continue;
            const Json p = Json::parse(a.paramsJson, nullptr, false);
            if (p.is_object() && p.value("action_id", std::string{}) == actionId) return a.id;
        }
        return std::nullopt;
    };

    for (const auto& e : arr) {
        if (!e.is_object()) continue;
        const std::string actionId = e.value("action_id", std::string{});
        const auto completed = actionId.empty() ? std::nullopt : findAudit(actionId, "action_completed");
        const bool reverted  = e.value("reverted", false) || (!actionId.empty() && findAudit(actionId, "action_reverted"));
        const std::string action = e.value("action", std::string{});
        std::string result       = e.value("result", std::string{});
        if (reverted) result = "reverted";
        const auto act = model::ActionKindFromString(action);
        out.push_back(Json{{"action_id", actionId},
                           {"audit_id", completed ? Json(*completed) : Json(nullptr)},
                           {"time", e.contains("ts") && e["ts"].is_number() ? Json(Iso(e["ts"].get<int64_t>())) : Json(nullptr)},
                           {"action", action},
                           {"target", e.value("target", std::string{})},
                           {"initiator", e.value("automatic", false) ? std::string("rule_engine")
                                                                      : e.value("actor", std::string{"analyst"})},
                           {"result", result},
                           {"reversible", act ? model::IsReversible(*act) : false},
                           {"reverted", reverted}});
    }
    return out;
}

std::string SignatureStatusOf(const std::optional<bool>& valid, const std::optional<std::string>& signer)
{
    if (!valid) return "unknown";
    if (*valid) return "valid";
    if (!signer || signer->empty()) return "unsigned";
    return "invalid";
}

Json ProcessNodeJson(const store::ProcessNodeRecord& n, const std::string& focusGuid)
{
    std::string state = "running";
    if (n.terminatedByUs) state = "terminated_by_cairn";
    else if (n.endTs) state = "exited";
    const std::string image = n.image.value_or(std::string{});
    return Json{{"process_guid", n.processGuid},
                {"parent_guid", StrOrNull(n.parentProcessGuid)},
                {"pid", n.pid},
                {"name", image.empty() ? std::string("(unknown)") : BaseName(image)},
                {"image_path", image},
                {"image_sha256", StrOrNull(n.sha256)},
                {"command_line", n.commandLine.value_or(std::string{})},
                {"command_line_decoded", nullptr},
                {"decode_source", nullptr},
                {"signer", StrOrNull(n.signer)},
                {"signature_status", SignatureStatusOf(n.signatureValid, n.signer)},
                {"created_at", Iso(n.startTs)},
                {"terminated_at", IsoOrNull(n.endTs)},
                {"state", state},
                {"risk_score", ScoreDisplay(n.scoreDeltaMilli)},
                {"rule_hits", n.ruleIds},
                {"depth", n.depth},
                {"is_focus", n.processGuid == focusGuid},
                {"preexisting", n.placeholder},
                {"child_count", n.childCount},
                {"hidden_low_risk_children", 0},
                {"user_name", StrOrNull(n.userName)},
                {"integrity_level", StrOrNull(n.integrityLevel)}};
}

Json TimelineJson(const std::vector<store::TimelineEntry>& t)
{
    Json out = Json::array();
    int  seq = 0;
    int64_t running = 0;
    for (const auto& te : t) {
        const auto& e = te.event;
        Json hits = Json::array();
        for (const auto& h : te.hits) {
            hits.push_back(Json{{"rule_id", h.ruleId},
                                {"step", te.stepIndex ? Json("step" + std::to_string(*te.stepIndex + 1)) : Json(nullptr)},
                                {"score_delta", (h.dryrun || h.suppressed) ? 0 : ScoreDisplay(h.scoreDeltaMilli)},
                                {"dryrun", h.dryrun},
                                {"suppressed", h.suppressed}});
            if (!h.dryrun && !h.suppressed) running += h.scoreDeltaMilli;
        }
        std::optional<std::string> target;
        if (e.targetFilename) target = e.targetFilename;
        else if (e.registryPath) target = e.registryPath;
        else if (e.queryName) target = e.queryName;
        else if (e.targetImage) target = e.targetImage;
        else if (e.pipeName) target = e.pipeName;

        Json j{{"seq", ++seq},
               {"event_id", e.id},
               {"time", Iso(e.ts)},
               {"process_guid", e.processGuid.value_or(std::string{})},
               {"event_type", e.eventType},
               {"summary", store::SummarizeEvent(e)},
               {"target", StrOrNull(target)},
               {"rule_hits", std::move(hits)},
               {"score_after", ScoreDisplay(running)},
               {"action_taken", nullptr},
               {"source", e.source},
               {"role", te.role}};
        if (e.destIp) j["remote_addr"] = *e.destIp;
        if (e.destPort) j["remote_port"] = *e.destPort;
        Json details = Json::object();
        details["eid"] = e.sourceEventId;
        if (e.image) details["image"] = *e.image;
        if (e.commandLine) details["command_line"] = *e.commandLine;
        if (e.grantedAccess) {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(*e.grantedAccess));
            details["granted_access"] = buf;
        }
        if (e.registryDetails) details["registry_details"] = *e.registryDetails;
        if (e.scriptBlock) details["script_block"] = e.scriptBlock->substr(0, 4096);
        if (e.sha256) details["sha256"] = *e.sha256;
        j["details"] = std::move(details);
        out.push_back(std::move(j));
    }
    return out;
}

Json InjectionEdgesJson(const std::vector<store::TimelineEntry>& t)
{
    Json out = Json::array();
    for (const auto& te : t) {
        const auto& e = te.event;
        if (!e.targetProcessGuid || !e.processGuid) continue;
        std::string technique;
        if (e.eventType == "REMOTE_THREAD") technique = "CreateRemoteThread";
        else if (e.eventType == "PROCESS_ACCESS") technique = "OpenProcess";
        else continue;
        std::string outcome = "observed";
        if (e.grantedAccess) {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "access 0x%llX", static_cast<unsigned long long>(*e.grantedAccess));
            outcome = buf;
        }
        out.push_back(Json{{"edge_id", "E-" + std::to_string(e.id)},
                           {"source_guid", *e.processGuid},
                           {"target_guid", *e.targetProcessGuid},
                           {"technique", technique},
                           {"occurred_at", Iso(e.ts)},
                           {"outcome", outcome},
                           {"evidence_source", "sysmon:" + std::to_string(e.sourceEventId)}});
    }
    return out;
}

Json MatchedRulesJson(const store::AlertDetail& d, const std::vector<rules::RuleInfo>& infos)
{
    std::vector<std::string> ids = d.alert.ruleIds;
    for (const auto& h : d.hits)
        if (std::find(ids.begin(), ids.end(), h.ruleId) == ids.end()) ids.push_back(h.ruleId);

    Json out = Json::array();
    for (const auto& id : ids) {
        const rules::RuleInfo* info = nullptr;
        for (const auto& r : infos)
            if (r.id == id) info = &r;
        bool counted = false;
        int  steps   = 0;
        for (const auto& h : d.hits)
            if (h.ruleId == id && !h.dryrun && !h.suppressed) counted = true;
        for (const auto& te : d.timeline)
            for (const auto& h : te.hits)
                if (h.ruleId == id && te.stepIndex) steps = std::max(steps, *te.stepIndex + 1);
        Json j{{"rule_id", id},
               {"title", info ? info->title : id},
               {"severity", info ? info->severity : std::string("high")},
               {"status", info ? info->status : std::string("enabled")},
               {"score", info ? info->score : 0},
               {"attack_ids", info ? info->attackIds : std::vector<std::string>{}},
               {"counted_toward_score", counted}};
        if (steps > 0) j["steps_matched"] = steps;
        out.push_back(std::move(j));
    }
    return out;
}

Json AlertDetailJson(const store::AlertDetail& d, const std::string& hostname, const std::vector<rules::RuleInfo>& infos,
                     const Json& actionsTaken)
{
    const auto& a      = d.alert;
    const std::string focus = a.triggerProcessGuid.value_or(a.rootProcessGuid);
    const std::string scoreState = d.score ? d.score->state : std::string("normal");

    Json tree = Json::array();
    std::optional<std::string> userName;
    for (const auto& n : d.processTree) {
        tree.push_back(ProcessNodeJson(n, focus));
        if (n.processGuid == a.rootProcessGuid && n.userName) userName = n.userName;
        if (!userName && n.userName) userName = n.userName;
    }
    Json files = Json::array();
    for (const auto& f : d.availableTargets.files) files.push_back(Json{{"path", f.path}, {"label", BaseName(f.path)}});
    Json ips = Json::array();
    for (const auto& ip : d.availableTargets.ips) {
        Json j{{"ip", ip.ip}};
        if (ip.port) j["port"] = *ip.port;
        ips.push_back(std::move(j));
    }

    Json j{{"alert_id", std::to_string(a.id)},
           {"created_at", Iso(a.ts)},
           {"hostname", hostname},
           {"severity", a.severity},
           {"risk_score", ScoreDisplay(a.scoreAtTriggerMilli)},
           {"title", a.title},
           {"summary", StrOrNull(a.summary)},
           {"status", WorkflowStatusOf(a.analystVerdict, scoreState)},
           {"analyst_verdict", StrOrNull(a.analystVerdict)},
           {"analyst_note", StrOrNull(a.analystNote)},
           {"user_name", StrOrNull(userName)},
           {"focus_process_guid", focus},
           {"root_process_guid", a.rootProcessGuid},
           {"process_tree", std::move(tree)},
           {"injection_edges", InjectionEdgesJson(d.timeline)},
           {"timeline", TimelineJson(d.timeline)},
           {"matched_rules", MatchedRulesJson(d, infos)},
           {"attack_ids", a.attackIds},
           {"actions_taken", actionsTaken.is_array() ? actionsTaken : Json::array()},
           {"telemetry_gaps", Json::array()},
           {"narrative_state", NarrativeStateOf(a.aiState)},
           {"available_targets", Json{{"files", std::move(files)}, {"ips", std::move(ips)}}}};
    if (d.score) {
        j["shadow_risk_score"]  = ScoreDisplay(d.score->shadowMilli);
        j["current_risk_score"] = ScoreDisplay(d.score->scoreMilli);
        j["peak_risk_score"]    = ScoreDisplay(d.score->peakMilli);
    }
    return j;
}

std::string AttackUrl(std::string_view id)
{
    std::string s(id);
    const auto dot = s.find('.');
    if (dot != std::string::npos) s = s.substr(0, dot) + "/" + s.substr(dot + 1);
    return "https://attack.mitre.org/techniques/" + s + "/";
}

Json NarrativeJson(const store::AlertRecord& a, int64_t nowMs, const std::string& llmDetail)
{
    const std::string state = NarrativeStateOf(a.aiState);
    const int score = ScoreDisplay(a.scoreAtTriggerMilli);

    std::string ruleList;
    for (const auto& r : a.ruleIds) ruleList += (ruleList.empty() ? "" : "、") + r;
    Json j{{"alert_id", std::to_string(a.id)},
           {"state", state},
           {"disclaimer",
            Json{{"text", "以下內容由本機 AI 模型自動生成，僅供參考，可能有誤。偵測與處置決策不依賴此內容。"},
                 {"actual_decision_basis",
                  Json{{"rule_ids", a.ruleIds},
                       {"risk_score", score},
                       {"threshold", 80},
                       {"sentence", "此告警由規則 " + ruleList + " 依確定性計分（" + std::to_string(score) +
                                        " 分，門檻 80）判定，AI 未參與判定。"}}}}}};

    if (state == "ready") {
        j["narrative"] = Json{{"what_happened", a.aiNarrative.value_or(std::string{})},
                              {"why_suspicious", a.summary.value_or(std::string{})},
                              {"what_it_means", std::string{}}};
        // 建議以換行或「；」分段（LLM 輸出為單一字串）
        Json recs = Json::array();
        if (a.aiRecommendation) {
            std::string cur;
            for (char c : *a.aiRecommendation + "\n") {
                if (c == '\n') {
                    while (!cur.empty() && (cur.back() == ' ' || cur.back() == '\r')) cur.pop_back();
                    if (!cur.empty()) recs.push_back(cur);
                    cur.clear();
                } else {
                    cur.push_back(c);
                }
            }
        }
        j["recommendations"]      = std::move(recs);
        j["recommendations_note"] = "建議僅供參考，不會自動執行；處置請使用上方的回應動作並經二次確認。";
        Json mapping = Json::array();
        for (const auto& id : a.aiAttackIds)
            mapping.push_back(Json{{"id", id}, {"name", id}, {"url", AttackUrl(id)}, {"offline_description", ""}});
        j["attack_mapping"] = std::move(mapping);
        if (a.aiConfidence) {
            j["confidence"]       = *a.aiConfidence;
            j["confidence_label"] = *a.aiConfidence >= 0.75 ? "high" : (*a.aiConfidence >= 0.4 ? "medium" : "low");
        }
        j["provenance"] = Json{{"model_id", a.aiModelId.value_or(std::string{})},
                               {"model_sha256", a.aiModelId.value_or(std::string{})},
                               {"generated_at", Iso(a.ts + a.aiLatencyMs.value_or(0))},
                               {"duration_ms", a.aiLatencyMs.value_or(0)},
                               {"backend", "llama.cpp"},
                               {"device", ""},
                               {"schema_validated", true},
                               {"attack_ids_whitelisted", true}};
    } else if (state == "pending") {
        j["progress"] = Json{{"elapsed_ms", std::max<int64_t>(0, nowMs - a.ts)}, {"expected_ms", 20'000}, {"streaming", false}};
        j["hint"]     = "AI 敘事生成中；偵測與處置不受影響。";
    } else {
        Json err{{"code", state == "failed" ? "SCHEMA_VIOLATION" : (state == "timeout" ? "TIMEOUT" : (state == "skipped" ? "SKIPPED" : "UNAVAILABLE"))},
                 {"message", state == "failed"      ? "AI 輸出未通過驗證，已捨棄"
                             : state == "timeout"   ? "AI 敘事生成逾時"
                             : state == "skipped"   ? "AI 敘事已略過（負載過高）"
                                                    : "本機 AI 未啟用或無法使用"},
                 {"detection_unaffected", true},
                 {"raw_output_available", false},
                 {"raw_output", nullptr}};
        if (state == "timeout") err["limit_ms"] = 30'000;
        if (state == "unavailable" && !llmDetail.empty()) err["user_note"] = llmDetail;
        j["error"]     = std::move(err);
        j["retryable"] = true;
        j["retry_options"] = Json::array({Json{{"mode", "same"}, {"label", "重新生成"}},
                                          Json{{"mode", "reduced_context"}, {"label", "以較少事件重新生成"}, {"event_count", 20}}});
    }
    return j;
}

// ============================================================ 排除清單

Json ExclusionJson(const store::ExclusionRecord& e)
{
    return Json{{"exclusion_id", e.id},
                {"kind", e.kind},
                {"value", e.value},
                {"scope_rule_id", e.scopeRuleId},
                {"created_by", e.createdBy},
                {"created_from_alert_id", nullptr},
                {"created_at", Iso(e.createdTs)},
                {"expires_at", IsoOrNull(e.expiresTs)},
                {"suppressed_count_30d", e.suppressedCount30d},
                {"hit_count", e.hitCount},
                {"last_hit_at", IsoOrNull(e.lastHitTs)},
                {"reason", StrOrNull(e.reason)},
                {"enabled", e.enabled}};
}

Json ExclusionPreviewJson(const store::ExclusionPreview& p, const std::vector<store::AlertSummary>& samples)
{
    Json s = Json::array();
    for (const auto& a : samples)
        s.push_back(Json{{"alert_id", std::to_string(a.id)}, {"title", a.title}, {"time", Iso(a.ts)}});
    // 樣本查詢失敗時仍至少回 id
    if (s.empty()) {
        for (auto id : p.sampleAlertIds) s.push_back(Json{{"alert_id", std::to_string(id)}, {"title", ""}, {"time", nullptr}});
    }
    return Json{{"would_suppress_count", p.wouldSuppressCount},
                {"previously_true_positive_count", p.previouslyTruePositiveCount},
                {"sample_alerts", std::move(s)}};
}

Json SuggestionJson(const store::ExclusionSuggestion& s)
{
    std::vector<std::string> samples;
    for (auto id : s.sampleAlertIds) samples.push_back(std::to_string(id));
    std::string rationale = s.source == "false_positive"
                                ? "此程序的告警曾被標記為誤報 " + std::to_string(s.triggeredCount) + " 次"
                                : "觀察期內 dry-run 規則命中 " + std::to_string(s.triggeredCount) + " 次，未構成真實威脅";
    return Json{{"suggestion_id", s.suggestionId},
                {"type", s.kind},
                {"value", s.value},
                {"scope", s.scopeRuleId},
                {"rationale", rationale},
                {"source", s.source},
                {"triggered_count", s.triggeredCount},
                {"affected_rule_ids", s.affectedRuleIds},
                {"sample_alert_ids", samples}};
}

std::optional<rules::ExclusionEntry> ToEngineExclusion(const store::ExclusionRecord& e)
{
    auto kind = model::ExclusionKindFromString(e.kind);
    if (!kind) return std::nullopt;
    rules::ExclusionEntry x;
    x.id          = e.id;
    x.kind        = *kind;
    x.value       = e.value;
    x.scopeRuleId = e.scopeRuleId;
    x.reason      = e.reason.value_or(std::string{});
    x.createdBy   = e.createdBy;
    x.enabled     = e.enabled;
    x.expiresTs   = e.expiresTs;
    return x;
}

// ============================================================ 規則

Json RuleInfoJson(const rules::RuleInfo& r, const store::RuleStats* st)
{
    const double fp = (st && st->alerts30d > 0) ? static_cast<double>(st->fpAlerts30d) / static_cast<double>(st->alerts30d) : 0.0;
    const double sfp = (st && st->shadowAlerts30d > 0)
                           ? static_cast<double>(st->shadowFpAlerts30d) / static_cast<double>(st->shadowAlerts30d)
                           : 0.0;
    return Json{{"rule_id", r.id},
                {"title", r.title},
                {"severity", r.severity},
                {"status", r.status},
                {"declared_status", r.declaredStatus},
                {"score", r.score},
                {"attack_ids", r.attackIds},
                {"deterministic", r.deterministic},
                {"content_hash", r.contentHash},
                {"hits_30d", st ? st->hits30d : 0},
                {"dryrun_hits_30d", st ? st->dryrunHits30d : 0},
                {"suppressed_30d", st ? st->suppressed30d : 0},
                {"fp_rate_30d", fp},
                {"shadow_alerts_30d", st ? st->shadowAlerts30d : 0},
                {"shadow_fp_rate_30d", sfp},
                {"load_error", r.loadError.empty() ? Json(nullptr) : Json(r.loadError)}};
}

// ============================================================ 稽核 / 隔離

Json AuditEntryJson(const store::AuditRecord& a)
{
    const Json p = Json::parse(a.paramsJson, nullptr, false);
    auto pstr = [&](const char* k) -> Json {
        if (p.is_object() && p.contains(k) && p[k].is_string() && !p[k].get_ref<const std::string&>().empty())
            return p[k];
        return nullptr;
    };
    return Json{{"audit_id", a.id},
                {"time", Iso(a.ts)},
                {"action", a.action},
                {"target", StrOrNull(a.target)},
                {"initiator", a.actor},
                {"reason", pstr("reason")},
                {"result", a.result},
                {"error", StrOrNull(a.error)},
                {"related_alert_id", a.alertId ? Json(std::to_string(*a.alertId)) : Json(nullptr)},
                {"chain_hash", a.rowHash},
                {"confirmation_token_sha256", pstr("confirmation_token_sha256")},
                {"impact_snapshot_sha256", pstr("impact_hash")},
                {"event_kind", StrOrNull(a.eventKind)}};
}

Json QuarantineItemJson(const response::QuarantineEntry& q, bool restored, std::optional<int64_t> auditId)
{
    return Json{{"quarantine_id", q.quarantineId},
                {"original_path", q.originalPath},
                {"sha256", q.sha256},
                {"size_bytes", q.sizeBytes},
                {"quarantined_at", Iso(q.quarantinedTs)},
                {"alert_id", q.alertId ? Json(std::to_string(q.alertId)) : Json(nullptr)},
                {"audit_id", auditId ? Json(*auditId) : Json(nullptr)},
                {"action_id", StrOrNull(q.actionId)},
                {"restored", restored}};
}

// ============================================================ 回應動作

namespace {
Json ImpactJson(const response::PrepareResponse& r)
{
    Json procs = Json::array(), files = Json::array(), ips = Json::array();
    for (const auto& it : r.impact.items) {
        auto warn = [&]() { return it.warning.empty() ? Json(nullptr) : Json(it.warning); };
        if (it.process) {
            Json p{{"process_guid", it.process->processGuid.ToString()},
                   {"pid", it.process->pid},
                   {"name", BaseName(it.process->image)},
                   {"image_path", it.process->image},
                   {"reachable", it.reachable},
                   {"protected", it.protectedTarget},
                   {"warning", warn()}};
            if (!it.warningLevel.empty()) p["warning_level"] = it.warningLevel;
            procs.push_back(std::move(p));
        } else if (it.filePath) {
            Json f{{"path", *it.filePath}, {"exists", it.reachable}, {"warning", warn()}};
            if (it.fileSize) f["size_bytes"] = *it.fileSize;
            if (it.fileSha256) f["sha256"] = *it.fileSha256;
            files.push_back(std::move(f));
        } else if (it.ip) {
            ips.push_back(Json{{"ip", *it.ip}, {"warning", warn()}});
        }
    }
    return Json{{"processes", std::move(procs)},
                {"files", std::move(files)},
                {"ips", std::move(ips)},
                {"total_count", r.impact.totalCount},
                {"protected_process_count", r.impact.protectedCount},
                {"warnings", r.impact.warnings}};
}
} // namespace

Json PrepareJson(const response::PrepareResponse& r)
{
    return Json{{"confirmation_token", StrOrNull(r.confirmationToken)},
                {"expires_at", r.expiresAt ? Json(Iso(r.expiresAt)) : Json(nullptr)},
                {"action", std::string(model::ActionKindToString(r.action))},
                {"risk_level", "L" + std::to_string(r.riskLevel)},
                {"reversible", r.reversible},
                {"require_token", r.requireToken},
                {"require_typed_confirmation", r.requireTypedConfirmation},
                {"typed_confirmation_expected", r.requireTypedConfirmation ? Json(r.typedConfirmationExpected) : Json(nullptr)},
                {"impact", ImpactJson(r)}};
}

namespace {
std::string OverallOf(response::ActionStatus s)
{
    switch (s) {
    case response::ActionStatus::Succeeded: return "success";
    case response::ActionStatus::PartiallySucceeded: return "partial_success";
    default: return "failed";
    }
}

Json ResultsJson(const std::vector<response::TargetOutcome>& outcomes)
{
    Json out = Json::array();
    for (const auto& t : outcomes) {
        Json j{{"target", t.key}, {"name", t.label}, {"result", t.ok ? "success" : "failed"}};
        // label 形如 "winword.exe (4820)"：取出 pid 供 UI 顯示
        if (const auto lp = t.label.rfind('('); lp != std::string::npos && t.label.back() == ')') {
            try {
                j["pid"]  = std::stoul(t.label.substr(lp + 1, t.label.size() - lp - 2));
                j["name"] = t.label.substr(0, lp > 0 ? lp - 1 : 0);
            } catch (...) {
            }
        }
        if (!t.ok) {
            if (t.win32Error) {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "0x%X", static_cast<unsigned>(t.win32Error));
                j["error_code"] = buf;
            } else {
                j["error_code"] = "FAILED";
            }
            j["error_message"] = t.reason;
        } else if (!t.reason.empty()) {
            j["note"] = t.reason;
        }
        out.push_back(std::move(j));
    }
    return out;
}
} // namespace

Json ExecuteJson(const response::ExecuteResponse& r, const std::optional<std::string>& undoToken)
{
    const bool automatic = r.actor == "rule_engine" || r.actor == "system";
    Json j{{"action_id", r.actionId},
           {"action", std::string(model::ActionKindToString(r.action))},
           {"overall_result", OverallOf(r.status)},
           {"executed_at", Iso(r.executedAt)},
           {"initiator", Json{{"type", automatic ? "rule_engine" : "analyst"}, {"name", r.actor}}},
           {"reason", r.reason},
           {"results", ResultsJson(r.results)},
           {"audit_entry_id", r.auditId ? Json(*r.auditId) : Json(nullptr)},
           {"reversible", r.reversible},
           {"undo_token", StrOrNull(undoToken)}};
    if (!r.errorSummary.empty()) j["error_summary"] = r.errorSummary;
    // part3 §3.8.4：部分成功 207、全部失敗 502（ApiBridge 讀 _http_status）
    if (r.status == response::ActionStatus::PartiallySucceeded) j["_http_status"] = 207;
    else if (r.status == response::ActionStatus::Failed) j["_http_status"] = 502;
    return j;
}

Json RevertJson(const response::RevertResponse& r, int64_t nowMs)
{
    Json j{{"action_id", r.actionId},
           {"reverted_at", Iso(nowMs)},
           {"result", OverallOf(r.status)},
           {"results", ResultsJson(r.results)},
           {"audit_entry_id", r.auditId ? Json(*r.auditId) : Json(nullptr)}};
    if (r.status == response::ActionStatus::PartiallySucceeded) j["_http_status"] = 207;
    else if (r.status == response::ActionStatus::Failed) j["_http_status"] = 502;
    return j;
}

// ============================================================ 健康度

Json HealthJson(const LiveHealth& h, const HealthExtras& x, int64_t nowMs)
{
    Json providers = Json::array();
    for (const auto& p : h.providers) providers.push_back(Json{{"name", p.name}, {"state", p.state}});
    Json anomalies = Json::array();
    for (const auto& a : h.anomalies24h) anomalies.push_back(Json{{"time", Iso(a.ts)}, {"message", a.message}});

    Json paused = nullptr;
    if (x.pausedUntil) {
        paused = *x.pausedUntil == std::numeric_limits<int64_t>::max() ? Json("until_reboot") : Json(Iso(*x.pausedUntil));
    }
    return Json{{"service", "CairnAgent"},
                {"version", h.serviceVersion},
                {"hostname", h.hostname},
                {"uptime_s", h.startedMs > 0 ? std::max<int64_t>(0, (nowMs - h.startedMs) / 1000) : 0},
                {"protection_state", x.protectionState},
                {"paused_until", paused},
                {"learning_mode", Json{{"active", x.learningActive}, {"day", x.learningDay}, {"total_days", x.learningTotalDays}}},
                {"providers", std::move(providers)},
                {"sysmon", Json{{"installed", h.sysmonInstalled}, {"version", StrOrNull(h.sysmonVersion)}, {"state", h.sysmonState}}},
                {"llm", Json{{"state", h.llmState},
                             {"device", h.llmDevice},
                             {"model_id", StrOrNull(h.llmModelId)},
                             {"detail", h.llmDetail},
                             {"p95_ms", h.llmP95Ms}}},
                {"resources", Json{{"cpu_p95", h.cpuP95Percent},
                                   {"ram_mb", h.ramMb},
                                   {"disk_mb", h.diskMb},
                                   {"events_per_sec", h.eventsPerSec},
                                   {"drop_rate", h.dropRate}}},
                {"dropped_by_priority", Json{{"critical", h.droppedByPriority[0]},
                                             {"high", h.droppedByPriority[1]},
                                             {"normal", h.droppedByPriority[2]},
                                             {"low", h.droppedByPriority[3]}}},
                {"tier2_p95_ms", h.tier2P95Ms},
                {"degraded", h.degraded},
                {"degraded_reasons", h.degradedReasons},
                {"anomalies_24h", std::move(anomalies)},
                {"self_protection",
                 Json{{"level", "none"},
                      {"disclosure", "M0 無核心驅動與 ELAM，系統管理員可停止本服務或刪除資料庫；稽核鏈只能證明單列未被竄改。"},
                      {"unexpected_terminations_30d", h.unexpectedTerminations30d}}},
                {"alerts_today", x.alertsToday},
                {"unread_high", x.unreadHigh}};
}

} // namespace cairn::host::conv
