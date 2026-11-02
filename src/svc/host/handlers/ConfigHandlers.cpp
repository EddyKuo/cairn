// exclusions.list / add / remove / preview / suggestions / dismissSuggestion · rules.list / setStatus / explain
#include <algorithm>
#include <set>

#include "host/HostState.h"
#include "host/PolicyConfig.h"
#include "host/handlers/Handlers.h"
#include "host/handlers/HandlerUtil.h"

namespace cairn::host {

using namespace handlers;

namespace {

// 危險排除（會讓整台機器失去偵測）一律拒絕：萬用字元吃掉全部路徑、空白值。
bool IsDangerousExclusion(model::ExclusionKind kind, const std::string& value)
{
    std::string v;
    for (char c : value)
        if (c != ' ' && c != '\t') v.push_back(c);
    if (v.empty()) return true;
    if (kind == model::ExclusionKind::PathGlob || kind == model::ExclusionKind::CmdlineGlob) {
        if (v == "*" || v == "**" || v == "*.*" || v == "*\\*" || v == "c:\\*" || v == "C:\\*") return true;
    }
    return false;
}

std::string ScopeParam(const Json& p)
{
    if (auto s = rpc::GetString(p, "scope_rule_id")) return *s;
    if (auto s = rpc::GetString(p, "scope")) return (*s == "all" || *s == "global") ? std::string{} : *s;
    return {};
}

std::optional<model::ExclusionKind> KindParam(const Json& p)
{
    auto s = rpc::GetString(p, "type");
    if (!s) s = rpc::GetString(p, "kind");
    return s ? model::ExclusionKindFromString(*s) : std::nullopt;
}

} // namespace

void RegisterConfigHandlers(rpc::JsonRpcDispatcher& disp, const HandlerDeps& deps)
{
    // ---------------------------------------------------------------- exclusions.list
    disp.Register("exclusions.list", [deps](const Json&, const RpcContext&) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto r = db.Value()->ListExclusions(deps.clock->NowMs(), /*includeDisabled*/ true);
        if (!r) return Fail(r.GetError());
        Json items = Json::array();
        for (const auto& e : r.Value()) items.push_back(conv::ExclusionJson(e));
        return RpcOutcome::Ok(Json{{"items", std::move(items)}});
    });

    // ---------------------------------------------------------------- exclusions.add
    disp.Register("exclusions.add", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto kind = KindParam(p);
        if (!kind) return BadParam("type 必須為 path | path_glob | sha256 | signer | rule_id | cmdline_glob");
        const std::string value = rpc::GetString(p, "value").value_or("");
        if (IsDangerousExclusion(*kind, value)) return BadParam("排除值為空或過於寬鬆（會停用整台機器的偵測）");

        model::ExclusionInsert ins;
        ins.kind        = *kind;
        ins.value       = value;
        ins.scopeRuleId = ScopeParam(p);
        ins.reason      = rpc::GetString(p, "reason").value_or("");
        ins.createdBy   = "user";
        ins.createdTs   = deps.clock->NowMs();
        if (p.contains("expires_at")) ins.expiresTs = conv::ParseTime(p["expires_at"]);
        const auto sourceAlert = conv::IdParam(p, {"source_alert_id"});

        auto id = WriteAndWait(deps, ins);
        if (!id) {
            if (id.Code() == ErrorCode::AlreadyExists) return Fail(conv::Err("CONFLICT", 409, "相同的排除規則已存在"));
            return Fail(id.GetError());
        }
        (void)deps.host->ReloadExclusions();
        Audit(deps, ctx, "exclusion_add", "exclusion_add", sourceAlert, value,
              Json{{"exclusion_id", id.Value()}, {"kind", std::string(model::ExclusionKindToString(*kind))},
                   {"scope_rule_id", ins.scopeRuleId}, {"reason", ins.reason}});

        Json resp{{"exclusion_id", id.Value()}};
        if (deps.undo) {
            UndoEntry ue;
            ue.kind        = UndoEntry::Kind::RemoveExclusion;
            ue.exclusionId = id.Value();
            ue.alertId     = sourceAlert.value_or(0);
            auto [tok, exp] = deps.undo->Issue(ue, NewToken(deps));
            resp["undo_token"]      = tok;
            resp["undo_expires_at"] = conv::Iso(exp);
        }
        return RpcOutcome::Ok(std::move(resp));
    });

    // ---------------------------------------------------------------- exclusions.remove
    disp.Register("exclusions.remove", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"exclusion_id", "id"});
        if (!id) return BadParam("exclusion_id 必填");
        auto w = WriteAndWait(deps, model::ExclusionRemove{*id});
        if (!w) return Fail(w.GetError());
        (void)deps.host->ReloadExclusions();
        Audit(deps, ctx, "exclusion_remove", "exclusion_remove", std::nullopt, std::to_string(*id), Json{{"exclusion_id", *id}});
        return RpcOutcome::Ok(Json{{"ok", true}});
    });

    // ---------------------------------------------------------------- exclusions.preview
    disp.Register("exclusions.preview", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        const auto kind = KindParam(p);
        const std::string value = rpc::GetString(p, "value").value_or("");
        if (!kind || value.empty()) return BadParam("type 與 value 必填");
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto r = db.Value()->PreviewExclusion(std::string(model::ExclusionKindToString(*kind)), value, ScopeParam(p),
                                              deps.clock->NowMs());
        if (!r) return Fail(r.GetError());
        std::vector<store::AlertSummary> samples;
        for (auto aid : r.Value().sampleAlertIds) {
            if (auto rec = db.Value()->GetAlertRecord(aid); rec && rec.Value()) {
                store::AlertSummary s;
                s.id    = rec.Value()->id;
                s.ts    = rec.Value()->ts;
                s.title = rec.Value()->title;
                samples.push_back(std::move(s));
            }
        }
        Json out = conv::ExclusionPreviewJson(r.Value(), samples);
        out["dangerous"] = IsDangerousExclusion(*kind, value);
        return RpcOutcome::Ok(std::move(out));
    });

    // ---------------------------------------------------------------- exclusions.suggestions
    disp.Register("exclusions.suggestions", [deps](const Json&, const RpcContext&) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        const int64_t now = deps.clock->NowMs();
        auto r = db.Value()->ExclusionSuggestions(now, deps.config->suggestionMinDryrunHits);
        if (!r) return Fail(r.GetError());
        Json items = Json::array();
        for (const auto& s : r.Value()) items.push_back(conv::SuggestionJson(s));
        return RpcOutcome::Ok(Json{{"items", std::move(items)},
                                   {"learning_mode",
                                    Json{{"active", deps.state->LearningActive(now, deps.config->learningDays,
                                                                               deps.config->learningEnabled)},
                                         {"day", deps.state->LearningDay(now)},
                                         {"total_days", deps.config->learningDays}}}});
    });

    // ---------------------------------------------------------------- exclusions.dismissSuggestion
    disp.Register("exclusions.dismissSuggestion", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const bool all = rpc::GetBool(p, "all").value_or(false);
        std::vector<std::string> ids;
        if (all) {
            auto db = Reader(deps);
            if (!db) return Fail(db.GetError());
            auto r = db.Value()->ExclusionSuggestions(deps.clock->NowMs(), deps.config->suggestionMinDryrunHits);
            if (!r) return Fail(r.GetError());
            for (const auto& s : r.Value()) ids.push_back(s.suggestionId);
        } else {
            auto id = rpc::GetString(p, "suggestion_id");
            if (!id) {
                if (auto n = rpc::GetInt(p, "suggestion_id")) id = std::to_string(*n);
            }
            if (!id || id->empty()) return BadParam("suggestion_id 必填");
            ids.push_back(*id);
        }
        for (const auto& id : ids) {
            model::SuggestionDismiss d{id, deps.clock->NowMs(), ActorOf(ctx)};
            if (auto w = WriteAndWait(deps, std::move(d)); !w) return Fail(w.GetError());
        }
        Audit(deps, ctx, "suggestion_dismiss", "suggestion_dismiss", std::nullopt, all ? "all" : ids.front(),
              Json{{"count", ids.size()}});
        return RpcOutcome::Ok(Json{{"ok", true}, {"dismissed", ids.size()}});
    });

    // ---------------------------------------------------------------- rules.list
    disp.Register("rules.list", [deps](const Json&, const RpcContext&) -> RpcOutcome {
        const auto infos = deps.host->RuleInfos();
        std::vector<store::RuleStats> stats;
        if (auto db = Reader(deps)) {
            if (auto st = db.Value()->RuleStatsAll(deps.clock->NowMs())) stats = std::move(st).Value();
        }
        Json items = Json::array();
        std::string packHash;
        for (const auto& r : infos) {
            const store::RuleStats* s = nullptr;
            for (const auto& x : stats)
                if (x.ruleId == r.id) s = &x;
            items.push_back(conv::RuleInfoJson(r, s));
            packHash += r.contentHash.substr(0, 4);
        }
        return RpcOutcome::Ok(Json{{"items", std::move(items)},
                                   {"pack_version", "m0-" + std::to_string(infos.size()) + "-" + packHash.substr(0, 16)},
                                   {"pack_signature_valid", false}});   // M0 規則包不簽章（誠實揭露）
    });

    // ---------------------------------------------------------------- rules.setStatus
    disp.Register("rules.setStatus", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto ruleId = rpc::GetString(p, "rule_id");
        if (!ruleId || ruleId->empty()) return BadParam("rule_id 必填");
        const auto status = model::RuleStatusFromString(rpc::GetString(p, "status").value_or(""));
        if (!status) return BadParam("status 必須為 enabled | dryrun | disabled");
        auto r = deps.host->SetRuleStatus(*ruleId, *status);
        if (!r) return Fail(r.GetError());
        Audit(deps, ctx, "rule_status", "rule_status", std::nullopt, *ruleId,
              Json{{"status", std::string(model::RuleStatusToString(*status))}});
        return RpcOutcome::Ok(Json{{"ok", true}, {"rule_id", *ruleId}, {"status", r.Value().status}});
    });

    // ---------------------------------------------------------------- rules.explain
    disp.Register("rules.explain", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        const auto ruleId = rpc::GetString(p, "rule_id");
        if (!ruleId) return BadParam("rule_id 必填");
        for (const auto& r : deps.host->RuleInfos()) {
            if (r.id != *ruleId) continue;
            std::string eids;
            for (auto e : r.requiresEids) eids += (eids.empty() ? "" : ", ") + std::to_string(e);
            std::string text = r.title + "（" + r.severity + "，" + std::to_string(r.score) + " 分";
            if (r.deterministic) text += "，確定性規則：命中即達阻擋門檻";
            text += "）。觀察的事件類型：Sysmon EID " + eids + "。狀態：" + r.status + "。";
            Json j = conv::RuleInfoJson(r, nullptr);
            j["explanation"] = text;
            j["source_file"] = r.sourceFile;
            return RpcOutcome::Ok(std::move(j));
        }
        return Fail(conv::Err("NOT_FOUND", 404, "規則不存在：" + *ruleId));
    });
}

} // namespace cairn::host
