// alerts.list / alerts.get / alerts.setVerdict / narrative.get / narrative.regenerate / narrative.feedback / events.query
#include "engine/AnalysisEngine.h"
#include "host/AnalysisTasks.h"
#include "host/handlers/Handlers.h"
#include "host/handlers/HandlerUtil.h"
#include "response/ResponseExecutor.h"

namespace cairn::host {

using namespace handlers;

namespace {

Json EventRecordJson(const store::EventRecord& e)
{
    Json j{{"event_id", e.id},
           {"time", conv::Iso(e.ts)},
           {"source", e.source},
           {"eid", e.sourceEventId},
           {"event_type", e.eventType},
           {"process_guid", conv::StrOrNull(e.processGuid)},
           {"root_process_guid", conv::StrOrNull(e.rootProcessGuid)},
           {"pid", e.pid},
           {"image", conv::StrOrNull(e.image)},
           {"command_line", conv::StrOrNull(e.commandLine)},
           {"summary", store::SummarizeEvent(e)},
           {"score_delta", conv::ScoreDisplay(e.scoreDeltaMilli)}};
    if (e.targetFilename) j["target_filename"] = *e.targetFilename;
    if (e.registryPath) j["registry_path"] = *e.registryPath;
    if (e.destIp) j["remote_addr"] = *e.destIp;
    if (e.destPort) j["remote_port"] = *e.destPort;
    if (e.queryName) j["query_name"] = *e.queryName;
    return j;
}

} // namespace

void RegisterAlertHandlers(rpc::JsonRpcDispatcher& disp, const HandlerDeps& deps)
{
    // ---------------------------------------------------------------- alerts.list
    disp.Register("alerts.list", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());

        store::AlertListFilter f;
        f.severities = conv::StringList(p, "severity");
        f.statuses   = conv::StringList(p, "status");
        if (p.contains("since")) f.since = conv::ParseTime(p["since"]);
        if (p.contains("until")) f.until = conv::ParseTime(p["until"]);
        if (auto q = rpc::GetString(p, "q")) f.q = *q;
        if (auto hn = rpc::GetBool(p, "has_narrative")) f.hasNarrative = *hn;
        if (auto bo = rpc::GetBool(p, "blocked_only")) f.blockedOnly = *bo;
        if (auto s = rpc::GetString(p, "sort")) f.sort = (*s == "risk_desc") ? store::AlertSort::RiskDesc : store::AlertSort::TimeDesc;
        if (auto l = rpc::GetInt(p, "limit")) f.limit = static_cast<int>(std::clamp<int64_t>(*l, 1, 200));
        if (auto c = rpc::GetString(p, "cursor"); c && !c->empty()) f.cursor = *c;

        auto r = db.Value()->ListAlerts(f, deps.clock->NowMs());
        if (!r) return Fail(r.GetError());
        return RpcOutcome::Ok(conv::AlertListJson(r.Value()));
    });

    // ---------------------------------------------------------------- alerts.get
    disp.Register("alerts.get", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto r = db.Value()->GetAlert(*id);
        if (!r) return Fail(r.GetError());
        if (!r.Value()) return Fail(conv::Err("NOT_FOUND", 404, "告警不存在：" + std::to_string(*id)));
        const auto& d = *r.Value();

        // actions_taken：優先以 ResponseExecutor 的動作紀錄（含 audit_id / reverted / quarantine_id）
        Json actions = Json::array();
        bool fromExecutor = false;
        if (deps.responses) {
            if (auto recs = deps.responses->ListActions(*id)) {
                for (const auto& rec : recs.Value()) actions.push_back(conv::ActionTakenJson(rec));
                fromExecutor = !recs.Value().empty();
            }
        }
        if (!fromExecutor) actions = conv::ActionsTakenFromDbJson(d.alert.actionsTakenJson, d.audits);

        const auto health = deps.host->Health();
        return RpcOutcome::Ok(conv::AlertDetailJson(d, health.hostname, deps.host->RuleInfos(), actions));
    });

    // ---------------------------------------------------------------- alerts.setVerdict（part3 §3.3.2）
    disp.Register("alerts.setVerdict", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");

        std::optional<model::Verdict> verdict;
        if (auto v = rpc::GetString(p, "verdict")) {
            verdict = model::VerdictFromString(*v);
            if (!verdict) return BadParam("verdict 必須為 true_positive | false_positive | benign");
        }
        const auto workflow = rpc::GetString(p, "workflow_status").value_or("");
        if (!verdict && workflow == "resolved") verdict = model::Verdict::Benign;   // 佇列的「已處理」
        if (!verdict) return BadParam("需提供 verdict 或 workflow_status=resolved");

        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto rec = db.Value()->GetAlertRecord(*id);
        if (!rec) return Fail(rec.GetError());
        if (!rec.Value()) return Fail(conv::Err("NOT_FOUND", 404, "告警不存在"));

        std::string note = rpc::GetString(p, "note").value_or("");
        if (auto fr = rpc::GetString(p, "fp_reason"); fr && !fr->empty()) note = note.empty() ? *fr : *fr + "；" + note;

        // 1) 落地 analyst_verdict（Urgent / Safe 交易）
        model::AlertVerdictUpdate vu{*id, *verdict, note, deps.clock->NowMs()};
        if (auto w = WriteAndWait(deps, std::move(vu)); !w) return Fail(w.GetError());

        // 2) 引擎狀態：該樹轉 Resolved（不再自動轉移）。失敗不回滾判定（判定已是事實），僅記錄。
        const int64_t alertId = *id;
        const auto v          = *verdict;
        auto applied = deps.analysis->Run([alertId, v](engine::AnalysisEngine& e) { return e.ApplyVerdict(alertId, v).HasValue(); },
                                          deps.analysisTimeout);

        Json resp{{"ok", true}, {"affected_alerts", Json::array({std::to_string(alertId)})},
                  {"engine_updated", applied && applied.Value()}};

        Json auditParams{{"verdict", std::string(model::VerdictToString(v))}, {"note", note}};

        // 3) 誤報 → 選擇性建立排除規則
        if (v == model::Verdict::FalsePositive && p.contains("create_exclusion") && p["create_exclusion"].is_object()) {
            const auto& ce = p["create_exclusion"];
            const auto kind = model::ExclusionKindFromString(ce.value("type", ce.value("kind", std::string{})));
            const std::string value = ce.value("value", std::string{});
            if (!kind || value.empty()) return BadParam("create_exclusion.type / value 不合法");
            model::ExclusionInsert ins;
            ins.kind        = *kind;
            ins.value       = value;
            ins.scopeRuleId = ce.value("scope", ce.value("scope_rule_id", std::string{}));
            ins.reason      = "誤報：" + note;
            ins.createdBy   = "user";
            ins.createdTs   = deps.clock->NowMs();
            auto exId = WriteAndWait(deps, ins);
            if (!exId) return Fail(exId.GetError());
            (void)deps.host->ReloadExclusions();
            Audit(deps, ctx, "exclusion_add", "exclusion_add", alertId, value,
                  Json{{"exclusion_id", exId.Value()}, {"kind", std::string(model::ExclusionKindToString(*kind))},
                       {"scope_rule_id", ins.scopeRuleId}, {"source_alert_id", alertId}});
            resp["exclusion_id"] = exId.Value();
            auditParams["exclusion_id"] = exId.Value();

            if (deps.undo) {
                UndoEntry ue;
                ue.kind        = UndoEntry::Kind::RemoveExclusion;
                ue.exclusionId = exId.Value();
                ue.alertId     = alertId;
                auto [tok, exp] = deps.undo->Issue(ue, NewToken(deps));
                resp["undo_token"]      = tok;
                resp["undo_expires_at"] = conv::Iso(exp);
            }
            // 同一樹的其他未判定告警也受影響（part3 §3.3.2：「將影響 N 則告警」）
            if (auto others = db.Value()->AlertsForRoot(rec.Value()->rootProcessGuid)) {
                for (auto oid : others.Value())
                    if (oid != alertId) resp["affected_alerts"].push_back(std::to_string(oid));
            }
        }

        Audit(deps, ctx, "verdict", "verdict", alertId, rec.Value()->rootProcessGuid, auditParams);
        return RpcOutcome::Ok(std::move(resp));
    });

    // ---------------------------------------------------------------- narrative.get
    disp.Register("narrative.get", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto rec = db.Value()->GetAlertRecord(*id);
        if (!rec) return Fail(rec.GetError());
        if (!rec.Value()) return Fail(conv::Err("NOT_FOUND", 404, "告警不存在"));
        return RpcOutcome::Ok(conv::NarrativeJson(*rec.Value(), deps.clock->NowMs(), deps.host->Health().llmDetail));
    });

    // ---------------------------------------------------------------- narrative.regenerate
    disp.Register("narrative.regenerate", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        const std::string mode = rpc::GetString(p, "mode").value_or("same");
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto rec = db.Value()->GetAlertRecord(*id);
        if (!rec) return Fail(rec.GetError());
        if (!rec.Value()) return Fail(conv::Err("NOT_FOUND", 404, "告警不存在"));

        model::NarrativeRequest req;
        req.alertId    = *id;
        req.scoreMilli = rec.Value()->scoreAtTriggerMilli;
        req.enqueuedTs = deps.clock->NowMs();
        req.manual     = true;
        if (!deps.host->EnqueueNarrative(req, mode == "reduced_context")) {
            return Fail(conv::Err("SERVICE_UNAVAILABLE", 503, "本機 AI 目前無法接受請求"));
        }
        // 先把 ai_state 標回 pending，UI 輪詢即可看到進度
        model::AlertNarrativeUpdate u;
        u.alertId = *id;
        u.aiState = model::AiState::Pending;
        (void)deps.writes->Post(model::WriteOp{std::move(u), {}});
        Audit(deps, ctx, "narrative_regenerate", "narrative_regenerate", *id, "", Json{{"mode", mode}});
        return RpcOutcome::Ok(Json{{"state", "pending"}, {"_http_status", 202}});
    });

    // ---------------------------------------------------------------- narrative.feedback
    disp.Register("narrative.feedback", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        const auto helpful = rpc::GetBool(p, "helpful");
        if (!helpful) return BadParam("helpful 必填");
        // M0 無專用表：以稽核列保存（可由 Export 匯出做 M-07 可讀性分析）
        Audit(deps, ctx, "narrative_feedback", "narrative_feedback", *id, "",
              Json{{"helpful", *helpful}, {"reason", rpc::GetString(p, "reason").value_or("")}});
        return RpcOutcome::Ok(Json{{"ok", true}});
    });

    // ---------------------------------------------------------------- events.query
    disp.Register("events.query", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        store::EventQuery q;
        if (p.contains("from")) q.from = conv::ParseTime(p["from"]);
        if (p.contains("to")) q.to = conv::ParseTime(p["to"]);
        if (auto g = rpc::GetString(p, "process_guid")) q.processGuid = *g;
        if (auto t = rpc::GetString(p, "event_type")) q.eventType = *t;
        if (auto t = rpc::GetString(p, "q")) q.textContains = *t;
        if (auto l = rpc::GetInt(p, "limit")) q.limit = static_cast<int>(std::clamp<int64_t>(*l, 1, 1000));
        if (auto b = rpc::GetInt(p, "before_id")) q.beforeId = *b;
        auto r = db.Value()->QueryEvents(q);
        if (!r) return Fail(r.GetError());
        Json items = Json::array();
        for (const auto& e : r.Value().items) items.push_back(EventRecordJson(e));
        return RpcOutcome::Ok(Json{{"items", std::move(items)},
                                   {"next_before_id", r.Value().nextBeforeId ? Json(*r.Value().nextBeforeId) : Json(nullptr)}});
    });
}

} // namespace cairn::host
