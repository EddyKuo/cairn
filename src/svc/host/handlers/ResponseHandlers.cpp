// response.prepare / response.execute / response.revert / quarantine.list / undo.apply
// 兩階段協定（SDD-03 §8.3）：prepare 無副作用、回影響清單與 token；execute 帶 token（L1 可省）。
// 程序清單一律由 AnalysisThread 取快照（SDD-01 §2.5.3：RPC 不得直接讀程序樹），引擎沒有時退回 DB。
#include <algorithm>
#include <limits>

#include "engine/AnalysisEngine.h"
#include "host/AnalysisTasks.h"
#include "host/handlers/Handlers.h"
#include "host/handlers/HandlerUtil.h"
#include "response/ConfirmationTokenStore.h"
#include "response/ResponseExecutor.h"
#include "response/ResponseJson.h"

namespace cairn::host {

using namespace handlers;

namespace {

RpcOutcome FromResponseError(const Error& e)
{
    const auto ri = response::RejectInfoOf(e);
    return Fail(conv::Err(ri.code.empty() ? "ACTION_FAILED" : ri.code, ri.httpStatus,
                          ri.message.empty() ? e.ToString() : ri.message));
}

std::optional<model::ActionKind> ActionParam(const Json& p)
{
    auto s = rpc::GetString(p, "action");
    return s ? model::ActionKindFromString(*s) : std::nullopt;
}

// 取得程序子樹（根 → 葉）。引擎優先；樹已被淘汰時退回 DB 的 process_tree。
Result<std::vector<model::ProcessRef>> ProcessesFor(const HandlerDeps& deps, store::ReadOnlyDb& db,
                                                   const std::string& guidStr)
{
    const auto guid = model::GuidValue::Parse(guidStr);
    if (!guid) return MakeError(ErrorCode::InvalidArgument, "target_guid 格式錯誤");
    const auto g = *guid;
    auto snap = deps.analysis->Run([g](engine::AnalysisEngine& e) { return e.SnapshotTree(g, /*aliveOnly*/ true); },
                                   deps.analysisTimeout);
    if (snap && !snap.Value().empty()) return std::move(snap).Value();

    CAIRN_TRY(auto nodes, db.GetProcessSubtree(guidStr));
    std::vector<model::ProcessRef> out;
    for (const auto& n : nodes) {
        if (n.placeholder || n.endTs || n.terminatedByUs) continue;
        model::ProcessRef r;
        if (auto pg = model::GuidValue::Parse(n.processGuid)) r.processGuid = *pg;
        r.pid       = n.pid;
        r.startTsMs = n.startTs;
        r.image     = n.image.value_or(std::string{});
        r.depth     = n.depth;
        out.push_back(std::move(r));
    }
    // 父先於子（暫停時先凍結父程序，防止暫停過程中派生新程序）
    std::stable_sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.depth < b.depth; });
    if (out.empty()) return MakeError(ErrorCode::NotFound, "目標程序樹中沒有仍在執行的程序");
    return out;
}

// 依 action 與參數組出目標。缺省值：程序類 → 告警的觸發程序（無則樹根）；檔案 / IP → 告警可選目標的第一個。
Result<model::ResponseTarget> BuildTarget(const HandlerDeps& deps, store::ReadOnlyDb& db, int64_t alertId,
                                          model::ActionKind action, const Json& p)
{
    model::ResponseTarget t;
    switch (action) {
    case model::ActionKind::SuspendProcess:
    case model::ActionKind::TerminateProcessTree: {
        std::string guid = rpc::GetString(p, "target_guid").value_or("");
        if (guid.empty()) {
            CAIRN_TRY(auto rec, db.GetAlertRecord(alertId));
            if (!rec) return MakeError(ErrorCode::NotFound, "告警不存在");
            guid = action == model::ActionKind::TerminateProcessTree ? rec->rootProcessGuid
                                                                      : rec->triggerProcessGuid.value_or(rec->rootProcessGuid);
        }
        CAIRN_TRY(t.processes, ProcessesFor(deps, db, guid));
        break;
    }
    case model::ActionKind::QuarantineFile: {
        if (auto path = rpc::GetString(p, "target_path"); path && !path->empty()) {
            t.filePath = *path;
        } else {
            CAIRN_TRY(auto d, db.GetAlert(alertId));
            if (!d || d->availableTargets.files.empty()) return MakeError(ErrorCode::InvalidArgument, "target_path 必填");
            t.filePath = d->availableTargets.files.front().path;
        }
        break;
    }
    case model::ActionKind::FirewallBlock: {
        if (auto ip = rpc::GetString(p, "target_ip"); ip && !ip->empty()) {
            t.ip = *ip;
            if (auto port = rpc::GetInt(p, "target_port")) t.port = static_cast<uint16_t>(*port);
        } else {
            CAIRN_TRY(auto d, db.GetAlert(alertId));
            if (!d || d->availableTargets.ips.empty()) return MakeError(ErrorCode::InvalidArgument, "target_ip 必填");
            t.ip = d->availableTargets.ips.front().ip;
            if (d->availableTargets.ips.front().port) t.port = static_cast<uint16_t>(*d->availableTargets.ips.front().port);
        }
        break;
    }
    }
    t.key = response::TargetKeyOf(action, t);
    return t;
}

} // namespace

void RegisterResponseHandlers(rpc::JsonRpcDispatcher& disp, const HandlerDeps& deps)
{
    // ---------------------------------------------------------------- response.prepare
    disp.Register("response.prepare", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        if (!deps.responses) return Fail(conv::Err("SERVICE_UNAVAILABLE", 503, "回應執行器未啟動"));
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        const auto action = ActionParam(p);
        if (!action) return BadParam("action 必須為 suspend_process | terminate_process_tree | quarantine_file | firewall_block");
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        auto target = BuildTarget(deps, *db.Value(), *id, *action, p);
        if (!target) return Fail(target.GetError());
        auto r = deps.responses->Prepare(*id, *action, target.Value(), ctx.clientUser);
        if (!r) return FromResponseError(r.GetError());
        return RpcOutcome::Ok(conv::PrepareJson(r.Value()));
    });

    // ---------------------------------------------------------------- response.execute
    disp.Register("response.execute", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        if (!deps.responses) return Fail(conv::Err("SERVICE_UNAVAILABLE", 503, "回應執行器未啟動"));
        const auto id = conv::IdParam(p, {"alert_id", "id"});
        if (!id) return BadParam("alert_id 必填");
        const auto action = ActionParam(p);
        if (!action) return BadParam("action 不合法");

        response::ExecuteRequest req;
        req.alertId           = *id;
        req.action            = *action;
        req.confirmationToken = rpc::GetString(p, "confirmation_token").value_or("");
        req.typedConfirmation = rpc::GetString(p, "typed_confirmation").value_or("");
        req.reason            = rpc::GetString(p, "reason").value_or("");
        req.actor             = ActorOf(ctx);
        req.peerSid           = ctx.clientUser;
        if (req.confirmationToken.empty()) {
            // L1（suspend_process）可不經 prepare：此時必須自行組出目標（UI 契約 3）
            if (model::RiskLevelOf(*action) > 1) {
                return Fail(conv::Err("CONFIRMATION_REQUIRED", 403, "此動作需先 prepare 並帶回 confirmation_token"));
            }
            auto db = Reader(deps);
            if (!db) return Fail(db.GetError());
            auto target = BuildTarget(deps, *db.Value(), *id, *action, p);
            if (!target) return Fail(target.GetError());
            req.target = std::move(target).Value();
        }

        auto r = deps.responses->Execute(req);
        if (!r) return FromResponseError(r.GetError());
        const auto& res = r.Value();

        // 暫停成功 → 發 undo token（「復原」按鈕 = revert 該動作）
        std::optional<std::string> undoToken;
        if (deps.undo && res.reversible && res.status != response::ActionStatus::Failed &&
            *action == model::ActionKind::SuspendProcess) {
            UndoEntry ue;
            ue.kind     = UndoEntry::Kind::RevertAction;
            ue.actionId = res.actionId;
            ue.alertId  = *id;
            undoToken   = deps.undo->Issue(ue, NewToken(deps)).first;
        }
        // 終止成功 → 通知引擎（is_terminated_by_us；ResponseExecutor 已寫 DB，這裡讓記憶體中的樹同步）
        if (*action == model::ActionKind::TerminateProcessTree) {
            std::vector<model::GuidValue> killed;
            for (const auto& t : res.results)
                if (t.ok)
                    if (auto g = model::GuidValue::Parse(t.key)) killed.push_back(*g);
            if (!killed.empty()) {
                deps.analysis->Post([killed](engine::AnalysisEngine& e) {
                    for (const auto& g : killed) e.MarkTerminatedByUs(g);
                });
            }
        }
        return RpcOutcome::Ok(conv::ExecuteJson(res, undoToken));
    });

    // ---------------------------------------------------------------- response.revert
    // UI 契約 1：第一次不帶 token → 403 CONFIRMATION_REQUIRED + details.confirmation_token
    //（quarantine_file 另附 typed_confirmation_expected）；帶 token 重送才真正還原。
    disp.Register("response.revert", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        if (!deps.responses) return Fail(conv::Err("SERVICE_UNAVAILABLE", 503, "回應執行器未啟動"));
        if (!deps.tokens) return Fail(conv::Err("INTERNAL", 500, "token store 未初始化"));
        const auto alertId = conv::IdParam(p, {"alert_id", "id"});
        if (!alertId) return BadParam("alert_id 必填");
        std::string ref = rpc::GetString(p, "audit_id").value_or("");
        if (ref.empty()) {
            if (auto n = rpc::GetInt(p, "audit_id")) ref = std::to_string(*n);
            else if (auto a = rpc::GetString(p, "action_id")) ref = *a;
        }
        if (ref.empty()) return BadParam("audit_id 必填");

        response::TokenBinding binding;
        binding.alertId    = *alertId;
        binding.actionName = "revert";
        binding.targetKey  = ref;
        binding.peerSid    = ctx.clientUser;

        const std::string token = rpc::GetString(p, "confirmation_token").value_or("");
        if (token.empty()) {
            // 找出原動作，判斷是否可逆、還原隔離檔時要打的字（原檔名）
            Json details = Json::object();
            if (auto recs = deps.responses->ListActions(*alertId)) {
                for (const auto& rec : recs.Value()) {
                    const bool match = rec.actionId == ref || (rec.auditId && std::to_string(*rec.auditId) == ref);
                    if (!match) continue;
                    if (!model::IsReversible(rec.action)) {
                        return Fail(conv::Err("NOT_REVERSIBLE", 409, "terminate_process_tree 不可還原"));
                    }
                    if (rec.reverted) return Fail(conv::Err("ALREADY_REVERTED", 409, "此動作已還原"));
                    details["action"] = std::string(model::ActionKindToString(rec.action));
                    if (rec.action == model::ActionKind::QuarantineFile && !rec.quarantineIds.empty()) {
                        if (auto q = deps.responses->ListQuarantine()) {
                            for (const auto& e : q.Value())
                                if (e.quarantineId == rec.quarantineIds.front())
                                    details["typed_confirmation_expected"] = conv::BaseName(e.originalPath);
                        }
                    }
                }
            }
            auto issued = deps.tokens->Issue(binding);
            if (!issued) return FromResponseError(issued.GetError());
            details["confirmation_token"] = issued.Value().token;
            details["expires_at"]         = conv::Iso(issued.Value().expiresAt);
            return Fail(conv::Err("CONFIRMATION_REQUIRED", 403, "請確認後帶 confirmation_token 重送", std::move(details)));
        }
        if (auto c = deps.tokens->Consume(token, binding, ""); !c) return FromResponseError(c.GetError());

        response::RevertRequest req;
        req.actionIdOrAuditId = ref;
        req.typedConfirmation = rpc::GetString(p, "typed_confirmation").value_or("");
        req.reason            = rpc::GetString(p, "reason").value_or("");
        req.actor             = ActorOf(ctx);
        auto r = deps.responses->Revert(req);
        if (!r) return FromResponseError(r.GetError());
        return RpcOutcome::Ok(conv::RevertJson(r.Value(), deps.clock->NowMs()));
    });

    // ---------------------------------------------------------------- quarantine.list
    disp.Register("quarantine.list", [deps](const Json&, const RpcContext&) -> RpcOutcome {
        if (!deps.responses) return RpcOutcome::Ok(Json{{"items", Json::array()}});
        auto q = deps.responses->ListQuarantine();
        if (!q) return FromResponseError(q.GetError());
        auto actions = deps.responses->ListActions();
        Json items = Json::array();
        for (const auto& e : q.Value()) {
            bool restored = false;
            std::optional<int64_t> auditId;
            if (actions) {
                for (const auto& a : actions.Value()) {
                    if (std::find(a.quarantineIds.begin(), a.quarantineIds.end(), e.quarantineId) == a.quarantineIds.end())
                        continue;
                    restored = a.reverted;
                    auditId  = a.auditId;
                }
            }
            items.push_back(conv::QuarantineItemJson(e, restored, auditId));
        }
        return RpcOutcome::Ok(Json{{"items", std::move(items)}});
    });

    // ---------------------------------------------------------------- undo.apply
    disp.Register("undo.apply", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        if (!deps.undo) return Fail(conv::Err("NOT_FOUND", 404, "undo 不可用"));
        const auto token = rpc::GetString(p, "undo_token");
        if (!token || token->empty()) return BadParam("undo_token 必填");
        const auto e = deps.undo->Take(*token);
        if (!e) return Fail(conv::Err("TOKEN_EXPIRED", 410, "復原期限已過或 token 無效"));

        if (e->kind == UndoEntry::Kind::RemoveExclusion) {
            auto w = WriteAndWait(deps, model::ExclusionRemove{e->exclusionId});
            if (!w) return Fail(w.GetError());
            (void)deps.host->ReloadExclusions();
            Audit(deps, ctx, "exclusion_remove", "undo", e->alertId ? std::optional<int64_t>(e->alertId) : std::nullopt,
                  std::to_string(e->exclusionId), Json{{"exclusion_id", e->exclusionId}});
            return RpcOutcome::Ok(Json{{"ok", true}});
        }
        if (!deps.responses) return Fail(conv::Err("SERVICE_UNAVAILABLE", 503, "回應執行器未啟動"));
        response::RevertRequest req;
        req.actionIdOrAuditId = e->actionId;
        req.reason            = "undo";
        req.actor             = ActorOf(ctx);
        auto r = deps.responses->Revert(req);
        if (!r) return FromResponseError(r.GetError());
        return RpcOutcome::Ok(Json{{"ok", r.Value().status != response::ActionStatus::Failed},
                                   {"result", conv::RevertJson(r.Value(), deps.clock->NowMs())}});
    });
}

} // namespace cairn::host
