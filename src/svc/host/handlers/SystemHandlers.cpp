// health.get / audit.list / protection.pause / protection.resume / learning.finish / export.create
#include <limits>

#include "host/HostState.h"
#include "host/PolicyConfig.h"
#include "host/handlers/Handlers.h"
#include "host/handlers/HandlerUtil.h"
#include "response/ConfirmationTokenStore.h"
#include "response/ResponseJson.h"

namespace cairn::host {

using namespace handlers;

namespace {
std::optional<int64_t> PauseDurationMs(const std::string& d)
{
    if (d == "15m") return 15LL * 60'000;
    if (d == "1h") return 60LL * 60'000;
    if (d == "until_reboot") return std::numeric_limits<int64_t>::max();
    return std::nullopt;
}
} // namespace

void RegisterSystemHandlers(rpc::JsonRpcDispatcher& disp, const HandlerDeps& deps)
{
    // ---------------------------------------------------------------- health.get
    disp.Register("health.get", [deps](const Json&, const RpcContext&) -> RpcOutcome {
        const int64_t now = deps.clock->NowMs();
        const auto live   = deps.host->Health();
        const auto st     = deps.state->Snapshot();

        conv::HealthExtras x;
        x.learningActive    = deps.state->LearningActive(now, deps.config->learningDays, deps.config->learningEnabled);
        x.learningDay       = deps.state->LearningDay(now);
        x.learningTotalDays = deps.config->learningDays;
        if (deps.state->Paused(now)) {
            x.protectionState = "paused";
            x.pausedUntil     = st.pausedUntilMs;
        } else if (x.learningActive) {
            x.protectionState = "learning";
        }
        if (auto db = Reader(deps)) {
            store::AlertListFilter f;
            f.limit = 1;
            if (auto r = db.Value()->ListAlerts(f, now)) x.alertsToday = r.Value().stats.today;
            f.severities = {"high", "critical"};
            f.statuses   = {"pending"};
            if (auto r = db.Value()->ListAlerts(f, now)) x.unreadHigh = r.Value().stats.totalMatched;
        }
        return RpcOutcome::Ok(conv::HealthJson(live, x, now));
    });

    // ---------------------------------------------------------------- audit.list
    disp.Register("audit.list", [deps](const Json& p, const RpcContext&) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        store::AuditQuery q;
        if (p.contains("from")) q.from = conv::ParseTime(p["from"]);
        if (p.contains("to")) q.to = conv::ParseTime(p["to"]);
        q.actions = conv::StringList(p, "action");
        if (auto a = rpc::GetString(p, "initiator")) q.actor = *a;
        if (auto s = rpc::GetString(p, "q")) q.q = *s;
        if (auto l = rpc::GetInt(p, "limit")) q.limit = static_cast<int>(std::clamp<int64_t>(*l, 1, 1000));
        if (auto b = rpc::GetInt(p, "before_id")) q.beforeId = *b;
        auto r = db.Value()->ListAudit(q);
        if (!r) return Fail(r.GetError());
        Json items = Json::array();
        for (const auto& a : r.Value().items) items.push_back(conv::AuditEntryJson(a));

        bool chainValid = false;
        Json chain      = Json::object();
        if (auto v = db.Value()->VerifyRecentAudit(1000)) {
            chainValid = v.Value().valid;
            chain      = Json{{"verified_count", v.Value().verifiedCount},
                              {"first_broken_id", v.Value().firstBrokenId ? Json(v.Value().firstBrokenId) : Json(nullptr)},
                              {"detail", v.Value().detail}};
        }
        return RpcOutcome::Ok(Json{{"items", std::move(items)},
                                   {"chain_valid", chainValid},
                                   {"chain", std::move(chain)},
                                   {"next_before_id", r.Value().nextBeforeId ? Json(*r.Value().nextBeforeId) : Json(nullptr)}});
    });

    // ---------------------------------------------------------------- protection.pause
    // UI 契約 1：第一次不帶 token → 403 CONFIRMATION_REQUIRED + details.confirmation_token；確認後帶 token 重送。
    disp.Register("protection.pause", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        if (!deps.tokens) return Fail(conv::Err("INTERNAL", 500, "token store 未初始化"));
        const std::string duration = rpc::GetString(p, "duration").value_or("15m");
        const auto durMs = PauseDurationMs(duration);
        if (!durMs) return BadParam("duration 必須為 15m | 1h | until_reboot");
        const std::string reason = rpc::GetString(p, "reason").value_or("");

        response::TokenBinding binding;
        binding.alertId    = 0;
        binding.actionName = "protection.pause";
        binding.targetKey  = duration;
        binding.peerSid    = ctx.clientUser;

        const std::string token = rpc::GetString(p, "confirmation_token").value_or("");
        if (token.empty()) {
            auto issued = deps.tokens->Issue(binding);
            if (!issued) return Fail(conv::Err("TOKEN_LIMIT", 429, issued.GetError().context));
            return Fail(conv::Err("CONFIRMATION_REQUIRED", 403, "暫停防護需要確認",
                                  Json{{"confirmation_token", issued.Value().token},
                                       {"expires_at", conv::Iso(issued.Value().expiresAt)},
                                       {"duration", duration}}));
        }
        if (auto c = deps.tokens->Consume(token, binding, ""); !c) {
            const auto ri = response::RejectInfoOf(c.GetError());
            return Fail(conv::Err(ri.code.empty() ? "TOKEN_INVALID" : ri.code, ri.httpStatus, ri.message));
        }
        const int64_t now   = deps.clock->NowMs();
        const int64_t until = *durMs == std::numeric_limits<int64_t>::max() ? *durMs : now + *durMs;
        if (auto s = deps.host->SetProtectionPaused(true, until, reason); !s) return Fail(s.GetError());
        Audit(deps, ctx, "protection_pause", "protection_pause", std::nullopt, duration, Json{{"reason", reason}});
        return RpcOutcome::Ok(Json{{"ok", true},
                                   {"paused_until", until == std::numeric_limits<int64_t>::max() ? Json(nullptr) : Json(conv::Iso(until))},
                                   {"until_reboot", until == std::numeric_limits<int64_t>::max()}});
    });

    // ---------------------------------------------------------------- protection.resume
    disp.Register("protection.resume", [deps](const Json&, const RpcContext& ctx) -> RpcOutcome {
        if (auto s = deps.host->SetProtectionPaused(false, 0, ""); !s) return Fail(s.GetError());
        Audit(deps, ctx, "protection_resume", "protection_resume", std::nullopt, "", Json::object());
        return RpcOutcome::Ok(Json{{"ok", true}});
    });

    // ---------------------------------------------------------------- learning.finish
    disp.Register("learning.finish", [deps](const Json&, const RpcContext& ctx) -> RpcOutcome {
        if (auto s = deps.host->FinishLearning(); !s) return Fail(s.GetError());
        Audit(deps, ctx, "learning_finish", "learning_finish", std::nullopt, "", Json::object());
        return RpcOutcome::Ok(Json{{"ok", true}});
    });

    // ---------------------------------------------------------------- export.create
    // 單一告警：告警詳情 + 時間軸 + 稽核；未指定：近 N 天告警清單 + 稽核 + 鏈驗證結果。
    disp.Register("export.create", [deps](const Json& p, const RpcContext& ctx) -> RpcOutcome {
        auto db = Reader(deps);
        if (!db) return Fail(db.GetError());
        const int64_t now = deps.clock->NowMs();
        Json out{{"format", "cairn-export/1"}, {"generated_at", conv::Iso(now)}, {"hostname", deps.host->Health().hostname}};

        if (const auto id = conv::IdParam(p, {"alert_id", "id"})) {
            auto r = db.Value()->GetAlert(*id);
            if (!r) return Fail(r.GetError());
            if (!r.Value()) return Fail(conv::Err("NOT_FOUND", 404, "告警不存在"));
            const auto& d = *r.Value();
            out["alert"] = conv::AlertDetailJson(d, out["hostname"].get<std::string>(), deps.host->RuleInfos(),
                                                 conv::ActionsTakenFromDbJson(d.alert.actionsTakenJson, d.audits));
            if (auto rec = db.Value()->GetAlertRecord(*id); rec && rec.Value())
                out["narrative"] = conv::NarrativeJson(*rec.Value(), now, "");
            Json audits = Json::array();
            for (const auto& a : d.audits) audits.push_back(conv::AuditEntryJson(a));
            out["audit"] = std::move(audits);
        } else {
            const int64_t days = std::clamp<int64_t>(rpc::GetInt(p, "days").value_or(7), 1, 90);
            store::AlertListFilter f;
            f.since = now - days * 86'400'000;
            f.limit = 200;
            auto r = db.Value()->ListAlerts(f, now);
            if (!r) return Fail(r.GetError());
            out["alerts"] = conv::AlertListJson(r.Value());
            store::AuditQuery aq;
            aq.from  = f.since;
            aq.limit = 1000;
            if (auto a = db.Value()->ListAudit(aq)) {
                Json audits = Json::array();
                for (const auto& x : a.Value().items) audits.push_back(conv::AuditEntryJson(x));
                out["audit"] = std::move(audits);
            }
        }
        if (auto v = db.Value()->VerifyRecentAudit(1000)) out["audit_chain_valid"] = v.Value().valid;
        Audit(deps, ctx, "export", "export", conv::IdParam(p, {"alert_id", "id"}), "", Json::object());
        return RpcOutcome::Ok(std::move(out));
    });
}

} // namespace cairn::host
