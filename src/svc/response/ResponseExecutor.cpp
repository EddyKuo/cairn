// src/svc/response/ResponseExecutor.cpp       Win32 實作（T6 ResponseThread）
#include "response/ResponseExecutor.h"

#include <windows.h>
#include <objbase.h>
#include <bcrypt.h>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <unordered_map>

#include "base/BlockingQueue.h"
#include "response/ActionRecordStore.h"
#include "response/ConfirmationTokenStore.h"
#include "response/FirewallResponder.h"
#include "response/ProcessResponder.h"
#include "response/QuarantineStore.h"
#include "response/ResponseJson.h"
#include "response/Sha256.h"

namespace cairn::response {

namespace {

std::array<uint8_t, 16> SystemRandom16()
{
    std::array<uint8_t, 16> b{};
    const NTSTATUS st = ::BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    // 取亂數失敗屬系統異常：中止而非退回可預測來源（可預測 token = 繞過二次確認）
    CAIRN_ASSERT(BCRYPT_SUCCESS(st));
    return b;
}

std::string JoinFailures(const std::vector<TargetOutcome>& outcomes)
{
    std::string s;
    int n = 0;
    for (const auto& o : outcomes) {
        if (o.ok) continue;
        if (n++ == 3) {
            s += "; ...";
            break;
        }
        if (!s.empty()) s += "; ";
        s += o.label + ": " + o.reason;
    }
    return s;
}

// 同步呼叫的結果傳遞
template <class T>
using Promise = std::shared_ptr<std::promise<Result<T>>>;

} // namespace

struct PreparedPlan {
    int64_t               alertId = 0;
    model::ActionKind     action = model::ActionKind::SuspendProcess;
    model::ResponseTarget target;
    UnixMs                expiresAt = 0;
};

struct ResponseExecutor::Impl {
    ResponseExecutorConfig cfg;
    model::IWriteSink*     writes = nullptr;
    const IClock*          clock  = nullptr;

    ConfirmationTokenStore tokens;
    ActionRecordStore      records;
    QuarantineStore        vault;

    // 動作實作 —— 僅 T6 使用
    SuspendProcessAction   suspend;
    TerminateTreeAction    terminate;
    QuarantineFileAction   quarantine{vault};
    FirewallBlockAction    firewall;
    Status                 suspendInit = Ok();
    Status                 terminateInit = Ok();
    Status                 vaultInit = Ok();

    // T6 工作佇列
    // shared_ptr：WriterThread 的 onDone 回呼可能晚於本物件存活，回呼只持有佇列，
    // 投遞的工作只會在 T6 存活期間（含關機排空）執行；Close 後的投遞被拒絕。
    std::shared_ptr<BlockingQueue<std::function<void()>>> jobs;
    std::jthread                         thread;
    std::atomic<bool>                    started{false};
    std::atomic<bool>                    stopping{false};

    // 自動回應聚合
    std::mutex                          autoMutex;
    std::deque<model::ResponseCommand>  autoPending;
    int64_t                             lastAutoSubmitSteady = 0;

    // 僅 T6 存取
    std::unordered_map<std::string, PreparedPlan> prepared;   // token → 計畫
    int64_t lastSweepSteady = 0;

    mutable std::mutex statsMutex;
    ExecutorStats      stats;

    Impl(ResponseExecutorConfig c, model::IWriteSink* w, const IClock* clk)
        : cfg(std::move(c)), writes(w), clock(clk),
          tokens(*clk, &SystemRandom16, cfg.maxTokens, cfg.tokenTtl),
          records(cfg.dataDir / "actions"),
          vault(cfg.dataDir / "quarantine", *clk, cfg.applyVaultAcl),
          jobs(std::make_shared<BlockingQueue<std::function<void()>>>(cfg.queueCapacity))
    {
    }

    IResponseAction* ActionFor(model::ActionKind k)
    {
        switch (k) {
        case model::ActionKind::SuspendProcess: return &suspend;
        case model::ActionKind::TerminateProcessTree: return &terminate;
        case model::ActionKind::QuarantineFile: return &quarantine;
        case model::ActionKind::FirewallBlock: return &firewall;
        }
        return nullptr;
    }

    Status InitStatusFor(model::ActionKind k) const
    {
        switch (k) {
        case model::ActionKind::SuspendProcess: return suspendInit;
        case model::ActionKind::TerminateProcessTree: return terminateInit;
        case model::ActionKind::QuarantineFile: return vaultInit;
        case model::ActionKind::FirewallBlock: return Ok();
        }
        return Ok();
    }

    void Bump(uint64_t ExecutorStats::*field)
    {
        std::lock_guard lk{statsMutex};
        ++(stats.*field);
    }

    // ------------------------------------------------------------
    // 寫入（經 T4）
    // ------------------------------------------------------------
    void PostWrite(model::WritePayload payload, model::WriteCompletion onDone = {})
    {
        if (!writes) {
            if (onDone) onDone(MakeError(ErrorCode::NotInitialized, "no write sink"));
            return;
        }
        model::WriteOp op{std::move(payload), std::move(onDone)};
        if (!writes->Post(std::move(op))) {
            spdlog::error("response: write queue rejected an op (audit/actions may be missing)");
        }
    }

    void PostAudit(std::string_view eventKind, const ActionRecord& r, std::string_view tokenSha,
                   model::WriteCompletion onDone = {})
    {
        model::AuditRow a;
        a.ts        = clock->NowMs();
        a.actor     = r.actor;
        a.action    = std::string(model::ActionKindToString(r.action));
        if (r.alertId != 0) a.alertId = r.alertId;
        a.target    = r.results.empty() ? r.ip : r.results.front().key;
        if (r.results.size() > 1) a.target += " (+" + std::to_string(r.results.size() - 1) + ")";
        a.paramsJson = AuditParamsJson(eventKind, r, tokenSha);
        a.result    = eventKind == "action_started" ? "ok" : std::string(AuditResultOf(r.status));
        if (r.status != ActionStatus::Succeeded && eventKind != "action_started") {
            const auto f = JoinFailures(r.results);
            if (!f.empty()) a.error = f;
        }
        PostWrite(std::move(a), std::move(onDone));
    }

    // audit id 回填：onDone 在 WriterThread 上 → 投遞回 T6 寫檔，並通知等待中的呼叫端
    model::WriteCompletion AuditIdCallback(std::string actionId, bool isRevert,
                                           std::shared_ptr<std::promise<std::optional<int64_t>>> waiter)
    {
        return [this, q = jobs, actionId = std::move(actionId), isRevert, waiter](Result<int64_t> r) {
            std::optional<int64_t> id;
            if (r) id = r.Value();
            if (waiter) {
                try {
                    waiter->set_value(id);
                } catch (const std::future_error&) {
                }
            }
            if (!id) return;
            const int64_t auditId = *id;
            (void)q->Post([this, actionId, isRevert, auditId] {
                auto rec = records.Load(actionId);
                if (!rec) return;
                auto r2 = std::move(rec).Value();
                if (isRevert) r2.revertAuditId = auditId;
                else r2.auditId = auditId;
                if (auto st = records.Save(r2); !st)
                    spdlog::warn("response: failed to persist audit id for {}: {}", actionId, st.GetError().ToString());
            });
        };
    }

    // ------------------------------------------------------------
    // 動作執行（T6）
    // ------------------------------------------------------------
    struct RunResult {
        ExecuteResponse response;
        std::shared_ptr<std::promise<std::optional<int64_t>>> auditWaiter;
    };

    RunResult RunAction(int64_t alertId, model::ActionKind kind, const model::ResponseTarget& target,
                        const std::string& reason, const std::string& actor, bool automatic,
                        const std::string& impactHash, const std::string& tokenSha)
    {
        RunResult rr;
        IResponseAction* action = ActionFor(kind);

        ActionRecord rec;
        rec.actionId   = records.NextActionId(alertId);
        rec.alertId    = alertId;
        rec.action     = kind;
        rec.executedAt = clock->NowMs();
        rec.actor      = actor;
        rec.reason     = reason;
        rec.automatic  = automatic;
        rec.impactHash = impactHash;

        // 狀態機：Executing（action_started）
        PostAudit("action_started", rec, tokenSha);

        ActionContext ctx{alertId, kind, &target, reason, actor, automatic};
        if (auto init = InitStatusFor(kind); !init) {
            rec.results.push_back(TargetOutcome{TargetKeyOf(kind, target), std::string(model::ActionKindToString(kind)),
                                                false, init.GetError().win32, init.GetError().context});
        } else {
            rec.results = action->Execute(ctx, rec);
        }
        if (rec.results.empty()) {
            rec.results.push_back(TargetOutcome{TargetKeyOf(kind, target), std::string(model::ActionKindToString(kind)),
                                                false, 0, "no target"});
        }
        rec.status = ComputeStatus(rec.results);

        if (auto st = records.Save(rec); !st)
            spdlog::error("response: failed to persist action record {}: {}", rec.actionId, st.GetError().ToString());

        if (alertId != 0) PostWrite(model::AlertActionAppend{alertId, ActionTakenJson(rec)});

        if (kind == model::ActionKind::TerminateProcessTree) {
            for (const auto& o : rec.results) {
                if (!o.ok || o.reason != "terminated") continue;
                if (auto g = model::GuidValue::Parse(o.key)) PostWrite(model::ProcessTerminatedByUs{*g});
            }
        }

        rr.auditWaiter = std::make_shared<std::promise<std::optional<int64_t>>>();
        PostAudit("action_completed", rec, tokenSha, AuditIdCallback(rec.actionId, false, rr.auditWaiter));

        if (rec.status != ActionStatus::Succeeded) {
            spdlog::warn("response: {} {} for alert {} — {}", model::ActionKindToString(kind),
                         ActionStatusToString(rec.status), alertId, JoinFailures(rec.results));
        }

        auto& resp = rr.response;
        resp.actionId     = rec.actionId;
        resp.action       = kind;
        resp.status       = rec.status;
        resp.executedAt   = rec.executedAt;
        resp.actor        = rec.actor;
        resp.reason       = rec.reason;
        resp.results      = rec.results;
        resp.reversible   = model::IsReversible(kind);
        resp.errorSummary = JoinFailures(rec.results);
        Bump(automatic ? &ExecutorStats::automaticExecuted : &ExecutorStats::executed);
        return rr;
    }

    void PrunePrepared()
    {
        const UnixMs now = clock->NowMs();
        for (auto it = prepared.begin(); it != prepared.end();) {
            if (it->second.expiresAt <= now) it = prepared.erase(it);
            else ++it;
        }
    }

    Result<PrepareResponse> DoPrepare(int64_t alertId, model::ActionKind kind, const model::ResponseTarget& target,
                                      const std::string& peerSid)
    {
        IResponseAction* action = ActionFor(kind);
        if (!action) return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "unknown action");
        if (auto init = InitStatusFor(kind); !init)
            return MakeReject(ErrorCode::Unsupported, "ACTION_NOT_ALLOWED", init.GetError().context);

        ActionContext ctx{alertId, kind, &target, {}, {}, false};
        CAIRN_TRY(auto impact, action->Prepare(ctx));

        PrepareResponse resp;
        resp.action     = kind;
        resp.riskLevel  = model::RiskLevelOf(kind);
        resp.reversible = model::IsReversible(kind);
        resp.requireToken = resp.riskLevel >= 2;
        resp.requireTypedConfirmation = kind == model::ActionKind::TerminateProcessTree;
        resp.typedConfirmationExpected = resp.requireTypedConfirmation ? impact.typedExpected : std::string{};
        resp.impactHash = ComputeImpactHash(alertId, kind, impact);

        TokenBinding b;
        b.alertId       = alertId;
        b.actionName    = std::string(model::ActionKindToString(kind));
        b.targetKey     = TargetKeyOf(kind, target);
        b.impactHash    = resp.impactHash;
        b.typedExpected = resp.typedConfirmationExpected;
        b.peerSid       = peerSid;

        PrunePrepared();
        CAIRN_TRY(auto issued, tokens.Issue(std::move(b)));
        resp.confirmationToken = issued.token;
        resp.expiresAt         = issued.expiresAt;
        resp.impact            = std::move(impact);
        prepared[issued.token] = PreparedPlan{alertId, kind, target, issued.expiresAt};
        Bump(&ExecutorStats::prepared);
        return resp;
    }

    Result<RunResult> DoExecute(const ExecuteRequest& req)
    {
        IResponseAction* action = ActionFor(req.action);
        if (!action) return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "unknown action");
        const int risk = model::RiskLevelOf(req.action);

        // ---- L1 無 token：直接執行（part3 §3.3.3：缺 token 伺服器不拒絕）----
        if (req.confirmationToken.empty()) {
            if (risk >= 2) {
                Bump(&ExecutorStats::rejected);
                return MakeReject(ErrorCode::ConfirmationRequired, "CONFIRMATION_REQUIRED",
                                  "L2/L3 actions require a confirmation token from prepare");
            }
            if (!req.target) {
                Bump(&ExecutorStats::rejected);
                return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "target required when no token");
            }
            ActionContext ctx{req.alertId, req.action, &*req.target, req.reason, req.actor, false};
            std::string hash;
            if (auto impact = action->Prepare(ctx)) hash = ComputeImpactHash(req.alertId, req.action, impact.Value());
            return RunAction(req.alertId, req.action, *req.target, req.reason, req.actor, false, hash, {});
        }

        // ---- 有 token：取回 Prepare 時的計畫，重算 impactHash（樂觀併發控制，§8.3.3）----
        auto planIt = prepared.find(req.confirmationToken);
        if (planIt == prepared.end()) {
            Bump(&ExecutorStats::rejected);
            auto peek = tokens.Peek(req.confirmationToken);
            if (!peek) return peek.GetError();
            return MakeReject(ErrorCode::ConfirmationExpired, "TOKEN_INVALID", "no prepared plan for token");
        }
        const PreparedPlan plan = planIt->second;   // 複製：Consume 失敗時可能移除
        if (plan.action != req.action || plan.alertId != req.alertId) {
            Bump(&ExecutorStats::rejected);
            prepared.erase(planIt);
            (void)tokens.Consume(req.confirmationToken, TokenBinding{}, {});   // 使 token 失效
            return MakeReject(ErrorCode::ConfirmationRequired, "TOKEN_BINDING_MISMATCH",
                              "token was issued for a different alert or action");
        }

        ActionContext ctx{req.alertId, req.action, &plan.target, req.reason, req.actor, false};
        auto impact = action->Prepare(ctx);
        if (!impact) {
            Bump(&ExecutorStats::rejected);
            return impact.GetError();
        }
        TokenBinding expected;
        expected.alertId    = req.alertId;
        expected.actionName = std::string(model::ActionKindToString(req.action));
        expected.targetKey  = TargetKeyOf(req.action, plan.target);
        expected.impactHash = ComputeImpactHash(req.alertId, req.action, impact.Value());
        expected.peerSid    = req.peerSid;

        if (auto st = tokens.Consume(req.confirmationToken, expected, req.typedConfirmation); !st) {
            Bump(&ExecutorStats::rejected);
            // 打字不符時 token 保留（可重打）；其餘拒絕時 token 已被移除 → 計畫一併清除
            if (RejectInfoOf(st.GetError()).code != "TYPED_CONFIRMATION_MISMATCH") prepared.erase(req.confirmationToken);
            return st.GetError();
        }
        prepared.erase(req.confirmationToken);
        const std::string tokenSha = Sha256::HexOf(req.confirmationToken);
        return RunAction(req.alertId, req.action, plan.target, req.reason, req.actor, false, expected.impactHash,
                         tokenSha);
    }

    struct RevertRun {
        RevertResponse response;
        std::shared_ptr<std::promise<std::optional<int64_t>>> auditWaiter;
    };

    Result<RevertRun> DoRevert(const RevertRequest& req)
    {
        CAIRN_TRY(auto rec, records.Resolve(req.actionIdOrAuditId));
        if (!model::IsReversible(rec.action)) {
            Bump(&ExecutorStats::rejected);
            return MakeReject(ErrorCode::ActionNotAllowed, "NOT_REVERSIBLE",
                              "terminate_process_tree cannot be reverted");
        }
        if (rec.reverted) {
            Bump(&ExecutorStats::rejected);
            return MakeReject(ErrorCode::AlreadyExists, "ALREADY_REVERTED", rec.actionId);
        }

        // 還原隔離檔需打字確認：使用者正在還原一個已知惡意的檔案（SDD-03 §8.5.2）
        if (rec.action == model::ActionKind::QuarantineFile && !rec.quarantineIds.empty()) {
            std::string expected;
            if (auto meta = vault.Get(rec.quarantineIds.front())) expected = BaseNameLower(meta.Value().originalPath);
            if (!expected.empty() && !TypedConfirmationMatches(expected, req.typedConfirmation)) {
                Bump(&ExecutorStats::rejected);
                return MakeReject(ErrorCode::InvalidArgument, "TYPED_CONFIRMATION_MISMATCH",
                                  "type the original file name to confirm restore: " + expected);
            }
        }

        IResponseAction* action = ActionFor(rec.action);
        CAIRN_TRY(auto outcomes, action->Revert(rec));

        ActionRecord audit = rec;   // 稽核列沿用原動作名，event_kind='action_reverted'
        audit.results = outcomes;
        audit.status  = ComputeStatus(outcomes);
        audit.actor   = req.actor;
        audit.reason  = req.reason;

        if (audit.status != ActionStatus::Failed) {
            rec.reverted   = true;
            rec.revertedAt = clock->NowMs();
        }
        if (auto st = records.Save(rec); !st)
            spdlog::error("response: failed to persist revert of {}: {}", rec.actionId, st.GetError().ToString());

        RevertRun run;
        run.auditWaiter = std::make_shared<std::promise<std::optional<int64_t>>>();
        PostAudit("action_reverted", audit, {}, AuditIdCallback(rec.actionId, true, run.auditWaiter));
        if (rec.alertId != 0 && rec.reverted) PostWrite(model::AlertActionAppend{rec.alertId, ActionTakenJson(rec)});

        run.response.actionId = rec.actionId;
        run.response.status   = audit.status;
        run.response.results  = std::move(outcomes);
        Bump(&ExecutorStats::reverted);
        return run;
    }

    // 自動回應：取出聚合窗口內的全部指令，依（告警, §8.5.1 順序）排序後逐一執行
    void DrainAutomatic()
    {
        // 聚合窗口：讓同一告警接連送來的多個動作一起排序
        for (int i = 0; i < 10; ++i) {
            int64_t last = 0;
            {
                std::lock_guard lk{autoMutex};
                last = lastAutoSubmitSteady;
            }
            if (clock->SteadyMs() - last >= cfg.automaticCoalesce.count()) break;
            std::this_thread::sleep_for(cfg.automaticCoalesce / 5);
        }
        std::deque<model::ResponseCommand> batch;
        {
            std::lock_guard lk{autoMutex};
            batch.swap(autoPending);
        }
        if (batch.empty()) return;
        std::stable_sort(batch.begin(), batch.end(), [](const auto& a, const auto& b) {
            if (a.alertId != b.alertId) return a.alertId < b.alertId;
            return ActionOrderRank(a.action) < ActionOrderRank(b.action);
        });
        for (const auto& cmd : batch) {
            if (stopping.load()) break;
            // 任何一步失敗都不中止整個計畫（§8.5.1）
            (void)RunAction(cmd.alertId, cmd.action, cmd.target, cmd.reason,
                            cmd.actor.empty() ? "rule_engine" : cmd.actor, true, {}, {});
        }
    }

    void MaybeSweep()
    {
        const int64_t now = clock->SteadyMs();
        if (now - lastSweepSteady < 60'000) return;
        lastSweepSteady = now;
        tokens.SweepExpired();
        PrunePrepared();
    }

    void ThreadMain(std::stop_token st)
    {
        const HRESULT hrCo = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(hrCo)) spdlog::error("response: CoInitializeEx failed hr=0x{:08X}", static_cast<unsigned>(hrCo));

        suspendInit   = suspend.Init();
        terminateInit = terminate.Init();
        vaultInit     = vault.Init();
        if (!suspendInit) spdlog::error("response: suspend unavailable: {}", suspendInit.GetError().ToString());
        if (!vaultInit) spdlog::error("response: quarantine vault unavailable: {}", vaultInit.GetError().ToString());
        (void)records.EnsureDir();

        if (cfg.cleanupOrphanFirewallRules) {
            // 孤兒規則清理：保留仍有效（未還原）的封鎖紀錄，其餘以前綴開頭者移除
            std::vector<std::string> keep;
            for (const auto& r : records.List())
                if (r.action == model::ActionKind::FirewallBlock && !r.reverted && !r.firewallRuleName.empty())
                    keep.push_back(r.firewallRuleName);
            if (auto removed = firewall.CleanupOrphans(keep)) {
                for (const auto& n : removed.Value()) spdlog::warn("response: removed orphan firewall rule '{}'", n);
            }
        }

        while (!st.stop_requested()) {
            auto job = jobs->PopFor(std::chrono::milliseconds{500}, st);
            if (job) (*job)();
            MaybeSweep();
        }
        // 排空：佇列中的同步工作必須回覆呼叫端（以 stopping 旗標回 SERVICE_STOPPING）
        while (auto job = jobs->TryPop()) (*job)();

        firewall.ReleaseCom();   // COM 指標必須在 CoUninitialize 前於本執行緒釋放
        if (SUCCEEDED(hrCo)) ::CoUninitialize();
    }

    // 把工作投遞到 T6 並等待結果
    template <class T, class Fn>
    Result<T> Call(Fn fn)
    {
        if (!started.load() || stopping.load())
            return MakeReject(ErrorCode::ServiceUnavailable, "SERVICE_STOPPING", "response executor not running");
        auto promise = std::make_shared<std::promise<Result<T>>>();
        auto future  = promise->get_future();
        const bool posted = jobs->Post([this, promise, fn = std::move(fn)]() mutable {
            if (stopping.load()) {
                promise->set_value(MakeReject(ErrorCode::ServiceUnavailable, "SERVICE_STOPPING", "shutting down"));
                return;
            }
            promise->set_value(fn());
        });
        if (!posted) return MakeReject(ErrorCode::ServiceUnavailable, "SERVICE_STOPPING", "response queue full or closed");
        if (future.wait_for(cfg.syncCallTimeout) != std::future_status::ready)
            return MakeError(ErrorCode::Timeout, "response executor call timed out");
        return future.get();
    }
};

// ============================================================
// 公開介面
// ============================================================
ResponseExecutor::ResponseExecutor(std::unique_ptr<Impl> impl) : m_impl(std::move(impl)) {}

ResponseExecutor::~ResponseExecutor()
{
    Stop();
}

Result<std::unique_ptr<ResponseExecutor>> ResponseExecutor::Create(ResponseExecutorConfig cfg,
                                                                   model::IWriteSink* writes, const IClock* clock)
{
    if (!clock) return MakeError(ErrorCode::InvalidArgument, "clock is required");
    if (cfg.dataDir.empty()) return MakeError(ErrorCode::InvalidArgument, "dataDir is required");
    auto impl = std::make_unique<Impl>(std::move(cfg), writes, clock);
    if (auto st = impl->records.EnsureDir(); !st) return st.GetError();
    return std::unique_ptr<ResponseExecutor>(new ResponseExecutor(std::move(impl)));
}

Status ResponseExecutor::Start()
{
    if (m_impl->started.exchange(true)) return Ok();
    m_impl->thread = std::jthread([impl = m_impl.get()](std::stop_token st) { impl->ThreadMain(st); });
    return Ok();
}

void ResponseExecutor::Stop() noexcept
{
    if (!m_impl || !m_impl->started.load()) return;
    if (m_impl->stopping.exchange(true)) return;
    m_impl->jobs->Close();
    if (m_impl->thread.joinable()) {
        m_impl->thread.request_stop();
        m_impl->thread.join();
    }
}

Result<PrepareResponse> ResponseExecutor::Prepare(int64_t alertId, model::ActionKind action,
                                                  const model::ResponseTarget& target, const std::string& peerSid)
{
    return m_impl->Call<PrepareResponse>(
        [impl = m_impl.get(), alertId, action, target, peerSid] { return impl->DoPrepare(alertId, action, target, peerSid); });
}

Result<ExecuteResponse> ResponseExecutor::Execute(const ExecuteRequest& req)
{
    auto run = m_impl->Call<Impl::RunResult>([impl = m_impl.get(), req] { return impl->DoExecute(req); });
    if (!run) return run.GetError();
    auto rr = std::move(run).Value();
    // 盡量讓回應帶上 audit_log.id（WriterThread 對 Urgent 寫入通常在數毫秒內完成）
    if (rr.auditWaiter) {
        auto f = rr.auditWaiter->get_future();
        if (f.wait_for(m_impl->cfg.auditIdWait) == std::future_status::ready) rr.response.auditId = f.get();
    }
    return std::move(rr.response);
}

Result<RevertResponse> ResponseExecutor::Revert(const RevertRequest& req)
{
    auto run = m_impl->Call<Impl::RevertRun>([impl = m_impl.get(), req] { return impl->DoRevert(req); });
    if (!run) return run.GetError();
    auto rr = std::move(run).Value();
    if (rr.auditWaiter) {
        auto f = rr.auditWaiter->get_future();
        if (f.wait_for(m_impl->cfg.auditIdWait) == std::future_status::ready) rr.response.auditId = f.get();
    }
    return std::move(rr.response);
}

void ResponseExecutor::Submit(model::ResponseCommand&& cmd)
{
    if (!m_impl->started.load() || m_impl->stopping.load()) {
        m_impl->Bump(&ExecutorStats::automaticDropped);
        return;
    }
    {
        std::lock_guard lk{m_impl->autoMutex};
        if (m_impl->autoPending.size() >= m_impl->cfg.maxPendingAutomatic) {
            std::lock_guard sl{m_impl->statsMutex};
            ++m_impl->stats.automaticDropped;
            spdlog::error("response: automatic response queue full; dropped {} for alert {}",
                          model::ActionKindToString(cmd.action), cmd.alertId);
            return;
        }
        m_impl->autoPending.push_back(std::move(cmd));
        m_impl->lastAutoSubmitSteady = m_impl->clock->SteadyMs();
    }
    // 一次 drain 會處理所有累積的指令；多投遞的 drain 工作只會看到空佇列而立即返回
    if (!m_impl->jobs->Post([impl = m_impl.get()] { if (!impl->stopping.load()) impl->DrainAutomatic(); })) {
        m_impl->Bump(&ExecutorStats::automaticDropped);
    }
}

Result<std::vector<QuarantineEntry>> ResponseExecutor::ListQuarantine()
{
    return m_impl->Call<std::vector<QuarantineEntry>>(
        [impl = m_impl.get()]() -> Result<std::vector<QuarantineEntry>> { return impl->vault.List(); });
}

Result<std::vector<ActionRecord>> ResponseExecutor::ListActions(std::optional<int64_t> alertId)
{
    return m_impl->Call<std::vector<ActionRecord>>([impl = m_impl.get(), alertId]() -> Result<std::vector<ActionRecord>> {
        auto all = impl->records.List();
        if (alertId) {
            std::erase_if(all, [&](const ActionRecord& r) { return r.alertId != *alertId; });
        }
        std::sort(all.begin(), all.end(), [](const auto& a, const auto& b) { return a.executedAt > b.executedAt; });
        return all;
    });
}

void ResponseExecutor::SweepExpiredTokens()
{
    m_impl->tokens.SweepExpired();   // token store 自身以 mutex 保護；prepared 計畫由 T6 定期清理
}

ExecutorStats ResponseExecutor::Stats() const
{
    std::lock_guard lk{m_impl->statsMutex};
    ExecutorStats s = m_impl->stats;
    s.pendingTokens = m_impl->tokens.Size();
    return s;
}

} // namespace cairn::response
