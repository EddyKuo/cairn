#include "llm/LlmWorker.h"

#include <algorithm>
#include <chrono>

#include <spdlog/spdlog.h>

namespace cairn::llm {

namespace {

int64_t NowUnixMs() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t SteadyMs() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

} // namespace

model::AiState LlmWorker::MapErrorToAiState(ErrorCode c) noexcept
{
    switch (c) {
    case ErrorCode::LlmUnavailable: return model::AiState::Unavailable;
    case ErrorCode::LlmTimeout:
    case ErrorCode::Timeout:
    case ErrorCode::Cancelled: return model::AiState::Timeout;
    default: return model::AiState::SchemaViolation;   // LlmSchemaViolation / LlmHttpError / LlmContextOverflow / 其他
    }
}

Result<std::unique_ptr<LlmWorker>> LlmWorker::Create(LlmWorkerConfig cfg, std::unique_ptr<INarrativeEngine> engine,
                                                     model::IAlertContextProvider* provider, model::IWriteSink* sink)
{
    if (!sink) return MakeError(ErrorCode::InvalidArgument, "LlmWorker: IWriteSink 為空");
    if (!provider) return MakeError(ErrorCode::InvalidArgument, "LlmWorker: IAlertContextProvider 為空");
    if (cfg.queueCapacity == 0) return MakeError(ErrorCode::InvalidArgument, "LlmWorker: queueCapacity 不可為 0");
    if (!engine) engine = std::make_unique<NullNarrativeEngine>();
    if (!cfg.enabled) engine = std::make_unique<NullNarrativeEngine>();
    return std::unique_ptr<LlmWorker>(new LlmWorker(cfg, std::move(engine), provider, sink));
}

LlmWorker::~LlmWorker()
{
    Stop();
}

::cairn::Status LlmWorker::Start()
{
    if (m_thread.joinable()) return Ok();
    m_thread = std::jthread([this](std::stop_token st) { Run(st); });
    return Ok();
}

void LlmWorker::Stop() noexcept
{
    if (!m_thread.joinable()) return;
    m_thread.request_stop();       // stop_callback → 取消進行中的 WinHTTP 請求
    m_engine->CancelCurrent();
    m_qCv.notify_all();
    m_thread.join();
}

bool LlmWorker::HigherPriority(const Job& a, const Job& b) noexcept
{
    if (a.req.manual != b.req.manual) return a.req.manual;
    if (a.req.scoreMilli != b.req.scoreMilli) return a.req.scoreMilli > b.req.scoreMilli;
    return a.order < b.order;   // 同級 FIFO
}

EnqueueResult LlmWorker::Enqueue(const model::NarrativeRequest& req, bool reducedContext)
{
    if (!m_cfg.enabled) {
        model::AlertNarrativeUpdate u;
        u.alertId = req.alertId;
        u.aiState = model::AiState::Unavailable;
        PostUpdate(std::move(u));
        return EnqueueResult::Disabled;
    }
    if (!req.manual && req.scoreMilli < m_cfg.minScoreMilli) {
        PostSkipped(req.alertId);
        return EnqueueResult::BelowThreshold;
    }

    int64_t       evicted = 0;
    EnqueueResult result  = EnqueueResult::Accepted;
    {
        std::lock_guard lk{m_qMutex};
        // 同一告警已在佇列中：以較新的請求取代（manual 可提升優先度、改用 reduced context）
        for (auto& j : m_queue) {
            if (j.req.alertId == req.alertId) {
                if (req.manual) {
                    j.req.manual     = true;
                    j.reducedContext = reducedContext;
                }
                return EnqueueResult::Duplicate;
            }
        }
        if (m_currentAlertId.load() == req.alertId && !req.manual) return EnqueueResult::Duplicate;

        Job job{req, reducedContext, m_nextOrder++};
        if (m_queue.size() < m_cfg.queueCapacity) {
            m_queue.push_back(std::move(job));
        } else {
            // 找出最低優先度者
            auto victim = std::min_element(m_queue.begin(), m_queue.end(),
                                           [](const Job& a, const Job& b) { return HigherPriority(b, a); });
            if (HigherPriority(job, *victim)) {
                evicted = victim->req.alertId;
                *victim = std::move(job);
                result  = EnqueueResult::EvictedLowest;
            } else {
                evicted = req.alertId;
                result  = EnqueueResult::DroppedIncoming;
            }
        }
    }
    m_qCv.notify_one();
    if (evicted != 0) {
        spdlog::info("[llm] 敘事佇列已滿（{}），alert {} 標記為 skipped", m_cfg.queueCapacity, evicted);
        PostSkipped(evicted);
    }
    return result;
}

void LlmWorker::Run(std::stop_token st)
{
    spdlog::info("[llm] LlmWorker 啟動");
    while (!st.stop_requested()) {
        Job job;
        {
            std::unique_lock lk{m_qMutex};
            m_qCv.wait(lk, st, [&] { return !m_queue.empty(); });
            if (st.stop_requested()) break;
            if (m_queue.empty()) continue;
            auto best = std::min_element(m_queue.begin(), m_queue.end(), HigherPriority);
            job = std::move(*best);
            m_queue.erase(best);
            m_currentAlertId.store(job.req.alertId);
        }
        Process(job, st);
        m_currentAlertId.store(0);
    }
    spdlog::info("[llm] LlmWorker 停止（佇列剩餘 {} 筆，交由 pending 掃描器收尾）", Status().queueDepth);
}

void LlmWorker::Process(const Job& job, std::stop_token st)
{
    const int64_t alertId = job.req.alertId;
    const int64_t t0      = SteadyMs();

    // 1) 取脈絡。告警列與 NarrativeRequest 幾乎同時發出，T4 可能尚未提交 → 短暫重試
    Result<model::PromptInput> input = MakeError(ErrorCode::NotFound, "not loaded");
    for (int attempt = 0; attempt < std::max(1, m_cfg.contextLoadAttempts); ++attempt) {
        if (st.stop_requested()) return;
        input = m_provider->LoadPromptInput(alertId);
        if (input) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(m_cfg.contextRetryDelayMs));
    }
    if (!input) {
        spdlog::warn("[llm] alert {} 無法載入告警脈絡: {}", alertId, input.GetError().ToString());
        model::AlertNarrativeUpdate u;
        u.alertId = alertId;
        u.aiState = model::AiState::Unavailable;
        PostUpdate(std::move(u));
        return;
    }

    // 2) 生成；schema 違規重試 cfg.schemaRetries 次，逾時／不可用不重試
    GenerateOptions opt;
    opt.reducedContext = job.reducedContext;
    Result<model::NarrativeResult> r = MakeError(ErrorCode::LlmUnavailable, "not attempted");
    for (int attempt = 0; attempt <= m_cfg.schemaRetries; ++attempt) {
        r = m_engine->Generate(input.Value(), opt, st);
        if (r) break;
        const auto code = r.Code();
        if (code != ErrorCode::LlmSchemaViolation && code != ErrorCode::LlmHttpError) break;
        if (st.stop_requested()) break;
        spdlog::info("[llm] alert {} 第 {} 次輸出未通過驗證，重試", alertId, attempt + 1);
    }

    // 服務停止造成的取消：不回填，避免把「我們自己停掉」記成逾時
    if (!r && r.Code() == ErrorCode::Cancelled && st.stop_requested()) return;

    const int64_t now     = NowUnixMs();
    const int64_t latency = job.req.enqueuedTs > 0 ? std::max<int64_t>(0, now - job.req.enqueuedTs) : SteadyMs() - t0;

    model::AlertNarrativeUpdate u;
    u.alertId   = alertId;
    u.latencyMs = latency;
    const std::string modelId = m_engine->ModelId();
    if (!modelId.empty()) u.modelId = modelId;

    if (r) {
        auto& v          = r.Value();
        u.aiState        = model::AiState::Ok;
        u.narrative      = std::move(v.narrative);
        u.recommendation = std::move(v.recommendation);
        u.confidence     = v.confidence;
        u.aiAttackIds    = std::move(v.attackIds);
        RecordLatency(latency);
    } else {
        u.aiState = MapErrorToAiState(r.Code());
        spdlog::warn("[llm] alert {} 敘事失敗 → {}: {}", alertId, model::AiStateToString(u.aiState),
                     r.GetError().ToString());
    }

    {
        std::lock_guard lk{m_statsMutex};
        ++m_counters.processed;
        switch (u.aiState) {
        case model::AiState::Ok: ++m_counters.ok; m_consecutiveFailures = 0; break;
        case model::AiState::Timeout: ++m_counters.timeouts; ++m_consecutiveFailures; break;
        case model::AiState::SchemaViolation: ++m_counters.schemaViolations; ++m_consecutiveFailures; break;
        case model::AiState::Unavailable: ++m_counters.unavailable; ++m_consecutiveFailures; break;
        default: break;
        }
    }
    PostUpdate(std::move(u));
}

void LlmWorker::PostUpdate(model::AlertNarrativeUpdate&& u)
{
    const int64_t id = u.alertId;
    model::WriteOp op;
    op.payload = std::move(u);
    if (!m_sink->Post(std::move(op)))
        spdlog::warn("[llm] 寫入佇列已滿，alert {} 的敘事結果未能回填（pending 掃描器將收尾）", id);
}

void LlmWorker::PostSkipped(int64_t alertId)
{
    {
        std::lock_guard lk{m_statsMutex};
        ++m_counters.skipped;
    }
    model::AlertNarrativeUpdate u;
    u.alertId = alertId;
    u.aiState = model::AiState::Skipped;
    PostUpdate(std::move(u));
}

void LlmWorker::RecordLatency(int64_t ms)
{
    std::lock_guard lk{m_statsMutex};
    m_latencies.push_back(ms);
    while (m_latencies.size() > 200) m_latencies.pop_front();
}

void LlmWorker::Tick()
{
    m_engine->Tick();
}

void LlmWorker::RequestManualRestart()
{
    m_engine->RequestManualRestart();
}

LlmStatus LlmWorker::Status() const
{
    LlmStatus s;
    {
        std::lock_guard lk{m_statsMutex};
        s = m_counters;
        if (!m_latencies.empty()) {
            std::vector<int64_t> v(m_latencies.begin(), m_latencies.end());
            const size_t idx = std::min(v.size() - 1, (v.size() * 95 + 99) / 100 - 1);
            std::nth_element(v.begin(), v.begin() + static_cast<std::ptrdiff_t>(idx), v.end());
            s.p95Ms = static_cast<double>(v[idx]);
        }
        const auto avail = m_cfg.enabled ? m_engine->Availability() : EngineAvailability::Unavailable;
        if (avail == EngineAvailability::Unavailable) s.state = "unavailable";
        else if (avail == EngineAvailability::Degraded || m_consecutiveFailures >= 3 ||
                 (s.p95Ms > static_cast<double>(m_cfg.degradedP95Ms)))
            s.state = "degraded";
        else s.state = "ok";
    }
    {
        std::lock_guard lk{m_qMutex};
        s.queueDepth = m_queue.size();
    }
    s.restartsLastHour = m_engine->RestartsLastHour();
    s.supervisorDetail = m_engine->Detail();
    s.modelId          = m_engine->ModelId();
    s.currentAlertId   = m_currentAlertId.load();
    return s;
}

} // namespace cairn::llm
