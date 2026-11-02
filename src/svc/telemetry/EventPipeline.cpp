#include "telemetry/EventPipeline.h"

#include <chrono>

namespace cairn::telemetry {

namespace {
int64_t SteadyNowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
// 關機排空期間，AnalysisQueue 滿時最多等待的總時間；逾時就丟（關機不可無限期卡住）。
constexpr int64_t kDrainOutputWaitMs = 5'000;
} // namespace

EventPipeline::EventPipeline(model::StringInterner& interner, BlockingQueue<model::NormalizedEvent>& analysisQueue,
                             Config cfg)
    : m_interner(interner),
      m_out(analysisQueue),
      m_cfg(cfg),
      m_ring(std::make_unique<RawEventQueue>()),
      m_parser(interner, cfg.parser)
{
}

EventPipeline::~EventPipeline()
{
    StopSources();
    StopNormalizer();
}

void EventPipeline::AddSource(std::unique_ptr<IEventSource> source)
{
    if (source) m_sources.push_back(std::move(source));
}

Status EventPipeline::Start()
{
    if (m_normalizer.joinable()) return MakeError(ErrorCode::AlreadyExists, "EventPipeline already started");
    m_normalizer = std::jthread([this](std::stop_token st) { NormalizerLoop(st); });

    m_startResults.clear();
    size_t ok = 0;
    for (auto& src : m_sources) {
        Status st = src->Start(this);
        if (st) ++ok;
        m_startResults.push_back({std::string(src->Name()), st});
    }
    if (!m_sources.empty() && ok == 0) {
        return MakeError(ErrorCode::SubscribeFailed, "all event sources failed to start");
    }
    return Ok();
}

void EventPipeline::StopSources() noexcept
{
    if (m_sourcesStopped.exchange(true)) return;
    for (auto& src : m_sources) src->Stop();   // 阻塞至 in-flight 回呼結束
}

void EventPipeline::StopNormalizer() noexcept
{
    if (!m_normalizer.joinable()) return;
    m_drainRequested.store(true, std::memory_order_release);
    m_normalizer.request_stop();
    m_normalizer.join();
}

bool EventPipeline::Push(model::RawEvent&& ev) noexcept
{
    const auto prio = ev.priority;
    return m_ring->TryPush(std::move(ev), prio);
}

void EventPipeline::NormalizerLoop(std::stop_token st)
{
    model::RawEvent raw;
    int emptyStreak = 0;
    for (;;) {
        if (m_ring->TryPop(raw)) {
            emptyStreak = 0;
            ProcessOne(raw, st);
            continue;
        }
        // 佇列空：停止請求已到 → 已排空，結束
        if (st.stop_requested()) break;
        // 短暫自旋後睡眠，避免閒置時燒 CPU（閒置 CPU 預算 ≤ 2%，M0-P1）
        if (++emptyStreak < 64) {
            std::this_thread::yield();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(m_cfg.idleSleepMs));
        }
    }
}

void EventPipeline::ProcessOne(model::RawEvent& raw, const std::stop_token& st)
{
    model::NormalizedEvent ev;
    const Status s = m_parser.Normalize(raw, ev);
    if (!s) {
        m_parseFailures.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    ev.seq = m_nextSeq.fetch_add(1, std::memory_order_relaxed);
    m_lastLagMs.store(SteadyNowMs() - std::chrono::duration_cast<std::chrono::milliseconds>(
                                          raw.recvTime.time_since_epoch()).count(),
                      std::memory_order_relaxed);

    // 背壓：AnalysisQueue 滿 → 等待（不丟），壓力傳回環形佇列的分級丟棄。
    // 單一生產者（本執行緒）：先檢查容量再 Post，避免 Post 失敗灌高 BlockingQueue::Dropped()。
    const int64_t waitStart = SteadyNowMs();
    bool waited = false;
    while (m_out.Size() >= m_out.Capacity()) {
        if (!waited) {
            m_backpressureWaits.fetch_add(1, std::memory_order_relaxed);
            waited = true;
        }
        if (st.stop_requested() && SteadyNowMs() - waitStart > kDrainOutputWaitMs) return;   // 關機逾時：丟
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (m_out.Post(std::move(ev))) m_normalized.fetch_add(1, std::memory_order_relaxed);
}

PipelineStats EventPipeline::Stats() const
{
    PipelineStats s;
    s.ingested     = m_ring->PushedTotal();
    s.droppedTotal = m_ring->DroppedTotal();
    for (size_t i = 0; i < kPriorityCount; ++i) s.droppedByPriority[i] = m_ring->DroppedCount(static_cast<EventPriority>(i));
    s.normalized        = m_normalized.load(std::memory_order_relaxed);
    s.parseFailures     = m_parseFailures.load(std::memory_order_relaxed);
    s.backpressureWaits = m_backpressureWaits.load(std::memory_order_relaxed);
    s.rawQueueDepth     = m_ring->SizeApprox();
    s.rawQueueUsagePercent = m_ring->UsagePercent();
    s.analysisQueueDepth = m_out.Size();
    s.normalizerLagMs   = m_lastLagMs.load(std::memory_order_relaxed);
    s.internerSaturated = m_interner.IsSaturated();
    return s;
}

std::vector<IEventSource*> EventPipeline::Sources() const
{
    std::vector<IEventSource*> v;
    v.reserve(m_sources.size());
    for (const auto& s : m_sources) v.push_back(s.get());
    return v;
}

} // namespace cairn::telemetry
