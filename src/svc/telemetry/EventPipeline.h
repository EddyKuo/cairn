// src/svc/telemetry/EventPipeline.h           namespace cairn::telemetry
// 感測層的唯一擁有者（SDD-01 §3.1）：sources + RawEventQueue（MPSC 環形佇列）+ NormalizerThread（T2）。
//
// ★ 可攜程式碼：不 include <windows.h>。來源（IEventSource）由外部建立後注入，
//   因此可在測試中以 fake source 驅動整條管線。
//
// 資料流：
//   [OS 回呼 T1] --Push--> LockFreeRingBuffer<RawEvent,65536>（分級丟棄）
//        --TryPop--> [NormalizerThread T2] SysmonXmlParser + seq 指派
//        --Post--> BlockingQueue<NormalizedEvent>（AnalysisQueue，由整合層擁有，容量建議 32768）
//
// 背壓：AnalysisQueue 滿時 T2 等待（不丟），讓壓力傳回環形佇列，由其分級丟棄吸收（SDD-01 §2.5.2 / 附錄 B-3）。
// 擁有權：StringInterner 由整合層建立並以參考傳入（AnalysisEngine / WriterThread 也要用），
//         其生命週期必須長於本物件。
// 關機順序（SDD-01 §2.5.4）：StopSources()（階段 1）→ StopNormalizer()（階段 2，排空後停止）。
#pragma once
#include <array>
#include <atomic>
#include <memory>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "base/BlockingQueue.h"
#include "base/IEventSource.h"
#include "base/RingBuffer.h"
#include "model/NormalizedEvent.h"
#include "model/RawEvent.h"
#include "model/StringInterner.h"
#include "telemetry/SysmonXmlParser.h"

namespace cairn::telemetry {

inline constexpr size_t kRawQueueCapacity = 65536;

// part4 W1-3 的降險路徑：無鎖版本未在 ASan/TSan 穩定通過時，以 -DCAIRN_USE_LOCKED_RING 切回加鎖版本。
#if defined(CAIRN_USE_LOCKED_RING)
using RawEventQueue = BoundedQueue<model::RawEvent, kRawQueueCapacity>;
#else
using RawEventQueue = LockFreeRingBuffer<model::RawEvent, kRawQueueCapacity>;
#endif

struct SourceStartResult {
    std::string name;
    Status      status;
};

struct PipelineStats {
    uint64_t ingested       = 0;   // 成功進入 RawEventQueue 的事件數
    uint64_t droppedTotal   = 0;   // RawEventQueue 分級丟棄總數
    std::array<uint64_t, kPriorityCount> droppedByPriority{};   // 依 EventPriority 分項（Critical..Low）
    uint64_t normalized     = 0;   // 成功送進 AnalysisQueue
    uint64_t parseFailures  = 0;   // XML 無法解析 / EID 不支援
    uint64_t backpressureWaits = 0;// AnalysisQueue 滿而等待的次數
    size_t   rawQueueDepth  = 0;
    uint8_t  rawQueueUsagePercent = 0;
    size_t   analysisQueueDepth = 0;
    int64_t  normalizerLagMs = 0;  // 最近一筆事件：取出時間 - 收到時間（steady）
    bool     internerSaturated = false;
};

class EventPipeline final : public IRawEventSink {
public:
    struct Config {
        SysmonXmlParser::Options parser{};
        // 空佇列時的輪詢間隔：OS 回呼不得取鎖，因此消費端以短睡眠輪詢而非條件變數。
        // 2 ms 對端到端延遲無感（Event Log 本身批次投遞 50–500 ms，SDD-01 §3.5）。
        int idleSleepMs = 2;
    };

    EventPipeline(model::StringInterner& interner, BlockingQueue<model::NormalizedEvent>& analysisQueue)
        : EventPipeline(interner, analysisQueue, Config{}) {}
    EventPipeline(model::StringInterner& interner, BlockingQueue<model::NormalizedEvent>& analysisQueue,
                  Config cfg);
    ~EventPipeline() override;
    EventPipeline(const EventPipeline&) = delete;
    EventPipeline& operator=(const EventPipeline&) = delete;

    // 必須在 Start 之前呼叫。
    void AddSource(std::unique_ptr<IEventSource> source);

    // 啟動 NormalizerThread 後再逐一啟動來源（先開排水口再開水龍頭）。
    // 個別來源失敗不致命（降級），結果見 StartResults()；全部失敗才回傳錯誤。
    [[nodiscard]] Status Start();
    [[nodiscard]] const std::vector<SourceStartResult>& StartResults() const noexcept { return m_startResults; }

    // 關機階段 1：EvtClose 全部訂閱，阻塞至 in-flight 回呼結束。冪等。
    void StopSources() noexcept;
    // 關機階段 2：排空 RawEventQueue 後停止 T2。冪等。必須在 StopSources 之後呼叫。
    void StopNormalizer() noexcept;

    // IRawEventSink：由 OS 回呼執行緒呼叫，lock-free，不阻塞。
    [[nodiscard]] bool Push(model::RawEvent&& ev) noexcept override;

    [[nodiscard]] PipelineStats Stats() const;

    // Watchdog 用：檢查各來源健康度並重訂閱（非擁有指標，生命週期同本物件）。
    [[nodiscard]] std::vector<IEventSource*> Sources() const;

    // 下一個 seq（重啟時可由整合層以 events 表的最大值初始化，維持單調）。
    void SetNextSeq(uint64_t seq) noexcept { m_nextSeq.store(seq, std::memory_order_relaxed); }

private:
    void NormalizerLoop(std::stop_token st);
    void ProcessOne(model::RawEvent& raw, const std::stop_token& st);

    model::StringInterner&                    m_interner;
    BlockingQueue<model::NormalizedEvent>&    m_out;
    Config                                    m_cfg;
    std::unique_ptr<RawEventQueue>            m_ring;      // 數 MB，必須配置在堆積
    SysmonXmlParser                           m_parser;    // 只由 T2 使用
    std::vector<std::unique_ptr<IEventSource>> m_sources;
    std::vector<SourceStartResult>            m_startResults;
    std::jthread                              m_normalizer;

    std::atomic<bool>     m_sourcesStopped{false};
    std::atomic<bool>     m_drainRequested{false};
    std::atomic<uint64_t> m_nextSeq{1};
    std::atomic<uint64_t> m_normalized{0};
    std::atomic<uint64_t> m_parseFailures{0};
    std::atomic<uint64_t> m_backpressureWaits{0};
    std::atomic<int64_t>  m_lastLagMs{0};
};

} // namespace cairn::telemetry
