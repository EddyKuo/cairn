// src/svc/llm/LlmWorker.h                     namespace cairn::llm
// T5 LlmWorker（part2 §2.1.2、SDD-03 §7.5–§7.7）。
//   - 單一執行緒、併發 1（對應 llama-server --parallel 1）
//   - 有界佇列 32；滿載時踢掉優先度最低者（被踢者回填 ai_state='skipped'），新來的若不高於最低者則自己被丟
//     優先度：manual（使用者按「重新生成」）> scoreMilli 高者 > 先入列者
//   - 只處理分數 >= 80 的告警（manual 例外）
//   - schema 違規重試 1 次；逾時不重試（交給分析師按「重新生成」）
//   - 每個分支都回填終局 ai_state（ok / timeout / schema_violation / unavailable / skipped）；
//     服務停止時被取消的項目不回填，交由 store 的 pending 掃描器（> 5 分鐘 → timeout）收尾
//   - 結果一律以 model::AlertNarrativeUpdate 經 model::IWriteSink 投遞給 T4（唯一寫者）
// ★ 架構紅線：本類別只會產生 AlertNarrativeUpdate（只有 ai_* 欄位），不認識分數、不觸發回應。
#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "base/Result.h"
#include "llm/NarrativeEngine.h"
#include "model/NarrativeTypes.h"
#include "model/WriteOp.h"

namespace cairn::llm {

struct LlmWorkerConfig {
    bool    enabled        = true;
    size_t  queueCapacity  = 32;
    int64_t minScoreMilli  = 80'000;
    int     schemaRetries  = 1;
    int     contextLoadAttempts = 4;       // 告警列可能尚未被 T4 提交（與 NarrativeRequest 同時發出）
    int     contextRetryDelayMs = 300;
    int64_t degradedP95Ms  = 20'000;       // M0-P8：敘事 P95 > 20 s → degraded
};

enum class EnqueueResult { Accepted, EvictedLowest, DroppedIncoming, BelowThreshold, Duplicate, Disabled };

struct LlmStatus {
    std::string state = "unavailable";     // ok | degraded | unavailable（agent_health.llm_state）
    std::string supervisorDetail;          // 例如 "backoff: process exited"
    size_t      queueDepth = 0;
    double      p95Ms      = 0.0;          // 最近 200 筆成功敘事（告警產生 → 敘事完成）
    uint64_t    processed  = 0;
    uint64_t    ok         = 0;
    uint64_t    timeouts   = 0;
    uint64_t    schemaViolations = 0;
    uint64_t    unavailable = 0;
    uint64_t    skipped    = 0;
    int         restartsLastHour = 0;
    std::string modelId;
    int64_t     currentAlertId = 0;        // 0 = 閒置
};

class LlmWorker {
public:
    // provider：T5 上呼叫，以唯讀連線組出 PromptInput（store 子系統實作）。
    // sink    ：WriterThread 的佇列。兩者生命週期必須長於本物件。
    [[nodiscard]] static Result<std::unique_ptr<LlmWorker>> Create(LlmWorkerConfig cfg,
                                                                   std::unique_ptr<INarrativeEngine> engine,
                                                                   model::IAlertContextProvider* provider,
                                                                   model::IWriteSink* sink);
    ~LlmWorker();
    LlmWorker(const LlmWorker&)            = delete;
    LlmWorker& operator=(const LlmWorker&) = delete;

    [[nodiscard]] Status Start();
    // 停止預算內（≤ 20 s）收手：取消進行中的推論、join 執行緒。冪等。
    void Stop() noexcept;

    // 任意執行緒、非阻塞（AnalysisThread 的告警通知、RPC 的 narrative.regenerate）。
    EnqueueResult Enqueue(const model::NarrativeRequest& req, bool reducedContext = false);

    // T8 Watchdog（每 ≤ 30 秒）：閒置卸載、子程序崩潰偵測。
    void Tick();

    // UI「手動重啟本機 AI」
    void RequestManualRestart();

    [[nodiscard]] LlmStatus Status() const;

    // 以 ai_state 字串回報 Generate 錯誤碼的對應（測試與 RPC 共用）
    [[nodiscard]] static model::AiState MapErrorToAiState(ErrorCode c) noexcept;

private:
    struct Job {
        model::NarrativeRequest req;
        bool                    reducedContext = false;
        uint64_t                order = 0;
    };

    LlmWorker(LlmWorkerConfig cfg, std::unique_ptr<INarrativeEngine> engine, model::IAlertContextProvider* provider,
              model::IWriteSink* sink)
        : m_cfg(cfg), m_engine(std::move(engine)), m_provider(provider), m_sink(sink) {}

    static bool HigherPriority(const Job& a, const Job& b) noexcept;   // a 優先於 b
    void Run(std::stop_token st);
    void Process(const Job& job, std::stop_token st);
    void PostUpdate(model::AlertNarrativeUpdate&& u);
    void PostSkipped(int64_t alertId);
    void RecordLatency(int64_t ms);

    LlmWorkerConfig                    m_cfg;
    std::unique_ptr<INarrativeEngine>  m_engine;
    model::IAlertContextProvider*      m_provider;
    model::IWriteSink*                 m_sink;

    mutable std::mutex                 m_qMutex;
    std::condition_variable_any        m_qCv;
    std::vector<Job>                   m_queue;
    uint64_t                           m_nextOrder = 0;

    std::jthread                       m_thread;
    std::atomic<int64_t>               m_currentAlertId{0};

    mutable std::mutex                 m_statsMutex;
    std::deque<int64_t>                m_latencies;
    LlmStatus                          m_counters;
    int                                m_consecutiveFailures = 0;
};

} // namespace cairn::llm
