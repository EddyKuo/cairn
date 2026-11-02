// src/svc/host/ServiceHost.h                  namespace cairn::host
// CairnAgent.exe 的服務本體：擁有所有元件與執行緒，依 SDD-01 §2.6 啟動、§2.5.4 關機。
//
// 執行緒（SDD-01 §2.5.2）：
//   T1 EvtSubscribe 回呼（OS）→ T2 Normalizer（EventPipeline）→ T3 AnalysisThread（本類別）
//   T4 WriterThread（store）· T5 LlmWorker（llm）· T6 ResponseExecutor（response）
//   T7 PipeServer（1 accept + 4 worker）· T8 MaintenanceThread（本類別：Watchdog / 健康度 / 規則熱重載）
//
// 鐵則：AnalysisEngine 只在 T3 上被呼叫。其他執行緒一律經 AnalysisTasks 投遞。
#pragma once
#include <windows.h>
#include <winhttp.h>   // 必須先於任何 <wil/resource.h>，WIL 才會定義 unique_winhttp_hinternet（llm/ 標頭需要）

#include <atomic>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "base/BlockingQueue.h"
#include "base/IClock.h"
#include "engine/AnalysisEngine.h"
#include "host/AnalysisTasks.h"
#include "host/HandlerContext.h"
#include "host/HostState.h"
#include "host/PolicyConfig.h"
#include "host/ServiceControl.h"
#include "llm/LlamaServerSupervisor.h"
#include "llm/LlmWorker.h"
#include "model/StringInterner.h"
#include "response/ConfirmationTokenStore.h"
#include "response/ResponseExecutor.h"
#include "rpc/JsonRpcDispatcher.h"
#include "rpc/PipeServer.h"
#include "rules/RuleLoader.h"
#include "store/ReadOnlyDb.h"
#include "store/WriterThread.h"
#include "telemetry/BookmarkStore.h"
#include "telemetry/EventPipeline.h"
#include "telemetry/EvtChannelSource.h"

namespace cairn::host {

class ServiceHost final : public svc::IServiceBody, public IHostServices, public model::IAlertSink {
public:
    ServiceHost();
    ~ServiceHost() override;
    ServiceHost(const ServiceHost&) = delete;
    ServiceHost& operator=(const ServiceHost&) = delete;

    // ---- IServiceBody ----
    [[nodiscard]] bool Start(const svc::ProgressFn& progress, DWORD& exitCode) override;
    void Stop(const svc::ProgressFn& progress) noexcept override;

    // ---- IHostServices（RPC 執行緒呼叫）----
    [[nodiscard]] LiveHealth Health() override;
    [[nodiscard]] std::vector<rules::RuleInfo> RuleInfos() override;
    [[nodiscard]] Result<rules::RuleInfo> SetRuleStatus(const std::string& ruleId, model::RuleStatus s) override;
    [[nodiscard]] Status ReloadExclusions() override;
    [[nodiscard]] bool EnqueueNarrative(const model::NarrativeRequest& req, bool reducedContext) override;
    [[nodiscard]] Status SetProtectionPaused(bool paused, int64_t untilMs, const std::string& reason) override;
    [[nodiscard]] Status FinishLearning() override;

    // ---- IAlertSink（AnalysisThread 呼叫，非阻塞）----
    void OnAlertRaised(const model::AlertRaised& a) override;

private:
    // 啟動步驟
    [[nodiscard]] Status LoadConfig();
    [[nodiscard]] Status OpenStore();
    [[nodiscard]] Status LoadRules(bool initial);
    void SeedBuiltinExclusions();
    [[nodiscard]] Status CreateEngine();
    void CreateResponder();
    void CreateLlm();
    void RegisterRpc();
    [[nodiscard]] Status StartTelemetry();

    // 執行緒
    void AnalysisLoop(std::stop_token st);
    void MaintenanceLoop(std::stop_token st);
    void WatchSources(int64_t steadyNow);
    void SampleHealth(int64_t nowMs);
    void CheckRuleDirectory(int64_t steadyNow);
    void CheckPolicyTimers(int64_t nowMs);
    void AddAnomaly(std::string message);

    [[nodiscard]] std::vector<rules::ExclusionEntry> ReadExclusionsFromDb(store::ReadOnlyDb& db);
    [[nodiscard]] store::ReadOnlyDb* ThreadReader();
    [[nodiscard]] std::string RuleDirSignature() const;
    [[nodiscard]] bool LearningActiveNow() const;

    // ---- 路徑 / 設定 / 狀態 ----
    std::filesystem::path m_dataDir;
    std::filesystem::path m_exeDir;
    std::filesystem::path m_rulesDir;
    HostConfig            m_cfg;
    bool                  m_policyFellBack = false;
    SystemClock           m_clock;
    std::unique_ptr<HostState> m_state;
    int64_t               m_startedMs = 0;
    std::string           m_hostname;

    // ---- 元件（宣告順序 = 解構的反序；關機順序另由 Stop 明確控制）----
    std::unique_ptr<model::StringInterner>               m_interner;
    std::unique_ptr<rpc::JsonRpcDispatcher>              m_dispatcher;
    std::unique_ptr<rpc::PipeServer>                     m_pipe;
    std::unique_ptr<store::WriterThread>                 m_writer;
    std::unique_ptr<store::ReadOnlyDb>                   m_maintDb;   // 只給 T8
    std::unique_ptr<store::ReadOnlyDb>                   m_llmDb;     // 只給 T5（IAlertContextProvider）
    std::unique_ptr<response::ResponseExecutor>          m_responses;
    std::unique_ptr<response::ConfirmationTokenStore>    m_tokens;    // pause / revert 的確認 token
    std::unique_ptr<UndoStore>                           m_undo;
    std::unique_ptr<llm::LlamaServerSupervisor>          m_llamaSup;
    std::unique_ptr<llm::LlmWorker>                      m_llm;
    std::unique_ptr<BlockingQueue<model::NormalizedEvent>> m_analysisQueue;
    std::unique_ptr<engine::AnalysisEngine>              m_engine;
    AnalysisTasks                                        m_tasks;
    std::unique_ptr<telemetry::BookmarkStore>            m_bookmarks;
    std::unique_ptr<telemetry::EventPipeline>            m_pipeline;
    std::vector<telemetry::EvtChannelSource*>            m_sources;   // 非擁有（pipeline 擁有）
    bool                                                 m_sysmonMissing = false;

    // ---- 規則 ----
    mutable std::mutex           m_rulesMutex;
    std::vector<rules::RuleInfo> m_ruleInfos;
    uint32_t                     m_ruleGeneration = 0;
    std::string                  m_ruleSig;
    std::string                  m_pendingRuleSig;
    int64_t                      m_pendingRuleSigSince = 0;
    bool                         m_engineLearning = false;

    // ---- 執行緒 ----
    std::jthread m_analysisThread;
    std::jthread m_maintThread;
    std::atomic<bool> m_analysisStarted{false};
    std::atomic<uint64_t> m_eventsAnalyzed{0};

    // ---- 健康度（T8 寫、RPC 讀）----
    std::mutex       m_healthMutex;
    LiveHealth       m_live;
    std::deque<double> m_cpuSamples;       // 最近 1 小時
    int64_t          m_lastCpuWallMs = 0;
    uint64_t         m_lastCpuTime100ns = 0;
    uint64_t         m_lastIngested = 0, m_lastDropped = 0;
    int64_t          m_lastSampleMs = 0;
    std::deque<LiveHealth::Anomaly> m_anomalies;

    // ---- Watchdog 每來源的重訂閱退避 ----
    struct SourceWatch {
        int64_t nextAttemptSteadyMs = 0;
        int64_t backoffMs = 5'000;
    };
    std::vector<SourceWatch> m_sourceWatch;

    std::atomic<bool> m_stopped{false};
};

// config/policy.default.json 的內嵌副本（建置時由 CMake 產生）
[[nodiscard]] std::string_view EmbeddedDefaultPolicy() noexcept;

} // namespace cairn::host
