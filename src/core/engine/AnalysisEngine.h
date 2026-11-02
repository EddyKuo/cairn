// src/core/engine/AnalysisEngine.h            namespace cairn::engine
// 偵測核心的門面（SDD-02 §4.1）：唯一入口 OnEvent / OnTick。
// ★ AnalysisThread 獨佔：程序樹、分數、序列狀態全部單執行緒擁有，不加鎖。
//   其他執行緒（RPC、RuleWatcher）要改變引擎狀態，必須把工作投遞到 AnalysisThread 的佇列後再呼叫本類別。
// ★ 架構紅線：本檔不得 include 任何 llm/ 或 prompt/ 標頭（LLM 不參與計分與阻擋）。
// ★ 所有副作用皆為非阻塞的傳值投遞（IWriteSink / IAlertSink / IResponseSink），絕不等待 I/O。
#pragma once
#include <chrono>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/IClock.h"
#include "base/Result.h"
#include "engine/EnginePolicy.h"
#include "model/NarrativeTypes.h"
#include "model/NormalizedEvent.h"
#include "model/ResponseCommand.h"
#include "model/WriteOp.h"
#include "rules/Exclusions.h"
#include "rules/RuleEngine.h"
#include "score/ScoreBoard.h"
#include "tree/ProcessTree.h"

namespace cairn::engine {

struct EngineStats {
    uint64_t eventsProcessed    = 0;
    uint64_t ruleHits           = 0;
    uint64_t suppressedHits     = 0;
    uint64_t dryrunHits         = 0;
    uint64_t alertsRaised       = 0;
    uint64_t responsesSubmitted = 0;
    uint64_t responsesWithheld  = 0;   // 學習期 / 暫停 / 總開關關閉而未送出的自動回應
    uint64_t writeDropped       = 0;   // IWriteSink 拒收（佇列滿）
    double   tier2P95Ms         = 0;   // 規則求值 P95（毫秒，最近 1024 個事件）
    size_t   treeNodes          = 0;
    size_t   trees              = 0;
    size_t   scoredTrees        = 0;
    bool     degraded           = false;
    bool     protectionPaused   = false;
    bool     learningMode       = false;
    int64_t  nextEventId        = 1;
    int64_t  nextAlertId        = 1;
    tree::TreeStats       tree{};
    rules::RuleEngineStats rules{};
};

class AnalysisEngine {
public:
    struct Deps {
        model::StringInterner* interner = nullptr;   // 必填
        model::IWriteSink*     writes   = nullptr;   // 必填
        model::IAlertSink*     alerts   = nullptr;   // 可為空
        model::IResponseSink*  responses = nullptr;  // 可為空（= 不自動回應）
        const IClock*          clock    = nullptr;   // 必填
    };

    // P-3：建構不得失敗，依賴檢查以工廠函式回傳 Result。
    [[nodiscard]] static Result<std::unique_ptr<AnalysisEngine>> Create(Deps deps, EnginePolicy policy = {});

    AnalysisEngine(const AnalysisEngine&) = delete;
    AnalysisEngine& operator=(const AnalysisEngine&) = delete;

    // ---- 事件與定時器 ----
    void OnEvent(model::NormalizedEvent&& ev);
    void OnTick(UnixMs nowMs);   // 1 Hz：衰減掃描、孤兒逾時、序列過期；每 10 tick 跑一次 Reaper

    // ---- 啟動 ----
    // 由 svc 以 SELECT IFNULL(MAX(id),0)+1 初始化（SDD-02 §5.4「events.id 從哪裡來」）。
    void SetNextIds(int64_t nextEventId, int64_t nextAlertId) noexcept;
    // CreateToolhelp32Snapshot 的結果（part2 §2.4.1）。會為每個節點投遞 ProcessRow。
    void SeedProcesses(const std::vector<tree::SnapshotProcess>& procs);

    // ---- 規則 / 排除 / 政策（皆需在 AnalysisThread 上呼叫）----
    void ReplaceRuleSet(std::shared_ptr<const rules::RuleSet> rs);
    void ReplaceExclusions(std::vector<rules::ExclusionEntry> entries);
    void SetPolicy(EnginePolicy policy);
    void SetProtectionPaused(bool paused) noexcept;   // protection.pause / resume
    void SetLearningMode(bool on) noexcept;           // learning.finish → false

    // ---- 分析師操作 ----
    // alerts.setVerdict：該告警所屬的樹轉為 Resolved（不再自動轉移）。alerts.analyst_verdict 的落地由 RPC 層投遞。
    [[nodiscard]] Status ApplyVerdict(int64_t alertId, model::Verdict verdict);
    [[nodiscard]] Status ApplyVerdictByRoot(const model::GuidValue& root, model::Verdict verdict);
    // 回應執行器回報我方終止了某程序（is_terminated_by_us）
    void MarkTerminatedByUs(const model::GuidValue& processGuid);

    // ---- 查詢（RPC response.prepare 等，透過 AnalysisThread 任務呼叫）----
    // 根 → 葉前序走訪的程序清單。aliveOnly = true 時略過已結束者。
    [[nodiscard]] std::vector<model::ProcessRef> SnapshotTree(const model::GuidValue& root, bool aliveOnly = false) const;
    [[nodiscard]] std::optional<model::GuidValue> RootOfAlert(int64_t alertId) const;
    [[nodiscard]] int64_t CurrentScore(const model::GuidValue& root);
    [[nodiscard]] EngineStats Stats() const;
    [[nodiscard]] const rules::RuleSet* Rules() const noexcept { return m_rules.Rules(); }

private:
    AnalysisEngine(Deps deps, EnginePolicy policy);

    struct HitRecord {
        std::string               ruleId;
        std::string               title;
        model::Severity           severity = model::Severity::High;
        std::vector<std::string>  attackIds;
        rules::ResponseSpec       response;
        bool                      deterministic = false;
        bool                      sequence = false;
        int64_t                   scoreMilli = 0;
        int64_t                   tsMs = 0;
        std::vector<rules::StepRecord> evidence;
    };
    struct TreeEvidence {
        std::deque<HitRecord>      hits;          // 只收 enabled 且未被抑制的命中（上限 64）
        std::optional<std::string> lastDestIp;    // firewall_block 的目標
        std::optional<uint16_t>    lastDestPort;
    };
    struct PendingAlert {
        model::GuidValue root{};
        score::ScoreTransition tr{};
        std::vector<model::RuleHitRow> rows;
    };

    void PostWrite(model::WritePayload&& p);
    void PostScore(const model::GuidValue& root);
    [[nodiscard]] model::ProcessRow MakeProcessRow(const tree::ProcessNode& n) const;
    [[nodiscard]] std::string ImageOf(const tree::ProcessNode& n) const;
    void OnReroot(const model::GuidValue& oldRoot, const model::GuidValue& newRoot, int64_t nowMs);
    void RaiseAlert(PendingAlert&& pa, const model::NormalizedEvent& ev, int64_t eventId, int64_t tsMs);
    void PlanResponses(int64_t alertId, const model::GuidValue& root, const score::ScoreTransition& tr,
                       const model::NormalizedEvent& ev);
    void SetSampled(const model::GuidValue& root, bool on);
    [[nodiscard]] bool IsNeverTarget(std::string_view imagePath) const;
    void RecordLatency(int64_t micros);

    Deps          m_deps;
    EnginePolicy  m_policy;
    tree::ProcessTree   m_tree;
    score::ScoreBoard   m_scores;
    rules::RuleEngine   m_rules;
    rules::ExclusionSet m_exclusions;

    std::unordered_map<model::GuidValue, TreeEvidence, model::GuidHash> m_evidence;
    std::unordered_map<int64_t, model::GuidValue> m_alertRoots;
    std::deque<int64_t>                           m_alertOrder;   // m_alertRoots 的 FIFO 上限

    int64_t  m_nextEventId = 1;
    int64_t  m_nextAlertId = 1;
    uint64_t m_tickCount   = 0;
    bool     m_paused      = false;

    std::vector<int64_t> m_latencyUs;   // 環形，1024
    size_t               m_latencyPos = 0;
    EngineStats          m_stats;
};

} // namespace cairn::engine
