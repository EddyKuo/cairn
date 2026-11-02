// src/core/score/ScoreBoard.h                 namespace cairn::score
// 分數累加、衰減與狀態機轉移的唯一權威（SDD-02 §4.3.3 / §4.4 / §4.5）。
// ★ 不執行任何副作用：只回傳 ScoreTransition，由 AnalysisEngine 決定告警／回應。
// ★ 架構紅線：本檔與 score/ 目錄不得 include 任何 llm/ 或 prompt/ 標頭（LLM 不參與計分）。
// 執行緒：AnalysisThread 獨佔，故意不做執行緒安全。
#pragma once
#include <cstdint>
#include <functional>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "model/Domain.h"
#include "model/GuidValue.h"
#include "score/Decay.h"

namespace cairn::score {

using model::GuidValue;
using model::TreeState;

using model::kHysteresisMilli;
using model::kThresholdAlerted;
using model::kThresholdBlocked;
using model::kThresholdWatched;

struct RuleHit {
    std::string ruleId;
    int64_t     deltaMilli    = 0;
    int64_t     tsMs          = 0;
    uint32_t    halfLifeMs    = 0;
    bool        deterministic = false;   // 命中即跳 Blocked，不走累加
    bool        dryRun        = false;   // 只進 shadow，不轉移狀態
    bool        suppressed    = false;   // 命中排除清單：記錄但不加分
};

struct ScoreTransition {
    GuidValue root{};
    TreeState from = TreeState::Benign;
    TreeState to   = TreeState::Benign;
    int64_t   scoreMilli  = 0;
    int64_t   peakMilli   = 0;
    int64_t   shadowMilli = 0;
    RuleHit   trigger{};
    bool      cooledDown = false;        // 冷卻期內的重複命中：照常記錄但 delta 視為 0
    bool      erased     = false;        // SweepDecay：分數與影子分數皆歸零，已自 ScoreBoard 移除
    int64_t   appliedDeltaMilli = 0;     // 實際加進 scoreMilli 的分數（供 events.score_delta）

    [[nodiscard]] bool IsEscalation() const noexcept { return to > from && to <= TreeState::Blocked; }
};

struct TreeScore {
    GuidValue root{};
    int64_t   scoreMilli   = 0;
    int64_t   shadowMilli  = 0;
    int64_t   peakMilli    = 0;
    int64_t   lastUpdateMs = 0;
    int64_t   firstHitMs   = 0;
    uint32_t  maxHalfLifeMs = 0;         // 只由 enabled 命中更新（dryrun 不得間接拖慢真實分數的衰減）
    uint32_t  shadowHalfLifeMs = 0;      // 含 dryrun 命中的最長半衰期，僅用於影子分數
    uint32_t  decaySerial  = 0;
    TreeState state        = TreeState::Benign;
    int64_t   stateChangedMs = 0;
    int64_t   alertId      = 0;          // 0 = 尚無告警
    // 每條規則最近一次「實際計分」的時點，供重複命中冷卻
    std::vector<std::pair<std::string, int64_t>> lastHitMs;

    [[nodiscard]] bool WithinCooldown(const std::string& ruleId, int64_t nowMs, int64_t cooldownMs) const noexcept;
    void MarkHit(const std::string& ruleId, int64_t nowMs);
};

class ScoreBoard {
public:
    ScoreBoard() = default;
    ScoreBoard(const ScoreBoard&) = delete;
    ScoreBoard& operator=(const ScoreBoard&) = delete;

    // 唯一比較分數與閾值的函式。
    [[nodiscard]] ScoreTransition ApplyDelta(const GuidValue& root, const RuleHit& hit);

    // 讀取時惰性衰減到 now（不改變 state，只推進分數）。不存在回 0。
    [[nodiscard]] int64_t CurrentScore(const GuidValue& root, int64_t nowMs);

    // 1 Hz：處理到期的衰減排程，回傳降級（Watched → Benign）或歸零的轉移。
    [[nodiscard]] std::vector<ScoreTransition> SweepDecay(int64_t nowMs);

    // 暫定樹被修補掛載：分數與狀態併入新根（SDD-02 §4.2.3 的 ★）。
    // 回傳合併後新根的轉移（合併可能使分數跨過閾值，呼叫端需比照 ApplyDelta 處理升級）。
    [[nodiscard]] std::optional<ScoreTransition> MergeRoot(const GuidValue& from, const GuidValue& to, int64_t nowMs);

    // 分析師判定 → Resolved（不再自動轉移）。
    [[nodiscard]] bool MarkResolved(const GuidValue& root, int64_t nowMs);
    [[nodiscard]] bool MarkExcluded(const GuidValue& root, int64_t nowMs);

    void SetAlertId(const GuidValue& root, int64_t alertId);
    void Erase(const GuidValue& root);

    [[nodiscard]] const TreeScore* Find(const GuidValue& root) const noexcept;
    [[nodiscard]] size_t Size() const noexcept { return m_scores.size(); }

private:
    struct DecayTicket {
        int64_t   dueMs = 0;
        GuidValue root{};
        uint32_t  serial = 0;
        bool operator>(const DecayTicket& o) const noexcept { return dueMs > o.dueMs; }
    };

    static TreeState EscalateOnly(TreeState cur, int64_t score) noexcept;
    void RescheduleDecay(TreeScore& ts);
    static void DecayTo(TreeScore& ts, int64_t nowMs) noexcept;

    std::unordered_map<GuidValue, TreeScore, model::GuidHash> m_scores;
    std::priority_queue<DecayTicket, std::vector<DecayTicket>, std::greater<>> m_decayHeap;
};

} // namespace cairn::score
