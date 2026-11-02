// src/core/rules/SequenceMatcher.h            namespace cairn::rules
// 有狀態 sequence 比對（SDD-02 §5.4）與 threshold 滾動視窗計數（§5.4.6）。
// 執行緒：AnalysisThread 獨佔。
#pragma once
#include <array>
#include <cstdint>
#include <deque>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rules/Bindings.h"
#include "rules/Rule.h"

namespace cairn::rules {

inline constexpr size_t kMaxPartialPerKey    = 8;
inline constexpr size_t kMaxActiveSequences  = 20'000;
inline constexpr size_t kMaxDistinctPerCounter = 4'096;

struct StepRecord {
    int64_t          eventId = 0;   // events.id（由 AnalysisThread 顯式指定）
    int64_t          tsMs    = 0;
    model::GuidValue actorGuid{};
};

struct CompletedMatch {
    uint32_t                ruleIndex = 0;
    model::GuidValue        key{};
    std::vector<StepRecord> steps;   // steps[i] = 第 i 步的命中事件
    int64_t                 tsMs = 0;
};

struct SequenceStats {
    uint64_t evicted          = 0;   // seq_state_evicted：同 (rule,key) 超過 8 個，丟最舊
    uint64_t rejected         = 0;   // seq_state_rejected：全域超過 20,000，拒絕新比對
    uint64_t expired          = 0;
    uint64_t droppedRemoved   = 0;   // 熱重載：規則已不存在
    uint64_t droppedChanged   = 0;   // 熱重載：規則內容改變
    uint64_t distinctCapped   = 0;   // threshold_distinct_capped
};

class SequenceMatcher {
public:
    // 對單一規則處理一個事件：先 TryAdvance 既有的部分比對，再 TryStart。完整命中附加到 out。
    void Process(const RuleSet& rs, uint32_t ruleIndex, const EvalContext& base, const model::GuidValue& key,
                 int64_t eventId, int64_t tsMs, std::vector<CompletedMatch>& out);

    // 刪除 deadline < nowMs 的部分比對（within 視窗含邊界：ts == deadline 仍可推進）。
    size_t Expire(int64_t nowMs);

    // 暫定樹改根：進行中的部分比對與 threshold 計數改鍵（SDD-02 §4.2.3 的 ★）。
    void Rekey(const model::GuidValue& from, const model::GuidValue& to);

    // 熱重載：ContentHash 相同者保留（更新索引），不同或已移除者丟棄（§5.6）。
    void Reconcile(const RuleSet& oldSet, const RuleSet& newSet);

    [[nodiscard]] bool   HasActiveFor(const model::GuidValue& key) const noexcept;
    [[nodiscard]] size_t ActiveCount() const noexcept { return m_activeTotal; }
    [[nodiscard]] const SequenceStats& Stats() const noexcept { return m_stats; }

private:
    struct SeqKey {
        uint32_t         rule = 0;
        model::GuidValue key{};
        bool operator==(const SeqKey&) const noexcept = default;
    };
    struct SeqKeyHash {
        size_t operator()(const SeqKey& k) const noexcept { return k.key.Hash() ^ (static_cast<size_t>(k.rule) * 0x9E3779B97F4A7C15ull); }
    };
    struct SequenceState {
        uint8_t     nextStep  = 1;
        int64_t     startedMs = 0;
        int64_t     deadlineMs = 0;
        uint32_t    serial    = 0;
        BindingSet  bindings;
        std::array<StepRecord, kMaxSteps> matched{};
    };
    struct ExpiryTicket {
        int64_t  deadlineMs = 0;
        SeqKey   key{};
        uint32_t serial = 0;
        bool operator>(const ExpiryTicket& o) const noexcept { return deadlineMs > o.deadlineMs; }
    };
    struct ThreshKey {
        uint32_t         rule = 0;
        model::GuidValue key{};
        uint8_t          step = 0;
        uint32_t         serial = 0;   // 步驟 0 為 0；其餘綁定到所屬部分比對
        bool operator==(const ThreshKey&) const noexcept = default;
    };
    struct ThreshKeyHash {
        size_t operator()(const ThreshKey& k) const noexcept
        {
            return k.key.Hash() ^ (static_cast<size_t>(k.rule) * 0x9E3779B97F4A7C15ull) ^
                   (static_cast<size_t>(k.step) << 7) ^ (static_cast<size_t>(k.serial) << 13);
        }
    };
    struct SlidingCounter {
        std::deque<int64_t>              stamps;
        std::unordered_set<std::string>  distinct;   // 小寫化；上限 4,096
        std::deque<std::pair<int64_t, std::string>> distinctStamps;
        int64_t                          lastMs = 0;
        int64_t                          withinMs = 0;
    };

    bool ThresholdHit(const ThreshKey& tk, const ThresholdSpec& spec, const EvalContext& ctx, int64_t tsMs);
    void AddKeyRef(const model::GuidValue& k);
    void DropKeyRef(const model::GuidValue& k);

    std::unordered_map<SeqKey, std::vector<SequenceState>, SeqKeyHash> m_active;
    std::priority_queue<ExpiryTicket, std::vector<ExpiryTicket>, std::greater<>> m_expiry;
    std::unordered_map<ThreshKey, SlidingCounter, ThreshKeyHash> m_counters;
    std::unordered_map<model::GuidValue, uint32_t, model::GuidHash> m_keyRefs;
    size_t        m_activeTotal = 0;
    uint32_t      m_nextSerial  = 1;
    SequenceStats m_stats;
};

} // namespace cairn::rules
