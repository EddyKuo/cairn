// src/core/rules/RuleEngine.h                 namespace cairn::rules
// Tier-1 / Tier-2 求值的門面（SDD-02 §5.1 RuleEngine）。只回傳命中，不計分、不做副作用。
// 執行緒：AnalysisThread 獨佔。RuleSet 以 shared_ptr<const> 原子換手。
#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "rules/Rule.h"
#include "rules/SequenceMatcher.h"

namespace cairn::rules {

struct EngineHit {
    uint32_t                ruleIndex = 0;
    const Rule*             rule = nullptr;     // 指向目前 RuleSet；僅在下一次 SetRuleSet 前有效
    model::GuidValue        key{};
    int64_t                 scoreMilli = 0;
    std::string             boosterId;          // 非空 = booster 加分
    std::vector<StepRecord> evidence;           // 主命中：每步一筆；booster：觸發事件一筆
    int64_t                 tsMs = 0;
};

struct RuleEngineStats {
    SequenceStats seq;
    size_t        activeSequences = 0;
    uint64_t      boosterHits     = 0;
    uint32_t      generation      = 0;
    size_t        rulesLoaded     = 0;
};

class RuleEngine {
public:
    // 熱重載：進行中的部分比對依 ContentHash 保留或丟棄（§5.6）。
    void SetRuleSet(std::shared_ptr<const RuleSet> rs);
    [[nodiscard]] const RuleSet* Rules() const noexcept { return m_set.get(); }
    [[nodiscard]] std::shared_ptr<const RuleSet> RuleSetPtr() const noexcept { return m_set; }

    // base.ev 為觸發事件；node 已更新。回傳完整命中（含 booster）。
    [[nodiscard]] std::vector<EngineHit> Evaluate(const EvalContext& base, int64_t eventId, int64_t tsMs);

    void   Rekey(const model::GuidValue& from, const model::GuidValue& to);
    size_t Expire(int64_t nowMs);
    [[nodiscard]] bool HasActiveFor(const model::GuidValue& key) const noexcept { return m_seq.HasActiveFor(key); }
    [[nodiscard]] RuleEngineStats Stats() const noexcept;

private:
    struct BoosterKey {
        uint32_t         rule = 0;
        model::GuidValue key{};
        uint32_t         booster = 0;
        bool operator==(const BoosterKey&) const noexcept = default;
    };
    struct BoosterKeyHash {
        size_t operator()(const BoosterKey& k) const noexcept
        {
            return k.key.Hash() ^ (static_cast<size_t>(k.rule) * 0x9E3779B97F4A7C15ull) ^ (static_cast<size_t>(k.booster) << 17);
        }
    };
    struct ActivityKey {
        uint32_t         rule = 0;
        model::GuidValue key{};
        bool operator==(const ActivityKey&) const noexcept = default;
    };
    struct ActivityKeyHash {
        size_t operator()(const ActivityKey& k) const noexcept { return k.key.Hash() ^ (static_cast<size_t>(k.rule) * 0x9E3779B97F4A7C15ull); }
    };
    struct PendingBooster {
        int64_t    tsMs = 0;
        StepRecord rec{};
    };

    [[nodiscard]] static model::GuidValue KeyFor(const Rule& r, const EvalContext& ctx) noexcept;
    void EmitBooster(const Rule& r, uint32_t ruleIdx, uint32_t boosterIdx, const model::GuidValue& key,
                     const StepRecord& rec, int64_t tsMs, std::vector<EngineHit>& out);

    std::shared_ptr<const RuleSet> m_set;
    SequenceMatcher                m_seq;
    std::unordered_map<ActivityKey, int64_t, ActivityKeyHash>       m_lastActivity;   // 主規則最近一次完整命中
    std::unordered_map<BoosterKey, int64_t, BoosterKeyHash>         m_boosterApplied;
    std::unordered_map<BoosterKey, PendingBooster, BoosterKeyHash>  m_boosterPending; // 早於主命中的 booster
    uint64_t m_boosterHits = 0;
};

} // namespace cairn::rules
