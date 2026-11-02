#include "rules/RuleEngine.h"

#include <type_traits>

#include "tree/ProcessTree.h"

namespace cairn::rules {

void RuleEngine::SetRuleSet(std::shared_ptr<const RuleSet> rs)
{
    if (!rs) return;
    if (m_set) m_seq.Reconcile(*m_set, *rs);
    m_set = std::move(rs);
    // booster 狀態以規則索引為鍵；規則集換手後直接清空（最壞情況是少加一次 booster 分）
    m_lastActivity.clear();
    m_boosterApplied.clear();
    m_boosterPending.clear();
}

model::GuidValue RuleEngine::KeyFor(const Rule& r, const EvalContext& ctx) noexcept
{
    if (r.correlateBy == CorrelateBy::ProcessGuid) return ctx.ev.processGuid;
    if (ctx.node) return ctx.node->rootGuid;
    return ctx.ev.processGuid;
}

void RuleEngine::EmitBooster(const Rule& r, uint32_t ruleIdx, uint32_t boosterIdx, const model::GuidValue& key,
                             const StepRecord& rec, int64_t tsMs, std::vector<EngineHit>& out)
{
    const BoosterKey bk{ruleIdx, key, boosterIdx};
    // 同一個 booster 每個視窗只加一次（否則勒索的檔案事件會讓分數瞬間爆表）
    if (auto it = m_boosterApplied.find(bk); it != m_boosterApplied.end() && tsMs - it->second <= r.withinMs) return;
    m_boosterApplied[bk] = tsMs;
    EngineHit h;
    h.ruleIndex  = ruleIdx;
    h.rule       = &r;
    h.key        = key;
    h.scoreMilli = r.boosters[boosterIdx].scoreMilli;
    h.boosterId  = r.boosters[boosterIdx].id;
    h.evidence.push_back(rec);
    h.tsMs = tsMs;
    out.push_back(std::move(h));
    ++m_boosterHits;
}

std::vector<EngineHit> RuleEngine::Evaluate(const EvalContext& base, int64_t eventId, int64_t tsMs)
{
    std::vector<EngineHit> out;
    if (!m_set) return out;
    const RuleSet& rs = *m_set;
    const auto type = static_cast<size_t>(base.ev.type);
    const StepRecord rec{eventId, tsMs, base.ev.processGuid};

    std::vector<CompletedMatch> matches;
    for (uint32_t idx : rs.RulesFor(base.ev.type)) {
        const Rule& r = rs.At(idx);
        const model::GuidValue key = KeyFor(r, base);
        if (key.IsNull()) continue;

        // ---- 主規則（Tier-1 / Tier-2）----
        bool stepTyped = false;
        for (const auto& st : r.steps)
            if (st.types.test(type)) stepTyped = true;
        if (stepTyped) {
            matches.clear();
            m_seq.Process(rs, idx, base, key, eventId, tsMs, matches);
            for (auto& m : matches) {
                EngineHit h;
                h.ruleIndex  = idx;
                h.rule       = &r;
                h.key        = m.key;
                h.scoreMilli = r.scoreMilli;
                h.evidence   = std::move(m.steps);
                h.tsMs       = tsMs;
                out.push_back(std::move(h));
                m_lastActivity[ActivityKey{idx, key}] = tsMs;

                // 早於主命中、仍在視窗內的 booster 一併生效
                for (uint32_t b = 0; b < r.boosters.size(); ++b) {
                    auto pit = m_boosterPending.find(BoosterKey{idx, key, b});
                    if (pit == m_boosterPending.end()) continue;
                    if (tsMs - pit->second.tsMs <= r.withinMs) EmitBooster(r, idx, b, key, pit->second.rec, tsMs, out);
                    m_boosterPending.erase(pit);
                }
            }
        }

        // ---- boosters ----
        for (uint32_t b = 0; b < r.boosters.size(); ++b) {
            const Booster& bo = r.boosters[b];
            if (!bo.types.test(type)) continue;
            EvalContext ctx{base};
            ctx.bindings = nullptr;
            if (!bo.where->Evaluate(ctx)) continue;
            auto act = m_lastActivity.find(ActivityKey{idx, key});
            if (act != m_lastActivity.end() && tsMs - act->second <= r.withinMs) {
                EmitBooster(r, idx, b, key, rec, tsMs, out);
            } else {
                m_boosterPending[BoosterKey{idx, key, b}] = PendingBooster{tsMs, rec};
            }
        }
    }
    return out;
}

void RuleEngine::Rekey(const model::GuidValue& from, const model::GuidValue& to)
{
    m_seq.Rekey(from, to);
    auto moveKeys = [&](auto& map) {
        using MapT = std::decay_t<decltype(map)>;
        std::vector<typename MapT::key_type> keys;
        for (const auto& [k, v] : map)
            if (k.key == from) keys.push_back(k);
        for (const auto& k : keys) {
            auto node = map.extract(k);
            auto nk   = k;
            nk.key    = to;
            if (!map.count(nk)) map.emplace(nk, std::move(node.mapped()));
        }
    };
    moveKeys(m_lastActivity);
    moveKeys(m_boosterApplied);
    moveKeys(m_boosterPending);
}

size_t RuleEngine::Expire(int64_t nowMs)
{
    const size_t n = m_seq.Expire(nowMs);
    constexpr int64_t kMaxWindowMs = 600'000;   // within 上限
    auto prune = [&](auto& map, auto tsOf) {
        for (auto it = map.begin(); it != map.end();) {
            if (nowMs - tsOf(it->second) > kMaxWindowMs) it = map.erase(it);
            else ++it;
        }
    };
    prune(m_lastActivity, [](int64_t v) { return v; });
    prune(m_boosterApplied, [](int64_t v) { return v; });
    prune(m_boosterPending, [](const PendingBooster& p) { return p.tsMs; });
    return n;
}

RuleEngineStats RuleEngine::Stats() const noexcept
{
    RuleEngineStats s;
    s.seq             = m_seq.Stats();
    s.activeSequences = m_seq.ActiveCount();
    s.boosterHits     = m_boosterHits;
    s.generation      = m_set ? m_set->Generation() : 0;
    s.rulesLoaded     = m_set ? m_set->Size() : 0;
    return s;
}

} // namespace cairn::rules
