#include "rules/SequenceMatcher.h"

#include <algorithm>

namespace cairn::rules {

void SequenceMatcher::AddKeyRef(const model::GuidValue& k)
{
    ++m_keyRefs[k];
    ++m_activeTotal;
}

void SequenceMatcher::DropKeyRef(const model::GuidValue& k)
{
    if (auto it = m_keyRefs.find(k); it != m_keyRefs.end()) {
        if (--it->second == 0) m_keyRefs.erase(it);
    }
    if (m_activeTotal) --m_activeTotal;
}

bool SequenceMatcher::HasActiveFor(const model::GuidValue& key) const noexcept
{
    return m_keyRefs.count(key) != 0;
}

bool SequenceMatcher::ThresholdHit(const ThreshKey& tk, const ThresholdSpec& spec, const EvalContext& ctx,
                                   int64_t tsMs)
{
    SlidingCounter& c = m_counters[tk];
    c.withinMs = spec.withinMs;
    c.lastMs   = std::max(c.lastMs, tsMs);
    const int64_t cutoff = tsMs - spec.withinMs;   // 滾動視窗（非固定視窗，避免踩邊界規避）

    if (spec.distinctField) {
        while (!c.distinctStamps.empty() && c.distinctStamps.front().first < cutoff) {
            c.distinct.erase(c.distinctStamps.front().second);
            c.distinctStamps.pop_front();
        }
        const FieldValue v = ctx.Get(*spec.distinctField);
        const auto* s = std::get_if<std::string_view>(&v);
        if (!s) return false;   // 缺值不計
        std::string key = model::ToLowerAscii(*s);
        if (!c.distinct.count(key)) {
            if (c.distinct.size() >= kMaxDistinctPerCounter) {
                ++m_stats.distinctCapped;
            } else {
                c.distinct.insert(key);
                c.distinctStamps.emplace_back(tsMs, std::move(key));
            }
        } else {
            // 已存在：更新其時戳以維持滾動視窗語意
            for (auto& ds : c.distinctStamps)
                if (ds.second == key) ds.first = tsMs;
            std::stable_sort(c.distinctStamps.begin(), c.distinctStamps.end(),
                             [](const auto& a, const auto& b) { return a.first < b.first; });
        }
        if (c.distinct.size() >= spec.count) {
            m_counters.erase(tk);   // 成立後歸零：下一次命中需重新累積
            return true;
        }
        return false;
    }

    while (!c.stamps.empty() && c.stamps.front() < cutoff) c.stamps.pop_front();
    c.stamps.push_back(tsMs);
    if (c.stamps.size() >= spec.count) {
        m_counters.erase(tk);
        return true;
    }
    return false;
}

void SequenceMatcher::Process(const RuleSet& rs, uint32_t ruleIndex, const EvalContext& base,
                              const model::GuidValue& key, int64_t eventId, int64_t tsMs,
                              std::vector<CompletedMatch>& out)
{
    const Rule& r = rs.At(ruleIndex);
    const auto  type = static_cast<size_t>(base.ev.type);
    const SeqKey sk{ruleIndex, key};

    // ---- TryAdvance ----
    if (auto it = m_active.find(sk); it != m_active.end()) {
        auto& vec = it->second;
        for (size_t i = 0; i < vec.size();) {
            SequenceState& st = vec[i];
            if (tsMs > st.deadlineMs || st.nextStep >= r.steps.size()) {
                ++i;
                continue;
            }
            const Step& step = r.steps[st.nextStep];
            if (!step.types.test(type)) {   // 型別快速否決：零述詞求值
                ++i;
                continue;
            }
            EvalContext ctx{base};
            ctx.bindings = &st.bindings;
            if (!step.where->Evaluate(ctx)) {
                ++i;
                continue;
            }
            if (step.threshold &&
                !ThresholdHit(ThreshKey{ruleIndex, key, st.nextStep, st.serial}, *step.threshold, ctx, tsMs)) {
                ++i;
                continue;
            }
            st.matched[st.nextStep] = StepRecord{eventId, tsMs, base.ev.processGuid};
            for (FieldId f : step.exports) st.bindings.Set(st.nextStep, f, ctx.Get(f));
            ++st.nextStep;
            if (st.nextStep >= r.steps.size()) {
                CompletedMatch m;
                m.ruleIndex = ruleIndex;
                m.key       = key;
                m.tsMs      = tsMs;
                m.steps.assign(st.matched.begin(), st.matched.begin() + static_cast<std::ptrdiff_t>(r.steps.size()));
                out.push_back(std::move(m));
                vec.erase(vec.begin() + static_cast<std::ptrdiff_t>(i));   // heap 票留待自然到期（惰性刪除）
                DropKeyRef(key);
                continue;
            }
            ++i;
        }
        if (vec.empty()) m_active.erase(it);
    }

    // ---- TryStart ----
    const Step& s0 = r.steps[0];
    if (!s0.types.test(type)) return;
    EvalContext ctx{base};
    ctx.bindings = nullptr;
    if (!s0.where->Evaluate(ctx)) return;
    if (s0.threshold && !ThresholdHit(ThreshKey{ruleIndex, key, 0, 0}, *s0.threshold, ctx, tsMs)) return;

    if (r.steps.size() == 1) {   // Tier-1：單步即完整命中
        CompletedMatch m;
        m.ruleIndex = ruleIndex;
        m.key       = key;
        m.tsMs      = tsMs;
        m.steps.push_back(StepRecord{eventId, tsMs, base.ev.processGuid});
        out.push_back(std::move(m));
        return;
    }

    SequenceState st;
    st.nextStep   = 1;
    st.startedMs  = tsMs;
    st.deadlineMs = tsMs + r.withinMs;
    st.matched[0] = StepRecord{eventId, tsMs, base.ev.processGuid};
    for (FieldId f : s0.exports) st.bindings.Set(0, f, ctx.Get(f));

    auto& vec = m_active[sk];
    for (const auto& existing : vec) {
        if (existing.nextStep == 1 && existing.bindings == st.bindings && tsMs <= existing.deadlineMs) {
            if (vec.empty()) m_active.erase(sk);
            return;   // 相同綁定的步驟 0 已在等待中：不重複開比對（避免洪泛把有效狀態擠掉）
        }
    }
    if (m_activeTotal >= kMaxActiveSequences) {
        ++m_stats.rejected;
        if (vec.empty()) m_active.erase(sk);
        return;
    }
    if (vec.size() >= kMaxPartialPerKey) {
        vec.erase(vec.begin());   // 丟最舊（攻擊鏈通常是最近的）
        DropKeyRef(key);
        ++m_stats.evicted;
    }
    st.serial = m_nextSerial++;
    m_expiry.push(ExpiryTicket{st.deadlineMs, sk, st.serial});
    vec.push_back(std::move(st));
    AddKeyRef(key);
}

size_t SequenceMatcher::Expire(int64_t nowMs)
{
    size_t n = 0;
    while (!m_expiry.empty() && m_expiry.top().deadlineMs < nowMs) {
        const ExpiryTicket t = m_expiry.top();
        m_expiry.pop();
        auto it = m_active.find(t.key);
        if (it == m_active.end()) continue;
        auto& vec = it->second;
        auto sit  = std::find_if(vec.begin(), vec.end(), [&](const SequenceState& s) { return s.serial == t.serial; });
        if (sit == vec.end()) continue;
        // 綁定到此狀態的 threshold 計數一併清除
        for (uint8_t step = 1; step < kMaxSteps; ++step) m_counters.erase(ThreshKey{t.key.rule, t.key.key, step, t.serial});
        vec.erase(sit);
        DropKeyRef(t.key.key);
        ++n;
        if (vec.empty()) m_active.erase(it);
    }
    m_stats.expired += n;

    // 閒置的 threshold 計數器（步驟 0）：最後一次命中已超出視窗即移除
    for (auto it = m_counters.begin(); it != m_counters.end();) {
        if (nowMs - it->second.lastMs > it->second.withinMs) it = m_counters.erase(it);
        else ++it;
    }
    return n;
}

void SequenceMatcher::Rekey(const model::GuidValue& from, const model::GuidValue& to)
{
    if (from == to) return;
    std::vector<SeqKey> keys;
    for (const auto& [k, v] : m_active)
        if (k.key == from) keys.push_back(k);
    for (const auto& k : keys) {
        auto node = m_active.extract(k);
        SeqKey nk{k.rule, to};
        auto& dst = m_active[nk];
        for (auto& st : node.mapped()) {
            m_expiry.push(ExpiryTicket{st.deadlineMs, nk, st.serial});
            dst.push_back(std::move(st));
            DropKeyRef(from);
            AddKeyRef(to);
        }
        while (dst.size() > kMaxPartialPerKey) {
            dst.erase(dst.begin());
            DropKeyRef(to);
            ++m_stats.evicted;
        }
    }
    std::vector<ThreshKey> tks;
    for (const auto& [k, v] : m_counters)
        if (k.key == from) tks.push_back(k);
    for (const auto& k : tks) {
        auto node = m_counters.extract(k);
        ThreshKey nk = k;
        nk.key       = to;
        if (!m_counters.count(nk)) m_counters.emplace(nk, std::move(node.mapped()));
    }
}

void SequenceMatcher::Reconcile(const RuleSet& oldSet, const RuleSet& newSet)
{
    std::unordered_map<SeqKey, std::vector<SequenceState>, SeqKeyHash> next;
    size_t total = 0;
    m_keyRefs.clear();
    for (auto& [k, vec] : m_active) {
        const Rule& oldRule = oldSet.At(k.rule);
        const auto  nidx    = newSet.IndexOf(oldRule.id);
        if (!nidx) {
            m_stats.droppedRemoved += vec.size();
            continue;
        }
        const Rule& newRule = newSet.At(*nidx);
        if (newRule.contentHash != oldRule.contentHash || newRule.status == model::RuleStatus::Disabled) {
            m_stats.droppedChanged += vec.size();
            continue;
        }
        SeqKey nk{*nidx, k.key};
        for (auto& st : vec) {
            m_expiry.push(ExpiryTicket{st.deadlineMs, nk, st.serial});
            ++m_keyRefs[k.key];
            ++total;
        }
        auto& dst = next[nk];
        for (auto& st : vec) dst.push_back(std::move(st));
    }
    m_active      = std::move(next);
    m_activeTotal = total;
    m_counters.clear();   // threshold 計數不跨規則版本保留
}

} // namespace cairn::rules
