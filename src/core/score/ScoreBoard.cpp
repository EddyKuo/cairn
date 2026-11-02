#include "score/ScoreBoard.h"

#include <algorithm>

namespace cairn::score {

bool TreeScore::WithinCooldown(const std::string& ruleId, int64_t nowMs, int64_t cooldownMs) const noexcept
{
    for (const auto& [id, ts] : lastHitMs)
        if (id == ruleId) return nowMs - ts < cooldownMs;
    return false;
}

void TreeScore::MarkHit(const std::string& ruleId, int64_t nowMs)
{
    for (auto& [id, ts] : lastHitMs) {
        if (id == ruleId) {
            ts = nowMs;
            return;
        }
    }
    lastHitMs.emplace_back(ruleId, nowMs);
}

TreeState ScoreBoard::EscalateOnly(TreeState cur, int64_t score) noexcept
{
    const TreeState want = score >= kThresholdBlocked   ? TreeState::Blocked
                           : score >= kThresholdAlerted ? TreeState::Alerted
                           : score >= kThresholdWatched ? TreeState::Watched
                                                        : TreeState::Benign;
    return std::max(cur, want);
}

void ScoreBoard::DecayTo(TreeScore& ts, int64_t nowMs) noexcept
{
    const int64_t dt = nowMs - ts.lastUpdateMs;
    if (dt <= 0) return;
    if (ts.scoreMilli > 0 && ts.maxHalfLifeMs > 0) ts.scoreMilli = DecayMilli(ts.scoreMilli, dt, ts.maxHalfLifeMs);
    if (ts.shadowMilli > 0 && ts.shadowHalfLifeMs > 0)
        ts.shadowMilli = DecayMilli(ts.shadowMilli, dt, ts.shadowHalfLifeMs);
    // 影子分數恆 >= 真實分數（衰減半衰期不同時以此不變量修正）
    ts.shadowMilli  = std::max(ts.shadowMilli, ts.scoreMilli);
    ts.lastUpdateMs = nowMs;
}

ScoreTransition ScoreBoard::ApplyDelta(const GuidValue& root, const RuleHit& hit)
{
    auto [it, inserted] = m_scores.try_emplace(root);
    TreeScore& ts = it->second;
    if (inserted) {
        ts.root         = root;
        ts.lastUpdateMs = hit.tsMs;
        ts.firstHitMs   = hit.tsMs;
        ts.stateChangedMs = hit.tsMs;
    }

    // 1) 先把既有分數衰減到「現在」
    DecayTo(ts, hit.tsMs);

    ScoreTransition tr{};
    tr.root    = root;
    tr.from    = ts.state;
    tr.to      = ts.state;
    tr.trigger = hit;

    auto fill = [&] {
        tr.scoreMilli  = ts.scoreMilli;
        tr.peakMilli   = ts.peakMilli;
        tr.shadowMilli = ts.shadowMilli;
    };

    // 2) 排除命中：記錄但不加分、不轉移
    if (hit.suppressed) {
        fill();
        return tr;
    }

    // 2b) 重複命中冷卻：max(halfLife/4, 5s) 內的再次完整命中 delta 視為 0（照常寫 rule_hits）
    const int64_t cooldown = std::max<int64_t>(static_cast<int64_t>(hit.halfLifeMs) / 4, 5'000);
    if (ts.WithinCooldown(hit.ruleId, hit.tsMs, cooldown)) {
        tr.cooledDown = true;
        fill();
        return tr;
    }
    ts.MarkHit(hit.ruleId, hit.tsMs);

    // 3) ★ dryrun 命中只進 shadow，絕不進 score（CONVENTIONS C-9 shadow_score 語意）
    ts.shadowMilli      = std::min(ts.shadowMilli + hit.deltaMilli, kScoreMax);
    ts.shadowHalfLifeMs = std::max(ts.shadowHalfLifeMs, hit.halfLifeMs);
    if (hit.dryRun) {
        RescheduleDecay(ts);
        fill();
        return tr;
    }

    const int64_t before = ts.scoreMilli;
    if (hit.deterministic) {
        ts.scoreMilli = std::max(ts.scoreMilli, kThresholdBlocked);   // max：避免把 98,000 覆寫成 95,000
    } else {
        ts.scoreMilli = std::min(ts.scoreMilli + hit.deltaMilli, kScoreMax);
    }
    tr.appliedDeltaMilli = ts.scoreMilli - before;
    ts.shadowMilli       = std::max(ts.shadowMilli, ts.scoreMilli);
    ts.maxHalfLifeMs     = std::max(ts.maxHalfLifeMs, hit.halfLifeMs);

    // 4) peak 只增不減
    ts.peakMilli = std::max(ts.peakMilli, ts.scoreMilli);

    // 5) 狀態轉移（只升不降；Resolved / Excluded 不再自動轉移）
    if (ts.state != TreeState::Resolved && ts.state != TreeState::Excluded) {
        const TreeState next = EscalateOnly(ts.state, ts.scoreMilli);
        if (next != ts.state) {
            ts.state          = next;
            ts.stateChangedMs = hit.tsMs;
        }
    }

    // 6) 重排衰減堆積
    RescheduleDecay(ts);

    tr.to = ts.state;
    fill();
    return tr;
}

int64_t ScoreBoard::CurrentScore(const GuidValue& root, int64_t nowMs)
{
    auto it = m_scores.find(root);
    if (it == m_scores.end()) return 0;
    DecayTo(it->second, nowMs);
    return it->second.scoreMilli;
}

void ScoreBoard::RescheduleDecay(TreeScore& ts)
{
    ++ts.decaySerial;
    int64_t due = 0;
    if (ts.state == TreeState::Watched && ts.maxHalfLifeMs > 0) {
        // 降級需衰減到 threshold - 5 以下（遲滯）
        due = ts.lastUpdateMs + MsUntilBelow(ts.scoreMilli, kThresholdWatched - kHysteresisMilli, ts.maxHalfLifeMs);
    } else if (ts.state == TreeState::Benign) {
        // 何時真實分數與影子分數都歸零 → 移出 scores 表
        const int64_t a = ts.maxHalfLifeMs > 0 ? MsUntilBelow(ts.scoreMilli, 1, ts.maxHalfLifeMs) : 0;
        const int64_t b = ts.shadowHalfLifeMs > 0 ? MsUntilBelow(ts.shadowMilli, 1, ts.shadowHalfLifeMs) : 0;
        due = ts.lastUpdateMs + std::max(a, b);
    } else {
        return;   // Alerted 以上永不自動降級；Resolved/Excluded 由 Reaper 處理
    }
    m_decayHeap.push(DecayTicket{due, ts.root, ts.decaySerial});
}

std::vector<ScoreTransition> ScoreBoard::SweepDecay(int64_t nowMs)
{
    std::vector<ScoreTransition> out;
    while (!m_decayHeap.empty() && m_decayHeap.top().dueMs <= nowMs) {
        const DecayTicket t = m_decayHeap.top();
        m_decayHeap.pop();
        auto it = m_scores.find(t.root);
        if (it == m_scores.end()) continue;
        TreeScore& ts = it->second;
        if (ts.decaySerial != t.serial) continue;   // 惰性刪除：失效票

        DecayTo(ts, nowMs);

        ScoreTransition tr{};
        tr.root = ts.root;
        tr.from = ts.state;
        tr.to   = ts.state;

        if (ts.state == TreeState::Watched && ts.scoreMilli < kThresholdWatched - kHysteresisMilli) {
            ts.state          = TreeState::Benign;
            ts.stateChangedMs = nowMs;
            tr.to             = TreeState::Benign;
        }

        if (ts.state == TreeState::Benign && ts.scoreMilli == 0 && ts.shadowMilli == 0) {
            tr.erased = true;
            tr.scoreMilli = 0;
            tr.peakMilli  = ts.peakMilli;
            out.push_back(tr);
            m_scores.erase(it);
            continue;
        }

        tr.scoreMilli  = ts.scoreMilli;
        tr.peakMilli   = ts.peakMilli;
        tr.shadowMilli = ts.shadowMilli;
        RescheduleDecay(ts);
        if (tr.from != tr.to) out.push_back(tr);
    }
    return out;
}

std::optional<ScoreTransition> ScoreBoard::MergeRoot(const GuidValue& from, const GuidValue& to, int64_t nowMs)
{
    if (from == to) return std::nullopt;
    auto fit = m_scores.find(from);
    if (fit == m_scores.end()) return std::nullopt;

    TreeScore src = std::move(fit->second);
    m_scores.erase(fit);
    DecayTo(src, nowMs);

    auto [tit, inserted] = m_scores.try_emplace(to);
    TreeScore& dst = tit->second;
    ScoreTransition tr{};
    tr.root = to;

    if (inserted) {
        dst      = std::move(src);
        dst.root = to;
        tr.from  = TreeState::Benign;
        tr.to    = dst.state;
    } else {
        DecayTo(dst, nowMs);
        tr.from              = dst.state;
        dst.scoreMilli       = std::min(dst.scoreMilli + src.scoreMilli, kScoreMax);
        dst.shadowMilli      = std::min(dst.shadowMilli + src.shadowMilli, kScoreMax);
        dst.shadowMilli      = std::max(dst.shadowMilli, dst.scoreMilli);
        dst.peakMilli        = std::max({dst.peakMilli, src.peakMilli, dst.scoreMilli});
        dst.maxHalfLifeMs    = std::max(dst.maxHalfLifeMs, src.maxHalfLifeMs);
        dst.shadowHalfLifeMs = std::max(dst.shadowHalfLifeMs, src.shadowHalfLifeMs);
        dst.firstHitMs       = std::min(dst.firstHitMs, src.firstHitMs);
        if (dst.alertId == 0) dst.alertId = src.alertId;
        for (const auto& [rid, ms] : src.lastHitMs) {
            bool found = false;
            for (auto& [did, dms] : dst.lastHitMs) {
                if (did == rid) {
                    dms   = std::max(dms, ms);
                    found = true;
                    break;
                }
            }
            if (!found) dst.lastHitMs.emplace_back(rid, ms);
        }
        // 兩邊有任一已是終態（Resolved/Excluded）時保留目的端狀態，不自動轉移
        if (dst.state != TreeState::Resolved && dst.state != TreeState::Excluded) {
            TreeState merged = dst.state;
            if (src.state != TreeState::Resolved && src.state != TreeState::Excluded)
                merged = std::max(merged, src.state);
            dst.state = EscalateOnly(merged, dst.scoreMilli);
        }
        tr.to = dst.state;
    }
    if (tr.to != tr.from) dst.stateChangedMs = nowMs;
    RescheduleDecay(dst);
    tr.scoreMilli  = dst.scoreMilli;
    tr.peakMilli   = dst.peakMilli;
    tr.shadowMilli = dst.shadowMilli;
    return tr;
}

bool ScoreBoard::MarkResolved(const GuidValue& root, int64_t nowMs)
{
    auto it = m_scores.find(root);
    if (it == m_scores.end()) return false;
    DecayTo(it->second, nowMs);
    it->second.state          = TreeState::Resolved;
    it->second.stateChangedMs = nowMs;
    ++it->second.decaySerial;   // 作廢既有衰減票
    return true;
}

bool ScoreBoard::MarkExcluded(const GuidValue& root, int64_t nowMs)
{
    auto it = m_scores.find(root);
    if (it == m_scores.end()) return false;
    DecayTo(it->second, nowMs);
    it->second.state          = TreeState::Excluded;
    it->second.stateChangedMs = nowMs;
    ++it->second.decaySerial;
    return true;
}

void ScoreBoard::SetAlertId(const GuidValue& root, int64_t alertId)
{
    if (auto it = m_scores.find(root); it != m_scores.end()) it->second.alertId = alertId;
}

void ScoreBoard::Erase(const GuidValue& root)
{
    m_scores.erase(root);
}

const TreeScore* ScoreBoard::Find(const GuidValue& root) const noexcept
{
    auto it = m_scores.find(root);
    return it == m_scores.end() ? nullptr : &it->second;
}

} // namespace cairn::score
