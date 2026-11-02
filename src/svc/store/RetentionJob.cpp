#include "store/RetentionJob.h"

#include <algorithm>
#include <string>

namespace cairn::store {

Result<int64_t> RetentionJob::DatabaseBytes(SqliteDb& db)
{
    CAIRN_TRY(auto pages, db.QueryInt64("PRAGMA page_count;"));
    CAIRN_TRY(auto size, db.QueryInt64("PRAGMA page_size;"));
    CAIRN_TRY(auto freel, db.QueryInt64("PRAGMA freelist_count;"));
    // 使用中的位元組（freelist 頁會被 incremental_vacuum 回收，不計入）
    return (pages.value_or(0) - freel.value_or(0)) * size.value_or(4096);
}

Result<int64_t> RetentionJob::DeleteBatch(SqliteDb& db, Phase p, int64_t nowMs)
{
    const int64_t cutEvents = nowMs - m_cfg.eventTtlMs;
    const int64_t cutAlerts = nowMs - m_cfg.alertTtlMs;
    const int64_t cutHealth = nowMs - m_cfg.healthTtlMs;

    Transaction tx{db};
    CAIRN_CHECK(tx.Begin());
    switch (p) {
    case Phase::Events: {
        CAIRN_TRY(auto st, db.Prepare(
                               "DELETE FROM events WHERE id IN ("
                               " SELECT id FROM events WHERE ts < ?1"
                               "   AND id NOT IN (SELECT event_id FROM alert_events)"
                               " ORDER BY ts LIMIT ?2);"));
        st.Bind(1, cutEvents).Bind(2, static_cast<int64_t>(m_cfg.eventBatch));
        CAIRN_CHECK(st.Run());
        break;
    }
    case Phase::Processes: {
        CAIRN_TRY(auto st, db.Prepare(
                               "DELETE FROM process_tree WHERE process_guid IN ("
                               " SELECT process_guid FROM process_tree WHERE start_ts < ?1 AND end_ts IS NOT NULL"
                               "   AND process_guid NOT IN (SELECT root_process_guid FROM alerts WHERE ts >= ?2)"
                               " ORDER BY start_ts LIMIT ?3);"));
        // 仍被 90 天內告警引用的樹根保留（否則 CASCADE 掉 scores 且告警詳情失去程序樹根）
        st.Bind(1, cutEvents).Bind(2, cutAlerts).Bind(3, static_cast<int64_t>(m_cfg.eventBatch));
        CAIRN_CHECK(st.Run());
        break;
    }
    case Phase::RuleHits: {
        CAIRN_TRY(auto st, db.Prepare("DELETE FROM rule_hits WHERE id IN ("
                                      " SELECT id FROM rule_hits WHERE ts < ?1 ORDER BY ts LIMIT ?2);"));
        st.Bind(1, cutAlerts).Bind(2, static_cast<int64_t>(m_cfg.eventBatch));
        CAIRN_CHECK(st.Run());
        break;
    }
    case Phase::Alerts: {
        CAIRN_TRY(auto st, db.Prepare("DELETE FROM alerts WHERE id IN ("
                                      " SELECT id FROM alerts WHERE ts < ?1 ORDER BY ts LIMIT ?2);"));
        st.Bind(1, cutAlerts).Bind(2, static_cast<int64_t>(m_cfg.alertBatch));
        CAIRN_CHECK(st.Run());
        break;
    }
    case Phase::Health: {
        CAIRN_TRY(auto st, db.Prepare("DELETE FROM agent_health WHERE id IN ("
                                      " SELECT id FROM agent_health WHERE ts < ?1 ORDER BY ts LIMIT ?2);"));
        st.Bind(1, cutHealth).Bind(2, static_cast<int64_t>(m_cfg.eventBatch));
        CAIRN_CHECK(st.Run());
        break;
    }
    case Phase::HardCap: {
        if (m_hardCapRemaining <= 0) return int64_t{0};
        const int64_t n = std::min<int64_t>(m_hardCapRemaining, m_cfg.eventBatch);
        CAIRN_TRY(auto st, db.Prepare(
                               "DELETE FROM events WHERE id IN ("
                               " SELECT id FROM events WHERE id NOT IN (SELECT event_id FROM alert_events)"
                               " ORDER BY id LIMIT ?1);"));
        st.Bind(1, n);
        CAIRN_CHECK(st.Run());
        const int64_t changed = db.Changes();
        CAIRN_CHECK(tx.Commit());
        m_hardCapRemaining = changed == 0 ? 0 : m_hardCapRemaining - changed;
        return changed;
    }
    default:
        return int64_t{0};
    }
    const int64_t changed = db.Changes();
    CAIRN_CHECK(tx.Commit());
    return changed;
}

Result<RetentionStats> RetentionJob::Step(SqliteDb& db, int64_t nowMs)
{
    if (m_phase == Phase::Idle) {
        if (nowMs - m_lastRunMs < m_cfg.intervalMs) {
            RetentionStats idle;
            idle.completed = true;
            return idle;
        }
        m_lastRunMs  = nowMs;
        m_cycleNowMs = nowMs;
        m_cycle      = RetentionStats{};
        CAIRN_TRY(m_cycle.dbBytesBefore, DatabaseBytes(db));
        m_phase = Phase::Events;
    }

    int batches = 0;
    while (m_phase != Phase::Idle && batches < m_cfg.maxBatchesPerStep) {
        if (m_phase == Phase::Vacuum) {
            // 回收自由頁面（auto_vacuum=INCREMENTAL 的前提，見 SqliteDb::Open）
            CAIRN_CHECK(db.Exec("PRAGMA incremental_vacuum(" + std::to_string(m_cfg.vacuumPages) + ");"));
            CAIRN_TRY(m_cycle.dbBytesAfter, DatabaseBytes(db));
            m_cycle.completed = true;
            m_phase = Phase::Idle;
            break;
        }
        if (m_phase == Phase::HardCap && m_hardCapRemaining == 0) {
            // 進入硬上限階段時才量測：前面的正常保留期刪除可能已經讓大小回到上限內
            CAIRN_TRY(const int64_t bytes, DatabaseBytes(db));
            if (bytes > m_cfg.maxDbBytes) {
                CAIRN_TRY(auto total, db.QueryInt64("SELECT COUNT(*) FROM events;"));
                m_hardCapRemaining = std::max<int64_t>(1, total.value_or(0) / 10);   // 最舊 10%
            } else {
                m_phase = Phase::Vacuum;
                continue;
            }
        }

        CAIRN_TRY(const int64_t n, DeleteBatch(db, m_phase, m_cycleNowMs));
        ++batches;
        switch (m_phase) {
        case Phase::Events: m_cycle.events += n; break;
        case Phase::Processes: m_cycle.processes += n; break;
        case Phase::RuleHits: m_cycle.ruleHits += n; break;
        case Phase::Alerts: m_cycle.alerts += n; break;
        case Phase::Health: m_cycle.health += n; break;
        case Phase::HardCap: m_cycle.hardCapEvents += n; break;
        default: break;
        }
        const int64_t batchSize = (m_phase == Phase::Alerts) ? m_cfg.alertBatch : m_cfg.eventBatch;
        const bool phaseDone = (m_phase == Phase::HardCap) ? (m_hardCapRemaining <= 0 || n == 0) : (n < batchSize);
        if (phaseDone) {
            switch (m_phase) {
            case Phase::Events: m_phase = Phase::Processes; break;
            case Phase::Processes: m_phase = Phase::RuleHits; break;
            case Phase::RuleHits: m_phase = Phase::Alerts; break;
            case Phase::Alerts: m_phase = Phase::Health; break;
            case Phase::Health: m_phase = Phase::HardCap; break;
            case Phase::HardCap: m_hardCapRemaining = 0; m_phase = Phase::Vacuum; break;
            default: m_phase = Phase::Idle; break;
            }
        }
    }

    RetentionStats out = m_cycle;
    out.completed = (m_phase == Phase::Idle);
    return out;
}

} // namespace cairn::store
