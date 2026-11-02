// src/svc/store/RetentionJob.h                namespace cairn::store
// 保留期與資料庫大小控制（part2 §2.3.1 / §2.3.2 第 7 節、SDD-02 §6.6）。
// 在 WriterThread 內執行（借用同一條寫連線，避免第二個寫者）。
//
// 三個實作陷阱（SDD-02 §6.6）：
//   ① DELETE ... LIMIT 需非預設編譯選項 → 一律 `WHERE id IN (SELECT id ... ORDER BY ... LIMIT n)`
//   ② events 不可刪掉被 alert_events 引用者（否則 CASCADE 清空 90 天內的告警時間軸）
//   ③ process_tree 用 start_ts 且必須 end_ts IS NOT NULL（否則刪掉仍在執行的程序並 CASCADE 其 scores）
// audit_log 永不刪除（雜湊鏈不可斷；DB 層亦有 append-only 觸發器）。
//
// 分批且可中斷：每次 Step() 最多跑 kMaxBatchesPerStep 批（每批一個交易），未完成則回報 pending，
// WriterThread 在處理完佇列中的寫入後再呼叫 —— 長 DELETE 不會把寫入佇列卡住數十秒。
//
// ★ 可攜程式碼。
#pragma once
#include <cstdint>

#include "base/Result.h"
#include "store/SqliteDb.h"

namespace cairn::store {

struct RetentionConfig {
    int64_t intervalMs     = 3'600'000;          // 每小時
    int64_t eventTtlMs     = 7LL * 86'400'000;   // events / process_tree：7 天
    int64_t alertTtlMs     = 90LL * 86'400'000;  // alerts / rule_hits：90 天
    int64_t healthTtlMs    = 30LL * 86'400'000;  // agent_health：30 天
    int64_t maxDbBytes     = 4096LL * 1024 * 1024;   // max_db_size_mb = 4096
    int     eventBatch     = 50'000;
    int     alertBatch     = 5'000;
    int     vacuumPages    = 1'000;
    int     maxBatchesPerStep = 4;               // 單次 Step 的工作上限（約 1–2 秒）
};

struct RetentionStats {
    int64_t events = 0, processes = 0, ruleHits = 0, alerts = 0, health = 0;
    int64_t hardCapEvents = 0;   // 硬上限強制刪除的事件數（> 0 時 WriterThread 須寫 audit 並在 UI 告知）
    int64_t dbBytesBefore = 0, dbBytesAfter = 0;
    bool    completed = false;   // 本輪是否已全部完成
};

class RetentionJob {
public:
    explicit RetentionJob(RetentionConfig cfg = {}) noexcept : m_cfg(cfg) {}

    // 到期（或上一輪未完成）才做事。回傳本次 Step 的統計；無事可做時 stats.completed = true 且全 0。
    [[nodiscard]] Result<RetentionStats> Step(SqliteDb& db, int64_t nowMs);

    [[nodiscard]] bool Pending() const noexcept { return m_phase != Phase::Idle; }
    // 測試用：強制下一次 Step 立即執行一輪
    void ForceDue() noexcept { m_lastRunMs = INT64_MIN / 2; }

    [[nodiscard]] static Result<int64_t> DatabaseBytes(SqliteDb& db);

private:
    enum class Phase : uint8_t { Idle, Events, Processes, RuleHits, Alerts, Health, HardCap, Vacuum };

    // 執行一批：回傳刪除列數（0 = 該階段完成）
    [[nodiscard]] Result<int64_t> DeleteBatch(SqliteDb& db, Phase p, int64_t nowMs);

    RetentionConfig m_cfg;
    Phase           m_phase     = Phase::Idle;
    int64_t         m_lastRunMs = INT64_MIN / 2;
    int64_t         m_cycleNowMs = 0;            // 本輪的基準時間（跨多次 Step 不變）
    RetentionStats  m_cycle;                     // 本輪累計
    int64_t         m_hardCapRemaining = 0;
};

} // namespace cairn::store
