// src/svc/store/WriterThread.h                namespace cairn::store
// T4：唯一持有 SQLite 寫入連線者（part2 §2.3.3「單一 writer 原則」、SDD-02 §6.2–6.4）。
// 實作 model::IWriteSink：T3/T5/T6/T7/T8 一律以 Post(WriteOp) 投遞，絕不自行開寫入連線。
//
// 佇列：BlockingQueue<WriteOp>，容量 100,000（最壞 5,000 ev/s × 20 秒緩衝，SDD-02 §6.4）。
//   - 一般項目：滿則 Post 回 false（呼叫端計入 events_dropped）
//   - Urgent（alerts / audit / verdict / exclusions）：不受容量限制、優先取出、以 Safe 交易
//     （synchronous=FULL）立即提交並 PASSIVE checkpoint
// 批次：1000 筆或 200 ms 先到者 flush，一次 flush = 一個 BEGIN IMMEDIATE 交易。
// 錯誤路徑：
//   - SQLITE_BUSY：指數退避 5 → 10 → 20 → 40 → 80 ms，5 次皆失敗則丟棄該批（不無限重試），
//     含 alerts / audit 者改寫 spill JSONL，DB 恢復後補入
//   - SQLITE_CORRUPT：關閉連線、cairn.db(-wal/-shm) 更名為 cairn.corrupt.{ts}.*、重建空庫、寫 audit db_rebuilt
// 崩潰復原（SDD-02 §6.7.2）：啟動時檢查 clean_shutdown.marker；不存在 = 上次崩潰 →
//   quick_check、補入 spill、寫 audit unclean_start。正常停止：flush → checkpoint(TRUNCATE) → 寫 marker。
// Retention 在本執行緒內、佇列空檔時分段執行（RetentionJob::Step）。
//
// ★ 可攜程式碼（std::jthread + sqlite3）。
#pragma once
#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stop_token>
#include <thread>
#include <vector>

#include "base/BlockingQueue.h"
#include "base/IClock.h"
#include "base/Result.h"
#include "model/StringInterner.h"
#include "model/WriteOp.h"
#include "store/AuditChain.h"
#include "store/RetentionJob.h"
#include "store/SpillFile.h"
#include "store/SqliteDb.h"

namespace cairn::store {

struct WriterConfig {
    std::filesystem::path dbPath;            // %ProgramData%\Cairn\cairn.db
    std::filesystem::path spillDir;          // 空 = dbPath 同目錄下的 spill 子目錄
    std::filesystem::path markerPath;        // 空 = dbPath 同目錄下的 clean_shutdown.marker
    size_t  queueCapacity  = 100'000;
    size_t  batchMaxRows   = 1'000;
    int64_t batchMaxAgeMs  = 200;
    int     busyRetries    = 5;
    RetentionConfig retention{};
};

struct WriterStats {
    uint64_t rowsWritten     = 0;
    uint64_t batchesFlushed  = 0;
    uint64_t writeErrors     = 0;   // 單列失敗（不中斷整批）
    uint64_t busyGiveups     = 0;   // 5 次退避仍 BUSY 而丟棄的批次數
    uint64_t rowsDroppedOnFailure = 0;
    uint64_t spilledRecords  = 0;
    uint64_t queueDropped    = 0;   // Post 時佇列滿被拒的一般項目
    size_t   queueDepth      = 0;
    double   lastFlushMs     = 0;
    double   maxFlushMs      = 0;
    bool     degraded        = false;   // 近期發生過放棄寫入 → agent_health 應標 degraded
    bool     dbRebuilt       = false;
    bool     uncleanStart    = false;
    bool     autoVacuumOk    = true;
    int64_t  lastRetentionHardCapEvents = 0;
};

class WriterThread final : public model::IWriteSink {
public:
    // 開庫（Writer 連線 + schema）、載入稽核鏈、判定是否非正常結束、補入 spill。
    // 未啟動執行緒前即可 Post（項目會在 Start 後處理）。
    [[nodiscard]] static Result<std::unique_ptr<WriterThread>> Create(WriterConfig cfg,
                                                                      const model::StringInterner& interner,
                                                                      const IClock& clock);
    ~WriterThread() override;
    WriterThread(const WriterThread&) = delete;
    WriterThread& operator=(const WriterThread&) = delete;

    [[nodiscard]] bool Post(model::WriteOp&& op) override;

    [[nodiscard]] Status Start();
    // 優雅停止（關機階段 4）：拒收新項目 → 排空佇列 → COMMIT → wal_checkpoint(TRUNCATE) → 寫 clean marker → 關閉。
    void Stop() noexcept;

    [[nodiscard]] WriterStats Stats() const;
    [[nodiscard]] bool UncleanStart() const noexcept { return m_uncleanStart; }

private:
    WriterThread(WriterConfig cfg, const model::StringInterner& interner, const IClock& clock);

    [[nodiscard]] Status OpenDatabase();
    [[nodiscard]] Status RebuildCorruptDatabase(std::string_view reason);
    void ThreadMain(std::stop_token st);

    // 一般批次
    void AddToBatch(model::WriteOp&& op);
    void FlushBatch();
    [[nodiscard]] Status ApplyBatchOnce();
    [[nodiscard]] Status ApplyOne(const model::WriteOp& op, int64_t& newId);

    // Urgent
    void WriteUrgent(model::WriteOp&& op);
    void WriteUrgentNow(model::WriteOp&& op);
    [[nodiscard]] Result<int64_t> ApplyUrgentOnce(const model::WriteOp& op);
    void SpillIfPossible(const model::WriteOp& op);
    void ReplaySpill();

    void RunRetention();
    [[nodiscard]] Status DirectAudit(const model::AuditRow& row);   // 執行緒外（Create / 重建）使用

    WriterConfig                         m_cfg;
    const model::StringInterner&         m_interner;
    const IClock&                        m_clock;
    BlockingQueue<model::WriteOp>        m_queue;
    std::unique_ptr<SqliteDb>            m_db;
    std::unique_ptr<AuditChain>          m_chain;
    SpillFile                            m_spill;
    RetentionJob                         m_retention;
    std::vector<model::WriteOp>          m_batch;
    int64_t                              m_batchFirstMs = 0;
    std::jthread                         m_thread;
    bool                                 m_uncleanStart = false;
    std::atomic<bool>                    m_stopped{false};

    mutable std::mutex                   m_statsMutex;
    WriterStats                          m_stats;
};

} // namespace cairn::store
