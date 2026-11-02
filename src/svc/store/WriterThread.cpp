#include "store/WriterThread.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <variant>

#include "store/WriteDao.h"

namespace cairn::store {

using model::WriteOp;

namespace {

int64_t SteadyNowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool IsFatalForBatch(ErrorCode c) noexcept
{
    // 這些錯誤代表交易本身無法繼續（不是單列的約束錯誤）
    return c == ErrorCode::DbBusy || c == ErrorCode::DbCorrupt || c == ErrorCode::DbDiskFull ||
           c == ErrorCode::IoError || c == ErrorCode::DbOpenFailed;
}

void Complete(const WriteOp& op, Result<int64_t> r)
{
    if (op.onDone) op.onDone(std::move(r));
}

std::filesystem::path Sibling(const std::filesystem::path& db, const char* name)
{
    return db.parent_path() / name;
}

} // namespace

WriterThread::WriterThread(WriterConfig cfg, const model::StringInterner& interner, const IClock& clock)
    : m_cfg(std::move(cfg)),
      m_interner(interner),
      m_clock(clock),
      m_queue(m_cfg.queueCapacity),
      m_spill(m_cfg.spillDir.empty() ? Sibling(m_cfg.dbPath, "spill") : m_cfg.spillDir),
      m_retention(m_cfg.retention)
{
    if (m_cfg.markerPath.empty()) m_cfg.markerPath = Sibling(m_cfg.dbPath, "clean_shutdown.marker");
    m_batch.reserve(m_cfg.batchMaxRows);
}

Result<std::unique_ptr<WriterThread>> WriterThread::Create(WriterConfig cfg, const model::StringInterner& interner,
                                                           const IClock& clock)
{
    if (cfg.dbPath.empty()) return MakeError(ErrorCode::InvalidArgument, "WriterThread: empty dbPath");
    std::error_code ec;
    std::filesystem::create_directories(cfg.dbPath.parent_path(), ec);

    auto self = std::unique_ptr<WriterThread>(new WriterThread(std::move(cfg), interner, clock));

    // 1) 非正常結束判定：DB 已存在但沒有 clean marker
    const bool dbExisted = std::filesystem::exists(self->m_cfg.dbPath, ec);
    const bool hadMarker = std::filesystem::exists(self->m_cfg.markerPath, ec);
    self->m_uncleanStart = dbExisted && !hadMarker;
    std::filesystem::remove(self->m_cfg.markerPath, ec);   // 執行中不存在 marker；崩潰後下次即可偵測

    // 2) 開庫；損毀則更名保留並重建（失去歷史事件優於失去防護）
    if (Status st = self->OpenDatabase(); !st) {
        if (st.GetError().code == ErrorCode::DbCorrupt) {
            CAIRN_CHECK(self->RebuildCorruptDatabase(st.GetError().context));
        } else {
            return st.GetError();
        }
    }

    // 3) 崩潰路徑：quick_check（不是 integrity_check —— 4 GB 庫要數分鐘）
    if (self->m_uncleanStart) {
        auto ok = self->m_db->QuickCheck();
        if (!ok || !ok.Value()) {
            CAIRN_CHECK(self->RebuildCorruptDatabase("quick_check failed after unclean shutdown"));
        }
        model::AuditRow a;
        a.ts     = clock.NowMs();
        a.actor  = "system";
        a.action = "unclean_start";
        a.paramsJson = R"({"event_kind":"service_started","detail":"previous run did not shut down cleanly"})";
        a.result = "ok";
        (void)self->DirectAudit(a);
    }
    {
        std::lock_guard lk{self->m_statsMutex};
        self->m_stats.uncleanStart = self->m_uncleanStart;
        self->m_stats.autoVacuumOk = self->m_db->Info().autoVacuumOk;
    }

    // 4) 補入上次遺留的 spill（alerts / audit 不可遺失）
    self->ReplaySpill();
    return self;
}

WriterThread::~WriterThread()
{
    Stop();
}

Status WriterThread::OpenDatabase()
{
    m_chain.reset();
    m_db.reset();
    CAIRN_TRY(auto db, SqliteDb::Open(m_cfg.dbPath, ConnRole::Writer));
    m_db    = std::move(db);
    m_chain = std::make_unique<AuditChain>(*m_db);
    return m_chain->Load();
}

Status WriterThread::RebuildCorruptDatabase(std::string_view reason)
{
    m_chain.reset();
    m_db.reset();   // 先關閉連線才能更名

    const int64_t ts = m_clock.NowMs();
    std::error_code ec;
    const auto base = m_cfg.dbPath;
    const std::string stem = "cairn.corrupt." + std::to_string(ts);
    for (const char* suffix : {"", "-wal", "-shm"}) {
        auto from = base;
        from += suffix;
        if (!std::filesystem::exists(from, ec)) continue;
        auto to = base.parent_path() / (stem + ".db" + suffix);
        std::filesystem::rename(from, to, ec);
    }
    CAIRN_CHECK(OpenDatabase());
    {
        std::lock_guard lk{m_statsMutex};
        m_stats.dbRebuilt = true;
    }
    model::AuditRow a;
    a.ts         = ts;
    a.actor      = "system";
    a.action     = "db_rebuilt";
    a.target     = stem + ".db";
    a.paramsJson = R"({"event_kind":"service_started"})";
    a.error      = std::string(reason.substr(0, 500));   // 原因放 error 欄（自由文字），不拼進 JSON 以免跳脫問題
    a.result     = "ok";
    return DirectAudit(a);
}

Status WriterThread::DirectAudit(const model::AuditRow& row)
{
    if (!m_db || !m_chain) return MakeError(ErrorCode::NotInitialized, "db closed");
    (void)m_db->SetDurability(Durability::Safe);
    Transaction tx{*m_db};
    Status st = tx.Begin();
    if (st) {
        auto id = m_chain->Append(row);
        st = id ? tx.Commit() : Status{id.GetError()};
    }
    if (!st) {
        tx.Rollback();
        (void)m_chain->Reload();
    }
    (void)m_db->SetDurability(Durability::Fast);
    return st;
}

bool WriterThread::Post(WriteOp&& op)
{
    const bool urgent = op.IsUrgent();
    const bool ok = urgent ? m_queue.PostUrgent(std::move(op)) : m_queue.Post(std::move(op));
    if (!ok && !urgent) {
        std::lock_guard lk{m_statsMutex};
        ++m_stats.queueDropped;
    }
    return ok;
}

Status WriterThread::Start()
{
    if (m_thread.joinable()) return MakeError(ErrorCode::AlreadyExists, "WriterThread already started");
    if (m_stopped.load()) return MakeError(ErrorCode::Cancelled, "WriterThread stopped");
    m_thread = std::jthread([this](std::stop_token st) { ThreadMain(st); });
    return Ok();
}

void WriterThread::Stop() noexcept
{
    if (m_stopped.exchange(true)) return;
    m_queue.Close();   // 拒收新項目；已在佇列者照常排空
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_thread.join();
    } else {
        // 從未啟動：仍把已投遞的項目寫完（例如啟動失敗前排入的稽核）
        while (auto op = m_queue.TryPop()) {
            if (op->IsUrgent()) WriteUrgent(std::move(*op));
            else AddToBatch(std::move(*op));
        }
        FlushBatch();
    }
    if (m_db) {
        (void)m_db->Checkpoint(/*truncate*/ true);   // WAL 併回主檔並清空，下次啟動不需重播
        std::ofstream marker(m_cfg.markerPath, std::ios::trunc);
        marker << m_clock.NowMs();
    }
    m_chain.reset();
    m_db.reset();
}

void WriterThread::ThreadMain(std::stop_token st)
{
    for (;;) {
        // 等待時間：有待寫批次時等到批次逾齡為止，否則 200 ms（順便讓 retention 有機會跑）
        int64_t waitMs = m_cfg.batchMaxAgeMs;
        if (!m_batch.empty()) waitMs = std::max<int64_t>(1, m_cfg.batchMaxAgeMs - (SteadyNowMs() - m_batchFirstMs));

        auto op = m_queue.PopFor(std::chrono::milliseconds(waitMs), st);
        if (op) {
            if (op->IsUrgent()) {
                WriteUrgent(std::move(*op));
            } else {
                AddToBatch(std::move(*op));
                // 不等待地多取一些，湊滿批次（Urgent 由佇列保證優先取出）
                while (m_batch.size() < m_cfg.batchMaxRows) {
                    auto more = m_queue.TryPop();
                    if (!more) break;
                    if (more->IsUrgent()) {
                        WriteUrgent(std::move(*more));
                        continue;
                    }
                    AddToBatch(std::move(*more));
                }
            }
        }

        const bool aged = !m_batch.empty() && SteadyNowMs() - m_batchFirstMs >= m_cfg.batchMaxAgeMs;
        if (m_batch.size() >= m_cfg.batchMaxRows || aged) FlushBatch();

        const size_t depth = m_queue.Size();
        if (!op && m_batch.empty() && depth == 0 && st.stop_requested()) break;   // 已排空
        // Retention：未到期時 Step 立即返回；到期後每次最多跑 maxBatchesPerStep 批即讓出，
        // 穩態負載下佇列不會整整 200 ms 都是空的，因此不能只在閒置時才跑。
        if (m_batch.empty() && !st.stop_requested()) RunRetention();
        {
            std::lock_guard lk{m_statsMutex};
            m_stats.queueDepth = depth;
        }
    }
    FlushBatch();
}

void WriterThread::AddToBatch(WriteOp&& op)
{
    if (m_batch.empty()) m_batchFirstMs = SteadyNowMs();
    m_batch.push_back(std::move(op));
}

Status WriterThread::ApplyOne(const WriteOp& op, int64_t& newId)
{
    newId = 0;
    return std::visit(
        [&](const auto& p) -> Status {
            using T = std::decay_t<decltype(p)>;
            if constexpr (std::is_same_v<T, model::EventRow>) return InsertEvent(*m_db, m_interner, p);
            else if constexpr (std::is_same_v<T, model::ProcessRow>) return UpsertProcess(*m_db, p);
            else if constexpr (std::is_same_v<T, model::ProcessEndUpdate>) return UpdateProcessEnd(*m_db, p);
            else if constexpr (std::is_same_v<T, model::ProcessTerminatedByUs>) return MarkTerminatedByUs(*m_db, p);
            else if constexpr (std::is_same_v<T, model::ScoreRow>) return UpsertScore(*m_db, p);
            else if constexpr (std::is_same_v<T, model::RuleHitRow>) return InsertRuleHit(*m_db, p);
            else if constexpr (std::is_same_v<T, model::AlertNarrativeUpdate>) return UpdateNarrative(*m_db, p);
            else if constexpr (std::is_same_v<T, model::AlertActionAppend>) return AppendAlertAction(*m_db, p);
            else if constexpr (std::is_same_v<T, model::ExclusionHitIncrement>) return IncrementExclusionHits(*m_db, p);
            else if constexpr (std::is_same_v<T, model::HealthRow>) return InsertHealth(*m_db, p);
            else if constexpr (std::is_same_v<T, model::AlertRow>) {
                auto r = InsertAlert(*m_db, p);
                if (!r) return r.GetError();
                newId = r.Value();
                return Ok();
            } else if constexpr (std::is_same_v<T, model::AuditRow>) {
                auto r = m_chain->Append(p);
                if (!r) return r.GetError();
                newId = r.Value();
                return Ok();
            } else if constexpr (std::is_same_v<T, model::AlertVerdictUpdate>) {
                return UpdateVerdict(*m_db, p);
            } else if constexpr (std::is_same_v<T, model::ExclusionInsert>) {
                auto r = InsertExclusion(*m_db, p);
                if (!r) return r.GetError();
                newId = r.Value();
                return Ok();
            } else if constexpr (std::is_same_v<T, model::ExclusionRemove>) {
                return RemoveExclusion(*m_db, p);
            } else if constexpr (std::is_same_v<T, model::ExclusionSetEnabled>) {
                return SetExclusionEnabled(*m_db, p);
            } else if constexpr (std::is_same_v<T, model::SuggestionDismiss>) {
                return DismissSuggestion(*m_db, p);
            } else {
                static_assert(sizeof(T) == 0, "WriteOp payload 未處理");
            }
        },
        op.payload);
}

// FK 寫入順序：events → process_tree → scores → rule_hits → 其他。以穩定排序達成，不改變同類項目的相對順序。
static int OrderKey(const WriteOp& op)
{
    switch (op.payload.index()) {
    case 0: return 0;   // EventRow
    case 1: return 1;   // ProcessRow
    case 2: return 2;   // ProcessEndUpdate
    case 3: return 2;   // ProcessTerminatedByUs
    case 4: return 3;   // ScoreRow
    case 5: return 4;   // RuleHitRow
    default: return 5;
    }
}

Status WriterThread::ApplyBatchOnce()
{
    Transaction tx{*m_db};
    CAIRN_CHECK(tx.Begin());
    uint64_t rowErrors = 0;
    for (const auto& op : m_batch) {
        int64_t id = 0;
        Status st = ApplyOne(op, id);
        if (!st) {
            if (IsFatalForBatch(st.GetError().code)) return st;   // 解構時 ROLLBACK
            ++rowErrors;                                          // 單筆失敗不中斷整批
        }
    }
    CAIRN_CHECK(tx.Commit());
    std::lock_guard lk{m_statsMutex};
    m_stats.writeErrors += rowErrors;
    return Ok();
}

void WriterThread::FlushBatch()
{
    if (m_batch.empty() || !m_db) return;
    std::stable_sort(m_batch.begin(), m_batch.end(),
                     [](const WriteOp& a, const WriteOp& b) { return OrderKey(a) < OrderKey(b); });

    const int64_t t0 = SteadyNowMs();
    Status st = Ok();
    int    backoff = 5;
    for (int attempt = 0; attempt < m_cfg.busyRetries; ++attempt) {
        st = ApplyBatchOnce();
        if (st) break;
        const ErrorCode c = st.GetError().code;
        if (c == ErrorCode::DbCorrupt) {
            if (!RebuildCorruptDatabase(st.GetError().context)) break;
            continue;   // 在新庫上重試這一批
        }
        if (c != ErrorCode::DbBusy) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff));   // 5 → 10 → 20 → 40 → 80 ms
        backoff *= 2;
    }
    const double ms = static_cast<double>(SteadyNowMs() - t0);

    {
        std::lock_guard lk{m_statsMutex};
        m_stats.lastFlushMs = ms;
        m_stats.maxFlushMs  = std::max(m_stats.maxFlushMs, ms);
        if (st) {
            m_stats.rowsWritten += m_batch.size();
            ++m_stats.batchesFlushed;
        } else {
            // 刻意的選擇：無限重試會讓佇列爆掉並拖垮整個管線。丟一批 events 的代價遠低於整個 agent 失去回應。
            ++m_stats.busyGiveups;
            m_stats.rowsDroppedOnFailure += m_batch.size();
            m_stats.degraded = true;
        }
    }
    for (const auto& op : m_batch) Complete(op, st ? Result<int64_t>{int64_t{0}} : Result<int64_t>{st.GetError()});
    m_batch.clear();
}

Result<int64_t> WriterThread::ApplyUrgentOnce(const WriteOp& op)
{
    (void)m_db->SetDurability(Durability::Safe);
    Transaction tx{*m_db};
    Status st = tx.Begin();
    int64_t id = 0;
    if (st) st = ApplyOne(op, id);
    if (st) st = tx.Commit();
    if (!st) {
        tx.Rollback();
        if (std::holds_alternative<model::AuditRow>(op.payload)) (void)m_chain->Reload();   // 鏈尾回到 DB 真實狀態
    }
    (void)m_db->SetDurability(Durability::Fast);
    if (!st) return st.GetError();
    (void)m_db->Checkpoint(/*truncate*/ false);   // 告警盡快落到主 DB（PASSIVE，不阻塞讀者）
    return id;
}

void WriterThread::WriteUrgent(WriteOp&& op)
{
    // ★ Urgent 項目會插隊到一般項目之前；但告警的 alert_events / rule_hits 參照的事件
    //   是「同一個 AnalysisThread 稍早以一般項目投遞」的 EventRow —— 它們可能還在佇列裡。
    //   因此寫告警前先把當下佇列中的一般項目全部收進批次並 flush，其餘 Urgent 依序延後處理，
    //   否則告警的證據連結會因 FK（WHERE EXISTS）全部落空，時間軸變成空的。
    //   反過來，「參照此告警」的一般項目（敘事回填、actions_taken 附加、帶 alert_id 的命中）
    //   必須在告警「之後」才寫，否則 UPDATE 命中 0 列、alert_id 子查詢落為 NULL —— 這些先暫存。
    std::vector<WriteOp> deferred;
    std::vector<WriteOp> afterAlert;
    if (std::holds_alternative<model::AlertRow>(op.payload)) {
        const size_t pending = m_queue.Size();
        for (size_t i = 0; i < pending; ++i) {
            auto x = m_queue.TryPop();
            if (!x) break;
            if (x->IsUrgent()) {
                deferred.push_back(std::move(*x));
                continue;
            }
            const auto* hit = std::get_if<model::RuleHitRow>(&x->payload);
            const bool refersAlert = std::holds_alternative<model::AlertNarrativeUpdate>(x->payload) ||
                                     std::holds_alternative<model::AlertActionAppend>(x->payload) ||
                                     (hit && hit->alertId.has_value());
            if (refersAlert) afterAlert.push_back(std::move(*x));
            else AddToBatch(std::move(*x));
        }
    }
    FlushBatch();
    WriteUrgentNow(std::move(op));
    for (auto& a : afterAlert) AddToBatch(std::move(a));   // 照常隨下一批寫入（告警已落地）
    for (auto& d : deferred) {
        FlushBatch();
        WriteUrgentNow(std::move(d));
    }
}

void WriterThread::WriteUrgentNow(WriteOp&& op)
{
    if (!m_db) {
        SpillIfPossible(op);
        Complete(op, MakeError(ErrorCode::DbOpenFailed, "db unavailable"));
        return;
    }

    Result<int64_t> r = MakeError(ErrorCode::DbBusy, "not attempted");
    int backoff = 5;
    for (int attempt = 0; attempt < m_cfg.busyRetries; ++attempt) {
        r = ApplyUrgentOnce(op);
        if (r) break;
        const ErrorCode c = r.GetError().code;
        if (c == ErrorCode::DbCorrupt) {
            if (!RebuildCorruptDatabase(r.GetError().context)) break;
            continue;
        }
        if (c != ErrorCode::DbBusy) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
        backoff *= 2;
    }
    if (!r) {
        const ErrorCode c = r.GetError().code;
        // 業務錯誤（NotFound / 約束衝突）不是 DB 失效，不需 spill
        if (IsFatalForBatch(c)) {
            SpillIfPossible(op);
            std::lock_guard lk{m_statsMutex};
            m_stats.degraded = true;
        }
    } else {
        std::lock_guard lk{m_statsMutex};
        ++m_stats.rowsWritten;
    }
    const bool ok = static_cast<bool>(r);
    Complete(op, std::move(r));
    if (ok && m_spill.HasPending()) ReplaySpill();   // DB 恢復 → 補入先前的 spill
}

void WriterThread::SpillIfPossible(const WriteOp& op)
{
    std::optional<SpillRecord> rec;
    if (const auto* a = std::get_if<model::AlertRow>(&op.payload)) rec = SpillRecord{*a};
    else if (const auto* b = std::get_if<model::AuditRow>(&op.payload)) rec = SpillRecord{*b};
    if (!rec) return;
    if (m_spill.Append(*rec)) {
        std::lock_guard lk{m_statsMutex};
        ++m_stats.spilledRecords;
    }
}

void WriterThread::ReplaySpill()
{
    if (!m_db || !m_spill.HasPending()) return;
    auto r = m_spill.Replay([this](const SpillRecord& rec) -> bool {
        WriteOp op;
        if (const auto* a = std::get_if<model::AlertRow>(&rec)) op.payload = *a;
        else op.payload = std::get<model::AuditRow>(rec);
        return static_cast<bool>(ApplyUrgentOnce(op));
    });
    (void)r;
}

void WriterThread::RunRetention()
{
    if (!m_db) return;
    auto r = m_retention.Step(*m_db, m_clock.NowMs());
    if (!r) {
        if (r.GetError().code == ErrorCode::DbCorrupt) (void)RebuildCorruptDatabase(r.GetError().context);
        return;
    }
    const RetentionStats& s = r.Value();
    if (s.completed && s.hardCapEvents > 0) {
        // 硬上限觸發：不得靜默丟棄 —— 寫入稽核，UI 由 health / audit 呈現
        model::AuditRow a;
        a.ts     = m_clock.NowMs();
        a.actor  = "system";
        a.action = "db_hard_cap";
        a.paramsJson = R"({"event_kind":"retention","deleted_events":)" + std::to_string(s.hardCapEvents) +
                       R"(,"db_bytes_before":)" + std::to_string(s.dbBytesBefore) + "}";
        a.result = "ok";
        WriteOp op;
        op.payload = std::move(a);
        (void)ApplyUrgentOnce(op);
        std::lock_guard lk{m_statsMutex};
        m_stats.lastRetentionHardCapEvents = s.hardCapEvents;
    }
}

WriterStats WriterThread::Stats() const
{
    std::lock_guard lk{m_statsMutex};
    WriterStats s = m_stats;
    s.queueDepth  = m_queue.Size();
    return s;
}

} // namespace cairn::store
