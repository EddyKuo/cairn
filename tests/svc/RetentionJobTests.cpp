// tests/svc/RetentionJobTests.cpp
// 保留期與硬上限（part2 §2.3.2 第 7 節、SDD-02 §6.6）。臨時檔 DB。
// 三個實作陷阱各有一個測試：子查詢式分批、不刪被告警引用的事件、不刪仍在執行的程序。
#include <gtest/gtest.h>

#include "store/RetentionJob.h"
#include "store/SqliteDb.h"
#include "store/WriteDao.h"
#include "StoreTestUtil.h"

using namespace cairn;
using namespace cairn::store;
using namespace cairn::testutil;

namespace {

constexpr int64_t kDay = 86'400'000;
constexpr int64_t kNow = 1'787'000'000'000;

std::unique_ptr<SqliteDb> OpenWriter(const TempDir& d)
{
    auto db = SqliteDb::Open(d.Db(), ConnRole::Writer);
    EXPECT_TRUE(db) << (db ? "" : db.GetError().ToString());
    return std::move(db).Value();
}

int64_t Count(SqliteDb& db, const std::string& sql) { return db.QueryInt64(sql).Value().value_or(-1); }

// 跑到本輪完成（測試用：Step 為可中斷的分段執行）
RetentionStats RunToCompletion(RetentionJob& job, SqliteDb& db, int64_t now)
{
    job.ForceDue();
    RetentionStats s;
    for (int i = 0; i < 1000; ++i) {
        auto r = job.Step(db, now);
        EXPECT_TRUE(r) << (r ? "" : r.GetError().ToString());
        s = r.Value();
        if (s.completed) break;
    }
    return s;
}

} // namespace

TEST(RetentionJob, DeletesOldEventsButKeepsAlertEvidence)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    model::StringInterner in;
    Transaction tx{*db};
    ASSERT_TRUE(tx.Begin());
    for (int i = 1; i <= 100; ++i) ASSERT_TRUE(InsertEvent(*db, in, MakeEventRow(in, i, kNow - 10 * kDay + i, 1, 1)));
    for (int i = 101; i <= 110; ++i) ASSERT_TRUE(InsertEvent(*db, in, MakeEventRow(in, i, kNow - 1 * kDay, 1, 1)));
    model::AlertRow a;
    a.id = 1;
    a.ts = kNow - 10 * kDay;
    a.rootProcessGuid = MakeGuid(1);
    a.title = "t";
    a.events = {{5, 0, "trigger"}, {6, 1, "evidence"}};
    ASSERT_TRUE(InsertAlert(*db, a));
    ASSERT_TRUE(tx.Commit());

    RetentionConfig cfg;
    cfg.eventBatch = 7;   // 強迫多批次（驗證子查詢式分批的迴圈）
    RetentionJob job{cfg};
    const auto s = RunToCompletion(job, *db, kNow);
    EXPECT_TRUE(s.completed);
    EXPECT_EQ(s.events, 98);                                              // 100 筆舊事件 − 2 筆被告警引用
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM events;"), 12);           // 10 筆新 + 2 筆證據
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM alert_events;"), 2);      // 時間軸未被 CASCADE 清空
}

TEST(RetentionJob, KeepsRunningProcessesAndAlertedRoots)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    auto oldStart = kNow - 10 * kDay;
    model::ProcessRow running = MakeProcessRow(1, 0, 1, oldStart);                 // 仍在執行（end_ts NULL）
    model::ProcessRow ended   = MakeProcessRow(2, 0, 2, oldStart);
    ended.endTs = oldStart + 1000;
    model::ProcessRow alerted = MakeProcessRow(3, 0, 3, oldStart);                 // 已結束但為 30 天內告警的樹根
    alerted.endTs = oldStart + 1000;
    ASSERT_TRUE(UpsertProcess(*db, running));
    ASSERT_TRUE(UpsertProcess(*db, ended));
    ASSERT_TRUE(UpsertProcess(*db, alerted));
    model::ScoreRow sc;
    sc.rootProcessGuid = MakeGuid(1);
    sc.lastUpdateTs = sc.firstHitTs = oldStart;
    ASSERT_TRUE(UpsertScore(*db, sc));
    model::AlertRow a;
    a.id = 1;
    a.ts = kNow - 20 * kDay;
    a.rootProcessGuid = MakeGuid(3);
    a.title = "t";
    ASSERT_TRUE(InsertAlert(*db, a));

    RetentionJob job;
    RunToCompletion(job, *db, kNow);
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM process_tree;"), 2);                 // 只刪 ended
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM scores;"), 1);                       // 未被 CASCADE 刪除
}

TEST(RetentionJob, AlertsAndHitsFollow90DaysAndAuditIsNeverDeleted)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    for (int i = 1; i <= 3; ++i) {
        model::AlertRow a;
        a.id = i;
        a.ts = i == 1 ? kNow - 91 * kDay : kNow - 10 * kDay;
        a.rootProcessGuid = MakeGuid(static_cast<uint32_t>(i));
        a.title = "t";
        ASSERT_TRUE(InsertAlert(*db, a));
        model::RuleHitRow h;
        h.ts = a.ts;
        h.ruleId = "R-T1059-001";
        h.rootProcessGuid = a.rootProcessGuid;
        h.alertId = i;
        h.ruleHash = "x";
        ASSERT_TRUE(InsertRuleHit(*db, h));
    }
    ASSERT_TRUE(db->Exec("INSERT INTO audit_log(ts,actor,action,result,prev_hash,row_hash) VALUES(1,'system','x','ok','0','0');"));
    RetentionJob job;
    const auto s = RunToCompletion(job, *db, kNow);
    EXPECT_EQ(s.alerts, 1);
    EXPECT_EQ(s.ruleHits, 1);
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM alerts;"), 2);
    EXPECT_EQ(Count(*db, "SELECT COUNT(*) FROM audit_log;"), 1);   // 雜湊鏈不可斷
}

TEST(RetentionJob, NotDueDoesNothing)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    RetentionJob job;
    auto first = job.Step(*db, kNow);   // 首次必定到期
    ASSERT_TRUE(first);
    auto again = job.Step(*db, kNow + 1000);
    ASSERT_TRUE(again);
    if (first.Value().completed) {
        EXPECT_TRUE(again.Value().completed);
        EXPECT_EQ(again.Value().events, 0);
        EXPECT_FALSE(job.Pending());
    }
}

TEST(RetentionJob, HardCapDeletesOldestTenPercentOfUnreferencedEvents)
{
    TempDir dir;
    auto db = OpenWriter(dir);
    model::StringInterner in;
    Transaction tx{*db};
    ASSERT_TRUE(tx.Begin());
    for (int i = 1; i <= 1000; ++i) ASSERT_TRUE(InsertEvent(*db, in, MakeEventRow(in, i, kNow - 1000 + i, 1, 1)));
    ASSERT_TRUE(tx.Commit());

    RetentionConfig cfg;
    cfg.maxDbBytes = 1;   // 必然超過
    RetentionJob job{cfg};
    const auto s = RunToCompletion(job, *db, kNow);
    EXPECT_EQ(s.hardCapEvents, 100);
    EXPECT_EQ(Count(*db, "SELECT MIN(id) FROM events;"), 101);   // 刪最舊者
}
