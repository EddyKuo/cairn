// tests/svc/SqliteBatchWriterTests.cpp
// WriterThread（T4）+ ReadOnlyDb 的往返測試。臨時檔 DB，不需管理員、不需 Sysmon。
// 對應 SDD-02 §6.8 必測項：T-09（auto_vacuum 建表前生效）、T-10（背壓）、T-11 的寫入面。
#include <gtest/gtest.h>

#include <atomic>
#include <future>
#include <optional>

#include "base/IClock.h"
#include "store/ReadOnlyDb.h"
#include "store/SqliteDb.h"
#include "store/WriterThread.h"
#include "StoreTestUtil.h"

using namespace cairn;
using namespace cairn::store;
using namespace cairn::testutil;

namespace {

struct Fixture {
    TempDir               dir;
    model::StringInterner interner;
    FakeClock             clock{1'787'000'000'000};

    std::unique_ptr<WriterThread> MakeWriter(size_t capacity = 100'000)
    {
        WriterConfig cfg;
        cfg.dbPath        = dir.Db();
        cfg.queueCapacity = capacity;
        auto w = WriterThread::Create(cfg, interner, clock);
        EXPECT_TRUE(w) << (w ? "" : w.GetError().ToString());
        return w ? std::move(w).Value() : nullptr;
    }
    std::unique_ptr<ReadOnlyDb> Reader()
    {
        auto r = ReadOnlyDb::Open(dir.Db());
        EXPECT_TRUE(r) << (r ? "" : r.GetError().ToString());
        return r ? std::move(r).Value() : nullptr;
    }
};

} // namespace

TEST(SqliteSchema, AutoVacuumIsIncrementalBeforeTablesAreCreated)   // T-09
{
    TempDir dir;
    auto db = SqliteDb::Open(dir.Db(), ConnRole::Writer);
    ASSERT_TRUE(db) << db.GetError().ToString();
    EXPECT_TRUE(db.Value()->Info().created);
    EXPECT_TRUE(db.Value()->Info().autoVacuumOk);
    EXPECT_EQ(db.Value()->QueryInt64("PRAGMA auto_vacuum;").Value().value_or(-1), 2);
    EXPECT_EQ(db.Value()->QueryInt64("PRAGMA user_version;").Value().value_or(-1), kSchemaVersion);
    EXPECT_EQ(db.Value()->QueryInt64("PRAGMA foreign_keys;").Value().value_or(-1), 1);
    for (const char* t : {"events", "process_tree", "scores", "alerts", "exclusions", "rule_hits", "alert_events",
                          "audit_log", "agent_health", "dismissed_suggestions"}) {
        auto n = db.Value()->QueryInt64(std::string("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='") + t + "';");
        EXPECT_EQ(n.Value().value_or(0), 1) << t;
    }
}

TEST(SqliteSchema, ReopenIsIdempotentAndRefusesNewerSchema)
{
    TempDir dir;
    {
        auto db = SqliteDb::Open(dir.Db(), ConnRole::Writer);
        ASSERT_TRUE(db);
    }
    {
        auto db = SqliteDb::Open(dir.Db(), ConnRole::Writer);
        ASSERT_TRUE(db);
        EXPECT_FALSE(db.Value()->Info().created);
        ASSERT_TRUE(db.Value()->Exec("PRAGMA user_version = 99;"));
    }
    auto db = SqliteDb::Open(dir.Db(), ConnRole::Writer);
    ASSERT_FALSE(db);   // 防止舊版服務破壞新版資料（SDD-03 §10.4）
    EXPECT_EQ(db.GetError().code, ErrorCode::MigrationFailed);
}

TEST(SqliteSchema, ReaderIsReadOnly)
{
    TempDir dir;
    { ASSERT_TRUE(SqliteDb::Open(dir.Db(), ConnRole::Writer)); }
    auto r = SqliteDb::Open(dir.Db(), ConnRole::Reader);
    ASSERT_TRUE(r);
    EXPECT_FALSE(r.Value()->Exec("DELETE FROM events;"));
}

TEST(WriterThread, BatchedEventsLandAndAreQueryable)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w);
    ASSERT_TRUE(w->Start());
    constexpr int kN = 2500;   // 跨 3 個批次（1000 筆/批）
    ASSERT_TRUE(w->Post(Op(MakeProcessRow(1, 0, 1, f.clock.NowMs()))));
    for (int i = 1; i <= kN; ++i) ASSERT_TRUE(w->Post(Op(MakeEventRow(f.interner, i, f.clock.NowMs() + i, 1, 1))));
    w->Stop();

    auto r = f.Reader();
    ASSERT_TRUE(r);
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM events;").Value().value_or(0), kN);
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM events WHERE event_type='PROCESS_CREATE';").Value().value_or(0), kN);
    // interned 欄位以字串落地
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM events WHERE image='c:\\windows\\system32\\cmd.exe';").Value().value_or(0), kN);

    const auto stats = w->Stats();
    EXPECT_GE(stats.batchesFlushed, 3u);
    EXPECT_EQ(stats.busyGiveups, 0u);

    auto ids = r->QueryMaxIds();
    ASSERT_TRUE(ids);
    EXPECT_EQ(ids.Value().nextEventId, kN + 1);
}

TEST(WriterThread, ScoreWithoutProcessRowCreatesPlaceholderInsteadOfFkFailure)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    model::ScoreRow s;
    s.rootProcessGuid = MakeGuid(42);
    s.scoreMilli = s.peakMilli = 55'000;
    s.lastUpdateTs = s.firstHitTs = f.clock.NowMs();
    s.state = model::TreeState::Watched;
    ASSERT_TRUE(w->Post(Op(s)));
    w->Stop();

    auto r = f.Reader();
    EXPECT_EQ(r->Db().QueryInt64("SELECT score FROM scores;").Value().value_or(0), 55'000);
    EXPECT_EQ(r->Db().QueryInt64("SELECT pid FROM process_tree;").Value().value_or(-1), 0);   // 佔位節點
}

TEST(WriterThread, ProcessEndDoesNotCascadeDeleteScores)   // INSERT OR REPLACE 回歸（SDD-02 §6.3.1）
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    ASSERT_TRUE(w->Post(Op(MakeProcessRow(7, 0, 7, f.clock.NowMs()))));
    model::ScoreRow s;
    s.rootProcessGuid = MakeGuid(7);
    s.scoreMilli = s.peakMilli = 81'000;
    s.lastUpdateTs = s.firstHitTs = f.clock.NowMs();
    s.state = model::TreeState::Alerted;
    ASSERT_TRUE(w->Post(Op(s)));
    model::ProcessRow again = MakeProcessRow(7, 0, 7, f.clock.NowMs());
    again.endTs = f.clock.NowMs() + 10;
    ASSERT_TRUE(w->Post(Op(again)));                                                   // upsert 同一節點
    ASSERT_TRUE(w->Post(Op(model::ProcessEndUpdate{MakeGuid(7), f.clock.NowMs() + 20})));
    w->Stop();

    auto r = f.Reader();
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM scores;").Value().value_or(0), 1);
    EXPECT_EQ(r->Db().QueryInt64("SELECT peak_score FROM scores;").Value().value_or(0), 81'000);
    EXPECT_EQ(r->Db().QueryInt64("SELECT end_ts FROM process_tree;").Value().value_or(0), f.clock.NowMs() + 20);
}

TEST(WriterThread, RuleHitWithMissingReferencesStoresNull)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    model::RuleHitRow h;
    h.ts = f.clock.NowMs();
    h.ruleId = "R-T1059-001";
    h.rootProcessGuid = MakeGuid(1);
    h.eventId = 999'999;      // 事件被背壓丟掉
    h.alertId = 888;          // 告警不存在
    h.suppressedBy = 777;     // 排除不存在
    h.scoreDeltaMilli = 30'000;
    h.ruleHash = "abc";
    ASSERT_TRUE(w->Post(Op(h)));
    w->Stop();

    auto r = f.Reader();
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM rule_hits WHERE event_id IS NULL AND alert_id IS NULL"
                                 " AND suppressed_by IS NULL;").Value().value_or(0), 1);
}

TEST(WriterThread, UrgentAlertIsWrittenWithEvidenceAndHits)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    const int64_t t = f.clock.NowMs();
    ASSERT_TRUE(w->Post(Op(MakeProcessRow(1, 0, 1, t))));
    ASSERT_TRUE(w->Post(Op(MakeProcessRow(2, 1, 1, t + 1))));
    for (int i = 1; i <= 3; ++i) ASSERT_TRUE(w->Post(Op(MakeEventRow(f.interner, i, t + i, 2, 1))));

    model::AlertRow a;
    a.id = 1;
    a.ts = t + 10;
    a.rootProcessGuid = MakeGuid(1);
    a.triggerProcessGuid = MakeGuid(2);
    a.severity = model::Severity::Critical;
    a.scoreAtTriggerMilli = 96'000;
    a.ruleIds = {"R-T1055-001"};
    a.attackIds = {"T1055.001"};
    a.title = "Office 產生腳本直譯器並注入其他程序";
    a.events = {{1, 0, "trigger"}, {2, 1, "evidence"}, {3, 2, "evidence"}, {424242, std::nullopt, "context"}};
    model::RuleHitRow hit;
    hit.ts = t + 3;
    hit.ruleId = "R-T1055-001";
    hit.rootProcessGuid = MakeGuid(1);
    hit.eventId = 3;
    hit.scoreDeltaMilli = 96'000;
    hit.ruleHash = "h";
    a.hits = {hit};

    std::promise<std::optional<Result<int64_t>>> done;   // MSVC：promise<T> 的 T 需可預設建構
    model::WriteOp op = Op(a);
    op.onDone = [&](Result<int64_t> r) { done.set_value(std::move(r)); };   // 隱式轉 optional
    ASSERT_TRUE(w->Post(std::move(op)));
    auto res = std::move(*done.get_future().get());
    ASSERT_TRUE(res) << res.GetError().ToString();
    EXPECT_EQ(res.Value(), 1);

    ASSERT_TRUE(w->Post(Op(model::AlertNarrativeUpdate{1, model::AiState::Ok, std::string("敘事"), std::string("建議"),
                                                       0.8, {"T1055.001"}, std::string("a3f1"), 1500})));
    ASSERT_TRUE(w->Post(Op(model::AlertActionAppend{1, R"({"action":"suspend_process","result":"success"})"})));
    ASSERT_TRUE(w->Post(Op(model::AlertVerdictUpdate{1, model::Verdict::TruePositive, "確認", t + 100})));
    w->Stop();

    auto r = f.Reader();
    auto d = r->GetAlert(1);
    ASSERT_TRUE(d) << d.GetError().ToString();
    ASSERT_TRUE(d.Value().has_value());
    const AlertDetail& det = *d.Value();
    EXPECT_EQ(det.alert.severity, "critical");
    EXPECT_EQ(det.alert.ruleIds, std::vector<std::string>{"R-T1055-001"});
    EXPECT_EQ(det.timeline.size(), 3u);                       // 不存在的 event 424242 不會讓整筆告警失敗
    EXPECT_EQ(det.timeline.front().role, "trigger");
    ASSERT_EQ(det.timeline.back().hits.size(), 1u);
    EXPECT_EQ(det.processTree.size(), 2u);
    EXPECT_EQ(det.alert.aiState, "ok");
    EXPECT_EQ(det.alert.aiNarrative.value_or(""), "敘事");
    EXPECT_EQ(det.alert.analystVerdict.value_or(""), "true_positive");
    EXPECT_NE(det.alert.actionsTakenJson.find("suspend_process"), std::string::npos);
    ASSERT_EQ(det.hits.size(), 1u);
    EXPECT_EQ(det.hits[0].alertId.value_or(0), 1);

    auto list = r->ListAlerts(AlertListFilter{}, t + 1000);
    ASSERT_TRUE(list);
    ASSERT_EQ(list.Value().items.size(), 1u);
    EXPECT_EQ(list.Value().items[0].processName, "cmd.exe");
    EXPECT_EQ(list.Value().items[0].status, "resolved");

    auto prompt = r->LoadPromptInput(1);
    ASSERT_TRUE(prompt) << prompt.GetError().ToString();
    EXPECT_EQ(prompt.Value().processChain.size(), 2u);        // 根 → 觸發程序
    EXPECT_EQ(prompt.Value().timeline.size(), 3u);
    EXPECT_LE(prompt.Value().timeline.size(), 40u);
    EXPECT_EQ(prompt.Value().actionsTaken, std::vector<std::string>{"suspend_process"});
}

TEST(WriterThread, ExclusionInsertReturnsIdAndIsIdempotent)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    model::ExclusionInsert x;
    x.kind = model::ExclusionKind::Path;
    x.value = "C:\\Tools\\build.exe";
    x.createdTs = f.clock.NowMs();
    auto post = [&] {
        std::promise<std::optional<Result<int64_t>>> p;
        auto op = Op(x);
        op.onDone = [&](Result<int64_t> r) { p.set_value(std::move(r)); };
        EXPECT_TRUE(w->Post(std::move(op)));
        return std::move(*p.get_future().get());
    };
    auto a = post();
    auto b = post();
    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    EXPECT_EQ(a.Value(), b.Value());   // UNIQUE(kind,value,scope_rule_id) + upsert
    w->Stop();
    auto r = f.Reader();
    auto list = r->ListExclusions(f.clock.NowMs());
    ASSERT_TRUE(list);
    EXPECT_EQ(list.Value().size(), 1u);
}

TEST(WriterThread, BackpressureRejectsNormalButNeverUrgent)   // T-10 的寫入面
{
    Fixture f;
    auto w = f.MakeWriter(/*capacity*/ 10);
    // 不啟動執行緒：佇列只進不出
    int accepted = 0;
    for (int i = 1; i <= 50; ++i)
        if (w->Post(Op(MakeEventRow(f.interner, i, f.clock.NowMs(), 1, 1)))) ++accepted;
    EXPECT_EQ(accepted, 10);
    model::AuditRow a;
    a.ts = f.clock.NowMs();
    a.actor = "system";
    a.action = "test";
    a.result = "ok";
    EXPECT_TRUE(w->Post(Op(a)));   // 稽核永不因背壓被拒
    EXPECT_EQ(w->Stats().queueDropped, 40u);
    w->Stop();                     // 未啟動也必須把已排入者寫完
    auto r = f.Reader();
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM audit_log WHERE action='test';").Value().value_or(0), 1);
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM events;").Value().value_or(0), 10);
}

TEST(WriterThread, DetectsUncleanShutdown)
{
    Fixture f;
    {
        auto w = f.MakeWriter();
        EXPECT_FALSE(w->UncleanStart());   // 新庫
        ASSERT_TRUE(w->Start());
        w->Stop();                         // 寫 clean marker
    }
    {
        auto w = f.MakeWriter();
        EXPECT_FALSE(w->UncleanStart());   // 上次正常關閉
        w->Stop();
    }
    // 模擬崩潰：上次執行沒有留下 clean marker
    std::filesystem::remove(f.dir.Path() / "clean_shutdown.marker");
    auto w = f.MakeWriter();
    EXPECT_TRUE(w->UncleanStart());
    w->Stop();
    auto r = f.Reader();
    EXPECT_EQ(r->Db().QueryInt64("SELECT COUNT(*) FROM audit_log WHERE action='unclean_start';").Value().value_or(0), 1);
}

TEST(WriterThread, ListAlertsKeysetPagination)
{
    Fixture f;
    auto w = f.MakeWriter();
    ASSERT_TRUE(w->Start());
    for (int i = 1; i <= 25; ++i) {
        model::AlertRow a;
        a.id = i;
        a.ts = f.clock.NowMs() + i;
        a.rootProcessGuid = MakeGuid(static_cast<uint32_t>(i));
        a.severity = i % 2 ? model::Severity::High : model::Severity::Critical;
        a.scoreAtTriggerMilli = 80'000 + i;
        a.ruleIds = {"R-T1059-001"};
        a.title = "t" + std::to_string(i);
        ASSERT_TRUE(w->Post(Op(a)));
    }
    w->Stop();
    auto r = f.Reader();
    AlertListFilter flt;
    flt.limit = 10;
    std::vector<int64_t> seen;
    for (int page = 0; page < 5; ++page) {
        auto res = r->ListAlerts(flt, f.clock.NowMs() + 100);
        ASSERT_TRUE(res) << res.GetError().ToString();
        for (const auto& it : res.Value().items) seen.push_back(it.id);
        EXPECT_EQ(res.Value().stats.totalMatched, 25);
        if (!res.Value().nextCursor) break;
        flt.cursor = res.Value().nextCursor;
    }
    ASSERT_EQ(seen.size(), 25u);
    EXPECT_EQ(seen.front(), 25);   // time_desc
    EXPECT_EQ(seen.back(), 1);

    AlertListFilter crit;
    crit.severities = {"critical"};
    auto c = r->ListAlerts(crit, f.clock.NowMs() + 100);
    ASSERT_TRUE(c);
    EXPECT_EQ(c.Value().stats.totalMatched, 12);

    AlertListFilter bad;
    bad.cursor = "garbage";
    EXPECT_FALSE(r->ListAlerts(bad, f.clock.NowMs()));
}

TEST(WriterThread, SpillRecordsRoundTrip)
{
    model::AlertRow a;
    a.id = 9;
    a.ts = 123;
    a.rootProcessGuid = MakeGuid(9);
    a.severity = model::Severity::Medium;
    a.ruleIds = {"R-T1486-001"};
    a.title = "含 \"引號\" 與\n換行";
    a.events = {{5, 1, "trigger"}};
    auto s = SerializeSpill(SpillRecord{a});
    auto back = DeserializeSpill(s);
    ASSERT_TRUE(back);
    const auto& b = std::get<model::AlertRow>(back.Value());
    EXPECT_EQ(b.id, 9);
    EXPECT_EQ(b.title, a.title);
    EXPECT_EQ(b.rootProcessGuid, a.rootProcessGuid);
    ASSERT_EQ(b.events.size(), 1u);
    EXPECT_EQ(b.events[0].stepIndex.value_or(-1), 1);
    EXPECT_FALSE(DeserializeSpill("{not json"));
}
