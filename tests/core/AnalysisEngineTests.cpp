// AnalysisEngineTests —— 以 FakeClock + fake sinks 端到端餵事件序列：
//   程序樹 → 規則 → 排除 → 計分 → 告警 → 自動回應，全程不經 LLM（架構紅線）
#include <gtest/gtest.h>

#include <algorithm>

#include "TestHelpers.h"
#include "engine/AnalysisEngine.h"
#include "rules/RuleLoader.h"

using namespace cairn;
using cairn::model::ActionKind;
using cairn::model::TreeState;
using cairn::test::G;

namespace {
const char* kRules = R"(
id: R-T9200-001
title: PowerShell 編碼命令
severity: high
status: enabled
score: 45
decay: 600s
requires_events: [1]
event: PROCESS_CREATE
where:
  - field: image
    op: ends_with
    value: '\powershell.exe'
  - field: command_line
    op: contains
    value: ' -enc '
response:
  on_score_ge: 80
  actions: [suspend_process]
  require_confirmation: false
---
id: R-T1055-001
title: Office 產生腳本直譯器並注入其他程序
severity: critical
attack: [T1566.001, T1059.001, T1055.001]
status: enabled
score: 70
decay: 600s
requires_events: [1, 8]
sequence:
  within: 120s
  correlate_by: process_tree_root
  steps:
    - id: office_spawn
      event: PROCESS_CREATE
      where:
        - field: parent_image
          op: ends_with
          value: '\winword.exe'
    - id: remote_inject
      event: REMOTE_THREAD
      where:
        - field: process_guid
          op: equals_ref
          value: office_spawn.process_guid
response:
  on_score_ge: 80
  actions: [suspend_process]
  require_confirmation: false
---
id: R-T9300-001
title: 觀察中的規則
severity: medium
status: dryrun
score: 90
decay: 600s
requires_events: [11]
event: FILE_CREATE
where:
  - field: target_filename
    op: ends_with
    value: '.locked'
---
id: R-T9400-001
title: 高分但未達阻擋
severity: high
status: enabled
score: 85
decay: 600s
requires_events: [10]
event: PROCESS_ACCESS
where:
  - field: target_image
    op: ends_with
    value: '\lsass.exe'
response:
  on_score_ge: 80
  actions: [terminate_process_tree]
  require_confirmation: false
)";
} // namespace

class AnalysisEngineTest : public ::testing::Test {
protected:
    model::StringInterner    in;
    FakeClock                clock{1'700'000'000'000};
    test::FakeWriteSink      writes;
    test::FakeAlertSink      alerts;
    test::FakeResponseSink   responses;
    test::EventFactory       f{in, 1'700'000'000'000};
    std::unique_ptr<engine::AnalysisEngine> eng;

    void SetUp() override { Make({}); }

    void Make(engine::EnginePolicy policy)
    {
        auto r = engine::AnalysisEngine::Create({&in, &writes, &alerts, &responses, &clock}, std::move(policy));
        ASSERT_TRUE(r);
        eng = std::move(r).Value();
        auto rules = rules::LoadRuleTexts({{"t.yaml", kRules}}, in);
        ASSERT_TRUE(rules) << rules.GetError().ToString();
        for (const auto& i : rules.Value().rules) ASSERT_TRUE(i.loadError.empty()) << i.loadError;
        eng->ReplaceRuleSet(rules.Value().ruleSet);
        eng->SetNextIds(100, 7);
    }

    void Feed(model::NormalizedEvent e) { eng->OnEvent(std::move(e)); }

    // explorer → winword → powershell -enc → 遠端執行緒注入
    void RunOfficeChain()
    {
        Feed(f.ProcessCreate(1, 0, "C:\\Windows\\explorer.exe", ""));
        Feed(f.ProcessCreate(2, 1, "C:\\Program Files\\Office\\WINWORD.EXE", "C:\\Windows\\explorer.exe"));
        Feed(f.ProcessCreate(3, 2, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             "C:\\Program Files\\Office\\WINWORD.EXE", "powershell -nop -enc SQBFAFgA"));
        f.Advance(3'000);
        Feed(f.RemoteThread(3, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 9,
                            "C:\\Windows\\explorer.exe"));
    }
};

TEST_F(AnalysisEngineTest, CreateRejectsMissingDeps)
{
    EXPECT_FALSE(engine::AnalysisEngine::Create({nullptr, &writes, nullptr, nullptr, &clock}));
    EXPECT_FALSE(engine::AnalysisEngine::Create({&in, nullptr, nullptr, nullptr, &clock}));
    EXPECT_FALSE(engine::AnalysisEngine::Create({&in, &writes, nullptr, nullptr, nullptr}));
}

TEST_F(AnalysisEngineTest, EventIdsAreExplicitAndMonotonic)
{
    Feed(f.ProcessCreate(1, 0, "a.exe", ""));
    Feed(f.ProcessCreate(2, 1, "b.exe", "a.exe"));
    const auto evs = writes.All<model::EventRow>();
    ASSERT_EQ(evs.size(), 2u);
    EXPECT_EQ(evs[0]->id, 100);
    EXPECT_EQ(evs[1]->id, 101);
    EXPECT_EQ(evs[1]->rootProcessGuid, G(1));
    EXPECT_EQ(writes.All<model::ProcessRow>().size(), 2u);
}

TEST_F(AnalysisEngineTest, OfficeChainRaisesBlockedAlertAndTerminatesTree)
{
    RunOfficeChain();

    const auto alertRows = writes.All<model::AlertRow>();
    ASSERT_EQ(alertRows.size(), 1u) << "Watched → Blocked 在同一事件內只產生一則告警";
    const model::AlertRow& a = *alertRows[0];
    EXPECT_EQ(a.id, 7);
    EXPECT_EQ(a.rootProcessGuid, G(2)) << "explorer 為樹邊界，winword 為根";
    EXPECT_EQ(a.severity, model::Severity::Critical);
    EXPECT_EQ(a.scoreAtTriggerMilli, 100'000) << "45 + 70 飽和於 100";
    EXPECT_NE(std::find(a.ruleIds.begin(), a.ruleIds.end(), "R-T1055-001"), a.ruleIds.end());
    EXPECT_NE(std::find(a.ruleIds.begin(), a.ruleIds.end(), "R-T9200-001"), a.ruleIds.end());
    EXPECT_NE(std::find(a.attackIds.begin(), a.attackIds.end(), "T1055.001"), a.attackIds.end());
    EXPECT_EQ(a.title, "Office 產生腳本直譯器並注入其他程序");
    EXPECT_FALSE(a.summary.empty());
    EXPECT_EQ(a.aiState, model::AiState::Pending) << "LLM 事後補敘事，不在此路徑上";

    // alert_events：觸發事件 + 序列各步證據
    ASSERT_FALSE(a.events.empty());
    EXPECT_EQ(a.events.front().role, "trigger");
    EXPECT_EQ(a.events.front().eventId, 103);
    const bool hasStep0 = std::any_of(a.events.begin(), a.events.end(), [](const model::AlertEventLink& l) {
        return l.eventId == 102 && l.stepIndex == 0;
    });
    EXPECT_TRUE(hasStep0);
    ASSERT_FALSE(a.hits.empty());
    for (const auto& h : a.hits) EXPECT_EQ(h.alertId, 7);

    // 事件列先於告警投遞（WriterThread 依此保證 alert_events 的 FK）
    EXPECT_LT(writes.IndexOfFirst<model::EventRow>(), writes.IndexOfFirst<model::AlertRow>());

    ASSERT_EQ(alerts.raised.size(), 1u);
    EXPECT_EQ(alerts.raised[0].state, TreeState::Blocked);

    // >= 95：terminate_process_tree 取代 suspend；quarantine 略過（System32 的 powershell 不得隔離）；無外連 IP → 不封鎖
    ASSERT_EQ(responses.cmds.size(), 1u);
    const auto& c = responses.cmds[0];
    EXPECT_EQ(c.action, ActionKind::TerminateProcessTree);
    EXPECT_TRUE(c.automatic);
    EXPECT_EQ(c.alertId, 7);
    ASSERT_EQ(c.target.processes.size(), 2u);
    EXPECT_EQ(c.target.processes[0].processGuid, G(2)) << "根 → 葉前序";
    EXPECT_EQ(c.target.processes[1].processGuid, G(3));
    for (const auto& p : c.target.processes) EXPECT_EQ(p.image.find("explorer"), std::string::npos) << "不得波及 explorer";
}

TEST_F(AnalysisEngineTest, BlockedAddsFirewallWhenTreeHasOutboundIp)
{
    Feed(f.ProcessCreate(2, 0, "C:\\Office\\winword.exe", ""));
    Feed(f.ProcessCreate(3, 2, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe", "powershell -enc AAAA"));
    Feed(f.Network(3, "C:\\x\\powershell.exe", "185.1.2.3", 443));
    Feed(f.RemoteThread(3, "C:\\x\\powershell.exe", 9, "notepad.exe"));
    const auto fw = std::find_if(responses.cmds.begin(), responses.cmds.end(),
                                 [](const model::ResponseCommand& c) { return c.action == ActionKind::FirewallBlock; });
    ASSERT_NE(fw, responses.cmds.end());
    EXPECT_EQ(fw->target.ip, "185.1.2.3");
    EXPECT_EQ(fw->target.port, 443);
}

TEST_F(AnalysisEngineTest, TerminateDowngradedToSuspendBelow95)
{
    Feed(f.ProcessCreate(5, 0, "C:\\Users\\a\\Downloads\\dumper.exe", ""));
    Feed(f.ProcessAccess(5, "C:\\Users\\a\\Downloads\\dumper.exe", "C:\\Windows\\System32\\lsass.exe", 0x1010));
    ASSERT_EQ(alerts.raised.size(), 1u);
    EXPECT_EQ(alerts.raised[0].state, TreeState::Alerted);
    ASSERT_EQ(responses.cmds.size(), 1u);
    EXPECT_EQ(responses.cmds[0].action, ActionKind::SuspendProcess) << "C-8 原則 4：80–94 只執行可逆動作";
}

TEST_F(AnalysisEngineTest, LearningModeAlertsButWithholdsResponses)
{
    engine::EnginePolicy p;
    p.learningMode = true;
    Make(p);
    RunOfficeChain();
    EXPECT_EQ(writes.All<model::AlertRow>().size(), 1u);
    EXPECT_TRUE(responses.cmds.empty());
    EXPECT_GT(eng->Stats().responsesWithheld, 0u);
}

TEST_F(AnalysisEngineTest, PausedProtectionWithholdsResponses)
{
    eng->SetProtectionPaused(true);
    RunOfficeChain();
    EXPECT_TRUE(responses.cmds.empty());
    eng->SetProtectionPaused(false);
    EXPECT_FALSE(eng->Stats().protectionPaused);
}

TEST_F(AnalysisEngineTest, DryRunHitsNeverEscalate)
{
    Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\x.exe", ""));
    Feed(f.FileCreate(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\a.locked"));
    EXPECT_TRUE(writes.All<model::AlertRow>().empty());
    const auto hits = writes.All<model::RuleHitRow>();
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_TRUE(hits[0]->dryrun);
    EXPECT_EQ(hits[0]->scoreDeltaMilli, 90'000);
    const auto scores = writes.All<model::ScoreRow>();
    ASSERT_FALSE(scores.empty());
    EXPECT_EQ(scores.back()->scoreMilli, 0);
    EXPECT_EQ(scores.back()->shadowMilli, 90'000);
    EXPECT_EQ(scores.back()->state, TreeState::Benign);
}

TEST_F(AnalysisEngineTest, ExcludedHitIsRecordedButNotScored)
{
    rules::ExclusionEntry e;
    e.id    = 42;
    e.kind  = model::ExclusionKind::PathGlob;
    e.value = "c:\\tools\\*";
    eng->ReplaceExclusions({e});
    Feed(f.ProcessCreate(5, 0, "C:\\Tools\\dumper.exe", ""));
    Feed(f.ProcessAccess(5, "C:\\Tools\\dumper.exe", "C:\\Windows\\System32\\lsass.exe", 0x1010));
    EXPECT_TRUE(alerts.raised.empty());
    const auto hits = writes.All<model::RuleHitRow>();
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_TRUE(hits[0]->suppressed);
    EXPECT_EQ(hits[0]->suppressedBy, 42);
    EXPECT_EQ(hits[0]->scoreDeltaMilli, 0);
    const auto inc = writes.All<model::ExclusionHitIncrement>();
    ASSERT_EQ(inc.size(), 1u);
    EXPECT_EQ(inc[0]->id, 42) << "exclusions.hit_count++：可稽核這條排除擋掉了什麼";
}

TEST_F(AnalysisEngineTest, VerdictResolvesTree)
{
    RunOfficeChain();
    ASSERT_TRUE(eng->ApplyVerdict(7, model::Verdict::FalsePositive));
    EXPECT_EQ(writes.All<model::ScoreRow>().back()->state, TreeState::Resolved);
    EXPECT_EQ(eng->ApplyVerdict(999, model::Verdict::TruePositive).Code(), ErrorCode::NotFound);
    EXPECT_EQ(eng->RootOfAlert(7), G(2));
}

TEST_F(AnalysisEngineTest, TickDecaysWatchedBackToBenign)
{
    Feed(f.ProcessCreate(2, 0, "C:\\Office\\winword.exe", ""));
    Feed(f.ProcessCreate(3, 2, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe", "powershell -enc AAAA"));
    EXPECT_EQ(writes.All<model::ScoreRow>().back()->state, TreeState::Watched);
    clock.Advance(3'600'000);
    eng->OnTick(clock.NowMs());
    EXPECT_EQ(writes.All<model::ScoreRow>().back()->state, TreeState::Benign);
}

TEST_F(AnalysisEngineTest, SnapshotTreeIsRootToLeafAndAliveFilter)
{
    Feed(f.ProcessCreate(2, 0, "C:\\a.exe", ""));
    Feed(f.ProcessCreate(3, 2, "C:\\b.exe", "C:\\a.exe"));
    Feed(f.ProcessExit(3, "C:\\b.exe"));
    EXPECT_EQ(eng->SnapshotTree(G(2)).size(), 2u);
    const auto alive = eng->SnapshotTree(G(2), true);
    ASSERT_EQ(alive.size(), 1u);
    EXPECT_EQ(alive[0].processGuid, G(2));
    EXPECT_EQ(writes.All<model::ProcessEndUpdate>().size(), 1u);
}

TEST_F(AnalysisEngineTest, WriteQueueFullIsCountedNotBlocking)
{
    writes.rejectAll = true;
    Feed(f.ProcessCreate(1, 0, "a.exe", ""));
    EXPECT_GT(eng->Stats().writeDropped, 0u);
}

TEST_F(AnalysisEngineTest, StatsReportLatencyAndCounts)
{
    RunOfficeChain();
    const auto s = eng->Stats();
    EXPECT_EQ(s.eventsProcessed, 4u);
    EXPECT_EQ(s.alertsRaised, 1u);
    EXPECT_GE(s.ruleHits, 2u);
    EXPECT_GE(s.tier2P95Ms, 0.0);
    EXPECT_EQ(s.nextEventId, 104);
    EXPECT_EQ(s.nextAlertId, 8);
}
