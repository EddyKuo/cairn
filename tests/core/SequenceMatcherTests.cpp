// SequenceMatcherTests —— within 邊界、亂序、部分命中、跨樹不誤配、equals_ref 綁定、threshold、
//                          狀態爆炸防護、熱重載、改根（SDD-02 §5.4、§6.8 T-05/T-06/T-07）
#include "RuleTestFixture.h"

using namespace cairn;
using cairn::test::G;
using cairn::test::RuleFixture;

namespace {
const char* kOfficeInject = R"(
id: R-T1055-001
title: Office 產生腳本直譯器並注入
severity: critical
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
          op: ends_with_any
          value: ['\winword.exe', '\excel.exe']
        - field: image
          op: ends_with_any
          value: ['\powershell.exe', '\cmd.exe']
    - id: remote_inject
      event: REMOTE_THREAD
      where:
        - field: process_guid
          op: equals_ref
          value: office_spawn.process_guid
)";

const char* kMassWrite = R"(
id: R-T1486-001
title: 勒索
severity: critical
status: enabled
score: 95
decay: 300s
requires_events: [11, 23]
sequence:
  within: 60s
  correlate_by: process_tree_root
  steps:
    - id: mass_write
      event: FILE_CREATE
      threshold: {count: 5, within: 30s, distinct_field: target_filename}
      where:
        - field: target_filename
          op: contains
          value: '\documents\'
    - id: delete_originals
      event: FILE_DELETE
      threshold: {count: 3, within: 30s}
      where:
        - field: process_guid
          op: equals_ref
          value: mass_write.process_guid
boosters:
  - id: shadow_delete
    event: PROCESS_CREATE
    score: 40
    where:
      - field: command_line
        op: contains
        value: 'vssadmin delete shadows'
)";
} // namespace

class SequenceMatcherTest : public RuleFixture {
protected:
    void SetUp() override
    {
        Load(kOfficeInject);
        Feed(f.ProcessCreate(1, 0, "C:\\Office\\WINWORD.EXE", "C:\\Windows\\explorer.exe"));
    }
};

TEST_F(SequenceMatcherTest, TwoStepHitWithinWindow)
{
    EXPECT_TRUE(Feed(f.ProcessCreate(2, 1, "C:\\Windows\\System32\\powershell.exe", "C:\\Office\\winword.exe")).empty())
        << "步驟 0 單獨不計分";
    EXPECT_EQ(engine.Stats().activeSequences, 1u);
    f.Advance(23'700);
    auto hits = Feed(f.RemoteThread(2, "C:\\Windows\\System32\\powershell.exe", 9, "C:\\Windows\\notepad.exe"));
    ASSERT_TRUE(HasRule(hits, "R-T1055-001"));
    ASSERT_EQ(hits[0].evidence.size(), 2u);
    EXPECT_EQ(hits[0].evidence[1].tsMs - hits[0].evidence[0].tsMs, 23'700);
    EXPECT_EQ(hits[0].key, G(1)) << "correlate_by: process_tree_root";
    EXPECT_EQ(engine.Stats().activeSequences, 0u);
}

TEST_F(SequenceMatcherTest, WithinBoundaryInclusive)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    f.Advance(120'000);   // 恰好在 deadline
    EXPECT_TRUE(HasRule(Feed(f.RemoteThread(2, "C:\\x\\powershell.exe", 9, "notepad.exe")), "R-T1055-001"));
}

TEST_F(SequenceMatcherTest, WithinBoundaryPlusOneMsMisses)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    f.Advance(120'001);
    EXPECT_FALSE(HasRule(Feed(f.RemoteThread(2, "C:\\x\\powershell.exe", 9, "notepad.exe")), "R-T1055-001"));
}

TEST_F(SequenceMatcherTest, ExpireRemovesStaleState)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    EXPECT_EQ(engine.Expire(f.Now() + 120'000), 0u) << "deadline 當下仍有效";
    EXPECT_EQ(engine.Expire(f.Now() + 120'001), 1u);
    EXPECT_EQ(engine.Stats().activeSequences, 0u);
}

TEST_F(SequenceMatcherTest, OutOfOrderStepsDoNotMatch)
{
    Feed(f.RemoteThread(2, "C:\\x\\powershell.exe", 9, "notepad.exe"));   // 步驟 1 先到
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    EXPECT_EQ(engine.Stats().activeSequences, 1u);
}

TEST_F(SequenceMatcherTest, EqualsRefRequiresSameActor)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    Feed(f.ProcessCreate(3, 1, "C:\\x\\helper.exe", "C:\\Office\\winword.exe"));   // 同一棵樹的其他程序
    EXPECT_FALSE(HasRule(Feed(f.RemoteThread(3, "C:\\x\\helper.exe", 9, "notepad.exe")), "R-T1055-001"))
        << "注入者必須是 Office 生出來的那個程序";
}

TEST_F(SequenceMatcherTest, DifferentTreesDoNotCrossMatch)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    Feed(f.ProcessCreate(50, 0, "C:\\x\\other.exe", ""));
    EXPECT_FALSE(HasRule(Feed(f.RemoteThread(50, "C:\\x\\other.exe", 9, "notepad.exe")), "R-T1055-001"));
}

TEST_F(SequenceMatcherTest, StateExplosionBounded)
{
    // 反覆從 winword 啟動 cmd 卻不做第二步（SDD-02 §5.4.4）
    for (uint32_t i = 0; i < 10'000; ++i)
        Feed(f.ProcessCreate(1000 + i, 1, "C:\\Windows\\System32\\cmd.exe", "C:\\Office\\winword.exe"));
    const auto st = engine.Stats();
    EXPECT_LE(st.activeSequences, rules::kMaxPartialPerKey);
    EXPECT_EQ(st.seq.evicted, 10'000u - rules::kMaxPartialPerKey);
    // 最新的部分比對仍可完成
    EXPECT_TRUE(HasRule(Feed(f.RemoteThread(1000 + 9'999, "C:\\Windows\\System32\\cmd.exe", 9, "n.exe")), "R-T1055-001"));
}

TEST_F(SequenceMatcherTest, DuplicateStepZeroWithSameBindingNotReopened)
{
    auto e = f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe");
    Feed(e);
    Feed(e);   // 重複事件
    EXPECT_EQ(engine.Stats().activeSequences, 1u);
}

TEST_F(SequenceMatcherTest, HotReloadDropsChangedKeepsSame)
{
    Feed(f.ProcessCreate(2, 1, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));
    Load(kOfficeInject);   // 內容相同 → 保留
    EXPECT_EQ(engine.Stats().activeSequences, 1u);
    std::string changed = kOfficeInject;
    changed.replace(changed.find("within: 120s"), 12, "within: 119s");
    Load(changed);         // 內容改變 → 丟棄（告警必須能追溯到確定的規則文字）
    EXPECT_EQ(engine.Stats().activeSequences, 0u);
    EXPECT_EQ(engine.Stats().seq.droppedChanged, 1u);
}

TEST_F(SequenceMatcherTest, RekeyMovesPartialMatches)
{
    // 暫定樹上開始的部分比對，在父節點晚到改根後仍能完成
    Feed(f.ProcessCreate(21, 20, "C:\\x\\powershell.exe", "C:\\Office\\winword.exe"));   // 父 20 尚未到
    Feed(f.ProcessCreate(20, 0, "C:\\Office\\winword.exe", ""));                         // 改根 21 → 20
    auto hits = Feed(f.RemoteThread(21, "C:\\x\\powershell.exe", 9, "n.exe"));
    ASSERT_TRUE(HasRule(hits, "R-T1055-001"));
    EXPECT_EQ(hits[0].key, G(20));
}

class ThresholdTest : public RuleFixture {};

TEST_F(ThresholdTest, DistinctCountThenDeleteSequence)
{
    Load(kMassWrite);
    Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\x.exe", ""));
    for (int i = 0; i < 4; ++i) Feed(f.FileCreate(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f" + std::to_string(i) + ".locked"));
    // 重複檔名不增加 distinct 數
    Feed(f.FileCreate(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f0.locked"));
    EXPECT_EQ(engine.Stats().activeSequences, 0u);
    Feed(f.FileCreate(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f4.locked"));   // 第 5 個相異檔名
    EXPECT_EQ(engine.Stats().activeSequences, 1u);
    EXPECT_FALSE(HasRule(Feed(f.FileDelete(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f0.docx")), "R-T1486-001"));
    EXPECT_FALSE(HasRule(Feed(f.FileDelete(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f1.docx")), "R-T1486-001"));
    EXPECT_TRUE(HasRule(Feed(f.FileDelete(1, "C:\\Users\\a\\x.exe", "C:\\Users\\a\\Documents\\f2.docx")), "R-T1486-001"));
}

TEST_F(ThresholdTest, RollingWindowDropsOldStamps)
{
    Load(kMassWrite);
    Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\x.exe", ""));
    for (int i = 0; i < 4; ++i) Feed(f.FileCreate(1, "x.exe", "C:\\Users\\a\\Documents\\a" + std::to_string(i)));
    f.Advance(30'001);   // 前 4 筆滑出 30 s 視窗
    Feed(f.FileCreate(1, "x.exe", "C:\\Users\\a\\Documents\\b0"));
    EXPECT_EQ(engine.Stats().activeSequences, 0u);
}

TEST_F(ThresholdTest, BoosterBeforeMainHitAppliesOnCompletion)
{
    Load(kMassWrite);
    Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\x.exe", ""));
    // vssadmin 先於加密發生（同一棵樹）
    EXPECT_TRUE(Feed(f.ProcessCreate(2, 1, "C:\\Windows\\System32\\vssadmin.exe", "x.exe", "vssadmin delete shadows /all")).empty());
    for (int i = 0; i < 5; ++i) Feed(f.FileCreate(1, "x.exe", "C:\\Users\\a\\Documents\\f" + std::to_string(i)));
    Feed(f.FileDelete(1, "x.exe", "C:\\Users\\a\\Documents\\o0"));
    Feed(f.FileDelete(1, "x.exe", "C:\\Users\\a\\Documents\\o1"));
    auto hits = Feed(f.FileDelete(1, "x.exe", "C:\\Users\\a\\Documents\\o2"));
    EXPECT_TRUE(HasRule(hits, "R-T1486-001"));
    EXPECT_TRUE(HasRule(hits, "R-T1486-001", /*booster=*/true));
}

TEST_F(ThresholdTest, BoosterAppliedOncePerWindow)
{
    Load(kMassWrite);
    Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\x.exe", ""));
    for (int i = 0; i < 5; ++i) Feed(f.FileCreate(1, "x.exe", "C:\\Users\\a\\Documents\\f" + std::to_string(i)));
    for (int i = 0; i < 3; ++i) Feed(f.FileDelete(1, "x.exe", "C:\\Users\\a\\Documents\\o" + std::to_string(i)));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(2, 1, "vssadmin.exe", "x.exe", "vssadmin delete shadows")), "R-T1486-001", true));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(3, 1, "vssadmin.exe", "x.exe", "vssadmin delete shadows")), "R-T1486-001", true));
}
