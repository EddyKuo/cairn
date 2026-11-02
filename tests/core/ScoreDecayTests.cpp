// ScoreDecayTests —— 定點數衰減與 ScoreBoard 狀態機。分數一律 EXPECT_EQ 精確值（非 EXPECT_NEAR）。
#include <gtest/gtest.h>

#include "TestHelpers.h"
#include "score/Decay.h"
#include "score/ScoreBoard.h"

using namespace cairn;
using cairn::model::TreeState;
using cairn::score::DecayMilli;
using cairn::score::RuleHit;
using cairn::score::ScoreBoard;
using cairn::test::G;

namespace {
constexpr int64_t kT0 = 1'700'000'000'000;
constexpr uint32_t kHalf10m = 600'000;

RuleHit Hit(const char* id, int64_t milli, int64_t ts, uint32_t hl = kHalf10m)
{
    RuleHit h;
    h.ruleId     = id;
    h.deltaMilli = milli;
    h.tsMs       = ts;
    h.halfLifeMs = hl;
    return h;
}
} // namespace

// ---------------- DecayMilli ----------------
TEST(ScoreDecayTests, TableEndpoints)
{
    EXPECT_EQ(score::kPow2Neg[0], 65536u);
    EXPECT_EQ(score::kPow2Neg[128], 46341u);
    for (size_t i = 1; i < score::kPow2Neg.size(); ++i) EXPECT_LT(score::kPow2Neg[i], score::kPow2Neg[i - 1]);
}

TEST(ScoreDecayTests, ExactHalfLife)
{
    EXPECT_EQ(DecayMilli(80'000, 600'000, 600'000), 40'000);
    EXPECT_EQ(DecayMilli(80'000, 1'200'000, 600'000), 20'000);
    EXPECT_EQ(DecayMilli(100'000, 1'800'000, 600'000), 12'500);
}

TEST(ScoreDecayTests, HalfOfHalfLifeUsesTable)
{
    // 100000 * 46341 >> 16 = 4,634,100,000 / 65536 = 70710.75 → 70710（向下取整：殘餘分數單向偏保守）
    EXPECT_EQ(DecayMilli(100'000, 300'000, 600'000), 70'710);
}

TEST(ScoreDecayTests, NoDecayForZeroOrNegativeDt)
{
    EXPECT_EQ(DecayMilli(70'000, 0, 600'000), 70'000);
    EXPECT_EQ(DecayMilli(70'000, -5, 600'000), 70'000);
    EXPECT_EQ(DecayMilli(0, 600'000, 600'000), 0);
}

TEST(ScoreDecayTests, BelowFloorBecomesExactlyZero)
{
    EXPECT_EQ(DecayMilli(6'000, 600'000, 600'000), 0) << "3000 < 5000 地板 → 歸零（不是趨近零）";
    EXPECT_EQ(DecayMilli(100'000, 600'000LL * 70, 600'000), 0);
}

TEST(ScoreDecayTests, ZeroHalfLifeMeansImmediateExpiry)
{
    EXPECT_EQ(DecayMilli(50'000, 1, 0), 0);
}

TEST(ScoreDecayTests, MonotonicNonIncreasing)
{
    int64_t prev = 100'000;
    for (int64_t dt = 0; dt <= 3'000'000; dt += 7'919) {
        const int64_t v = DecayMilli(100'000, dt, 600'000);
        EXPECT_LE(v, prev);
        prev = v;
    }
}

TEST(ScoreDecayTests, MsUntilBelowIsTightBoundary)
{
    const int64_t due = score::MsUntilBelow(45'000, 35'000, kHalf10m);
    EXPECT_LT(DecayMilli(45'000, due, kHalf10m), 35'000);
    EXPECT_GE(DecayMilli(45'000, due - 1, kHalf10m), 35'000);
}

// ---------------- ScoreBoard ----------------
TEST(ScoreBoardTests, AccumulateAndEscalate)
{
    ScoreBoard sb;
    auto tr = sb.ApplyDelta(G(1), Hit("R-T1059-001", 45'000, kT0));
    EXPECT_EQ(tr.from, TreeState::Benign);
    EXPECT_EQ(tr.to, TreeState::Watched);
    EXPECT_EQ(tr.scoreMilli, 45'000);

    tr = sb.ApplyDelta(G(1), Hit("R-T1055-001", 40'000, kT0));
    EXPECT_EQ(tr.from, TreeState::Watched);
    EXPECT_EQ(tr.to, TreeState::Alerted);
    EXPECT_EQ(tr.scoreMilli, 85'000);
    EXPECT_EQ(tr.peakMilli, 85'000);
    EXPECT_TRUE(tr.IsEscalation());
}

TEST(ScoreBoardTests, SaturatesAtMax)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 95'000, kT0));
    auto tr = sb.ApplyDelta(G(1), Hit("B", 40'000, kT0));
    EXPECT_EQ(tr.scoreMilli, 100'000);
    EXPECT_EQ(tr.to, TreeState::Blocked);
}

TEST(ScoreBoardTests, DecayBeforeAdd)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 60'000, kT0));
    auto tr = sb.ApplyDelta(G(1), Hit("B", 10'000, kT0 + 600'000));
    EXPECT_EQ(tr.scoreMilli, 40'000) << "60000 衰減一個半衰期為 30000，再加 10000";
}

TEST(ScoreBoardTests, DryRunOnlyAffectsShadow)
{
    ScoreBoard sb;
    auto h  = Hit("R-T1053-001", 90'000, kT0);
    h.dryRun = true;
    auto tr = sb.ApplyDelta(G(1), h);
    EXPECT_EQ(tr.scoreMilli, 0);
    EXPECT_EQ(tr.shadowMilli, 90'000);
    EXPECT_EQ(tr.to, TreeState::Benign) << "dryrun 絕不轉移狀態";

    // 隨後的 enabled 命中不會被 dryrun 墊高（C-9 shadow_score 語意）
    tr = sb.ApplyDelta(G(1), Hit("R-T1059-001", 70'000, kT0));
    EXPECT_EQ(tr.scoreMilli, 70'000);
    EXPECT_EQ(tr.to, TreeState::Watched);
    EXPECT_GE(tr.shadowMilli, tr.scoreMilli);
}

TEST(ScoreBoardTests, SuppressedHitChangesNothing)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 30'000, kT0));
    auto h       = Hit("B", 60'000, kT0);
    h.suppressed = true;
    auto tr = sb.ApplyDelta(G(1), h);
    EXPECT_EQ(tr.scoreMilli, 30'000);
    EXPECT_EQ(tr.from, tr.to);
}

TEST(ScoreBoardTests, RepeatHitCooldown)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 30'000, kT0));
    // 冷卻 = max(600000/4, 5000) = 150000 ms
    auto tr = sb.ApplyDelta(G(1), Hit("A", 30'000, kT0 + 149'999));
    EXPECT_TRUE(tr.cooledDown);
    EXPECT_EQ(tr.appliedDeltaMilli, 0);
    tr = sb.ApplyDelta(G(1), Hit("A", 30'000, kT0 + 150'000));
    EXPECT_FALSE(tr.cooledDown);
    EXPECT_GT(tr.appliedDeltaMilli, 0);
}

TEST(ScoreBoardTests, DeterministicJumpsToBlockedWithoutLoweringScore)
{
    ScoreBoard sb;
    auto h          = Hit("R-T9999-001", 10'000, kT0);
    h.deterministic = true;
    auto tr = sb.ApplyDelta(G(1), h);
    EXPECT_EQ(tr.scoreMilli, 95'000);
    EXPECT_EQ(tr.to, TreeState::Blocked);

    ScoreBoard sb2;
    (void)sb2.ApplyDelta(G(2), Hit("A", 98'000, kT0));
    tr = sb2.ApplyDelta(G(2), h);
    EXPECT_EQ(tr.scoreMilli, 98'000) << "max 而非指派：不得把 98000 覆寫成 95000";
}

TEST(ScoreBoardTests, WatchedDowngradesOnlyBelowHysteresis)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 45'000, kT0));
    const int64_t due = kT0 + score::MsUntilBelow(45'000, 35'000, kHalf10m);
    EXPECT_TRUE(sb.SweepDecay(due - 1).empty());
    auto trs = sb.SweepDecay(due);
    ASSERT_EQ(trs.size(), 1u);
    EXPECT_EQ(trs[0].from, TreeState::Watched);
    EXPECT_EQ(trs[0].to, TreeState::Benign);
    EXPECT_LT(trs[0].scoreMilli, 35'000);
}

TEST(ScoreBoardTests, AlertedNeverAutoDowngrades)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 85'000, kT0));
    (void)sb.SweepDecay(kT0 + 86'400'000);
    const auto* ts = sb.Find(G(1));
    ASSERT_NE(ts, nullptr);
    EXPECT_EQ(ts->state, TreeState::Alerted);
    EXPECT_EQ(ts->peakMilli, 85'000) << "peak 只增不減";
}

TEST(ScoreBoardTests, BenignTreeErasedWhenFullyDecayed)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 20'000, kT0));
    auto trs = sb.SweepDecay(kT0 + 600'000LL * 64);
    ASSERT_EQ(trs.size(), 1u);
    EXPECT_TRUE(trs[0].erased);
    EXPECT_EQ(sb.Find(G(1)), nullptr);
}

TEST(ScoreBoardTests, MergeRootSumsAndEscalates)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(2), Hit("A", 50'000, kT0));   // 暫定根
    (void)sb.ApplyDelta(G(1), Hit("B", 40'000, kT0));   // 真正的根
    auto tr = sb.MergeRoot(G(2), G(1), kT0);
    ASSERT_TRUE(tr.has_value());
    EXPECT_EQ(tr->scoreMilli, 90'000);
    EXPECT_EQ(tr->to, TreeState::Alerted);
    EXPECT_EQ(sb.Find(G(2)), nullptr);
}

TEST(ScoreBoardTests, ResolvedStopsTransitions)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 85'000, kT0));
    EXPECT_TRUE(sb.MarkResolved(G(1), kT0));
    auto tr = sb.ApplyDelta(G(1), Hit("B", 15'000, kT0));
    EXPECT_EQ(tr.to, TreeState::Resolved);
}

TEST(ScoreBoardTests, LongestHalfLifeWins)
{
    ScoreBoard sb;
    (void)sb.ApplyDelta(G(1), Hit("A", 40'000, kT0, 60'000));
    (void)sb.ApplyDelta(G(1), Hit("B", 40'000, kT0, 600'000));
    // 最長半衰期 600 s：經過 600 s 後 80000 → 40000（若誤用最短 60 s 會幾乎歸零）
    EXPECT_EQ(sb.CurrentScore(G(1), kT0 + 600'000), 40'000);
}
