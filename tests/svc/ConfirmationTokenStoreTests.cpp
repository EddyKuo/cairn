// tests/svc/ConfirmationTokenStoreTests.cpp
// prepare → execute 的 token 協定（SDD-03 §8.3.2）與回應層的可攜工具。純邏輯，不需管理員。
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

#include "base/IClock.h"
#include "response/ConfirmationTokenStore.h"
#include "response/FirewallResponder.h"
#include "response/ResponseJson.h"
#include "response/Sha256.h"

using namespace cairn;
using namespace cairn::response;

namespace {

// 決定性亂數：每次呼叫遞增，確保 token 不重複且可重現
struct CountingRandom {
    std::shared_ptr<uint8_t> counter = std::make_shared<uint8_t>(0);
    std::array<uint8_t, 16> operator()() const
    {
        std::array<uint8_t, 16> b{};
        b.fill(0xA5);
        b[15] = ++*counter;
        return b;
    }
};

TokenBinding MakeBinding(std::string hash = "h1", std::string typed = {})
{
    TokenBinding b;
    b.alertId       = 4821;
    b.actionName    = "terminate_process_tree";
    b.targetKey     = "{D4E5F6A7-0000-0000-2B3C-01DCF0A2B1A2}";
    b.impactHash    = std::move(hash);
    b.typedExpected = std::move(typed);
    b.peerSid       = "S-1-5-21-1";
    return b;
}

std::string ApiCode(const Status& st)
{
    return st ? std::string{} : RejectInfoOf(st.GetError()).code;
}

} // namespace

TEST(ConfirmationTokenStore, IssueFormatAndTtl)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    auto t = store.Issue(MakeBinding());
    ASSERT_TRUE(t);
    EXPECT_EQ(t.Value().token.rfind("ct_", 0), 0u);
    EXPECT_EQ(t.Value().token.size(), 3u + 32u);
    EXPECT_EQ(t.Value().expiresAt, clock.NowMs() + 60'000);
    EXPECT_EQ(store.Size(), 1u);
}

TEST(ConfirmationTokenStore, ConsumeIsOneShot)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding()).Value().token;
    EXPECT_TRUE(store.Consume(tok, MakeBinding(), {}));
    // 重放必失敗
    const auto again = store.Consume(tok, MakeBinding(), {});
    EXPECT_FALSE(again);
    EXPECT_EQ(ApiCode(again), "TOKEN_INVALID");
    EXPECT_EQ(store.Size(), 0u);
}

TEST(ConfirmationTokenStore, ExpiredTokenReturns410)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding()).Value().token;
    clock.Advance(60'000);   // 恰好到期（expiresAt <= now 視為過期）
    const auto st = store.Consume(tok, MakeBinding(), {});
    EXPECT_EQ(ApiCode(st), "TOKEN_EXPIRED");
    EXPECT_EQ(RejectInfoOf(st.GetError()).httpStatus, 410);
    EXPECT_EQ(store.Size(), 0u);
}

TEST(ConfirmationTokenStore, ImpactChangedReturns409AndInvalidatesToken)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding("before")).Value().token;
    const auto st  = store.Consume(tok, MakeBinding("after"), {});
    EXPECT_EQ(ApiCode(st), "IMPACT_CHANGED");
    EXPECT_EQ(RejectInfoOf(st.GetError()).httpStatus, 409);
    // 樹已變化：舊 token 不得再被使用，必須重新 prepare
    EXPECT_EQ(ApiCode(store.Consume(tok, MakeBinding("before"), {})), "TOKEN_INVALID");
}

TEST(ConfirmationTokenStore, DifferentCallerIsRejected)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding()).Value().token;
    auto other = MakeBinding();
    other.peerSid = "S-1-5-21-2";
    EXPECT_EQ(ApiCode(store.Consume(tok, other, {})), "TOKEN_BINDING_MISMATCH");
}

TEST(ConfirmationTokenStore, TypedConfirmationMismatchKeepsToken)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding("h", "winword.exe")).Value().token;
    const auto bad = store.Consume(tok, MakeBinding("h"), "winword");
    EXPECT_EQ(ApiCode(bad), "TYPED_CONFIRMATION_MISMATCH");
    EXPECT_EQ(RejectInfoOf(bad.GetError()).httpStatus, 400);
    EXPECT_EQ(store.Size(), 1u);   // 保留：使用者可在 TTL 內重打
    // 大小寫與前後空白不影響
    EXPECT_TRUE(store.Consume(tok, MakeBinding("h"), "  WinWord.EXE "));
}

TEST(ConfirmationTokenStore, LimitAndSweep)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}, /*maxTokens=*/3};
    for (int i = 0; i < 3; ++i) ASSERT_TRUE(store.Issue(MakeBinding()));
    const auto full = store.Issue(MakeBinding());
    ASSERT_FALSE(full);
    EXPECT_EQ(RejectInfoOf(full.GetError()).code, "TOKEN_LIMIT");
    clock.Advance(61'000);
    // 滿載時 Issue 會先清除過期者
    EXPECT_TRUE(store.Issue(MakeBinding()));
    EXPECT_EQ(store.Size(), 1u);
    clock.Advance(61'000);
    store.SweepExpired();
    EXPECT_EQ(store.Size(), 0u);
}

TEST(ConfirmationTokenStore, PeekDoesNotConsume)
{
    FakeClock clock;
    ConfirmationTokenStore store{clock, CountingRandom{}};
    const auto tok = store.Issue(MakeBinding()).Value().token;
    auto b = store.Peek(tok);
    ASSERT_TRUE(b);
    EXPECT_EQ(b.Value().alertId, 4821);
    EXPECT_EQ(store.Size(), 1u);
}

// ---- 回應層可攜工具 ----

TEST(ResponseJson, ComputeStatusSemantics)
{
    EXPECT_EQ(ComputeStatus({}), ActionStatus::Failed);
    EXPECT_EQ(ComputeStatus({{"a", "a", true, 0, ""}}), ActionStatus::Succeeded);
    EXPECT_EQ(ComputeStatus({{"a", "a", true, 0, ""}, {"b", "b", false, 5, "denied"}}), ActionStatus::PartiallySucceeded);
    EXPECT_EQ(ComputeStatus({{"b", "b", false, 5, "denied"}}), ActionStatus::Failed);
    EXPECT_EQ(HttpStatusOf(ActionStatus::PartiallySucceeded), 207);
    EXPECT_EQ(HttpStatusOf(ActionStatus::Failed), 502);
}

TEST(ResponseJson, ActionOrderIsSuspendQuarantineFirewallTerminate)
{
    using model::ActionKind;
    EXPECT_LT(ActionOrderRank(ActionKind::SuspendProcess), ActionOrderRank(ActionKind::QuarantineFile));
    EXPECT_LT(ActionOrderRank(ActionKind::QuarantineFile), ActionOrderRank(ActionKind::FirewallBlock));
    EXPECT_LT(ActionOrderRank(ActionKind::FirewallBlock), ActionOrderRank(ActionKind::TerminateProcessTree));
}

TEST(ResponseJson, ImpactHashIgnoresOrderAndLabels)
{
    ActionImpact a;
    ImpactItem x;
    x.key = "k1";
    x.label = "winword.exe (1)";
    x.ip = "1.2.3.4";
    ImpactItem y;
    y.key = "k2";
    y.ip = "5.6.7.8";
    a.items = {x, y};
    ActionImpact b;
    y.label = "different label";
    x.warning = "different warning";
    b.items = {y, x};
    EXPECT_EQ(ComputeImpactHash(1, model::ActionKind::FirewallBlock, a),
              ComputeImpactHash(1, model::ActionKind::FirewallBlock, b));
    b.items.pop_back();   // 少一個目標 → hash 必須改變
    EXPECT_NE(ComputeImpactHash(1, model::ActionKind::FirewallBlock, a),
              ComputeImpactHash(1, model::ActionKind::FirewallBlock, b));
    EXPECT_NE(ComputeImpactHash(1, model::ActionKind::FirewallBlock, a),
              ComputeImpactHash(2, model::ActionKind::FirewallBlock, a));
}

TEST(ResponseJson, Base64RoundTrip)
{
    for (std::string s : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        const auto enc = Base64Encode(s.data(), s.size());
        std::vector<uint8_t> dec;
        ASSERT_TRUE(Base64Decode(enc, dec));
        EXPECT_EQ(std::string(dec.begin(), dec.end()), s);
    }
    EXPECT_EQ(Base64Encode("foobar", 6), "Zm9vYmFy");
}

TEST(ResponseJson, Sha256KnownVectors)
{
    EXPECT_EQ(Sha256::HexOf(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(Sha256::HexOf("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(Sha256::HexOf(std::string(1000, 'a')),
              "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
}

TEST(FirewallNaming, RuleNameAndIpValidation)
{
    EXPECT_EQ(FirewallRuleName(4821, "185.0.0.1"), "Cairn - Block 4821 (185.0.0.1)");
    EXPECT_TRUE(IsValidIpLiteral("185.0.0.1"));
    EXPECT_TRUE(IsValidIpLiteral("2001:db8::1"));
    EXPECT_TRUE(IsValidIpLiteral("::1"));
    EXPECT_TRUE(IsValidIpLiteral("::ffff:192.0.2.1"));
    EXPECT_FALSE(IsValidIpLiteral("256.0.0.1"));
    EXPECT_FALSE(IsValidIpLiteral("1.2.3"));
    EXPECT_FALSE(IsValidIpLiteral("01.2.3.4"));
    EXPECT_FALSE(IsValidIpLiteral("*"));
    EXPECT_FALSE(IsValidIpLiteral("LocalSubnet"));
    EXPECT_FALSE(IsValidIpLiteral("1.2.3.4,5.6.7.8"));   // 防止一次封鎖多個位址的注入
    EXPECT_FALSE(IsValidIpLiteral("2001:db8:::1"));
}
