// StringInternerTests / GuidValueTests / EventTypeTests —— core.common 的地基型別
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "model/EventType.h"
#include "model/GuidValue.h"
#include "model/StringInterner.h"

using namespace cairn::model;

// ---------------- StringInterner ----------------
TEST(StringInternerTests, SameStringSameId)
{
    StringInterner in;
    const auto a = in.Intern("c:\\windows\\system32\\cmd.exe");
    const auto b = in.Intern("c:\\windows\\system32\\cmd.exe");
    const auto c = in.Intern("c:\\windows\\explorer.exe");
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
    EXPECT_EQ(in.Resolve(a), "c:\\windows\\system32\\cmd.exe");
    EXPECT_EQ(in.Size(), 2u);
}

TEST(StringInternerTests, InternLowerFoldsCase)
{
    StringInterner in;
    EXPECT_EQ(in.InternLower("C:\\Windows\\CMD.EXE"), in.InternLower("c:\\windows\\cmd.exe"));
    EXPECT_EQ(in.Resolve(in.InternLower("ABC")), "abc");
}

TEST(StringInternerTests, CapacityLimitReturnsInvalid)
{
    StringInterner in(3);
    EXPECT_NE(in.Intern("a"), kInvalidInternId);
    EXPECT_NE(in.Intern("b"), kInvalidInternId);
    EXPECT_NE(in.Intern("c"), kInvalidInternId);
    EXPECT_EQ(in.Intern("d"), kInvalidInternId);
    EXPECT_TRUE(in.IsSaturated());
    EXPECT_NE(in.Intern("a"), kInvalidInternId) << "既有字串在飽和後仍可查到";
    EXPECT_TRUE(in.Resolve(kInvalidInternId).empty());
}

TEST(StringInternerTests, DequeKeepsViewsValidAcrossGrowth)
{
    StringInterner in;
    const auto first = in.Intern("first-string-that-is-long-enough-to-allocate");
    const std::string_view v = in.Resolve(first);
    for (int i = 0; i < 20'000; ++i) (void)in.Intern("s" + std::to_string(i));
    EXPECT_EQ(v, "first-string-that-is-long-enough-to-allocate") << "deque 擴容不得使既有 string_view 失效";
}

TEST(StringInternerTests, FindDoesNotInsert)
{
    StringInterner in;
    EXPECT_EQ(in.Find("x"), kInvalidInternId);
    EXPECT_EQ(in.Size(), 0u);
}

// ---------------- GuidValue ----------------
TEST(GuidValueTests, ParseAndRoundTrip)
{
    const auto g = GuidValue::Parse("{A1B2C3D4-E5F6-1234-5678-9ABCDEF01234}");
    ASSERT_TRUE(g.has_value());
    EXPECT_EQ(g->ToString(), "{A1B2C3D4-E5F6-1234-5678-9ABCDEF01234}");
    EXPECT_EQ(GuidValue::Parse(g->ToString()), g);
}

TEST(GuidValueTests, ParseAcceptsLowercaseAndNoBraces)
{
    const auto a = GuidValue::Parse("a1b2c3d4-e5f6-1234-5678-9abcdef01234");
    const auto b = GuidValue::Parse("{A1B2C3D4-E5F6-1234-5678-9ABCDEF01234}");
    ASSERT_TRUE(a && b);
    EXPECT_EQ(*a, *b);
}

TEST(GuidValueTests, ParseRejectsMalformed)
{
    EXPECT_FALSE(GuidValue::Parse(""));
    EXPECT_FALSE(GuidValue::Parse("{A1B2C3D4-E5F6-1234-5678-9ABCDEF0123}"));
    EXPECT_FALSE(GuidValue::Parse("{A1B2C3D4XE5F6-1234-5678-9ABCDEF01234}"));
    EXPECT_FALSE(GuidValue::Parse("{G1B2C3D4-E5F6-1234-5678-9ABCDEF01234}"));
}

TEST(GuidValueTests, NullAndHash)
{
    GuidValue z;
    EXPECT_TRUE(z.IsNull());
    const auto g = GuidValue::Parse("{00000000-0000-0000-0000-000000000001}");
    ASSERT_TRUE(g);
    EXPECT_FALSE(g->IsNull());
    EXPECT_NE(std::hash<GuidValue>{}(z), std::hash<GuidValue>{}(*g));
}

// ---------------- EventType ----------------
TEST(EventTypeTests, SysmonEidMapping)
{
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 1), EventType::ProcessCreate);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 8), EventType::CreateRemoteThread);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 23), EventType::FileDelete);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 26), EventType::FileDelete);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::PowerShell, 4104), EventType::ScriptBlock);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 4104), EventType::Unknown);
    EXPECT_EQ(EventTypeFromEid(EventSourceKind::Sysmon, 999), EventType::Unknown);
}

TEST(EventTypeTests, DbStringsRoundTrip)
{
    // part4 W1 出場條件 3 依賴這四個字串
    EXPECT_EQ(EventTypeToString(EventType::ProcessCreate), "PROCESS_CREATE");
    EXPECT_EQ(EventTypeToString(EventType::NetworkConnect), "NETWORK_CONNECT");
    EXPECT_EQ(EventTypeToString(EventType::RegistrySet), "REGISTRY_SET");
    EXPECT_EQ(EventTypeToString(EventType::DnsQuery), "DNS_QUERY");
    for (size_t i = 0; i < kEventTypeCount; ++i) {
        const auto t = static_cast<EventType>(i);
        EXPECT_EQ(EventTypeFromString(EventTypeToString(t)), t);
    }
}
