// ExclusionsTests —— 範圍排除、全域排除、glob、到期、規則自帶 exceptions（SDD-02 §5.5、§6.8 T-08）
#include <gtest/gtest.h>

#include <string>

#include "rules/Exclusions.h"
#include "rules/Rule.h"
#include "rules/RuleLoader.h"

using namespace cairn;
using namespace cairn::rules;
using K = cairn::model::ExclusionKind;

namespace {
ExclusionEntry E(int64_t id, K kind, std::string value, std::string scope = {})
{
    ExclusionEntry e;
    e.id          = id;
    e.kind        = kind;
    e.value       = std::move(value);
    e.scopeRuleId = std::move(scope);
    return e;
}

const ExclusionSubject kVeeam{"C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe", "ABCDEF", "Veeam Software Group GmbH",
                              "VeeamAgent.exe --job 1"};
} // namespace

TEST(ExclusionsTests, GlobalSignerSuppressesAnyRule)
{
    ExclusionSet s;
    s.Reload({E(7, K::Signer, "veeam software group gmbh")});
    auto r = s.IsSuppressed("R-T1486-001", {}, kVeeam, 0);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->exclusionId, 7);
}

TEST(ExclusionsTests, ScopedOnlyAffectsThatRule)
{
    ExclusionSet s;
    s.Reload({E(3, K::PathGlob, "c:\\program files\\veeam\\*", "R-T1486-001")});
    EXPECT_TRUE(s.IsSuppressed("R-T1486-001", {}, kVeeam, 0));
    EXPECT_FALSE(s.IsSuppressed("R-T1490-001", {}, kVeeam, 0));
}

TEST(ExclusionsTests, PathIsExactPathGlobIsWildcard)
{
    ExclusionSet s;
    s.Reload({E(1, K::Path, "C:\\Program Files\\Veeam\\Backup\\veeamagent.exe")});
    EXPECT_TRUE(s.IsSuppressed("R", {}, kVeeam, 0));
    s.Reload({E(1, K::Path, "C:\\Program Files\\Veeam\\")});
    EXPECT_FALSE(s.IsSuppressed("R", {}, kVeeam, 0));
}

TEST(ExclusionsTests, CmdlineGlobAndSha256AndRuleId)
{
    ExclusionSet s;
    s.Reload({E(1, K::CmdlineGlob, "*--job *")});
    EXPECT_TRUE(s.IsSuppressed("R", {}, kVeeam, 0));
    s.Reload({E(2, K::Sha256, "abcdef")});
    EXPECT_TRUE(s.IsSuppressed("R", {}, kVeeam, 0));
    s.Reload({E(3, K::RuleId, "R-T1053-001")});
    EXPECT_TRUE(s.IsSuppressed("R-T1053-001", {}, kVeeam, 0));
    EXPECT_FALSE(s.IsSuppressed("R-T1055-001", {}, kVeeam, 0));
}

TEST(ExclusionsTests, ExpiredAndDisabledEntriesIgnored)
{
    ExclusionSet s;
    auto e      = E(1, K::Signer, "veeam software group gmbh");
    e.expiresTs = 1000;
    auto d      = E(2, K::Sha256, "abcdef");
    d.enabled   = false;
    s.Reload({e, d});
    EXPECT_TRUE(s.IsSuppressed("R", {}, kVeeam, 999));
    EXPECT_FALSE(s.IsSuppressed("R", {}, kVeeam, 1000));
}

TEST(ExclusionsTests, RuleExceptionsHaveNoDbId)
{
    ExclusionSet s;
    std::vector<RuleException> ex{{K::Signer, "veeam software group gmbh"}};
    auto r = s.IsSuppressed("R-T1486-001", ex, kVeeam, 0);
    ASSERT_TRUE(r);
    EXPECT_FALSE(r->exclusionId.has_value());
    EXPECT_EQ(r->source, "rule_exception");
}

TEST(ExclusionsTests, EmptySubjectFieldsNeverMatch)
{
    ExclusionSet s;
    s.Reload({E(1, K::PathGlob, "*")});
    EXPECT_FALSE(s.IsSuppressed("R", {}, ExclusionSubject{}, 0)) << "缺值不構成命中";
}

// 內建排除範本：遠端存取工具只排除官方安裝目錄，同名的可攜版 / 偽冒檔不得被放行
TEST(ExclusionsTests, DefaultAnyDeskExclusionIsLimitedToInstallDir)
{
    auto r = LoadExclusionsYaml(std::string(CAIRN_RULES_DIR) + "/exclusions.default.yaml");
    ASSERT_TRUE(r) << r.GetError().ToString();
    ExclusionSet s;
    s.Reload(r.Value());

    const auto subject = [](std::string_view image) { return ExclusionSubject{image, "", "", ""}; };
    EXPECT_TRUE(s.IsSuppressed("R-T1219-001", {}, subject("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe"), 0));
    EXPECT_TRUE(s.IsSuppressed("R-T1219-001", {}, subject("C:\\Program Files\\AnyDesk\\AnyDesk.exe"), 0));
    EXPECT_FALSE(s.IsSuppressed("R-T1219-001", {}, subject("C:\\Users\\victim\\Downloads\\AnyDesk.exe"), 0));
    EXPECT_FALSE(s.IsSuppressed("R-T1219-001", {}, subject("C:\\Windows\\Temp\\AnyDesk.exe"), 0));
}
