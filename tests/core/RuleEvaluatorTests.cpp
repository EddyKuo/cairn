// RuleEvaluatorTests —— 每個運算子 × 命中 / 未命中 / 邊界；三值約定（缺欄位一律 false，含否定）
#include "RuleTestFixture.h"
#include "rules/Expr.h"
#include "rules/TextMatch.h"

using namespace cairn;
using cairn::test::RuleFixture;

namespace {
std::string Tier1(const std::string& event, const std::string& where)
{
    return "id: R-T9100-001\ntitle: t\nseverity: high\nstatus: enabled\nscore: 50\ndecay: 600s\n"
           "requires_events: [1]\nevent: " + event + "\nwhere:\n" + where;
}
} // namespace

class RuleEvaluatorTest : public RuleFixture {};

TEST_F(RuleEvaluatorTest, EndsWithAnyIsCaseInsensitive)
{
    Load(Tier1("PROCESS_CREATE", "  - field: image\n    op: ends_with_any\n    value: ['\\POWERSHELL.EXE', '\\pwsh.exe']\n"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(1, 0, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe", "")), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(2, 0, "C:\\Windows\\System32\\cmd.exe", "")), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, ContainsAndNotContains)
{
    Load(Tier1("PROCESS_CREATE",
               "  - field: command_line\n    op: contains\n    value: 'DownloadString'\n"
               "  - field: command_line\n    op: not_contains\n    value: 'trusted-update'\n"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(1, 0, "p.exe", "", "IEX (x).downloadstring('u')")), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(2, 0, "p.exe", "", "downloadstring trusted-update")), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, NegatedOperatorOnMissingFieldIsFalse)
{
    // command_line 缺值：not_contains 不得翻轉為 true（SDD-02 §5.4.6）
    Load(Tier1("PROCESS_CREATE", "  - field: command_line\n    op: not_contains\n    value: 'x'\n"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(1, 0, "p.exe", "")), "R-T9100-001"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(2, 0, "p.exe", "", "abc")), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, HasAnyMask)
{
    Load(Tier1("PROCESS_ACCESS",
               "  - field: granted_access\n    op: has_any\n    value: ['0x0010']\n"
               "  - field: target_image\n    op: ends_with\n    value: '\\lsass.exe'\n"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessAccess(1, "C:\\x\\procdump64.exe", "C:\\Windows\\System32\\lsass.exe", 0x1FFFFF)), "R-T9100-001"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessAccess(2, "C:\\x\\m.exe", "C:\\Windows\\System32\\lsass.exe", 0x1010)), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessAccess(3, "C:\\x\\t.exe", "C:\\Windows\\System32\\lsass.exe", 0x1000)), "R-T9100-001"))
        << "只有 QUERY_LIMITED_INFORMATION 不算";
}

TEST_F(RuleEvaluatorTest, InAndNotInIntegers)
{
    Load(Tier1("NETWORK_CONNECT", "  - field: dest_port\n    op: in\n    value: [4444, '8443']\n"));
    EXPECT_TRUE(HasRule(Feed(f.Network(1, "a.exe", "1.2.3.4", 4444)), "R-T9100-001"));
    EXPECT_TRUE(HasRule(Feed(f.Network(2, "a.exe", "1.2.3.4", 8443)), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.Network(3, "a.exe", "1.2.3.4", 443)), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, GtLtBoundaries)
{
    Load(Tier1("NETWORK_CONNECT",
               "  - field: dest_port\n    op: gt\n    value: 1024\n"
               "  - field: dest_port\n    op: lt\n    value: 2048\n"));
    EXPECT_FALSE(HasRule(Feed(f.Network(1, "a.exe", "1.1.1.1", 1024)), "R-T9100-001"));
    EXPECT_TRUE(HasRule(Feed(f.Network(2, "a.exe", "1.1.1.1", 1025)), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.Network(3, "a.exe", "1.1.1.1", 2048)), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, MatchesRegexIcaseWithPrefilter)
{
    Load(Tier1("PROCESS_CREATE",
               "  - field: command_line\n    op: matches\n"
               "    value: '(?i)vssadmin.*delete\\s+shadows'\n    prefilter: [vssadmin]\n"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(1, 0, "v.exe", "", "VSSADMIN.EXE Delete Shadows /all /quiet")), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(2, 0, "v.exe", "", "vssadmin list shadows")), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, AnyOfGroup)
{
    Load(Tier1("[PROCESS_CREATE, SCRIPT_BLOCK]",
               "  - any_of:\n"
               "      - field: command_line\n        op: contains\n        value: 'frombase64string'\n"
               "      - field: script_block\n        op: contains\n        value: 'invoke-mimikatz'\n"));
    EXPECT_TRUE(HasRule(Feed(f.ScriptBlock(1, "powershell.exe", "Invoke-Mimikatz -DumpCreds")), "R-T9100-001"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(2, 0, "p.exe", "", "[Convert]::FromBase64String('x')")), "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(3, 0, "p.exe", "", "Get-Date")), "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, BoolEqualsAndDerivedFields)
{
    Load(Tier1("PROCESS_CREATE",
               "  - field: image_in_user_writable_dir\n    op: equals\n    value: true\n"
               "  - field: parent_is_office\n    op: equals\n    value: true\n"));
    EXPECT_TRUE(HasRule(Feed(f.ProcessCreate(1, 0, "C:\\Users\\a\\AppData\\Local\\Temp\\x.exe",
                                             "C:\\Program Files\\Office\\WINWORD.EXE")),
                        "R-T9100-001"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(2, 0, "C:\\Windows\\System32\\x.exe",
                                              "C:\\Program Files\\Office\\WINWORD.EXE")),
                         "R-T9100-001"));
}

TEST_F(RuleEvaluatorTest, EventTypeIndexSkipsUnrelatedRules)
{
    Load(Tier1("REMOTE_THREAD", "  - field: image\n    op: ends_with\n    value: '.exe'\n"));
    EXPECT_FALSE(HasRule(Feed(f.ProcessCreate(1, 0, "a.exe", "")), "R-T9100-001"));
    EXPECT_TRUE(engine.Rules()->RulesFor(model::EventType::ProcessCreate).empty());
    EXPECT_EQ(engine.Rules()->RulesFor(model::EventType::CreateRemoteThread).size(), 1u);
}

TEST(TextMatchTests, GlobAndCaseInsensitive)
{
    using namespace cairn::rules;
    EXPECT_TRUE(GlobMatchCi("C:\\Program Files\\Veeam\\Backup\\x.exe", "c:\\program files\\*\\backup*\\*"));
    EXPECT_TRUE(GlobMatchCi("abc", "a?c"));
    EXPECT_FALSE(GlobMatchCi("abd", "a?c"));
    EXPECT_TRUE(GlobMatchCi("", "*"));
    EXPECT_FALSE(GlobMatchCi("abc", ""));
    EXPECT_TRUE(ContainsCi("Hello WORLD", "o wor"));
    EXPECT_TRUE(EndsWithCi("C:\\X\\A.EXE", "\\a.exe"));
    EXPECT_FALSE(StartsWithCi("ab", "abc"));
}
