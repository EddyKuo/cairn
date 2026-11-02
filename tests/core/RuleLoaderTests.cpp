// RuleLoaderTests —— 規則包載入、schema / 語意錯誤只讓單條規則失敗、狀態覆寫、排除清單 YAML
#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "rules/RuleCompiler.h"
#include "rules/RuleLoader.h"

using namespace cairn;
using namespace cairn::rules;

namespace {
const char* kMinimalRule = R"(
id: R-T9000-001
title: 測試規則
severity: high
status: enabled
score: 50
decay: 600s
requires_events: [1]
event: PROCESS_CREATE
where:
  - field: image
    op: ends_with
    value: '\evil.exe'
)";

Result<RuleLoadReport> LoadOne(const std::string& text, model::StringInterner& in, RuleLoadOptions opts = {})
{
    return LoadRuleTexts({{"test.yaml", text}}, in, opts);
}
} // namespace

TEST(RuleLoaderTests, ShippedRulePackLoadsCompletely)
{
    model::StringInterner in;
    auto r = LoadRuleDirectory(CAIRN_RULES_DIR, in);
    ASSERT_TRUE(r) << r.GetError().ToString();
    const auto& rep = r.Value();
    for (const auto& i : rep.rules) EXPECT_TRUE(i.loadError.empty()) << i.id << ": " << i.loadError;
    EXPECT_TRUE(rep.fileErrors.empty());
    EXPECT_EQ(rep.failed, 0u);
    EXPECT_EQ(rep.loaded, 19u) << "12 條首批 + 7 條延伸矩陣（R-T1486-002 canary 留 M1）";
    ASSERT_TRUE(rep.ruleSet);
    EXPECT_EQ(rep.ruleSet->Size(), 19u);

    // 紅隊矩陣必過項對應的規則必須存在且 enabled（dryrun 不產生告警，不得列為通過項）
    for (const char* id : {"R-T1055-002", "R-T1486-001", "R-T1490-001", "R-T1003-001", "R-T1547-001"}) {
        const Rule* rule = rep.ruleSet->Find(id);
        ASSERT_NE(rule, nullptr) << id;
        EXPECT_EQ(rule->status, model::RuleStatus::Enabled) << id;
    }
    // part2 §2.5 首發 dryrun 的首批規則
    EXPECT_EQ(rep.ruleSet->Find("R-T1053-001")->status, model::RuleStatus::DryRun);
    EXPECT_EQ(rep.ruleSet->Find("R-T1071-001")->status, model::RuleStatus::DryRun);
    EXPECT_EQ(rep.ruleSet->Find("R-T1486-002"), nullptr) << "canary 已移出 M0";
}

TEST(RuleLoaderTests, ShippedRansomwareRuleShape)
{
    model::StringInterner in;
    auto r = LoadRuleDirectory(CAIRN_RULES_DIR, in);
    ASSERT_TRUE(r);
    const Rule* rule = r.Value().ruleSet->Find("R-T1486-001");
    ASSERT_NE(rule, nullptr);
    EXPECT_EQ(rule->scoreMilli, 95'000);
    EXPECT_EQ(rule->steps.size(), 2u);
    ASSERT_TRUE(rule->steps[0].threshold.has_value());
    EXPECT_EQ(rule->steps[0].threshold->count, 30u);
    EXPECT_EQ(rule->steps[1].threshold->count, 20u);
    EXPECT_EQ(rule->boosters.size(), 2u);
    ASSERT_EQ(rule->steps[0].exports.size(), 1u) << "delete_originals 引用 mass_write.process_guid";
    EXPECT_EQ(rule->steps[0].exports[0], FieldId::ProcessGuid);
    EXPECT_EQ(rule->hashHex.size(), 16u);
}

TEST(RuleLoaderTests, MinimalRuleCompiles)
{
    model::StringInterner in;
    auto r = LoadOne(kMinimalRule, in);
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_EQ(r.Value().loaded, 1u);
    const Rule& rule = r.Value().ruleSet->At(0);
    EXPECT_EQ(rule.scoreMilli, 50'000);
    EXPECT_EQ(rule.halfLifeMs, 600'000u);
    EXPECT_FALSE(rule.IsSequence());
    EXPECT_TRUE(rule.triggerMask.test(static_cast<size_t>(model::EventType::ProcessCreate)));
}

TEST(RuleLoaderTests, OneBadRuleDoesNotTakeDownOthers)
{
    model::StringInterner in;
    std::string text = kMinimalRule;
    text += R"(
---
id: BAD-ID
title: 壞規則
severity: high
score: 50
decay: 600s
requires_events: [1]
event: PROCESS_CREATE
)";
    auto r = LoadOne(text, in);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().loaded, 1u);
    EXPECT_EQ(r.Value().failed, 1u);
    const auto bad = std::find_if(r.Value().rules.begin(), r.Value().rules.end(),
                                  [](const RuleInfo& i) { return i.id == "BAD-ID"; });
    ASSERT_NE(bad, r.Value().rules.end());
    EXPECT_FALSE(bad->loadError.empty());
}

TEST(RuleLoaderTests, UnknownFieldRejected)
{
    model::StringInterner in;
    std::string text = kMinimalRule;
    text.replace(text.find("field: image"), 12, "field: imagez");
    auto r = LoadOne(text, in);
    EXPECT_FALSE(r);
    EXPECT_EQ(r.Code(), ErrorCode::NoRulesLoaded);
}

TEST(RuleLoaderTests, EqualsRefToLaterStepRejected)
{
    model::StringInterner in;
    auto r = LoadOne(R"(
id: R-T9000-002
title: ref 錯誤
severity: high
score: 50
decay: 600s
requires_events: [1, 8]
sequence:
  within: 60s
  correlate_by: process_tree_root
  steps:
    - id: a
      event: PROCESS_CREATE
      where:
        - field: process_guid
          op: equals_ref
          value: b.process_guid
    - id: b
      event: REMOTE_THREAD
)", in);
    EXPECT_FALSE(r);
}

TEST(RuleLoaderTests, ThresholdWithinLargerThanSequenceRejected)
{
    model::StringInterner in;
    auto r = LoadOne(R"(
id: R-T9000-003
title: threshold 錯誤
severity: high
score: 50
decay: 600s
requires_events: [11]
sequence:
  within: 30s
  correlate_by: process_tree_root
  steps:
    - id: a
      event: FILE_CREATE
      threshold: {count: 5, within: 60s}
)", in);
    EXPECT_FALSE(r);
}

TEST(RuleLoaderTests, YamlSyntaxErrorReportedAsFileError)
{
    model::StringInterner in;
    auto r = LoadRuleTexts({{"broken.yaml", "id: [unterminated"}, {"ok.yaml", kMinimalRule}}, in);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().fileErrors.size(), 1u);
    EXPECT_EQ(r.Value().loaded, 1u) << "語法錯誤的檔案不影響其他檔案";
}

TEST(RuleLoaderTests, StatusOverridesAndForceDryRun)
{
    model::StringInterner in;
    RuleLoadOptions o;
    o.overrides["R-T9000-001"] = model::RuleStatus::Disabled;
    auto r = LoadOne(kMinimalRule, in, o);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().ruleSet->At(0).status, model::RuleStatus::Disabled);
    EXPECT_EQ(r.Value().rules[0].declaredStatus, "enabled");
    EXPECT_TRUE(r.Value().ruleSet->RulesFor(model::EventType::ProcessCreate).empty()) << "disabled 不建索引";

    RuleLoadOptions dry;
    dry.forceDryRun = true;
    auto r2 = LoadOne(kMinimalRule, in, dry);
    ASSERT_TRUE(r2);
    EXPECT_EQ(r2.Value().ruleSet->At(0).status, model::RuleStatus::DryRun);
}

TEST(RuleLoaderTests, ContentHashIgnoresCommentsButTracksContent)
{
    model::StringInterner in;
    auto a = LoadOne(kMinimalRule, in);
    auto b = LoadOne(std::string("# 註解\n") + kMinimalRule, in);
    std::string changed = kMinimalRule;
    changed.replace(changed.find("score: 50"), 9, "score: 51");
    auto c = LoadOne(changed, in);
    ASSERT_TRUE(a && b && c);
    EXPECT_EQ(a.Value().ruleSet->At(0).contentHash, b.Value().ruleSet->At(0).contentHash);
    EXPECT_NE(a.Value().ruleSet->At(0).contentHash, c.Value().ruleSet->At(0).contentHash);
}

TEST(RuleLoaderTests, DurationAndIdParsing)
{
    EXPECT_EQ(ParseDurationMs("600s"), 600'000);
    EXPECT_EQ(ParseDurationMs("10m"), 600'000);
    EXPECT_FALSE(ParseDurationMs("10h"));
    EXPECT_FALSE(ParseDurationMs("s"));
    EXPECT_TRUE(IsValidRuleId("R-T1055-001"));
    EXPECT_TRUE(IsValidRuleId("R-T1566.001-002"));
    EXPECT_FALSE(IsValidRuleId("R-T1055-01"));
    EXPECT_FALSE(IsValidRuleId("MYEDR-T1055-001"));
}

TEST(RuleLoaderTests, DefaultExclusionsParse)
{
    auto r = LoadExclusionsYaml(std::string(CAIRN_RULES_DIR) + "/exclusions.default.yaml");
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_GT(r.Value().size(), 10u);
    for (const auto& e : r.Value()) {
        EXPECT_EQ(e.createdBy, "builtin");
        EXPECT_FALSE(e.value.empty());
    }
}

TEST(RuleLoaderTests, MissingDirectoryIsNotFound)
{
    model::StringInterner in;
    auto r = LoadRuleDirectory("/definitely/not/here", in);
    EXPECT_EQ(r.Code(), ErrorCode::NotFound);
}
