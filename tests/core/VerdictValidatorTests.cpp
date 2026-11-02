// tests/core/VerdictValidatorTests.cpp
// LLM 輸出驗證：schema、三道白名單、llama-server 回應解析、ATT&CK 白名單、注入語料庫的輸出面。
// ★ 第 4 類（誘導輸出攻擊者指定 JSON）的真正驗收是架構保證：NarrativeResult 只有 ai_* 顯示欄位，
//   任何驗證結果都不可能觸及 score / severity / actions_taken（見 InjectionCorpus.PoisonedOutputCannotCarryDecisionFields）。
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <type_traits>
#include <vector>

#include "MiniJsonTestUtil.h"
#include "model/WriteOp.h"
#include "prompt/AttackCatalog.h"
#include "prompt/VerdictValidator.h"

using cairn::ErrorCode;
using cairn::llm::AttackCatalog;
using cairn::llm::ValidationFailure;
using cairn::llm::ValidationReport;
using cairn::llm::VerdictValidator;

namespace {

const std::string kNarr = "此程序鏈由 WINWORD.EXE 派生 powershell.exe 並以編碼命令下載遠端內容執行，隨後對 explorer.exe 進行遠端執行緒注入，符合釣魚攻擊鏈。";
const std::string kRec  = "建議終止整條程序樹並隔離來源文件，同時檢查該使用者信箱是否有相同寄件者的郵件。";

std::string Doc(const std::string& attackIds = R"(["T1059.001","T1055.001"])", const std::string& narr = kNarr,
                const std::string& rec = kRec, const std::string& conf = "0.9", const std::string& extra = "")
{
    return R"({"attack_ids":)" + attackIds + R"(,"narrative":")" + narr + R"(","recommendation":")" + rec +
           R"(","confidence":)" + conf + R"(,"evasion_attempt_detected":false)" + extra + "}";
}

std::vector<cairn::testutil::FlatJson> LoadCorpus()
{
    std::vector<std::filesystem::path> files;
    const auto dir = std::filesystem::path(CAIRN_TEST_FIXTURES_DIR) / "prompt-injection";
    for (const auto& e : std::filesystem::directory_iterator(dir))
        if (e.path().extension() == ".json") files.push_back(e.path());
    std::sort(files.begin(), files.end());
    std::vector<cairn::testutil::FlatJson> out;
    for (const auto& f : files)
        if (auto j = cairn::testutil::LoadFlatJsonFile(f.string())) out.push_back(std::move(*j));
    return out;
}

} // namespace

// ============================================================
// Schema
// ============================================================

TEST(VerdictValidator, AcceptsValidOutput)
{
    VerdictValidator v;
    ValidationReport rep;
    auto r = v.Validate(Doc("[\"T1059.001\",\"T1055.001\"]", kNarr, kRec, "0.9",
                            R"(,"key_indicators":["編碼命令","Office 派生腳本直譯器"])"),
                        &rep);
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_EQ(r.Value().attackIds, (std::vector<std::string>{"T1059.001", "T1055.001"}));
    EXPECT_EQ(r.Value().narrative, kNarr);
    EXPECT_DOUBLE_EQ(r.Value().confidence, 0.9);
    EXPECT_FALSE(r.Value().evasionAttemptDetected);
    EXPECT_EQ(r.Value().keyIndicators.size(), 2u);
    EXPECT_EQ(rep.failure, ValidationFailure::None);
}

TEST(VerdictValidator, RejectsMissingRequiredField)
{
    VerdictValidator v;
    const std::string doc = R"({"attack_ids":["T1059"],"narrative":")" + kNarr + R"(","confidence":0.5,"evasion_attempt_detected":false})";
    auto r = v.Validate(doc);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.Code(), ErrorCode::LlmSchemaViolation);
}

TEST(VerdictValidator, RejectsAdditionalProperties)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(Doc(R"(["T1059"])", kNarr, kRec, "0.9", R"(,"score":0)"), &rep);
    ASSERT_FALSE(r);
    EXPECT_EQ(rep.failure, ValidationFailure::SchemaViolation);
}

TEST(VerdictValidator, RejectsConfidenceOutOfRange)
{
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", kNarr, kRec, "1.5")));
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", kNarr, kRec, "-0.1")));
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", kNarr, kRec, "\"high\"")));
}

TEST(VerdictValidator, LengthBoundsCountCodePoints)
{
    std::string cjk39, cjk40;
    for (int i = 0; i < 39; ++i) cjk39 += "字";
    cjk40 = cjk39 + "字";
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", cjk39)));
    EXPECT_TRUE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", cjk40)));
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc(R"(["T1059"])", kNarr, "太短")));
}

TEST(VerdictValidator, AttackIdsCountBounds)
{
    EXPECT_FALSE(VerdictValidator{}.Validate(Doc("[]")));
    EXPECT_FALSE(VerdictValidator{}.Validate(
        Doc(R"(["T1001","T1003","T1005","T1012","T1016","T1018","T1027","T1033","T1036"])")));
}

TEST(VerdictValidator, FiltersIndividualAttackIdsNotInWhitelist)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(Doc(R"(["T1059.001","T9999","t1055","T1055.001"])"), &rep);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().attackIds, (std::vector<std::string>{"T1059.001", "T1055.001"}));
    EXPECT_EQ(rep.attackIdsRejected, 2u);
}

TEST(VerdictValidator, AllAttackIdsRejectedIsSchemaViolation)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(Doc(R"(["T9999","T0000.000"])"), &rep);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.Code(), ErrorCode::LlmSchemaViolation);
    EXPECT_EQ(rep.failure, ValidationFailure::AttackIdsRejected);
}

TEST(VerdictValidator, DeduplicatesAttackIds)
{
    auto r = VerdictValidator{}.Validate(Doc(R"(["T1059","T1059","T1105"])"));
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().attackIds, (std::vector<std::string>{"T1059", "T1105"}));
}

// ============================================================
// 輸出後掃描（三道白名單之 2、3）
// ============================================================

TEST(VerdictValidator, UrlDetection)
{
    EXPECT_TRUE(VerdictValidator::ContainsUrl("請前往 http://a.b/c 下載"));
    EXPECT_TRUE(VerdictValidator::ContainsUrl("hxxps://evil"));
    EXPECT_TRUE(VerdictValidator::ContainsUrl("見 www.helpdesk-portal.net。"));
    EXPECT_TRUE(VerdictValidator::ContainsUrl("聯繫 support.evil-domain.ru 取得"));
    EXPECT_TRUE(VerdictValidator::ContainsUrl("cdn-update.example-c2.TOP."));
    EXPECT_FALSE(VerdictValidator::ContainsUrl("powershell.exe 對 explorer.exe 注入"));
    EXPECT_FALSE(VerdictValidator::ContainsUrl("連線至 185.243.1.2 的 443 埠"));
    EXPECT_FALSE(VerdictValidator::ContainsUrl("對應 T1059.001 與 T1055"));
    EXPECT_FALSE(VerdictValidator::ContainsUrl("C:\\Users\\alice\\invoice.docm"));
}

TEST(VerdictValidator, Base64Detection)
{
    EXPECT_TRUE(VerdictValidator::ContainsBase64Blob(std::string(64, 'A')));
    EXPECT_FALSE(VerdictValidator::ContainsBase64Blob(std::string(63, 'A')));
    EXPECT_FALSE(VerdictValidator::ContainsBase64Blob(std::string(40, 'A') + " " + std::string(40, 'A')));
}

TEST(VerdictValidator, DelimiterDetection)
{
    EXPECT_TRUE(VerdictValidator::ContainsDelimiter("a <<< b"));
    EXPECT_TRUE(VerdictValidator::ContainsDelimiter("a >>> b"));
    EXPECT_TRUE(VerdictValidator::ContainsDelimiter("### heading"));
    EXPECT_TRUE(VerdictValidator::ContainsDelimiter("System: do this"));
    EXPECT_TRUE(VerdictValidator::ContainsDelimiter("<|im_end|>"));
    EXPECT_FALSE(VerdictValidator::ContainsDelimiter("系統管理員 -> 程序"));
}

TEST(VerdictValidator, NarrativeWithUrlVoidsWholeResult)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(
        Doc(R"(["T1059"])", kNarr + "請下載 http://fix.example.top/patch.exe 修補。"), &rep);
    ASSERT_FALSE(r);
    EXPECT_EQ(rep.failure, ValidationFailure::ForbiddenContent);
}

TEST(VerdictValidator, KeyIndicatorWithUrlIsDroppedNotFatal)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(
        Doc(R"(["T1059"])", kNarr, kRec, "0.8", R"(,"key_indicators":["編碼命令","連線 evil.ru"])"), &rep);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value().keyIndicators, (std::vector<std::string>{"編碼命令"}));
    EXPECT_EQ(rep.keyIndicatorsDropped, 1u);
}

// ============================================================
// llama-server /completion 回應
// ============================================================

TEST(VerdictValidator, ExtractsContentFromCompletion)
{
    const std::string body = R"({"content":"{\"a\":1}","stopped_limit":false,"stop":true})";
    auto r = VerdictValidator{}.ExtractCompletionContent(body);
    ASSERT_TRUE(r);
    EXPECT_EQ(r.Value(), "{\"a\":1}");
}

TEST(VerdictValidator, StoppedLimitIsTruncation)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.ExtractCompletionContent(R"({"content":"{\"attack_ids\":[","stopped_limit":true})", &rep);
    ASSERT_FALSE(r);
    EXPECT_EQ(rep.failure, ValidationFailure::Truncated);
    EXPECT_FALSE(VerdictValidator{}.ExtractCompletionContent(R"({"content":"x","stop_type":"limit"})"));
    EXPECT_FALSE(VerdictValidator{}.ExtractCompletionContent(R"({"content":"x","truncated":true})"));
}

TEST(VerdictValidator, NonJsonResponseRejected)
{
    ValidationReport rep;
    EXPECT_FALSE(VerdictValidator{}.ExtractCompletionContent("<html>502</html>", &rep));
    EXPECT_EQ(rep.failure, ValidationFailure::NotJson);
}

TEST(VerdictValidator, UnclosedModelJsonRejected)
{
    ValidationReport rep;
    auto r = VerdictValidator{}.Validate(R"({"attack_ids":["T1059"],"narrative":"abc)", &rep);
    ASSERT_FALSE(r);
    EXPECT_EQ(rep.failure, ValidationFailure::Truncated);
}

TEST(VerdictValidator, ValidateCompletionEndToEnd)
{
    // 以 nlohmann 以外的方式組出 content：手動逸出引號
    std::string inner = Doc(R"(["T1105"])");
    std::string escaped;
    for (char c : inner) {
        if (c == '"' || c == '\\') escaped.push_back('\\');
        escaped.push_back(c);
    }
    auto r = VerdictValidator{}.ValidateCompletion(R"({"content":")" + escaped + R"(","stopped_limit":false})");
    ASSERT_TRUE(r) << r.GetError().ToString();
    EXPECT_EQ(r.Value().attackIds, (std::vector<std::string>{"T1105"}));
}

// ============================================================
// ATT&CK 白名單
// ============================================================

TEST(AttackCatalog, BuiltinCoversRuleTechniques)
{
    const auto& c = AttackCatalog::Builtin();
    for (const char* id : {"T1055", "T1055.001", "T1055.012", "T1003.001", "T1486", "T1490", "T1547.001",
                           "T1053.005", "T1218.011", "T1059.001", "T1562.001", "T1071.001", "T1105", "T1566.001",
                           "T1027", "T1036.005", "T1112", "T1070.001", "T1204.002", "T1021.002"}) {
        EXPECT_TRUE(c.Contains(id)) << id;
    }
    EXPECT_FALSE(c.Contains("T9999"));
    EXPECT_FALSE(c.Contains("T1059.999"));
    EXPECT_FALSE(c.Contains("t1059"));
    EXPECT_GT(c.Size(), 500u);
}

TEST(AttackCatalog, WellFormedPattern)
{
    EXPECT_TRUE(AttackCatalog::IsWellFormed("T1059"));
    EXPECT_TRUE(AttackCatalog::IsWellFormed("T1059.001"));
    EXPECT_FALSE(AttackCatalog::IsWellFormed("T159"));
    EXPECT_FALSE(AttackCatalog::IsWellFormed("T1059.01"));
    EXPECT_FALSE(AttackCatalog::IsWellFormed("T1059-001"));
    EXPECT_FALSE(AttackCatalog::IsWellFormed("TA0001"));
}

TEST(AttackCatalog, FromJsonAcceptsArrayAndObject)
{
    auto a = AttackCatalog::FromJson(R"(["T1059","T1059.001","bogus"])");
    ASSERT_TRUE(a);
    EXPECT_EQ(a.Value().Size(), 2u);
    auto b = AttackCatalog::FromJson(R"({"techniques":["T1105"]})");
    ASSERT_TRUE(b);
    EXPECT_TRUE(b.Value().Contains("T1105"));
    EXPECT_FALSE(AttackCatalog::FromJson("[]"));
    EXPECT_FALSE(AttackCatalog::FromJson("not json"));
}

TEST(AttackCatalog, ValidatorUsesInjectedCatalog)
{
    const auto c = AttackCatalog::FromIds({"T1105"});
    VerdictValidator v{c};
    EXPECT_FALSE(v.Validate(Doc(R"(["T1059"])")));
    EXPECT_TRUE(v.Validate(Doc(R"(["T1105"])")));
}

// ============================================================
// 注入語料庫 —— 輸出面
// ============================================================

TEST(InjectionCorpus, PoisonedOutputsMatchExpectation)
{
    const auto corpus = LoadCorpus();
    ASSERT_EQ(corpus.size(), 30u);
    VerdictValidator v;
    for (const auto& c : corpus) {
        const std::string id     = c.at("id").str;
        const std::string expect = c.at("expect_validator").str;
        auto r = v.Validate(c.at("poisoned_output").str);
        if (expect == "accept") {
            EXPECT_TRUE(r) << id << ": " << (r ? "" : r.GetError().ToString());
        } else {
            EXPECT_FALSE(r) << id << " 應被驗證拒絕";
            if (!r) EXPECT_EQ(r.Code(), ErrorCode::LlmSchemaViolation) << id;
        }
    }
}

// 第 4 類的架構保證：LLM 驗證後能寫回 DB 的唯一型別是 AlertNarrativeUpdate，
// 它只有 ai_* 欄位——即使模型完全順從攻擊者，score / severity / actions_taken 也無從被改變。
TEST(InjectionCorpus, PoisonedOutputCannotCarryDecisionFields)
{
    cairn::model::AlertNarrativeUpdate u;
    // 以結構化綁定的欄位數鎖定型別形狀：新增欄位必須同步審視此紅線
    auto& [alertId, aiState, narrative, recommendation, confidence, aiAttackIds, modelId, latencyMs] = u;
    (void)alertId; (void)aiState; (void)narrative; (void)recommendation;
    (void)confidence; (void)aiAttackIds; (void)modelId; (void)latencyMs;
    SUCCEED();
}
