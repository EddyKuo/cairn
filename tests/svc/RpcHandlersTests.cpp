// tests/svc/RpcHandlersTests.cpp
// 整合層的可攜邏輯：UI 契約 JSON 轉換、時間解析、設定解析、持久狀態、undo、AnalysisTasks、錯誤映射。
// 不需 Win32、不需資料庫。
#include <gtest/gtest.h>

#include <limits>
#include <thread>

#include "host/AnalysisTasks.h"
#include "host/HostState.h"
#include "host/PolicyConfig.h"
#include "host/handlers/Convert.h"

using namespace cairn;
using namespace cairn::host;
using Json = nlohmann::json;

// ============================================================ 時間 / 分數

TEST(RpcConvert, IsoRoundTrip)
{
    EXPECT_EQ(conv::Iso(0), "1970-01-01T00:00:00.000Z");
    EXPECT_EQ(conv::Iso(1'755'584'769'331), "2025-08-19T06:26:09.331Z");
    const int64_t t = 1'789'000'123'456;
    EXPECT_EQ(conv::ParseIso(conv::Iso(t)).value_or(-1), t);
}

TEST(RpcConvert, ParseIsoVariants)
{
    EXPECT_EQ(conv::ParseIso("1970-01-01T00:00:00Z").value_or(-1), 0);
    EXPECT_EQ(conv::ParseIso("1970-01-01T08:00:00+08:00").value_or(-1), 0);
    EXPECT_EQ(conv::ParseIso("1970-01-01T00:00:01.5Z").value_or(-1), 1500);
    EXPECT_EQ(conv::ParseIso("1970-01-02").value_or(-1), 86'400'000);
    EXPECT_FALSE(conv::ParseIso("2026-13-01T00:00:00Z").has_value());
    EXPECT_FALSE(conv::ParseIso("not a date").has_value());
    EXPECT_FALSE(conv::ParseIso("2026-01-01T00:00:00Zjunk").has_value());
}

TEST(RpcConvert, ParseTimeAcceptsNumberAndString)
{
    EXPECT_EQ(conv::ParseTime(Json(1234)).value_or(-1), 1234);
    EXPECT_EQ(conv::ParseTime(Json("1234")).value_or(-1), 1234);
    EXPECT_EQ(conv::ParseTime(Json("1970-01-01T00:00:01Z")).value_or(-1), 1000);
    EXPECT_FALSE(conv::ParseTime(Json(true)).has_value());
}

TEST(RpcConvert, ScoreDisplayRoundsAndClamps)
{
    EXPECT_EQ(conv::ScoreDisplay(80'000), 80);
    EXPECT_EQ(conv::ScoreDisplay(79'500), 80);
    EXPECT_EQ(conv::ScoreDisplay(79'499), 79);
    EXPECT_EQ(conv::ScoreDisplay(250'000), 100);
    EXPECT_EQ(conv::ScoreDisplay(-5'000), 0);
}

TEST(RpcConvert, NarrativeStateMapping)
{
    EXPECT_EQ(conv::NarrativeStateOf("ok"), "ready");
    EXPECT_EQ(conv::NarrativeStateOf("schema_violation"), "failed");
    EXPECT_EQ(conv::NarrativeStateOf("timeout"), "timeout");
    EXPECT_EQ(conv::NarrativeStateOf(""), "pending");
}

// ============================================================ 參數

TEST(RpcConvert, StringListAcceptsScalarArrayAndCsv)
{
    EXPECT_EQ(conv::StringList(Json{{"severity", "high"}}, "severity"), std::vector<std::string>{"high"});
    EXPECT_EQ(conv::StringList(Json{{"severity", Json::array({"high", "critical"})}}, "severity"),
              (std::vector<std::string>{"high", "critical"}));
    EXPECT_EQ(conv::StringList(Json{{"severity", "high,low"}}, "severity"), (std::vector<std::string>{"high", "low"}));
    EXPECT_TRUE(conv::StringList(Json::object(), "severity").empty());
}

TEST(RpcConvert, IdParamAcceptsStringNumberAndPrefix)
{
    EXPECT_EQ(conv::IdParam(Json{{"alert_id", "42"}}, {"alert_id", "id"}).value_or(-1), 42);
    EXPECT_EQ(conv::IdParam(Json{{"id", 7}}, {"alert_id", "id"}).value_or(-1), 7);
    EXPECT_EQ(conv::IdParam(Json{{"alert_id", "A-4821"}}, {"alert_id"}).value_or(-1), 4821);
    EXPECT_FALSE(conv::IdParam(Json{{"alert_id", "abc"}}, {"alert_id"}).has_value());
}

// ============================================================ 錯誤

TEST(RpcConvert, ErrorShapeCarriesCodeHttpDetails)
{
    const auto e = conv::Err("CONFIRMATION_REQUIRED", 403, "need token", Json{{"confirmation_token", "t"}});
    const Json j = e.ToJson();
    EXPECT_EQ(j["code"], rpc::kAppError);
    EXPECT_EQ(j["data"]["code"], "CONFIRMATION_REQUIRED");
    EXPECT_EQ(j["data"]["http"], 403);
    EXPECT_EQ(j["data"]["details"]["confirmation_token"], "t");

    const Json inv = conv::Err("INVALID_PARAMS", 400, "x").ToJson();
    EXPECT_EQ(inv["code"], rpc::kInvalidParams);
    EXPECT_FALSE(inv["data"].contains("details"));
}

TEST(RpcConvert, FromErrorMapsKnownCodes)
{
    EXPECT_EQ(conv::FromError(MakeError(ErrorCode::NotFound, "")).appCode, "NOT_FOUND");
    EXPECT_EQ(conv::FromError(MakeError(ErrorCode::ImpactChanged, "")).appCode, "IMPACT_CHANGED");
    EXPECT_EQ(conv::FromError(MakeError(ErrorCode::ConfirmationExpired, "")).data["http"], 410);
    EXPECT_EQ(conv::FromError(MakeError(ErrorCode::DbCorrupt, "")).appCode, "INTERNAL");
}

// ============================================================ 告警

TEST(RpcConvert, AlertSummaryShape)
{
    store::AlertSummary a;
    a.id                  = 4821;
    a.ts                  = 0;
    a.severity            = "critical";
    a.scoreAtTriggerMilli = 92'400;
    a.title               = "Office 產生腳本直譯器並注入";
    a.processName         = "powershell.exe";
    a.ruleIds             = {"R-T1055-001"};
    a.aiState             = "ok";
    a.status              = "pending";
    a.processChain        = {{"winword.exe", 100, 0, 0}, {"powershell.exe", 200, 60'000, 1}};
    const Json j = conv::AlertSummaryJson(a);
    EXPECT_EQ(j["alert_id"], "4821");   // ID 一律字串
    EXPECT_EQ(j["risk_score"], 92);
    EXPECT_EQ(j["narrative_state"], "ready");
    EXPECT_TRUE(j["parent_name"].is_null());
    ASSERT_EQ(j["process_chain"].size(), 2u);
    EXPECT_EQ(j["process_chain"][1]["risk_score"], 60);
}

TEST(RpcConvert, FalsePositiveVerdictOverridesStatus)
{
    store::AlertSummary a;
    a.status         = "resolved";
    a.analystVerdict = "false_positive";
    EXPECT_EQ(conv::AlertSummaryJson(a)["status"], "false_positive");
    EXPECT_EQ(conv::WorkflowStatusOf(std::nullopt, "blocked"), "auto_blocked");
    EXPECT_EQ(conv::WorkflowStatusOf(std::nullopt, "watching"), "observing");
    EXPECT_EQ(conv::WorkflowStatusOf(std::string("true_positive"), "blocked"), "resolved");
}

TEST(RpcConvert, SignatureStatus)
{
    EXPECT_EQ(conv::SignatureStatusOf(true, std::string("Microsoft")), "valid");
    EXPECT_EQ(conv::SignatureStatusOf(false, std::nullopt), "unsigned");
    EXPECT_EQ(conv::SignatureStatusOf(false, std::string("Evil Corp")), "invalid");
    EXPECT_EQ(conv::SignatureStatusOf(std::nullopt, std::nullopt), "unknown");
}

TEST(RpcConvert, ActionsTakenFromDbDerivesAuditIdAndReverted)
{
    const std::string actions =
        R"J([{"action":"suspend_process","target":"powershell.exe (200)","result":"success","ts":1000,"action_id":"ACT-1-01","automatic":false,"actor":"user:X","reversible":true,"reverted":false}])J";
    store::AuditRecord completed;
    completed.id         = 11;
    completed.eventKind  = "action_completed";
    completed.paramsJson = R"({"action_id":"ACT-1-01"})";
    store::AuditRecord reverted;
    reverted.id         = 12;
    reverted.eventKind  = "action_reverted";
    reverted.paramsJson = R"({"action_id":"ACT-1-01"})";

    Json j = conv::ActionsTakenFromDbJson(actions, {completed});
    ASSERT_EQ(j.size(), 1u);
    EXPECT_EQ(j[0]["audit_id"], 11);
    EXPECT_EQ(j[0]["reverted"], false);
    EXPECT_EQ(j[0]["initiator"], "user:X");

    j = conv::ActionsTakenFromDbJson(actions, {completed, reverted});
    EXPECT_EQ(j[0]["reverted"], true);
    EXPECT_EQ(j[0]["result"], "reverted");

    EXPECT_TRUE(conv::ActionsTakenFromDbJson("not json", {}).empty());
}

TEST(RpcConvert, TimelineAccumulatesOnlyCountedScore)
{
    store::TimelineEntry a;
    a.event.id        = 1;
    a.event.eventType = "PROCESS_CREATE";
    a.event.processGuid = "{G}";
    a.stepIndex       = 0;
    a.hits            = {{"R-1", 40'000, false, false}};
    store::TimelineEntry b;
    b.event.id        = 2;
    b.event.eventType = "REMOTE_THREAD";
    b.event.processGuid = "{G}";
    b.event.targetProcessGuid = "{T}";
    b.hits            = {{"R-2", 30'000, /*dryrun*/ true, false}};
    const Json t = conv::TimelineJson({a, b});
    ASSERT_EQ(t.size(), 2u);
    EXPECT_EQ(t[0]["score_after"], 40);
    EXPECT_EQ(t[0]["rule_hits"][0]["step"], "step1");
    EXPECT_EQ(t[1]["score_after"], 40);              // dryrun 不計分
    EXPECT_EQ(t[1]["rule_hits"][0]["score_delta"], 0);

    const Json edges = conv::InjectionEdgesJson({a, b});
    ASSERT_EQ(edges.size(), 1u);
    EXPECT_EQ(edges[0]["technique"], "CreateRemoteThread");
    EXPECT_EQ(edges[0]["target_guid"], "{T}");
}

TEST(RpcConvert, NarrativeStatesAndDisclaimerAlwaysPresent)
{
    store::AlertRecord a;
    a.id                  = 5;
    a.ts                  = 1000;
    a.scoreAtTriggerMilli = 85'000;
    a.ruleIds             = {"R-T1059-001"};

    a.aiState   = "pending";
    Json j      = conv::NarrativeJson(a, 6000, "");
    EXPECT_EQ(j["state"], "pending");
    EXPECT_EQ(j["progress"]["elapsed_ms"], 5000);
    EXPECT_EQ(j["disclaimer"]["actual_decision_basis"]["risk_score"], 85);

    a.aiState          = "ok";
    a.aiNarrative      = "PowerShell 被 Word 啟動";
    a.aiRecommendation = "隔離主機\n重設帳號密碼";
    a.aiAttackIds      = {"T1059.001"};
    a.aiConfidence     = 0.8;
    j                  = conv::NarrativeJson(a, 6000, "");
    EXPECT_EQ(j["state"], "ready");
    EXPECT_EQ(j["recommendations"].size(), 2u);
    EXPECT_EQ(j["attack_mapping"][0]["url"], "https://attack.mitre.org/techniques/T1059/001/");
    EXPECT_EQ(j["confidence_label"], "high");

    a.aiState = "schema_violation";
    j         = conv::NarrativeJson(a, 6000, "");
    EXPECT_EQ(j["state"], "failed");
    EXPECT_EQ(j["error"]["detection_unaffected"], true);
    EXPECT_TRUE(j["disclaimer"].is_object());
}

// ============================================================ 回應動作

TEST(RpcConvert, ExecuteJsonSetsHttpStatusForPartialAndFailed)
{
    response::ExecuteResponse r;
    r.actionId = "ACT-1-01";
    r.action   = model::ActionKind::TerminateProcessTree;
    r.actor    = "user:X";
    r.results  = {{"k1", "a.exe (10)", true, 0, ""}, {"k2", "b.exe (11)", false, 5, "access denied"}};
    r.status   = response::ActionStatus::PartiallySucceeded;
    Json j = conv::ExecuteJson(r, std::nullopt);
    EXPECT_EQ(j["overall_result"], "partial_success");
    EXPECT_EQ(j["_http_status"], 207);
    EXPECT_EQ(j["results"][0]["pid"], 10);
    EXPECT_EQ(j["results"][0]["name"], "a.exe");
    EXPECT_EQ(j["results"][1]["error_code"], "0x5");
    EXPECT_EQ(j["initiator"]["type"], "analyst");

    r.status = response::ActionStatus::Failed;
    EXPECT_EQ(conv::ExecuteJson(r, std::nullopt)["_http_status"], 502);
    r.status = response::ActionStatus::Succeeded;
    j        = conv::ExecuteJson(r, std::string("undo-1"));
    EXPECT_FALSE(j.contains("_http_status"));
    EXPECT_EQ(j["undo_token"], "undo-1");
}

TEST(RpcConvert, PrepareJsonUsesUiImpactKeys)
{
    response::PrepareResponse r;
    r.action    = model::ActionKind::FirewallBlock;
    r.riskLevel = 2;
    response::ImpactItem ip;
    ip.key = "ip:1.2.3.4";
    ip.ip  = "1.2.3.4";
    r.impact.items.push_back(ip);
    r.impact.totalCount = 1;
    const Json j = conv::PrepareJson(r);
    EXPECT_EQ(j["risk_level"], "L2");
    ASSERT_EQ(j["impact"]["ips"].size(), 1u);   // UI 契約為 ips（非 addresses）
    EXPECT_TRUE(j["confirmation_token"].is_null());
}

// ============================================================ 健康度

TEST(RpcConvert, HealthJsonShape)
{
    LiveHealth h;
    h.startedMs = 1000;
    h.hostname  = "WS-01";
    h.providers = {{"sysmon", "healthy"}};
    conv::HealthExtras x;
    x.protectionState = "paused";
    x.pausedUntil     = std::numeric_limits<int64_t>::max();
    const Json j = conv::HealthJson(h, x, 11'000);
    EXPECT_EQ(j["uptime_s"], 10);
    EXPECT_EQ(j["paused_until"], "until_reboot");
    EXPECT_EQ(j["providers"][0]["name"], "sysmon");
    EXPECT_EQ(j["self_protection"]["level"], "none");
}

// ============================================================ 設定

TEST(PolicyConfig, ParsesKnownFieldsAndWarnsOnBadTypes)
{
    const std::string text = R"({
        "response": {"auto_response_enabled": true, "confirmation_token_ttl_seconds": 90},
        "process_tree": {"max_nodes": 1000, "retention_after_exit_minutes": 2},
        "storage": {"db_path": "%X%\\cairn.db", "events_retention_days": 3},
        "llm": {"ctx_size": 4096, "min_score_for_narrative": 85, "port": "bad"},
        "mystery": 1
    })";
    auto r = ParsePolicyJson(text, "/data", "/exe", [](std::string_view s) {
        std::string out(s);
        if (auto p = out.find("%X%"); p != std::string::npos) out.replace(p, 3, "C:");
        return out;
    });
    ASSERT_TRUE(r.HasValue());
    const auto& c = r.Value();
    EXPECT_TRUE(c.engine.autoResponseEnabled);
    EXPECT_EQ(c.tokenTtl.count(), 90);
    EXPECT_EQ(c.engine.treeLimits.maxNodes, 1000u);
    EXPECT_EQ(c.engine.treeLimits.retentionAfterExitMs, 120'000);
    EXPECT_EQ(c.eventTtlMs, 3LL * 86'400'000);
    EXPECT_EQ(c.llmCtxSize, 8192);              // < 8192 自動校正
    EXPECT_EQ(c.llmMinScoreMilli, 85'000);
    EXPECT_EQ(c.llmPort, 8080);                 // 型別錯誤保留預設
    EXPECT_EQ(c.dbPath.generic_string(), "C:\\cairn.db");
    bool sawUnknown = false, sawPort = false;
    for (const auto& w : c.warnings) {
        sawUnknown |= w.find("mystery") != std::string::npos;
        sawPort |= w.find("llm.port") != std::string::npos;
    }
    EXPECT_TRUE(sawUnknown);
    EXPECT_TRUE(sawPort);
}

TEST(PolicyConfig, CorruptJsonIsError)
{
    EXPECT_FALSE(ParsePolicyJson("{ not json", "/d", "/e", {}).HasValue());
}

TEST(PolicyConfig, DefaultsMatchDemoPolicy)
{
    const auto c = DefaultHostConfig("/d", "/e");
    EXPECT_FALSE(c.engine.autoResponseEnabled);   // part1 §5：demo 預設關閉自動回應
    EXPECT_EQ(c.dbPath.filename().string(), "cairn.db");
}

// ============================================================ 持久狀態

TEST(HostState, SerializeRoundTripDropsUntilReboot)
{
    HostStateData d;
    d.installTs        = 123;
    d.learningFinished = true;
    d.ruleOverrides["R-T1053-001"] = model::RuleStatus::Enabled;
    d.pausedUntilMs = std::numeric_limits<int64_t>::max();
    d.pauseReason   = "maintenance";
    auto r = HostState::Deserialize(HostState::Serialize(d));
    ASSERT_TRUE(r.HasValue());
    EXPECT_EQ(r.Value().installTs, 123);
    EXPECT_TRUE(r.Value().learningFinished);
    EXPECT_EQ(r.Value().ruleOverrides.at("R-T1053-001"), model::RuleStatus::Enabled);
    EXPECT_EQ(r.Value().pausedUntilMs, 0);       // until_reboot 不持久化
}

TEST(HostState, ComposeOverridesUserWinsOverLearning)
{
    HostStateData d;
    d.ruleOverrides["R-T1053-001"] = model::RuleStatus::Enabled;
    const std::vector<std::string> forced{"R-T1053-001", "R-T1071-001"};
    auto o = ComposeRuleOverrides(d, forced, /*learning*/ true);
    EXPECT_EQ(o.at("R-T1053-001"), model::RuleStatus::Enabled);
    EXPECT_EQ(o.at("R-T1071-001"), model::RuleStatus::DryRun);
    o = ComposeRuleOverrides(d, forced, /*learning*/ false);
    EXPECT_EQ(o.count("R-T1071-001"), 0u);
}

// ============================================================ Undo / AnalysisTasks

TEST(UndoStore, OneShotAndExpiry)
{
    FakeClock clock;
    UndoStore u(clock, std::chrono::seconds{30});
    UndoEntry e;
    e.exclusionId = 9;
    u.Issue(e, "tok");
    auto t = u.Take("tok");
    ASSERT_TRUE(t.has_value());
    EXPECT_EQ(t->exclusionId, 9);
    EXPECT_FALSE(u.Take("tok").has_value());   // 一次性

    u.Issue(e, "tok2");
    clock.Advance(31'000);
    EXPECT_FALSE(u.Take("tok2").has_value());  // 過期
}

// AnalysisTasks 只轉交參考、從不解參考；測試以不透明的位址充當引擎（不得在此定義 AnalysisEngine，
// 否則與 cairn_rules 中的真實定義違反 ODR）。
namespace {
engine::AnalysisEngine& OpaqueEngine()
{
    alignas(std::max_align_t) static unsigned char storage[16];
    return *reinterpret_cast<engine::AnalysisEngine*>(storage);
}
} // namespace

TEST(AnalysisTasks, RunReturnsValueFromDrainingThread)
{
    AnalysisTasks tasks;
    engine::AnalysisEngine& fake = OpaqueEngine();
    std::atomic<bool> stop{false};
    std::thread t([&] {
        while (!stop) {
            tasks.Drain(fake);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
    auto r = tasks.Run([](engine::AnalysisEngine&) { return 42; }, std::chrono::milliseconds(2000));
    stop = true;
    t.join();
    ASSERT_TRUE(r.HasValue());
    EXPECT_EQ(r.Value(), 42);
}

TEST(AnalysisTasks, TimesOutWhenNobodyDrains)
{
    AnalysisTasks tasks;
    auto r = tasks.Run([](engine::AnalysisEngine&) { return 1; }, std::chrono::milliseconds(20));
    EXPECT_EQ(r.Code(), ErrorCode::Timeout);
}

TEST(AnalysisTasks, ClosedQueueRejects)
{
    AnalysisTasks tasks;
    tasks.Close();
    auto r = tasks.Run([](engine::AnalysisEngine&) { return 1; }, std::chrono::milliseconds(20));
    EXPECT_EQ(r.Code(), ErrorCode::ServiceUnavailable);
}
