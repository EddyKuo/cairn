// tests/svc/SysmonXmlParserTests.cpp
// 每個 EID mapper 一組 fixture（tests/fixtures/sysmon-samples）＋ 黃金檔比對（tests/fixtures/expected）。
// 解析器為可攜程式碼，本測試不需 Windows 事件、不需 Sysmon、不需管理員權限。
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

#include "base/IClock.h"
#include "model/NormalizedEvent.h"
#include "model/StringInterner.h"
#include "telemetry/EventXml.h"
#include "telemetry/SysmonXmlParser.h"

using namespace cairn;
using namespace cairn::telemetry;
using nlohmann::json;

namespace {

const std::filesystem::path kFixtures = CAIRN_TEST_FIXTURES_DIR;

std::string ReadFile(const std::filesystem::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

model::RawEvent RawFrom(const std::string& name, const std::string& kind)
{
    model::RawEvent r;
    r.kind = kind == "powershell" ? model::EventSourceKind::PowerShell
           : kind == "security"   ? model::EventSourceKind::SecurityLog
                                  : model::EventSourceKind::Sysmon;
    r.xml      = ReadFile(kFixtures / "sysmon-samples" / (name + ".xml"));
    r.eventId  = PeekEventId(r.xml);
    r.priority = PriorityOfEid(r.eventId);
    return r;
}

// NormalizedEvent → 黃金檔格式（只輸出非空欄位，與 make_sysmon_fixtures.py 的約定一致）
json ToGolden(const model::NormalizedEvent& e, const model::StringInterner& in)
{
    json j;
    j["eid"]      = e.sourceEventId;
    j["type"]     = std::string(model::EventTypeToString(e.type));
    j["source"]   = std::string(model::SourceKindToString(e.source));
    j["priority"] = static_cast<int>(e.priority);
    j["time_ms"]  = ToUnixMs(e.time);
    auto str = [&](const char* k, std::string_view v) {
        if (!v.empty()) j[k] = std::string(v);
    };
    auto opt = [&](const char* k, const std::optional<std::string>& v) {
        if (v && !v->empty()) j[k] = *v;
    };
    if (!e.processGuid.IsNull()) j["process_guid"] = e.processGuid.ToString();
    if (!e.parentProcessGuid.IsNull()) j["parent_process_guid"] = e.parentProcessGuid.ToString();
    if (e.pid) j["pid"] = e.pid;
    if (e.parentPid) j["parent_pid"] = e.parentPid;
    str("image", model::ResolveField(in, e.image, e.imageFallback));
    str("parent_image", model::ResolveField(in, e.parentImage, e.parentImageFallback));
    str("user", model::ResolveField(in, e.user, std::nullopt));
    str("signer", model::ResolveField(in, e.signer, e.signerFallback));
    if (e.signatureValid) j["signature_valid"] = *e.signatureValid;
    str("integrity", e.integrityLevel);
    str("command_line", e.commandLine);
    str("parent_command_line", e.parentCommandLine);
    str("sha256", e.sha256);
    if (e.targetProcessGuid) j["target_process_guid"] = e.targetProcessGuid->ToString();
    if (e.targetPid) j["target_pid"] = *e.targetPid;
    if (e.targetImage) str("target_image", model::ResolveField(in, *e.targetImage, e.targetImageFallback));
    if (e.grantedAccess) j["granted_access"] = *e.grantedAccess;
    opt("target_filename", e.targetFilename);
    opt("registry_event_type", e.registryEventType);
    opt("registry_path", e.registryPath);
    opt("registry_details", e.registryDetails);
    opt("dest_ip", e.destinationIp);
    if (e.destinationPort) j["dest_port"] = *e.destinationPort;
    opt("dest_hostname", e.destinationHostname);
    opt("query_name", e.queryName);
    opt("query_results", e.queryResults);
    opt("pipe_name", e.pipeName);
    opt("script_block", e.scriptBlock);
    opt("tamper_type", e.tamperType);
    return j;
}

} // namespace

// ============================================================ 黃金檔回歸（每個 EID mapper 一組）

class SysmonGoldenTest : public ::testing::TestWithParam<std::string> {};

TEST_P(SysmonGoldenTest, MatchesGolden)
{
    const json manifest = json::parse(ReadFile(kFixtures / "sysmon-samples" / "manifest.json"));
    json entry;
    for (const auto& m : manifest)
        if (m["name"] == GetParam()) entry = m;
    ASSERT_FALSE(entry.is_null()) << "manifest 缺少 " << GetParam();

    model::StringInterner interner;
    SysmonXmlParser       parser{interner};
    model::NormalizedEvent ev;
    const Status st = parser.Normalize(RawFrom(GetParam(), entry["kind"].get<std::string>()), ev);

    if (!entry["expect_ok"].get<bool>()) {
        ASSERT_FALSE(st) << "預期解析失敗：" << GetParam();
        EXPECT_EQ(st.GetError().code, ErrorCode::MalformedEventXml);
        return;
    }
    ASSERT_TRUE(st) << st.GetError().ToString();

    json expected = json::parse(ReadFile(kFixtures / "expected" / (GetParam() + ".json")));
    json actual   = ToGolden(ev, interner);
    if (expected.contains("synthetic_guid")) {
        // 4688 降級路徑：合成 GUID = (pid, 建立時間)；父程序未見過 → (ppid, 0)
        expected.erase("synthetic_guid");
        EXPECT_EQ(ev.processGuid, SysmonXmlParser::SyntheticGuid(ev.pid, expected["time_ms"].get<int64_t>()));
        EXPECT_EQ(ev.parentProcessGuid, SysmonXmlParser::SyntheticGuid(ev.parentPid, 0));
        actual.erase("process_guid");
        actual.erase("parent_process_guid");
    }
    EXPECT_EQ(actual, expected) << "actual:\n" << actual.dump(2) << "\nexpected:\n" << expected.dump(2);
}

INSTANTIATE_TEST_SUITE_P(
    Fixtures, SysmonGoldenTest,
    ::testing::Values("eid01_process_create", "eid03_network_connect", "eid05_process_terminate",
                      "eid07_image_load_unsigned", "eid07_image_load_signed", "eid08_create_remote_thread",
                      "eid10_process_access_lsass", "eid11_file_create", "eid12_registry_create_key",
                      "eid13_registry_set_run", "eid14_registry_rename", "eid15_file_stream_hash", "eid17_pipe_create",
                      "eid18_pipe_connect", "eid22_dns_query", "eid23_file_delete_archived", "eid25_process_tampering",
                      "eid26_file_delete_detected", "edge_entities_cmdline", "edge_missing_guid",
                      "edge_unsupported_eid6", "ps4104_script_block", "sec4688_process_create"),
    [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

TEST(SysmonXmlParser, ManifestCoversEverySampleFile)
{
    const json manifest = json::parse(ReadFile(kFixtures / "sysmon-samples" / "manifest.json"));
    size_t xmlCount = 0;
    for (const auto& f : std::filesystem::directory_iterator(kFixtures / "sysmon-samples"))
        if (f.path().extension() == ".xml") ++xmlCount;
    EXPECT_EQ(manifest.size(), xmlCount);
}

// ============================================================ 結構與邊界

TEST(SysmonXmlParser, InternsPathsLowercase)
{
    model::StringInterner in;
    SysmonXmlParser p{in};
    model::NormalizedEvent a, b;
    ASSERT_TRUE(p.Normalize(RawFrom("eid01_process_create", "sysmon"), a));
    ASSERT_TRUE(p.Normalize(RawFrom("eid03_network_connect", "sysmon"), b));
    // 同一個映像（大小寫不同的來源亦然）必須 intern 成同一個 id：規則比對退化為整數比較
    EXPECT_EQ(a.image, b.image);
    EXPECT_NE(a.image, model::kInvalidInternId);
}

TEST(SysmonXmlParser, InternerSaturationFallsBackToString)
{
    model::StringInterner tiny{1};
    (void)tiny.Intern("occupied");   // 填滿
    SysmonXmlParser p{tiny};
    model::NormalizedEvent e;
    ASSERT_TRUE(p.Normalize(RawFrom("eid01_process_create", "sysmon"), e));
    // ★ 飽和不得讓欄位消失（否則攻擊者先撐爆 interner 就能讓 image 規則全部失效）
    EXPECT_EQ(e.image, model::kInvalidInternId);
    ASSERT_TRUE(e.imageFallback.has_value());
    EXPECT_EQ(*e.imageFallback, R"(c:\windows\system32\windowspowershell\v1.0\powershell.exe)");
    ASSERT_TRUE(e.parentImageFallback.has_value());
}

TEST(SysmonXmlParser, KeepRawXmlOption)
{
    model::StringInterner in;
    SysmonXmlParser::Options opt;
    opt.keepRawXml = true;
    SysmonXmlParser p{in, opt};
    model::NormalizedEvent e;
    auto raw = RawFrom("eid08_create_remote_thread", "sysmon");
    ASSERT_TRUE(p.Normalize(raw, e));
    ASSERT_TRUE(e.rawXml.has_value());
    EXPECT_EQ(*e.rawXml, raw.xml);
}

TEST(SysmonXmlParser, CommandLineIsTruncatedOnUtf8Boundary)
{
    model::StringInterner in;
    SysmonXmlParser::Options opt;
    opt.maxCommandLine = 5;
    SysmonXmlParser p{in, opt};
    model::RawEvent raw = RawFrom("eid01_process_create", "sysmon");
    // 把命令列換成 "abcd中文"（"中" 為 3 bytes，從第 5 byte 起；截在 5 會切到字元中間）
    const auto pos = raw.xml.find("powershell.exe -nop");
    ASSERT_NE(pos, std::string::npos);
    raw.xml.replace(pos, std::string("powershell.exe -nop -w hidden -enc SQBFAFgA").size(), "abcd\xE4\xB8\xAD\xE6\x96\x87");
    model::NormalizedEvent e;
    ASSERT_TRUE(p.Normalize(raw, e));
    EXPECT_EQ(e.commandLine, "abcd");
}

TEST(SysmonXmlParser, Security4688ChainsSyntheticParent)
{
    model::StringInterner in;
    SysmonXmlParser p{in};
    model::NormalizedEvent parent, child;
    auto raw = RawFrom("sec4688_process_create", "security");
    ASSERT_TRUE(p.Normalize(raw, parent));
    // 第二筆：父程序 = 前一筆的新程序（pid 0x1e20）
    std::string x = raw.xml;
    x.replace(x.find("<Data Name='NewProcessId'>0x1e20</Data>"), std::string("<Data Name='NewProcessId'>0x1e20</Data>").size(),
              "<Data Name='NewProcessId'>0x2000</Data>");
    x.replace(x.find("<Data Name='ProcessId'>0x12d0</Data>"), std::string("<Data Name='ProcessId'>0x12d0</Data>").size(),
              "<Data Name='ProcessId'>0x1e20</Data>");
    raw.xml = x;
    ASSERT_TRUE(p.Normalize(raw, child));
    EXPECT_EQ(child.parentProcessGuid, parent.processGuid);   // 降級路徑仍能建樹
}

TEST(SysmonXmlParser, RejectsGarbage)
{
    model::StringInterner in;
    SysmonXmlParser p{in};
    model::NormalizedEvent e;
    for (const char* junk : {"", "<", "<Event>", "<Event xmlns='x'><System><EventID>1</EventID></System>",
                             "<Event><System><EventID>abc</EventID></System><EventData></EventData></Event>",
                             "not xml at all", "<Event><System><EventID>1</EventID><TimeCreated SystemTime='x'/>"
                                               "</System><EventData><Data Name='ProcessGuid'>{zz}</Data></EventData></Event>"}) {
        model::RawEvent r;
        r.xml = junk;
        EXPECT_FALSE(p.Normalize(r, e)) << "應拒絕：" << junk;
    }
    EXPECT_GT(p.ParseFailures(), 0u);
}

// ============================================================ EventXml 工具函式

TEST(EventXml, DecodesEntities)
{
    EXPECT_EQ(DecodeXmlEntities("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;"), "a & b <c> \"d\" 'e'");
    EXPECT_EQ(DecodeXmlEntities("&#65;&#x42;&#x4E2D;"), "AB\xE4\xB8\xAD");
    EXPECT_EQ(DecodeXmlEntities("&unknown; &#xZZ; & alone"), "&unknown; &#xZZ; & alone");   // 不丟字元
    EXPECT_EQ(DecodeXmlEntities("&#0;"), "\xEF\xBF\xBD");                                   // NUL → U+FFFD
    EXPECT_EQ(DecodeXmlEntities("&#x110000;"), "&#x110000;");                               // 超出 Unicode 範圍
}

TEST(EventXml, ParsesUtcTime)
{
    // 2026-08-19 06:22:01.220 UTC
    EXPECT_EQ(ParseUtcTimeMs("2026-08-19 06:22:01.220").value(), 1787120521220);
    EXPECT_EQ(ParseUtcTimeMs("2026-08-19T06:22:01.2201234Z").value(), 1787120521220);
    EXPECT_EQ(ParseUtcTimeMs("1970-01-01 00:00:00.000").value(), 0);
    EXPECT_EQ(ParseUtcTimeMs("2024-02-29 12:00:00.5").value(), 1709208000500);   // 閏日、單位數小數
    EXPECT_FALSE(ParseUtcTimeMs("2026-13-01 00:00:00.000"));
    EXPECT_FALSE(ParseUtcTimeMs("garbage"));
    EXPECT_FALSE(ParseUtcTimeMs(""));
}

TEST(EventXml, ParsesUInt)
{
    EXPECT_EQ(ParseUInt("0x1F0FFF").value(), 0x1F0FFFu);
    EXPECT_EQ(ParseUInt("  7712 ").value(), 7712u);
    EXPECT_FALSE(ParseUInt("0x"));
    EXPECT_FALSE(ParseUInt("12a"));
    EXPECT_FALSE(ParseUInt("99999999999999999999999"));   // 溢位
}

TEST(EventXml, ExtractsSha256)
{
    const std::string h(64, 'a');
    EXPECT_EQ(ExtractSha256("SHA1=00,MD5=11,SHA256=" + h + ",IMPHASH=22"), std::string(64, 'A'));
    EXPECT_EQ(ExtractSha256("sha256=" + h), std::string(64, 'A'));
    EXPECT_EQ(ExtractSha256("MD5=11"), "");
    EXPECT_EQ(ExtractSha256("SHA256=abc"), "");   // 長度不足視為無
}

TEST(EventXml, PeeksEventId)
{
    EXPECT_EQ(PeekEventId("<Event><System><EventID>13</EventID>"), 13);
    EXPECT_EQ(PeekEventId("<Event><System><EventID Qualifiers='0'>4688</EventID>"), 4688);
    EXPECT_EQ(PeekEventId("<Event>"), 0);
    EXPECT_EQ(PeekEventIdW(L"<EventID>8</EventID>"), 8);
}

TEST(EventXml, FieldNameIsCaseInsensitiveAndDashIsEmpty)
{
    const std::string xml =
        "<Event xmlns='x'><System><EventID>10</EventID></System><EventData>"
        "<Data Name='SourceProcessGUID'>{A1B2C3D4-0000-0000-0000-000000000001}</Data>"
        "<Data Name='RuleName'>-</Data><Data Name='Empty'/></EventData></Event>";
    auto v = EventXmlView::Parse(xml);
    ASSERT_TRUE(v);
    EXPECT_TRUE(v->Field("SourceProcessGuid").has_value());
    EXPECT_FALSE(v->Field("RuleName").has_value());   // Sysmon 以 "-" 表示空值
    EXPECT_FALSE(v->Field("Empty").has_value());
    EXPECT_FALSE(v->Field("Missing").has_value());
}
