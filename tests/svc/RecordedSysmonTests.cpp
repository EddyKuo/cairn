// 實機錄製樣本回歸（ADR_002 第 5 條：回歸測試必須包含原樣取自實機通道的事件）。
//
// tests/fixtures/sysmon-recorded/idle_workstation_sample.xml：
//   Sysmon 15.21（schema 4.91）+ config/sysmon.xml，閒置工作站，EvtRender 原樣輸出——
//   單引號屬性、單行、每筆皆含 <Data Name='RuleName'>。每個 EID 一筆；EID 4 / 16 為不支援的 EID。
//   已去識別化（主機名、使用者、SID、IP、ProcessGuid 的機器前綴、本機路徑），格式與欄位結構未動。
//
// 期望值不取自解析器本身：以與 EventXml 無關的字串搜尋從原文取欄位，再與解析結果比對。
// 合成 fixture 的教訓是「手寫樣本只會寫出自己解析器吃得下的形狀」；這裡反過來，以實機形狀檢驗解析器。
#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "base/EventPriority.h"
#include "model/NormalizedEvent.h"
#include "model/StringInterner.h"
#include "telemetry/EventXml.h"
#include "telemetry/SysmonXmlParser.h"

using namespace cairn;
using namespace cairn::telemetry;

namespace {

const std::filesystem::path kSample =
    std::filesystem::path(CAIRN_TEST_FIXTURES_DIR) / "sysmon-recorded" / "idle_workstation_sample.xml";

std::string ReadAll(const std::filesystem::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::vector<std::string> SplitEvents(const std::string& all)
{
    std::vector<std::string> out;
    for (size_t pos = 0;;) {
        const auto b = all.find("<Event ", pos);
        if (b == std::string::npos) break;
        const auto e = all.find("</Event>", b);
        if (e == std::string::npos) break;
        out.push_back(all.substr(b, e + 8 - b));
        pos = e + 8;
    }
    return out;
}

// 與 EventXml 無關的取值：找 <Data Name='X'>v</Data>（樣本不含實體參照，故不需解碼）
std::optional<std::string> DataField(const std::string& xml, const std::string& name)
{
    const std::string open = "<Data Name='" + name + "'>";
    const auto b = xml.find(open);
    if (b == std::string::npos) return std::nullopt;
    const auto v = b + open.size();
    const auto e = xml.find("</Data>", v);
    if (e == std::string::npos) return std::nullopt;
    return xml.substr(v, e - v);
}

int EventIdOf(const std::string& xml)
{
    const auto b = xml.find("<EventID>") + 9;
    return std::stoi(xml.substr(b, xml.find('<', b) - b));
}

std::string Lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

class RecordedSysmonTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        all    = ReadAll(kSample);
        events = SplitEvents(all);
        ASSERT_FALSE(events.empty()) << "找不到樣本：" << kSample.string();
    }

    Status Parse(const std::string& xml, model::NormalizedEvent& out)
    {
        model::RawEvent raw;
        raw.kind     = model::EventSourceKind::Sysmon;
        raw.xml      = xml;
        raw.eventId  = PeekEventId(raw.xml);
        raw.priority = PriorityOfEid(raw.eventId);
        return parser.Normalize(raw, out);
    }

    std::string              all;
    std::vector<std::string> events;
    model::StringInterner    interner;
    SysmonXmlParser          parser{interner};
};

} // namespace

// 防止樣本被「整理」成手寫形狀：一旦改成雙引號或多行，這份 fixture 就失去存在意義
TEST_F(RecordedSysmonTest, FixtureKeepsEvtRenderShape)
{
    EXPECT_EQ(all.find("Name=\""), std::string::npos) << "實機樣本不得改成雙引號屬性";
    for (const auto& ev : events) {
        EXPECT_EQ(ev.find('\n'), std::string::npos) << "EvtRender 輸出為單行";
        EXPECT_NE(ev.find("Name='"), std::string::npos);
    }
    std::set<int> eids;
    for (const auto& ev : events) eids.insert(EventIdOf(ev));
    for (int expected : {1, 3, 5, 7, 8, 11, 12, 13, 17, 18, 22, 23, 25})
        EXPECT_TRUE(eids.count(expected)) << "樣本缺少 EID " << expected;
}

// 下游非零斷言（ADR_002「遺留的教訓」）：解析成功之外，關鍵欄位必須與原文一致
TEST_F(RecordedSysmonTest, ParsedFieldsMatchSourceXml)
{
    size_t supported = 0;
    for (const auto& xml : events) {
        const int eid = EventIdOf(xml);
        SCOPED_TRACE("EID " + std::to_string(eid));
        if (eid == 4 || eid == 16) continue;   // 另測
        ++supported;

        model::NormalizedEvent ev;
        const Status st = Parse(xml, ev);
        ASSERT_TRUE(st) << st.GetError().ToString();
        EXPECT_EQ(ev.sourceEventId, eid);

        const bool sourced = eid == 8 || eid == 10;
        const auto guidText = DataField(xml, sourced ? "SourceProcessGuid" : "ProcessGuid");
        ASSERT_TRUE(guidText);
        const auto guid = model::GuidValue::Parse(*guidText);
        ASSERT_TRUE(guid);
        EXPECT_FALSE(ev.processGuid.IsNull());
        EXPECT_EQ(ev.processGuid, *guid);

        const auto image = DataField(xml, sourced ? "SourceImage" : "Image");
        ASSERT_TRUE(image);
        ASSERT_NE(ev.image, model::kInvalidInternId);
        EXPECT_EQ(std::string(interner.Resolve(ev.image)), Lower(*image));

        switch (eid) {
        case 1:
            EXPECT_EQ(ev.commandLine, *DataField(xml, "CommandLine"));
            EXPECT_EQ(ev.parentProcessGuid, *model::GuidValue::Parse(*DataField(xml, "ParentProcessGuid")));
            break;
        case 3:
            ASSERT_TRUE(ev.destinationIp);
            EXPECT_EQ(*ev.destinationIp, *DataField(xml, "DestinationIp"));
            break;
        case 8:
            ASSERT_TRUE(ev.targetProcessGuid);
            EXPECT_EQ(*ev.targetProcessGuid, *model::GuidValue::Parse(*DataField(xml, "TargetProcessGuid")));
            break;
        case 11:
        case 23:
            ASSERT_TRUE(ev.targetFilename);
            EXPECT_EQ(Lower(*ev.targetFilename), Lower(*DataField(xml, "TargetFilename")));
            break;
        case 12:
        case 13:
            ASSERT_TRUE(ev.registryPath);
            EXPECT_EQ(Lower(*ev.registryPath), Lower(*DataField(xml, "TargetObject")));
            break;
        case 17:
        case 18:
            ASSERT_TRUE(ev.pipeName);
            EXPECT_EQ(Lower(*ev.pipeName), Lower(*DataField(xml, "PipeName")));
            break;
        case 22:
            ASSERT_TRUE(ev.queryName);
            EXPECT_EQ(Lower(*ev.queryName), Lower(*DataField(xml, "QueryName")));
            break;
        case 25:
            ASSERT_TRUE(ev.tamperType);
            EXPECT_EQ(*ev.tamperType, *DataField(xml, "Type"));
            break;
        default: break;
        }
    }
    EXPECT_GE(supported, 13u);
    EXPECT_EQ(parser.ParseFailures(), 0u);
}

// 屬性名須為完整 token：每筆都以 RuleName 開頭，子字串比對會把 RuleName 的值（'-'）當成別的欄位
TEST_F(RecordedSysmonTest, RuleNameIsNotMistakenForOtherFields)
{
    for (const auto& xml : events) {
        const int eid = EventIdOf(xml);
        if (eid == 4 || eid == 16) continue;
        SCOPED_TRACE("EID " + std::to_string(eid));
        ASSERT_EQ(DataField(xml, "RuleName").value_or(""), "-");
        model::NormalizedEvent ev;
        ASSERT_TRUE(Parse(xml, ev));
        EXPECT_NE(std::string(interner.Resolve(ev.image)), "-");
    }
}

TEST_F(RecordedSysmonTest, UnsupportedEidsAreCountedNotMisparsed)
{
    size_t seen = 0;
    for (const auto& xml : events) {
        const int eid = EventIdOf(xml);
        if (eid != 4 && eid != 16) continue;
        ++seen;
        model::NormalizedEvent ev;
        EXPECT_FALSE(Parse(xml, ev)) << "EID " << eid << " 不應被解析成事件";
    }
    EXPECT_EQ(seen, 2u);
    EXPECT_EQ(parser.UnsupportedEids(), 2u);
}
