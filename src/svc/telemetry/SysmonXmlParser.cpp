#include "telemetry/SysmonXmlParser.h"

#include <chrono>

#include "telemetry/EventXml.h"

namespace cairn::telemetry {

using model::EventSourceKind;
using model::EventType;
using model::GuidValue;
using model::InternId;
using model::kInvalidInternId;
using model::NormalizedEvent;

namespace {

std::chrono::system_clock::time_point ToTimePoint(int64_t ms)
{
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{ms}};
}

std::optional<uint32_t> ToU32(const std::optional<std::string>& s)
{
    if (!s) return std::nullopt;
    auto v = ParseUInt(*s);
    if (!v || *v > 0xFFFFFFFFull) return std::nullopt;
    return static_cast<uint32_t>(*v);
}

std::optional<GuidValue> ToGuid(const std::optional<std::string>& s)
{
    if (!s) return std::nullopt;
    return GuidValue::Parse(*s);
}

void Truncate(std::string& s, size_t maxLen)
{
    if (s.size() <= maxLen) return;
    // 不要切在 UTF-8 多位元組字元中間
    size_t cut = maxLen;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
    s.resize(cut);
}

std::string IntegrityFromLabel(std::string_view sid)
{
    if (sid == "S-1-16-4096") return "Low";
    if (sid == "S-1-16-8192") return "Medium";
    if (sid == "S-1-16-8448") return "MediumPlus";
    if (sid == "S-1-16-12288") return "High";
    if (sid == "S-1-16-16384") return "System";
    if (sid == "S-1-16-0") return "Untrusted";
    return std::string(sid);
}

} // namespace

SysmonXmlParser::SysmonXmlParser(model::StringInterner& interner, Options opt)
    : m_interner(interner), m_opt(opt)
{
}

GuidValue SysmonXmlParser::SyntheticGuid(uint32_t pid, int64_t createMs) noexcept
{
    GuidValue g;
    g.bytes[0] = 0xCA;
    g.bytes[1] = 0x1E;
    g.bytes[2] = 0x46;
    g.bytes[3] = 0x88;
    for (int i = 0; i < 4; ++i) g.bytes[4 + i] = static_cast<uint8_t>((pid >> (8 * i)) & 0xFF);
    const auto t = static_cast<uint64_t>(createMs);
    for (int i = 0; i < 8; ++i) g.bytes[8 + i] = static_cast<uint8_t>((t >> (8 * i)) & 0xFF);
    return g;
}

InternId SysmonXmlParser::InternPath(std::string_view s, std::optional<std::string>& fallback)
{
    if (s.empty()) return kInvalidInternId;
    const InternId id = m_interner.InternLower(s);
    if (id == kInvalidInternId) fallback = model::ToLowerAscii(s);
    return id;
}

Status SysmonXmlParser::Normalize(const model::RawEvent& raw, NormalizedEvent& out)
{
    out = NormalizedEvent{};
    auto view = EventXmlView::Parse(raw.xml);
    if (!view) {
        ++m_parseFailures;
        return MakeError(ErrorCode::MalformedEventXml, "EventXmlView::Parse");
    }

    out.recvTime      = raw.recvTime;
    out.sourceEventId = view->EventId();
    out.priority      = PriorityOfEid(view->EventId());

    // 依來源種類分派；種類未知時以 Provider 名稱判斷（防呆：來源端填錯 kind 也能正確解析）
    EventSourceKind kind = raw.kind;
    const std::string_view provider = view->ProviderName();
    if (provider == "Microsoft-Windows-Sysmon") kind = EventSourceKind::Sysmon;
    else if (provider == "Microsoft-Windows-PowerShell") kind = EventSourceKind::PowerShell;
    else if (provider == "Microsoft-Windows-Security-Auditing") kind = EventSourceKind::SecurityLog;
    out.source = kind;
    out.type   = model::EventTypeFromEid(kind, view->EventId());
    if (out.type == EventType::Unknown) {
        ++m_unsupported;
        return MakeError(ErrorCode::MalformedEventXml, "unsupported event id");
    }

    // 時間：優先 Sysmon 的 UtcTime（事件發生時間），否則 System/TimeCreated
    std::optional<int64_t> ms;
    if (auto ut = view->RawField("UtcTime")) ms = ParseUtcTimeMs(*ut);
    if (!ms) ms = ParseUtcTimeMs(view->SystemTime());
    if (!ms) {
        ++m_parseFailures;
        return MakeError(ErrorCode::MalformedEventXml, "missing event time");
    }
    out.time = ToTimePoint(*ms);

    Status st = Ok();
    switch (kind) {
    case EventSourceKind::Sysmon: st = MapSysmon(*view, out); break;
    case EventSourceKind::PowerShell: st = MapPowerShell4104(*view, out); break;
    case EventSourceKind::SecurityLog: st = MapSecurity4688(*view, out); break;
    }
    if (!st) {
        ++m_parseFailures;
        return st;
    }
    if (m_opt.keepRawXml) out.rawXml = raw.xml;
    return Ok();
}

Status SysmonXmlParser::MapSysmon(const EventXmlView& x, NormalizedEvent& e)
{
    const uint16_t eid = x.EventId();

    // ---- 主體程序：EID 8/10 的主體是 Source*，其餘是 Process* ----
    const bool sourced = (eid == 8 || eid == 10);
    const auto guid = ToGuid(x.Field(sourced ? "SourceProcessGuid" : "ProcessGuid"));
    if (!guid) return MakeError(ErrorCode::MalformedEventXml, "missing ProcessGuid");
    e.processGuid = *guid;
    if (auto pid = ToU32(x.Field(sourced ? "SourceProcessId" : "ProcessId"))) e.pid = *pid;

    if (auto img = x.Field(sourced ? "SourceImage" : "Image")) e.image = InternPath(*img, e.imageFallback);
    if (auto user = x.Field(sourced ? "SourceUser" : "User")) {
        std::optional<std::string> unused;
        e.user = InternPath(*user, unused);   // user 飽和時不設退路（規則不以 user 做偵測主鍵）
    }

    switch (eid) {
    case 1: {   // ProcessCreate
        if (auto v = x.Field("CommandLine")) {
            e.commandLine = std::move(*v);
            Truncate(e.commandLine, m_opt.maxCommandLine);
        }
        if (auto v = ToGuid(x.Field("ParentProcessGuid"))) e.parentProcessGuid = *v;
        if (auto v = ToU32(x.Field("ParentProcessId"))) e.parentPid = *v;
        if (auto v = x.Field("ParentImage")) e.parentImage = InternPath(*v, e.parentImageFallback);
        if (auto v = x.Field("ParentCommandLine")) {
            e.parentCommandLine = std::move(*v);
            Truncate(e.parentCommandLine, m_opt.maxCommandLine);
        }
        if (auto v = x.Field("Hashes")) e.sha256 = ExtractSha256(*v);
        if (auto v = x.Field("IntegrityLevel")) e.integrityLevel = std::move(*v);
        break;
    }
    case 3: {   // NetworkConnect
        if (auto v = x.Field("DestinationIp")) e.destinationIp = std::move(*v);
        if (auto v = ToU32(x.Field("DestinationPort")); v && *v <= 0xFFFF) e.destinationPort = static_cast<uint16_t>(*v);
        if (auto v = x.Field("DestinationHostname")) e.destinationHostname = std::move(*v);
        break;
    }
    case 5:   // ProcessTerminate：只需主體欄位
        break;
    case 7: {   // ImageLoad：簽章欄位描述的是「被載入的模組」
        if (auto v = x.Field("ImageLoaded")) e.targetFilename = std::move(*v);
        if (auto v = x.Field("Hashes")) e.sha256 = ExtractSha256(*v);
        if (auto v = x.Field("Signature")) e.signer = InternPath(*v, e.signerFallback);
        if (auto v = x.Field("SignatureStatus")) e.signatureValid = (*v == "Valid");
        else if (auto s = x.Field("Signed")) e.signatureValid = (*s == "true");
        break;
    }
    case 8: {   // CreateRemoteThread
        if (auto v = ToGuid(x.Field("TargetProcessGuid"))) e.targetProcessGuid = *v;
        if (auto v = ToU32(x.Field("TargetProcessId"))) e.targetPid = *v;
        if (auto v = x.Field("TargetImage")) {
            std::optional<std::string> fb;
            e.targetImage = InternPath(*v, fb);
            if (fb) e.targetImageFallback = std::move(fb);
        }
        break;
    }
    case 10: {   // ProcessAccess（Sysmon 此 EID 用 GUID 大寫，Field 比對不分大小寫）
        if (auto v = ToGuid(x.Field("TargetProcessGuid"))) e.targetProcessGuid = *v;
        if (auto v = ToU32(x.Field("TargetProcessId"))) e.targetPid = *v;
        if (auto v = x.Field("TargetImage")) {
            std::optional<std::string> fb;
            e.targetImage = InternPath(*v, fb);
            if (fb) e.targetImageFallback = std::move(fb);
        }
        if (auto v = ToU32(x.Field("GrantedAccess"))) e.grantedAccess = *v;
        break;
    }
    case 11:    // FileCreate
    case 15:    // FileCreateStreamHash
    case 23:    // FileDelete（歸檔）
    case 26: {  // FileDeleteDetected
        if (auto v = x.Field("TargetFilename")) e.targetFilename = std::move(*v);
        if (auto v = x.Field(eid == 15 ? "Hash" : "Hashes")) e.sha256 = ExtractSha256(*v);
        break;
    }
    case 12:
    case 13:
    case 14: {  // Registry
        if (auto v = x.Field("EventType")) e.registryEventType = std::move(*v);
        if (auto v = x.Field("TargetObject")) e.registryPath = std::move(*v);
        if (eid == 13) {
            if (auto v = x.Field("Details")) e.registryDetails = std::move(*v);
        } else if (eid == 14) {
            if (auto v = x.Field("NewName")) e.registryDetails = std::move(*v);
        }
        break;
    }
    case 17:
    case 18: {  // Pipe
        if (auto v = x.Field("PipeName")) e.pipeName = std::move(*v);
        break;
    }
    case 22: {  // DnsQuery
        if (auto v = x.Field("QueryName")) e.queryName = std::move(*v);
        if (auto v = x.Field("QueryResults")) e.queryResults = std::move(*v);
        break;
    }
    case 25: {  // ProcessTampering
        if (auto v = x.Field("Type")) e.tamperType = std::move(*v);
        break;
    }
    default:
        ++m_unsupported;
        return MakeError(ErrorCode::MalformedEventXml, "unsupported sysmon event id");
    }
    return Ok();
}

Status SysmonXmlParser::MapPowerShell4104(const EventXmlView& x, NormalizedEvent& e)
{
    if (x.EventId() != 4104) return MakeError(ErrorCode::MalformedEventXml, "powershell: not 4104");
    // 4104 沒有 ProcessGuid：以 System/Execution 的 ProcessID 交給 AnalysisThread 依 PID 關聯。
    e.pid = x.ExecutionProcessId();
    auto sb = x.Field("ScriptBlockText");
    if (!sb) return MakeError(ErrorCode::MalformedEventXml, "powershell: missing ScriptBlockText");
    Truncate(*sb, m_opt.maxScriptBlock);
    e.scriptBlock = std::move(*sb);
    if (auto p = x.Field("Path")) e.targetFilename = std::move(*p);
    if (!x.SecurityUserId().empty()) {
        std::optional<std::string> unused;
        e.user = InternPath(x.SecurityUserId(), unused);
    }
    return Ok();
}

Status SysmonXmlParser::MapSecurity4688(const EventXmlView& x, NormalizedEvent& e)
{
    if (x.EventId() != 4688) return MakeError(ErrorCode::MalformedEventXml, "security: not 4688");
    auto newPid = ToU32(x.Field("NewProcessId"));
    if (!newPid) return MakeError(ErrorCode::MalformedEventXml, "security: missing NewProcessId");
    e.pid = *newPid;
    if (auto v = ToU32(x.Field("ProcessId"))) e.parentPid = *v;

    const int64_t createMs = std::chrono::duration_cast<std::chrono::milliseconds>(e.time.time_since_epoch()).count();
    e.processGuid = SyntheticGuid(e.pid, createMs);
    if (auto it = m_syntheticByPid.find(e.parentPid); it != m_syntheticByPid.end()) {
        e.parentProcessGuid = it->second;
    } else if (e.parentPid != 0) {
        e.parentProcessGuid = SyntheticGuid(e.parentPid, 0);   // 父程序建立時間未知
    }
    if (m_syntheticByPid.size() >= m_opt.maxSyntheticPids) m_syntheticByPid.clear();   // 有界：寧可斷樹不可吃光記憶體
    m_syntheticByPid[e.pid] = e.processGuid;

    if (auto v = x.Field("NewProcessName")) e.image = InternPath(*v, e.imageFallback);
    if (auto v = x.Field("ParentProcessName")) e.parentImage = InternPath(*v, e.parentImageFallback);
    if (auto v = x.Field("CommandLine")) {
        e.commandLine = std::move(*v);
        Truncate(e.commandLine, m_opt.maxCommandLine);
    }
    // 新程序的使用者：Target* 有值時（Win10+）優先，否則 Subject*
    auto domain = x.Field("TargetDomainName");
    auto name   = x.Field("TargetUserName");
    if (!name) {
        domain = x.Field("SubjectDomainName");
        name   = x.Field("SubjectUserName");
    }
    if (name) {
        const std::string u = domain ? (*domain + "\\" + *name) : *name;
        std::optional<std::string> unused;
        e.user = InternPath(u, unused);
    }
    if (auto v = x.Field("MandatoryLabel")) e.integrityLevel = IntegrityFromLabel(*v);
    return Ok();
}

} // namespace cairn::telemetry
