#include "model/EventType.h"

#include <array>

namespace cairn::model {

namespace {
struct TypeName {
    EventType        type;
    std::string_view name;
};

constexpr std::array<TypeName, kEventTypeCount> kNames{{
    {EventType::Unknown, "UNKNOWN"},
    {EventType::ProcessCreate, "PROCESS_CREATE"},
    {EventType::NetworkConnect, "NETWORK_CONNECT"},
    {EventType::ProcessTerminate, "PROCESS_TERMINATE"},
    {EventType::ImageLoad, "IMAGE_LOAD"},
    {EventType::CreateRemoteThread, "REMOTE_THREAD"},
    {EventType::RawAccessRead, "RAW_ACCESS_READ"},
    {EventType::ProcessAccess, "PROCESS_ACCESS"},
    {EventType::FileCreate, "FILE_CREATE"},
    {EventType::RegistryAdd, "REGISTRY_ADD"},
    {EventType::RegistrySet, "REGISTRY_SET"},
    {EventType::RegistryRename, "REGISTRY_RENAME"},
    {EventType::FileStreamHash, "FILE_STREAM_HASH"},
    {EventType::PipeCreate, "PIPE_CREATE"},
    {EventType::PipeConnect, "PIPE_CONNECT"},
    {EventType::WmiEvent, "WMI_EVENT"},
    {EventType::DnsQuery, "DNS_QUERY"},
    {EventType::FileDelete, "FILE_DELETE"},
    {EventType::ProcessTampering, "PROCESS_TAMPERING"},
    {EventType::ScriptBlock, "SCRIPT_BLOCK"},
    {EventType::SecurityProcessCreate, "SECURITY_PROCESS_CREATE"},
}};
} // namespace

EventType EventTypeFromEid(EventSourceKind src, uint16_t eid) noexcept
{
    if (src == EventSourceKind::PowerShell) return eid == 4104 ? EventType::ScriptBlock : EventType::Unknown;
    if (src == EventSourceKind::SecurityLog) return eid == 4688 ? EventType::SecurityProcessCreate : EventType::Unknown;
    switch (eid) {
    case 1: return EventType::ProcessCreate;
    case 3: return EventType::NetworkConnect;
    case 5: return EventType::ProcessTerminate;
    case 7: return EventType::ImageLoad;
    case 8: return EventType::CreateRemoteThread;
    case 9: return EventType::RawAccessRead;
    case 10: return EventType::ProcessAccess;
    case 11: return EventType::FileCreate;
    case 12: return EventType::RegistryAdd;
    case 13: return EventType::RegistrySet;
    case 14: return EventType::RegistryRename;
    case 15: return EventType::FileStreamHash;
    case 17: return EventType::PipeCreate;
    case 18: return EventType::PipeConnect;
    case 19: case 20: case 21: return EventType::WmiEvent;
    case 22: return EventType::DnsQuery;
    case 23: case 26: return EventType::FileDelete;
    case 25: return EventType::ProcessTampering;
    default: return EventType::Unknown;
    }
}

std::string_view EventTypeToString(EventType t) noexcept
{
    const auto i = static_cast<size_t>(t);
    return i < kNames.size() ? kNames[i].name : std::string_view{"UNKNOWN"};
}

std::optional<EventType> EventTypeFromString(std::string_view s) noexcept
{
    for (const auto& n : kNames)
        if (n.name == s) return n.type;
    return std::nullopt;
}

std::string_view SourceKindToString(EventSourceKind k) noexcept
{
    switch (k) {
    case EventSourceKind::Sysmon: return "sysmon";
    case EventSourceKind::PowerShell: return "powershell";
    case EventSourceKind::SecurityLog: return "security";
    }
    return "sysmon";
}

} // namespace cairn::model
