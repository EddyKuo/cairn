// src/core/model/EventType.h                  namespace cairn::model
// 事件型別。合併 part2 §2.1.3 與 SDD-01 §3.4.1 兩版列舉（取聯集）。
// DB 的 events.event_type 為 TEXT（PROCESS_CREATE / NETWORK_CONNECT / ...，part4 W1 出場條件 3/4）。
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace cairn::model {

enum class EventType : uint16_t {
    Unknown = 0,
    ProcessCreate,       // EID 1
    NetworkConnect,      // EID 3
    ProcessTerminate,    // EID 5
    ImageLoad,           // EID 7
    CreateRemoteThread,  // EID 8
    RawAccessRead,       // EID 9
    ProcessAccess,       // EID 10
    FileCreate,          // EID 11
    RegistryAdd,         // EID 12（建立/刪除鍵）
    RegistrySet,         // EID 13
    RegistryRename,      // EID 14
    FileStreamHash,      // EID 15（ADS）
    PipeCreate,          // EID 17
    PipeConnect,         // EID 18
    WmiEvent,            // EID 19/20/21
    DnsQuery,            // EID 22
    FileDelete,          // EID 23 / 26
    ProcessTampering,    // EID 25
    ScriptBlock,         // PowerShell 4104
    SecurityProcessCreate, // Security 4688（Sysmon 缺席時的降級來源）
    Count_               // 哨兵，勿用
};

inline constexpr size_t kEventTypeCount = static_cast<size_t>(EventType::Count_);

enum class EventSourceKind : uint8_t { Sysmon = 0, PowerShell = 1, SecurityLog = 2 };

// Sysmon EID / 4104 / 4688 → EventType。未知回傳 Unknown。
[[nodiscard]] EventType EventTypeFromEid(EventSourceKind src, uint16_t eid) noexcept;

// DB / RPC / 規則 YAML 使用的字串形式："PROCESS_CREATE" 等。
[[nodiscard]] std::string_view EventTypeToString(EventType t) noexcept;
[[nodiscard]] std::optional<EventType> EventTypeFromString(std::string_view s) noexcept;

[[nodiscard]] std::string_view SourceKindToString(EventSourceKind k) noexcept;   // sysmon | powershell | security

} // namespace cairn::model
