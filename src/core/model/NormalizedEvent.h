// src/core/model/NormalizedEvent.h            namespace cairn::model
// 統一事件模型。規則引擎只看這個型別，不看 Sysmon 原始 XML。
// 以 SDD-01 §3.4.1 為主（含 interner 飽和時的 fallback 欄位），補上 part2 §2.1.3 / DDL 的欄位。
#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>

#include "base/EventPriority.h"
#include "model/EventType.h"
#include "model/GuidValue.h"
#include "model/StringInterner.h"

namespace cairn::model {

using cairn::EventPriority;

struct NormalizedEvent {
    // ---- 骨幹 ----
    std::chrono::system_clock::time_point time{};       // 事件發生時間（Sysmon UtcTime）
    std::chrono::steady_clock::time_point recvTime{};   // 我方收到時間（量測投遞延遲）
    EventSourceKind source        = EventSourceKind::Sysmon;
    uint16_t        sourceEventId = 0;                  // Sysmon EID / 4104 / 4688
    EventType       type          = EventType::Unknown;
    EventPriority   priority      = EventPriority::Normal;
    uint64_t        seq           = 0;                  // 端點單調序號（NormalizerThread 指派）

    // ---- 程序識別（以 GUID 為主，PID 僅供顯示與 Win32 呼叫）----
    GuidValue processGuid{};
    GuidValue parentProcessGuid{};
    uint32_t  pid       = 0;
    uint32_t  parentPid = 0;

    // ---- 高重複欄位：駐留（一律以 InternLower 小寫化後 intern）----
    InternId image       = kInvalidInternId;
    InternId parentImage = kInvalidInternId;
    InternId user        = kInvalidInternId;
    InternId signer      = kInvalidInternId;
    std::optional<bool> signatureValid;                 // nullopt = 未知（DB 寫 NULL）
    std::string integrityLevel;                         // Low / Medium / High / System

    // ---- interner 飽和時的退路（SDD-01 §3.4.3）：id 無效時規則以此原字串比對 ----
    std::optional<std::string> imageFallback;
    std::optional<std::string> parentImageFallback;
    std::optional<std::string> signerFallback;

    // ---- 低重複 / 攻擊者可控：絕不駐留 ----
    std::string commandLine;          // ⚠ 攻擊者可控
    std::string parentCommandLine;    // ⚠ 攻擊者可控
    std::string sha256;               // 64 hex（大寫），無則空

    // ---- 事件型別專屬欄位 ----
    std::optional<GuidValue>   targetProcessGuid;   // EID 8 / 10
    std::optional<InternId>    targetImage;         // EID 8 / 10
    std::optional<std::string> targetImageFallback;
    std::optional<uint32_t>    targetPid;
    std::optional<uint32_t>    grantedAccess;       // EID 10，位元遮罩
    std::optional<std::string> targetFilename;      // EID 11 / 15 / 23 / 26 ⚠ 部分可控
    std::optional<std::string> registryEventType;   // EID 12：CreateKey / DeleteKey / SetValue ...
    std::optional<std::string> registryPath;        // EID 12 / 13 / 14（TargetObject）
    std::optional<std::string> registryDetails;     // EID 13 Details ⚠
    std::optional<std::string> destinationIp;       // EID 3
    std::optional<uint16_t>    destinationPort;
    std::optional<std::string> destinationHostname;
    std::optional<std::string> queryName;           // EID 22 ⚠
    std::optional<std::string> queryResults;
    std::optional<std::string> pipeName;            // EID 17 / 18
    std::optional<std::string> scriptBlock;         // 4104 ⚠ 攻擊者可控，可能數 KB
    std::optional<std::string> tamperType;          // EID 25：Image is replaced / Image is locked for access

    // ---- 原始資料（預設不保留，除錯或高分事件才填）----
    std::optional<std::string> rawXml;
};

static_assert(std::is_move_constructible_v<NormalizedEvent>);
static_assert(std::is_default_constructible_v<NormalizedEvent>);

// 讀取 interned 欄位的便利函式：id 有效時查 interner，否則回傳 fallback。
[[nodiscard]] inline std::string_view ResolveField(const StringInterner& in, InternId id,
                                                   const std::optional<std::string>& fallback) noexcept
{
    if (id != kInvalidInternId) return in.Resolve(id);
    return fallback ? std::string_view{*fallback} : std::string_view{};
}

} // namespace cairn::model
