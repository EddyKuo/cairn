// src/core/tree/ProcessNode.h                 namespace cairn::tree
// 單一程序的中繼資料與子節點索引（SDD-02 §4.2.2）。以 ProcessGuid 為鍵，PID 僅供顯示與回應動作。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "model/GuidValue.h"
#include "model/StringInterner.h"

namespace cairn::tree {

using model::GuidValue;
using model::InternId;
using model::kInvalidInternId;

enum class NodeFlags : uint16_t {
    None           = 0,
    Provisional    = 1 << 0,   // 父節點尚未到達，rootGuid 為暫定值
    Exited         = 1 << 1,   // 已收到 EID 5
    SignedValid    = 1 << 2,
    Elevated       = 1 << 3,   // High / System integrity
    TerminatedByUs = 1 << 4,
    Sampled        = 1 << 5,   // 所屬樹處於 Watched 以上
    Stub           = 1 << 6,   // 未見 EID 1，由其他事件或啟動快照補建
    Boundary       = 1 << 7,   // 樹邊界程序（explorer / services / svchost ...），其子程序自成一棵樹
    Synthetic      = 1 << 8,   // 啟動快照合成的 GUID（非 Sysmon 提供）
};

[[nodiscard]] constexpr NodeFlags operator|(NodeFlags a, NodeFlags b) noexcept
{
    return static_cast<NodeFlags>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}
[[nodiscard]] constexpr bool HasFlag(NodeFlags v, NodeFlags f) noexcept
{
    return (static_cast<uint16_t>(v) & static_cast<uint16_t>(f)) != 0;
}
constexpr void SetFlag(NodeFlags& v, NodeFlags f) noexcept { v = v | f; }
constexpr void ClearFlag(NodeFlags& v, NodeFlags f) noexcept
{
    v = static_cast<NodeFlags>(static_cast<uint16_t>(v) & ~static_cast<uint16_t>(f));
}

inline constexpr uint16_t kMaxDepth = 64;
inline constexpr size_t   kMaxCommandLineKept = 4096;   // M0 只保留前 4 KB

struct ProcessNode {
    GuidValue guid{};
    GuidValue parentGuid{};
    GuidValue rootGuid{};          // Provisional 時 == guid

    uint32_t  pid       = 0;
    uint32_t  parentPid = 0;
    uint16_t  depth     = 0;
    NodeFlags flags     = NodeFlags::None;

    InternId  image  = kInvalidInternId;    // 小寫化後 intern
    InternId  signer = kInvalidInternId;
    InternId  user   = kInvalidInternId;
    std::string imageFallback;              // interner 飽和時的原字串（小寫）
    std::string commandLine;                // ⚠ 攻擊者可控；截斷至 4 KB
    std::string sha256;
    std::string integrityLevel;
    std::optional<bool> signatureValid;

    int64_t   startMs     = 0;
    int64_t   endMs       = 0;   // 0 = 仍在執行
    uint32_t  eventCount  = 0;
    int64_t   lastEventMs = 0;   // Reaper 的 LRU 依據

    std::vector<GuidValue> children;   // 直接子節點（含跨邊界者，供顯示）
};

// 啟動快照（CreateToolhelp32Snapshot）由 svc 以此值型別注入（part2 §2.4.1 的 IProcessSnapshot）。
struct SnapshotProcess {
    GuidValue   guid{};          // Sysmon 未提供時由 svc 合成（機器 GUID + 建立時間 + PID）
    GuidValue   parentGuid{};    // 可為空（父程序已不存在）
    uint32_t    pid       = 0;
    uint32_t    parentPid = 0;
    std::string image;           // 完整路徑
    int64_t     startMs   = 0;
    bool        synthetic = true;
};

} // namespace cairn::tree
