// src/core/base/EventPriority.h               namespace cairn
// 分級丟棄的優先級（part2 §2.1.3 表、SDD-01 §3.3.4）。
#pragma once
#include <cstddef>
#include <cstdint>

namespace cairn {

enum class EventPriority : uint8_t { Critical = 0, High = 1, Normal = 2, Low = 3 };
inline constexpr size_t kPriorityCount = 4;

// 來源端在 Push 之前就要決定優先級（SDD-01 §3.2.1 的 ⚠）。成本為一次 switch。
// sourceEventId：Sysmon EID，或 4104（PowerShell）/ 4688（Security）。
[[nodiscard]] constexpr EventPriority PriorityOfEid(uint16_t eid) noexcept
{
    switch (eid) {
    case 8: case 10: case 25: case 23: case 26: case 4104:
        return EventPriority::Critical;
    case 1: case 3: case 22: case 12: case 13: case 14: case 4688:
        return EventPriority::High;
    case 11: case 17: case 18: case 15:
        return EventPriority::Normal;
    case 5: case 7:
        return EventPriority::Low;
    default:
        return EventPriority::Normal;
    }
}

} // namespace cairn
