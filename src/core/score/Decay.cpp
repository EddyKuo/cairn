#include "score/Decay.h"

#include <algorithm>

namespace cairn::score {

int64_t MsUntilBelow(int64_t score, int64_t target, int64_t halfLifeMs) noexcept
{
    target = std::max<int64_t>(target, 1);
    if (score < target) return 0;
    if (halfLifeMs <= 0) return 0;

    // 二分搜尋最小的 dt 使 DecayMilli(score, dt, hl) < target。DecayMilli 對 dt 單調不增。
    int64_t lo = 0;
    int64_t hi = halfLifeMs * 64;   // 64 個半衰期後必為 0
    while (lo < hi) {
        const int64_t mid = lo + (hi - lo) / 2;
        if (DecayMilli(score, mid, halfLifeMs) < target) hi = mid;
        else lo = mid + 1;
    }
    return lo;
}

} // namespace cairn::score
