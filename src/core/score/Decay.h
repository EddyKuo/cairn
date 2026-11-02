// src/core/score/Decay.h                      namespace cairn::score
// 定點數指數衰減（SDD-02 §4.3.2、part2 §2.4.3）。全程無執行期浮點：
//   score_now = score_last * 2^(-dt / halfLife)
//   拆成「整數次半衰（右移）」與「小數部分查表（Q16）」。
// kPow2Neg 於編譯期以 constexpr 級數算出（不依賴 <cmath> 的 constexpr 支援），跨機器逐位元相同。
#pragma once
#include <array>
#include <cstdint>

#include "model/Domain.h"

namespace cairn::score {

using model::kScoreMax;
using model::kScoreScale;

inline constexpr int64_t kScoreFloor     = 5 * kScoreScale;   // 5 分以下直接歸零（part2 §2.4.3）
inline constexpr size_t  kDecayTableSize = 256;

namespace detail {
// 編譯期計算 2^(-i/256)：以 e^(-x·ln2) 的泰勒級數展開，x ∈ [0,1)，40 項足以收斂到 double 精度。
constexpr double Pow2NegFrac(double x)
{
    constexpr double kLn2 = 0.69314718055994530942;
    const double     y    = -x * kLn2;
    double term = 1.0;
    double sum  = 1.0;
    for (int n = 1; n < 40; ++n) {
        term *= y / static_cast<double>(n);
        sum += term;
    }
    return sum;
}

constexpr std::array<uint32_t, kDecayTableSize> MakePow2NegTable()
{
    std::array<uint32_t, kDecayTableSize> t{};
    for (size_t i = 0; i < kDecayTableSize; ++i) {
        const double v = Pow2NegFrac(static_cast<double>(i) / static_cast<double>(kDecayTableSize)) * 65536.0;
        t[i] = static_cast<uint32_t>(v + 0.5);   // round half up（v > 0）
    }
    return t;
}
} // namespace detail

// kPow2Neg[i] = round(2^(-i/256) * 65536)，i ∈ [0,256)。kPow2Neg[0] == 65536。
inline constexpr std::array<uint32_t, kDecayTableSize> kPow2Neg = detail::MakePow2NegTable();
static_assert(kPow2Neg[0] == 65536u);
static_assert(kPow2Neg[128] == 46341u);   // round(2^-0.5 * 65536) = round(46340.95)

// score 與回傳值皆為 milli-point。保證：結果 <= score；足夠大的 dt 必回傳 0（不是趨近 0）。
[[nodiscard]] constexpr int64_t DecayMilli(int64_t score, int64_t dtMs, int64_t halfLifeMs) noexcept
{
    if (score <= 0 || dtMs <= 0) return score;
    if (halfLifeMs <= 0) return 0;

    const uint64_t q     = (static_cast<uint64_t>(dtMs) << 8) / static_cast<uint64_t>(halfLifeMs);
    const uint64_t whole = q >> 8;
    const uint32_t frac  = static_cast<uint32_t>(q & 0xFF);
    if (whole >= 63) return 0;

    int64_t v = (score * static_cast<int64_t>(kPow2Neg[frac])) >> 16;
    v >>= whole;
    return (v < kScoreFloor) ? 0 : v;
}

// 反解「分數衰減到 target 以下所需的毫秒數」。只決定何時檢查，不決定檢查結果（SDD-02 §4.5.1）。
// 不用 <cmath>：以整數模擬，逐格（1/256 半衰期）推進直到低於 target，最多 63*256 步。
[[nodiscard]] int64_t MsUntilBelow(int64_t score, int64_t target, int64_t halfLifeMs) noexcept;

} // namespace cairn::score
