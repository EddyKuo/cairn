// src/core/model/GuidValue.h                  namespace cairn::model
// Sysmon ProcessGuid 的值型別。std::array<uint8_t,16> + std::hash 特化。
// 不用 Win32 GUID：會把 <windows.h> 拖進 src/core（part2 §2.1.3）。
#pragma once
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace cairn::model {

struct GuidValue {
    std::array<uint8_t, 16> bytes{};

    [[nodiscard]] bool IsNull() const noexcept
    {
        for (auto b : bytes)
            if (b != 0) return false;
        return true;
    }

    // 接受 "{1a2b3c4d-....}" 或不含大括號的 36 字元形式，大小寫不拘。
    // 位元組順序：直接依字串的十六進位順序存放（非 Win32 GUID 的 little-endian 欄位），
    // 因此 Parse(ToString()) 必為恆等，且與 DB 中的 TEXT 欄位一一對應。
    [[nodiscard]] static std::optional<GuidValue> Parse(std::string_view s) noexcept;

    // 輸出大寫、含大括號：{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}，與 Sysmon XML 一致。
    [[nodiscard]] std::string ToString() const;

    [[nodiscard]] size_t Hash() const noexcept
    {
        // FNV-1a 64-bit
        uint64_t h = 1469598103934665603ull;
        for (auto b : bytes) {
            h ^= b;
            h *= 1099511628211ull;
        }
        return static_cast<size_t>(h);
    }

    friend bool operator==(const GuidValue&, const GuidValue&) noexcept = default;
    friend auto operator<=>(const GuidValue&, const GuidValue&) noexcept = default;
};

using ProcessGuid = GuidValue;

struct GuidHash {
    size_t operator()(const GuidValue& g) const noexcept { return g.Hash(); }
};

} // namespace cairn::model

template <>
struct std::hash<cairn::model::GuidValue> {
    size_t operator()(const cairn::model::GuidValue& g) const noexcept { return g.Hash(); }
};
