#include "model/GuidValue.h"

namespace cairn::model {

namespace {
int HexVal(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
} // namespace

std::optional<GuidValue> GuidValue::Parse(std::string_view s) noexcept
{
    // 去除前後空白與大括號
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    if (s.size() == 38 && s.front() == '{' && s.back() == '}') s = s.substr(1, 36);
    if (s.size() != 36) return std::nullopt;
    if (s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') return std::nullopt;

    GuidValue g;
    size_t    bi = 0;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '-') {
            ++i;
            continue;
        }
        if (i + 1 >= s.size()) return std::nullopt;
        const int hi = HexVal(s[i]);
        const int lo = HexVal(s[i + 1]);
        if (hi < 0 || lo < 0 || bi >= 16) return std::nullopt;
        g.bytes[bi++] = static_cast<uint8_t>((hi << 4) | lo);
        i += 2;
    }
    if (bi != 16) return std::nullopt;
    return g;
}

std::string GuidValue::ToString() const
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(38);
    out.push_back('{');
    for (size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(kHex[bytes[i] >> 4]);
        out.push_back(kHex[bytes[i] & 0x0F]);
    }
    out.push_back('}');
    return out;
}

} // namespace cairn::model
