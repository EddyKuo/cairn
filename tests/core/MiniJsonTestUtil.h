// tests/core/MiniJsonTestUtil.h
// 測試專用的極簡 JSON 讀取器：只支援「扁平物件」（值為字串／布林／數值／null），
// 用來讀 tests/fixtures/prompt-injection/*.json。
// 為何不用 nlohmann：它是 cairn_common 的 PRIVATE 相依，測試目標拿不到其 include 路徑。
#pragma once
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>

namespace cairn::testutil {

struct JsonValue {
    enum class Kind { Null, String, Bool, Number } kind = Kind::Null;
    std::string str;
    bool        b   = false;
    double      num = 0.0;
};

using FlatJson = std::map<std::string, JsonValue>;

namespace detail {
inline void AppendUtf8(std::string& out, uint32_t cp)
{
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

inline void SkipWs(const std::string& s, size_t& i)
{
    while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')) ++i;
}

inline uint32_t Hex4(const std::string& s, size_t i)
{
    uint32_t v = 0;
    for (size_t k = 0; k < 4 && i + k < s.size(); ++k) {
        const char c = s[i + k];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<uint32_t>(c - 'A' + 10);
    }
    return v;
}

inline std::optional<std::string> ParseString(const std::string& s, size_t& i)
{
    if (i >= s.size() || s[i] != '"') return std::nullopt;
    ++i;
    std::string out;
    while (i < s.size()) {
        const char c = s[i++];
        if (c == '"') return out;
        if (c != '\\') {
            out.push_back(c);
            continue;
        }
        if (i >= s.size()) return std::nullopt;
        const char e = s[i++];
        switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
            uint32_t cp = Hex4(s, i);
            i += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                const uint32_t lo = Hex4(s, i + 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    i += 6;
                }
            }
            AppendUtf8(out, cp);
            break;
        }
        default: return std::nullopt;
        }
    }
    return std::nullopt;
}
} // namespace detail

inline std::optional<FlatJson> ParseFlatJson(const std::string& s)
{
    using namespace detail;
    FlatJson obj;
    size_t   i = 0;
    SkipWs(s, i);
    if (i >= s.size() || s[i] != '{') return std::nullopt;
    ++i;
    for (;;) {
        SkipWs(s, i);
        if (i < s.size() && s[i] == '}') return obj;
        auto key = ParseString(s, i);
        if (!key) return std::nullopt;
        SkipWs(s, i);
        if (i >= s.size() || s[i] != ':') return std::nullopt;
        ++i;
        SkipWs(s, i);
        JsonValue v;
        if (i < s.size() && s[i] == '"') {
            auto str = ParseString(s, i);
            if (!str) return std::nullopt;
            v.kind = JsonValue::Kind::String;
            v.str  = std::move(*str);
        } else if (s.compare(i, 4, "true") == 0) {
            v.kind = JsonValue::Kind::Bool; v.b = true; i += 4;
        } else if (s.compare(i, 5, "false") == 0) {
            v.kind = JsonValue::Kind::Bool; v.b = false; i += 5;
        } else if (s.compare(i, 4, "null") == 0) {
            i += 4;
        } else {
            size_t j = i;
            while (j < s.size() && (s[j] == '-' || s[j] == '+' || s[j] == '.' || s[j] == 'e' || s[j] == 'E' ||
                                    (s[j] >= '0' && s[j] <= '9')))
                ++j;
            if (j == i) return std::nullopt;
            v.kind = JsonValue::Kind::Number;
            v.num  = std::stod(s.substr(i, j - i));
            i      = j;
        }
        obj[*key] = std::move(v);
        SkipWs(s, i);
        if (i < s.size() && s[i] == ',') { ++i; continue; }
        if (i < s.size() && s[i] == '}') return obj;
        return std::nullopt;
    }
}

inline std::optional<FlatJson> LoadFlatJsonFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::stringstream ss;
    ss << f.rdbuf();
    return ParseFlatJson(ss.str());
}

} // namespace cairn::testutil
