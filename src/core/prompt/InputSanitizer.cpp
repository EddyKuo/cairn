#include "prompt/InputSanitizer.h"

#include <cstdint>

namespace cairn::llm {

namespace {

constexpr std::string_view kZwnj      = "\xE2\x80\x8C";   // U+200C
constexpr std::string_view kEllipsis  = "\xE2\x80\xA6";   // U+2026
constexpr std::string_view kReplacement = "\xEF\xBF\xBD"; // U+FFFD

// 解碼一個 code point。輸入必須是已修補的合法 UTF-8。回傳位元組長度。
size_t DecodeOne(std::string_view s, size_t i, uint32_t& cp) noexcept
{
    const auto c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
        cp = c;
        return 1;
    }
    if ((c >> 5) == 0x6 && i + 1 < s.size()) {
        cp = ((c & 0x1Fu) << 6) | (static_cast<unsigned char>(s[i + 1]) & 0x3Fu);
        return 2;
    }
    if ((c >> 4) == 0xE && i + 2 < s.size()) {
        cp = ((c & 0x0Fu) << 12) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 6) |
             (static_cast<unsigned char>(s[i + 2]) & 0x3Fu);
        return 3;
    }
    if ((c >> 3) == 0x1E && i + 3 < s.size()) {
        cp = ((c & 0x07u) << 18) | ((static_cast<unsigned char>(s[i + 1]) & 0x3Fu) << 12) |
             ((static_cast<unsigned char>(s[i + 2]) & 0x3Fu) << 6) | (static_cast<unsigned char>(s[i + 3]) & 0x3Fu);
        return 4;
    }
    cp = 0xFFFD;
    return 1;
}

bool IsCont(unsigned char c) noexcept { return (c & 0xC0) == 0x80; }

} // namespace

std::string InputSanitizer::RepairUtf8(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        size_t     len = 0;
        uint32_t   minCp = 0;
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        if ((c >> 5) == 0x6) { len = 2; minCp = 0x80; }
        else if ((c >> 4) == 0xE) { len = 3; minCp = 0x800; }
        else if ((c >> 3) == 0x1E) { len = 4; minCp = 0x10000; }

        bool ok = len != 0 && i + len <= s.size();
        for (size_t k = 1; ok && k < len; ++k) ok = IsCont(static_cast<unsigned char>(s[i + k]));
        if (ok) {
            uint32_t cp = 0;
            (void)DecodeOne(s, i, cp);
            // 拒絕過長編碼、代理區、超出 Unicode 範圍
            if (cp < minCp || (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) ok = false;
        }
        if (ok) {
            out.append(s.substr(i, len));
            i += len;
        } else {
            out.append(kReplacement);
            ++i;
        }
    }
    return out;
}

size_t InputSanitizer::CodePointCount(std::string_view s) noexcept
{
    size_t n = 0;
    for (char ch : s)
        if (!IsCont(static_cast<unsigned char>(ch))) ++n;
    return n;
}

std::string InputSanitizer::StripControlChars(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        uint32_t     cp  = 0;
        const size_t len = DecodeOne(s, i, cp);
        const std::string_view bytes = s.substr(i, len);
        i += len;

        if (cp == '\t') { out.push_back('\t'); continue; }
        // 換行類：以空格取代，避免偽造新訊息段落又不把前後字黏在一起
        if (cp == '\n' || cp == '\r' || cp == 0x0B || cp == 0x0C || cp == 0x85 || cp == 0x2028 || cp == 0x2029) {
            out.push_back(' ');
            continue;
        }
        if (cp < 0x20 || cp == 0x7F || (cp >= 0x80 && cp <= 0x9F)) continue;     // C0 / DEL / C1
        if (cp >= 0x202A && cp <= 0x202E) continue;                                 // BiDi 嵌入／覆寫
        if (cp >= 0x2066 && cp <= 0x2069) continue;                                 // BiDi 隔離
        if (cp == 0x200E || cp == 0x200F || cp == 0x061C) continue;                 // LRM / RLM / ALM
        if (cp == 0xFEFF) continue;                                                 // BOM / ZWNBSP
        out.append(bytes);
    }
    return out;
}

std::string InputSanitizer::EscapeDelimiters(std::string_view s)
{
    std::string out;
    out.reserve(s.size() + s.size() / 8);
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        out.push_back(c);
        if (i + 1 >= s.size()) break;
        const char n = s[i + 1];
        // `<<` / `>>`：任何連續兩個角括號之間插入 ZWNJ，`<<<` 因此必然被打斷
        // `<|` / `|>`：ChatML 特殊 token 的邊界
        if ((c == '<' && (n == '<' || n == '|')) || (c == '>' && n == '>') || (c == '|' && n == '>')) {
            out.append(kZwnj);
        }
    }
    return out;
}

std::string InputSanitizer::TruncateUtf8(std::string_view s, size_t maxLen)
{
    if (CodePointCount(s) <= maxLen) return std::string(s);
    std::string out;
    size_t      count = 0;
    size_t      i     = 0;
    const size_t keep = maxLen > 0 ? maxLen - 1 : 0;   // 留一個位置給 "…"
    while (i < s.size() && count < keep) {
        uint32_t     cp  = 0;
        const size_t len = DecodeOne(s, i, cp);
        out.append(s.substr(i, len));
        i += len;
        ++count;
    }
    if (maxLen > 0) out.append(kEllipsis);
    return out;
}

std::string InputSanitizer::Sanitize(std::string_view raw, size_t maxLen) const
{
    // 順序：修補 → 剝控制字元 → 截斷 → 逸出（逸出最後做，截斷不會切開 ZWNJ 插入點）
    const std::string repaired = RepairUtf8(raw);
    const std::string stripped = StripControlChars(repaired);
    const std::string cut      = TruncateUtf8(stripped, maxLen);
    return EscapeDelimiters(cut);
}

std::string InputSanitizer::Wrap(std::string_view raw, size_t maxLen) const
{
    std::string body = Sanitize(raw, maxLen);
    // 開頭／結尾若為角括號或 |，與包裹標記相鄰會形成 ">>>>" 或 "<<<<"；插 ZWNJ 隔開。
    std::string out;
    out.reserve(body.size() + kUntrustedOpen.size() + kUntrustedClose.size() + 6);
    out.append(kUntrustedOpen);
    if (!body.empty() && (body.front() == '>' || body.front() == '|')) out.append(kZwnj);
    out.append(body);
    if (!body.empty() && (body.back() == '<' || body.back() == '|')) out.append(kZwnj);
    out.append(kUntrustedClose);
    return out;
}

} // namespace cairn::llm
