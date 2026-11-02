#include "telemetry/EventXml.h"

#include <array>

namespace cairn::telemetry {

namespace {

constexpr bool IsSpace(char c) noexcept { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

constexpr char LowerAscii(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool EqualsNoCase(std::string_view a, std::string_view b) noexcept
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (LowerAscii(a[i]) != LowerAscii(b[i])) return false;
    return true;
}

// 從 pos（指向 '<' 之後的標籤名稱起點）找出標籤結尾 '>' 的位置，略過引號內的 '>'。
size_t FindTagEnd(std::string_view s, size_t pos) noexcept
{
    char quote = 0;
    for (size_t i = pos; i < s.size(); ++i) {
        const char c = s[i];
        if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '\'' || c == '"') {
            quote = c;
        } else if (c == '>') {
            return i;
        }
    }
    return std::string_view::npos;
}

// 在標籤內容（'<Tag' 與 '>' 之間）找屬性值，未解碼。
std::optional<std::string_view> FindAttr(std::string_view tag, std::string_view attr) noexcept
{
    size_t i = 0;
    while (i < tag.size()) {
        // 跳到下一個屬性名起點
        while (i < tag.size() && (IsSpace(tag[i]) || tag[i] == '/')) ++i;
        const size_t nameBeg = i;
        while (i < tag.size() && !IsSpace(tag[i]) && tag[i] != '=' && tag[i] != '/' && tag[i] != '>') ++i;
        const std::string_view name = tag.substr(nameBeg, i - nameBeg);
        while (i < tag.size() && IsSpace(tag[i])) ++i;
        if (i >= tag.size() || tag[i] != '=') {
            if (i == nameBeg) ++i;   // 防止無進展
            continue;
        }
        ++i;   // '='
        while (i < tag.size() && IsSpace(tag[i])) ++i;
        if (i >= tag.size()) return std::nullopt;
        const char q = tag[i];
        if (q != '\'' && q != '"') return std::nullopt;
        const size_t valBeg = i + 1;
        const size_t valEnd = tag.find(q, valBeg);
        if (valEnd == std::string_view::npos) return std::nullopt;
        if (EqualsNoCase(name, attr)) return tag.substr(valBeg, valEnd - valBeg);
        i = valEnd + 1;
    }
    return std::nullopt;
}

struct Element {
    std::string_view attrs;   // 標籤名之後到 '>' 之前
    std::string_view text;    // 開始標籤與結束標籤之間；自閉合則為空
    bool             found = false;
};

// 在 [from, to) 範圍中找第一個 <name ...> 元素。name 之後必須是空白、'>' 或 '/'。
Element FindElement(std::string_view s, std::string_view name, size_t from = 0,
                    size_t to = std::string_view::npos) noexcept
{
    Element el;
    if (to > s.size()) to = s.size();
    size_t pos = from;
    while (pos < to) {
        const size_t lt = s.find('<', pos);
        if (lt == std::string_view::npos || lt >= to) return el;
        const size_t nameBeg = lt + 1;
        if (s.compare(nameBeg, name.size(), name) == 0) {
            const size_t after = nameBeg + name.size();
            if (after < s.size() && (IsSpace(s[after]) || s[after] == '>' || s[after] == '/')) {
                const size_t gt = FindTagEnd(s, after);
                if (gt == std::string_view::npos) return el;
                el.found = true;
                const bool selfClosing = gt > after && s[gt - 1] == '/';
                el.attrs = s.substr(after, (selfClosing ? gt - 1 : gt) - after);
                if (!selfClosing) {
                    std::string closing;
                    closing.reserve(name.size() + 3);
                    closing.append("</").append(name).append(">");
                    const size_t close = s.find(closing, gt + 1);
                    if (close != std::string_view::npos) el.text = s.substr(gt + 1, close - gt - 1);
                }
                return el;
            }
        }
        pos = lt + 1;
    }
    return el;
}

void AppendUtf8(std::string& out, uint32_t cp)
{
    if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        out.append("\xEF\xBF\xBD");   // U+FFFD
        return;
    }
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

std::string_view Trim(std::string_view s) noexcept
{
    while (!s.empty() && IsSpace(s.front())) s.remove_prefix(1);
    while (!s.empty() && IsSpace(s.back())) s.remove_suffix(1);
    return s;
}

// days from civil（Howard Hinnant 的演算法）：1970-01-01 起的日數。
constexpr int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) noexcept
{
    y -= m <= 2 ? 1 : 0;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

bool ReadDigits(std::string_view s, size_t pos, size_t n, int64_t& out) noexcept
{
    if (pos + n > s.size()) return false;
    int64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

} // namespace

std::string DecodeXmlEntities(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); ++i) {
        const char c = raw[i];
        if (c != '&') {
            out.push_back(c);
            continue;
        }
        const size_t semi = raw.find(';', i + 1);
        if (semi == std::string_view::npos || semi - i > 12) {
            out.push_back(c);
            continue;
        }
        const std::string_view ent = raw.substr(i + 1, semi - i - 1);
        if (ent == "amp") out.push_back('&');
        else if (ent == "lt") out.push_back('<');
        else if (ent == "gt") out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (!ent.empty() && ent[0] == '#') {
            uint32_t cp  = 0;
            bool     ok  = ent.size() > 1;
            const bool hex = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X');
            for (size_t k = hex ? 2 : 1; ok && k < ent.size(); ++k) {
                const char d = ent[k];
                uint32_t v;
                if (d >= '0' && d <= '9') v = static_cast<uint32_t>(d - '0');
                else if (hex && d >= 'a' && d <= 'f') v = static_cast<uint32_t>(d - 'a' + 10);
                else if (hex && d >= 'A' && d <= 'F') v = static_cast<uint32_t>(d - 'A' + 10);
                else { ok = false; break; }
                cp = cp * (hex ? 16u : 10u) + v;
                if (cp > 0x10FFFF) ok = false;
            }
            if (hex && ent.size() == 2) ok = false;
            if (!ok) {
                out.append(raw.substr(i, semi - i + 1));
            } else {
                AppendUtf8(out, cp);
            }
        } else {
            out.append(raw.substr(i, semi - i + 1));   // 未知 entity 原樣保留
        }
        i = semi;
    }
    return out;
}

std::optional<EventXmlView> EventXmlView::Parse(std::string_view xml)
{
    const Element ev = FindElement(xml, "Event");
    if (!ev.found || ev.text.empty()) return std::nullopt;
    const std::string_view body = ev.text;

    EventXmlView v;
    const Element sys = FindElement(body, "System");
    if (!sys.found) return std::nullopt;
    const std::string_view s = sys.text;

    if (const Element e = FindElement(s, "EventID"); e.found) {
        if (auto n = ParseUInt(Trim(e.text)); n && *n <= 0xFFFF) v.m_eventId = static_cast<uint16_t>(*n);
    }
    if (v.m_eventId == 0) return std::nullopt;

    if (const Element e = FindElement(s, "Provider"); e.found) {
        if (auto a = FindAttr(e.attrs, "Name")) v.m_provider = *a;
    }
    if (const Element e = FindElement(s, "TimeCreated"); e.found) {
        if (auto a = FindAttr(e.attrs, "SystemTime")) v.m_systemTime = *a;
    }
    if (const Element e = FindElement(s, "Execution"); e.found) {
        if (auto a = FindAttr(e.attrs, "ProcessID")) {
            if (auto n = ParseUInt(*a); n && *n <= 0xFFFFFFFFull) v.m_execPid = static_cast<uint32_t>(*n);
        }
    }
    if (const Element e = FindElement(s, "EventRecordID"); e.found) {
        if (auto n = ParseUInt(Trim(e.text))) v.m_recordId = *n;
    }
    if (const Element e = FindElement(s, "Channel"); e.found) v.m_channel = Trim(e.text);
    if (const Element e = FindElement(s, "Computer"); e.found) v.m_computer = Trim(e.text);
    if (const Element e = FindElement(s, "Security"); e.found) {
        if (auto a = FindAttr(e.attrs, "UserID")) v.m_userSid = *a;
    }

    // EventData：逐一取 <Data Name='X'>v</Data>
    const Element data = FindElement(body, "EventData");
    if (data.found && !data.text.empty()) {
        const std::string_view d = data.text;
        v.m_fields.reserve(24);
        size_t pos = 0;
        while (pos < d.size()) {
            const size_t lt = d.find("<Data", pos);
            if (lt == std::string_view::npos) break;
            const size_t after = lt + 5;
            if (after >= d.size()) break;
            if (!(IsSpace(d[after]) || d[after] == '>' || d[after] == '/')) {
                pos = after;
                continue;
            }
            const size_t gt = FindTagEnd(d, after);
            if (gt == std::string_view::npos) break;
            const bool selfClosing = gt > after && d[gt - 1] == '/';
            const std::string_view attrs = d.substr(after, (selfClosing ? gt - 1 : gt) - after);
            DataField f;
            if (auto n = FindAttr(attrs, "Name")) f.name = *n;
            if (selfClosing) {
                pos = gt + 1;
            } else {
                const size_t close = d.find("</Data>", gt + 1);
                if (close == std::string_view::npos) break;   // 結構破損：保留已解析者
                f.raw = d.substr(gt + 1, close - gt - 1);
                pos   = close + 7;
            }
            v.m_fields.push_back(f);
        }
    }
    return v;
}

std::optional<std::string_view> EventXmlView::RawField(std::string_view name) const noexcept
{
    for (const auto& f : m_fields)
        if (EqualsNoCase(f.name, name)) return f.raw;
    return std::nullopt;
}

std::optional<std::string> EventXmlView::Field(std::string_view name) const
{
    auto raw = RawField(name);
    if (!raw) return std::nullopt;
    const std::string_view t = Trim(*raw);
    if (t.empty() || t == "-") return std::nullopt;
    return DecodeXmlEntities(*raw);
}

uint16_t PeekEventId(std::string_view xml) noexcept
{
    const size_t p = xml.find("<EventID");
    if (p == std::string_view::npos) return 0;
    const size_t gt = xml.find('>', p);
    if (gt == std::string_view::npos) return 0;
    uint32_t v = 0;
    size_t   i = gt + 1;
    bool     any = false;
    for (; i < xml.size() && xml[i] >= '0' && xml[i] <= '9' && v <= 0xFFFF; ++i) {
        v = v * 10 + static_cast<uint32_t>(xml[i] - '0');
        any = true;
    }
    return (any && v <= 0xFFFF) ? static_cast<uint16_t>(v) : 0;
}

uint16_t PeekEventIdW(std::wstring_view xml) noexcept
{
    const size_t p = xml.find(L"<EventID");
    if (p == std::wstring_view::npos) return 0;
    const size_t gt = xml.find(L'>', p);
    if (gt == std::wstring_view::npos) return 0;
    uint32_t v = 0;
    bool     any = false;
    for (size_t i = gt + 1; i < xml.size() && xml[i] >= L'0' && xml[i] <= L'9' && v <= 0xFFFF; ++i) {
        v = v * 10 + static_cast<uint32_t>(xml[i] - L'0');
        any = true;
    }
    return (any && v <= 0xFFFF) ? static_cast<uint16_t>(v) : 0;
}

std::optional<int64_t> ParseUtcTimeMs(std::string_view s) noexcept
{
    s = Trim(s);
    // YYYY-MM-DD[ T]hh:mm:ss[.fraction][Z]
    int64_t y, mo, d, h, mi, se;
    if (!ReadDigits(s, 0, 4, y) || s.size() < 19 || s[4] != '-' || !ReadDigits(s, 5, 2, mo) || s[7] != '-' ||
        !ReadDigits(s, 8, 2, d) || (s[10] != ' ' && s[10] != 'T') || !ReadDigits(s, 11, 2, h) || s[13] != ':' ||
        !ReadDigits(s, 14, 2, mi) || s[16] != ':' || !ReadDigits(s, 17, 2, se)) {
        return std::nullopt;
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return std::nullopt;
    int64_t ms = 0;
    size_t  i  = 19;
    if (i < s.size() && s[i] == '.') {
        ++i;
        int digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            if (digits < 3) ms = ms * 10 + (s[i] - '0');
            ++digits;
            ++i;
        }
        for (int k = digits; k < 3; ++k) ms *= 10;   // ".2" → 200 ms
    }
    const int64_t days = DaysFromCivil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
    return ((days * 24 + h) * 60 + mi) * 60'000 + se * 1000 + ms;
}

std::optional<uint64_t> ParseUInt(std::string_view s) noexcept
{
    s = Trim(s);
    if (s.empty()) return std::nullopt;
    uint64_t v = 0;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        if (s.size() > 18) return std::nullopt;
        for (size_t i = 2; i < s.size(); ++i) {
            const char c = s[i];
            uint64_t d;
            if (c >= '0' && c <= '9') d = static_cast<uint64_t>(c - '0');
            else if (c >= 'a' && c <= 'f') d = static_cast<uint64_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = static_cast<uint64_t>(c - 'A' + 10);
            else return std::nullopt;
            v = (v << 4) | d;
        }
        return v;
    }
    if (s.size() > 20) return std::nullopt;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

std::string ExtractSha256(std::string_view hashes)
{
    // 大小寫不敏感找 "SHA256="
    size_t pos = std::string_view::npos;
    for (size_t i = 0; i + 7 <= hashes.size(); ++i) {
        if (EqualsNoCase(hashes.substr(i, 7), "SHA256=")) {
            // 必須在開頭或逗號之後（避免誤認其他欄位內的子字串）
            if (i == 0 || hashes[i - 1] == ',' || IsSpace(hashes[i - 1])) {
                pos = i + 7;
                break;
            }
        }
    }
    if (pos == std::string_view::npos) return {};
    std::string out;
    out.reserve(64);
    for (size_t i = pos; i < hashes.size() && out.size() < 64; ++i) {
        const char c = hashes[i];
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) out.push_back(c);
        else if (c >= 'a' && c <= 'f') out.push_back(static_cast<char>(c - 'a' + 'A'));
        else break;
    }
    return out.size() == 64 ? out : std::string{};
}

} // namespace cairn::telemetry
