// src/svc/response/FirewallNaming.cpp         可攜：規則命名與 IP 字面值驗證
#include <cstdlib>
#include <string>

#include "response/FirewallResponder.h"

namespace cairn::response {

std::string FirewallRuleName(int64_t alertId, const std::string& ip)
{
    return std::string(kFirewallRulePrefix) + std::to_string(alertId) + " (" + ip + ")";
}

namespace {
bool IsIpv4(const std::string& s)
{
    int parts = 0;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = i;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') ++j;
        const size_t len = j - i;
        if (len == 0 || len > 3) return false;
        if (len > 1 && s[i] == '0') return false;   // 不接受前導零（避免八進位歧義）
        if (std::atoi(s.substr(i, len).c_str()) > 255) return false;
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
    }
    return parts == 4;
}

bool IsHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

bool IsIpv6(const std::string& s)
{
    if (s.size() < 2 || s.size() > 45) return false;
    int groups = 0;
    bool doubleColon = false;
    size_t i = 0;
    if (s.compare(0, 2, "::") == 0) {
        doubleColon = true;
        i = 2;
        if (i == s.size()) return true;
    }
    while (i < s.size()) {
        size_t j = i;
        while (j < s.size() && IsHex(s[j])) ++j;
        const size_t len = j - i;
        if (j < s.size() && s[j] == '.') {   // 內嵌 IPv4 尾段
            return IsIpv4(s.substr(i)) && groups + 2 <= 8 && (doubleColon || groups + 2 == 8);
        }
        if (len == 0 || len > 4) return false;
        ++groups;
        if (j == s.size()) break;
        if (s[j] != ':') return false;
        if (j + 1 < s.size() && s[j + 1] == ':') {
            if (doubleColon) return false;
            doubleColon = true;
            i = j + 2;
            if (i == s.size()) break;
        } else {
            i = j + 1;
            if (i == s.size()) return false;
        }
    }
    return doubleColon ? groups < 8 : groups == 8;
}
} // namespace

bool IsValidIpLiteral(const std::string& ip)
{
    if (ip.empty()) return false;
    if (ip.find(':') != std::string::npos) return IsIpv6(ip);
    return IsIpv4(ip);
}

} // namespace cairn::response
