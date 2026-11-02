#include "rules/TextMatch.h"

namespace cairn::rules {

bool EqualsCi(std::string_view hay, std::string_view lowerNeedle) noexcept
{
    if (hay.size() != lowerNeedle.size()) return false;
    for (size_t i = 0; i < hay.size(); ++i)
        if (LowerAscii(hay[i]) != lowerNeedle[i]) return false;
    return true;
}

bool StartsWithCi(std::string_view hay, std::string_view lowerNeedle) noexcept
{
    return hay.size() >= lowerNeedle.size() && EqualsCi(hay.substr(0, lowerNeedle.size()), lowerNeedle);
}

bool EndsWithCi(std::string_view hay, std::string_view lowerNeedle) noexcept
{
    return hay.size() >= lowerNeedle.size() && EqualsCi(hay.substr(hay.size() - lowerNeedle.size()), lowerNeedle);
}

bool ContainsCi(std::string_view hay, std::string_view lowerNeedle) noexcept
{
    if (lowerNeedle.empty()) return true;
    if (hay.size() < lowerNeedle.size()) return false;
    const char first = lowerNeedle[0];
    for (size_t i = 0; i + lowerNeedle.size() <= hay.size(); ++i) {
        if (LowerAscii(hay[i]) != first) continue;
        size_t j = 1;
        while (j < lowerNeedle.size() && LowerAscii(hay[i + j]) == lowerNeedle[j]) ++j;
        if (j == lowerNeedle.size()) return true;
    }
    return false;
}

bool GlobMatchCi(std::string_view text, std::string_view p) noexcept
{
    size_t t = 0, i = 0;
    size_t starP = std::string_view::npos, starT = 0;
    while (t < text.size()) {
        if (i < p.size() && (p[i] == '?' || p[i] == LowerAscii(text[t]))) {
            ++t;
            ++i;
        } else if (i < p.size() && p[i] == '*') {
            starP = i++;
            starT = t;
        } else if (starP != std::string_view::npos) {
            i = starP + 1;
            t = ++starT;
        } else {
            return false;
        }
    }
    while (i < p.size() && p[i] == '*') ++i;
    return i == p.size();
}

} // namespace cairn::rules
