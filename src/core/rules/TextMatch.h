// src/core/rules/TextMatch.h                  namespace cairn::rules
// ASCII 大小寫不敏感的字串比對與 glob。Windows 路徑、簽章者、命令列關鍵字的比對一律不分大小寫。
// 規則常數在編譯期已小寫化，因此「pattern 已是小寫」是所有函式的前置條件。
#pragma once
#include <string_view>

namespace cairn::rules {

[[nodiscard]] constexpr char LowerAscii(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// lowerNeedle 必須已小寫
[[nodiscard]] bool EqualsCi(std::string_view hay, std::string_view lowerNeedle) noexcept;
[[nodiscard]] bool StartsWithCi(std::string_view hay, std::string_view lowerNeedle) noexcept;
[[nodiscard]] bool EndsWithCi(std::string_view hay, std::string_view lowerNeedle) noexcept;
[[nodiscard]] bool ContainsCi(std::string_view hay, std::string_view lowerNeedle) noexcept;

// glob：'*' 任意長度、'?' 單一字元；lowerPattern 必須已小寫。以迭代＋回溯實作，O(n·m) 最壞，無遞迴。
[[nodiscard]] bool GlobMatchCi(std::string_view text, std::string_view lowerPattern) noexcept;

} // namespace cairn::rules
