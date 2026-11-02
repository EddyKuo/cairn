// src/core/prompt/InputSanitizer.h            namespace cairn::llm
// 不可信字串的四道處理（SDD-03 §7.3.2）：
//   S1 長度截斷（UTF-8 邊界安全，預設 512 字元 = code point）
//   S2 控制字元剝除（U+0000–001F 除 \t、U+007F、U+0080–009F、U+2028/2029、BiDi 覆寫 U+202A–202E / U+2066–2069）
//      換行類字元一律替換為空格（不是刪除），避免把兩個字黏成新字。
//   S3 Delimiter 逸出：`<<<` / `>>>` 以 U+200C（ZWNJ）打斷；另加碼逸出 ChatML 特殊 token 的 `<|` / `|>`
//      （Qwen2.5 使用 ChatML 樣板，`<|im_end|>` 若原樣出現在不可信資料中可偽造訊息邊界——SDD 未列，本實作補上）
//   S4 顯式包裹：<<<UNTRUSTED_DATA>>> … <<<END_UNTRUSTED_DATA>>>
// 純字串處理，無狀態，可 const 共用。
#pragma once
#include <cstddef>
#include <string>
#include <string_view>

namespace cairn::llm {

inline constexpr std::string_view kUntrustedOpen  = "<<<UNTRUSTED_DATA>>>";
inline constexpr std::string_view kUntrustedClose = "<<<END_UNTRUSTED_DATA>>>";

class InputSanitizer {
public:
    static constexpr size_t kDefaultMaxLen = 512;

    // S1+S2+S3。回傳可放入 prompt 的字串（不含包裹標記）。
    [[nodiscard]] std::string Sanitize(std::string_view raw, size_t maxLen = kDefaultMaxLen) const;

    // S1–S4。回傳 "<<<UNTRUSTED_DATA>>>…<<<END_UNTRUSTED_DATA>>>"。
    [[nodiscard]] std::string Wrap(std::string_view raw, size_t maxLen = kDefaultMaxLen) const;

    // 以下為可單獨測試的步驟
    [[nodiscard]] static std::string StripControlChars(std::string_view s);
    [[nodiscard]] static std::string EscapeDelimiters(std::string_view s);
    // 截斷至 maxLen 個 code point；不切斷多位元組序列。截斷時附加 "…"（U+2026）。
    [[nodiscard]] static std::string TruncateUtf8(std::string_view s, size_t maxLen);
    // 修補非法 UTF-8：非法位元組以 U+FFFD 取代（Sysmon 的字串理論上合法，但 4104 可含任意位元組）。
    [[nodiscard]] static std::string RepairUtf8(std::string_view s);
    // code point 數
    [[nodiscard]] static size_t CodePointCount(std::string_view s) noexcept;
};

} // namespace cairn::llm
