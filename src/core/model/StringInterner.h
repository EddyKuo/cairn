// src/core/model/StringInterner.h             namespace cairn::model
// 字串駐留表（SDD-01 §3.4.3）。
//   - Intern() 只由 NormalizerThread（T2）與規則載入時呼叫（寫者）
//   - Resolve() 由 T3/T4/T5/T7 呼叫（多讀者）
// deque 而非 vector：擴容不搬移既有元素，已發出的 string_view 永久有效。
// 容量上限 100,000：防攻擊者以大量隨機路徑撐爆記憶體；飽和時回 kInvalidInternId，
// 呼叫端必須退回字串路徑（NormalizedEvent::imageFallback 等），只損失效能不損失偵測。
#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace cairn::model {

using InternId = uint32_t;
inline constexpr InternId kInvalidInternId = 0xFFFFFFFFu;

class StringInterner {
public:
    explicit StringInterner(size_t maxEntries = 100'000);
    StringInterner(const StringInterner&) = delete;
    StringInterner& operator=(const StringInterner&) = delete;

    // 大小寫敏感：路徑比對的大小寫不敏感由規則編譯期的正規化處理
    // （規則常數與事件欄位皆在 intern 前轉小寫，見 InternLower）。
    [[nodiscard]] InternId Intern(std::string_view s);

    // 先 ASCII 小寫化再 intern。Windows 路徑／簽章者比對一律不分大小寫，
    // 規則引擎與正規化器都必須走這個入口，intern 後的整數比較才會一致。
    [[nodiscard]] InternId InternLower(std::string_view s);

    // 唯讀查詢：存在則回 id，不存在不新增（規則求值時用）。
    [[nodiscard]] InternId Find(std::string_view s) const;

    [[nodiscard]] std::string_view Resolve(InternId id) const;

    [[nodiscard]] size_t Size() const;
    [[nodiscard]] bool   IsSaturated() const;

private:
    mutable std::shared_mutex                      m_mutex;
    std::deque<std::string>                        m_storage;
    std::unordered_map<std::string_view, InternId> m_index;
    size_t                                         m_maxEntries;
};

// ASCII 小寫化（不處理非 ASCII：Windows 檔案系統的大小寫摺疊表不在 core 的範圍內）。
[[nodiscard]] std::string ToLowerAscii(std::string_view s);

} // namespace cairn::model
