// src/core/rules/Bindings.h                   namespace cairn::rules
// 序列步驟間的變數綁定（SDD-02 §5.4.2）。只匯出真正被後續 equals_ref 引用的欄位。
// 與 SDD 的差異：字串值以 std::string 保存（截斷至 512 字元）而非 InternId ——
//   T3 不寫 interner（寫者僅 T2），且 interner 飽和時 id 會失效。每狀態至多 6 個綁定，記憶體有界。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "rules/Fields.h"

namespace cairn::rules {

inline constexpr size_t kMaxBindingsPerState = 6;
inline constexpr size_t kMaxBindingStringLen = 512;

class BindingSet {
public:
    void Set(uint8_t step, FieldId field, const FieldValue& v);
    [[nodiscard]] FieldValue Get(uint8_t step, FieldId field) const noexcept;
    [[nodiscard]] size_t Size() const noexcept { return m_items.size(); }
    [[nodiscard]] bool operator==(const BindingSet& o) const noexcept;

private:
    struct Binding {
        uint8_t step = 0;
        FieldId field = FieldId::Image;
        std::variant<std::monostate, std::string, int64_t, bool, model::GuidValue> value;
    };
    std::vector<Binding> m_items;
};

} // namespace cairn::rules
