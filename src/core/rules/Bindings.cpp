#include "rules/Bindings.h"

namespace cairn::rules {

void BindingSet::Set(uint8_t step, FieldId field, const FieldValue& v)
{
    Binding* slot = nullptr;
    for (auto& b : m_items)
        if (b.step == step && b.field == field) slot = &b;
    if (!slot) {
        if (m_items.size() >= kMaxBindingsPerState) return;
        m_items.push_back(Binding{step, field, std::monostate{}});
        slot = &m_items.back();
    }
    if (const auto* s = std::get_if<std::string_view>(&v)) {
        slot->value = std::string(s->substr(0, kMaxBindingStringLen));
    } else if (const auto* i = std::get_if<int64_t>(&v)) {
        slot->value = *i;
    } else if (const auto* b = std::get_if<bool>(&v)) {
        slot->value = *b;
    } else if (const auto* g = std::get_if<model::GuidValue>(&v)) {
        slot->value = *g;
    } else {
        slot->value = std::monostate{};
    }
}

FieldValue BindingSet::Get(uint8_t step, FieldId field) const noexcept
{
    for (const auto& b : m_items) {
        if (b.step != step || b.field != field) continue;
        if (const auto* s = std::get_if<std::string>(&b.value)) return std::string_view{*s};
        if (const auto* i = std::get_if<int64_t>(&b.value)) return *i;
        if (const auto* x = std::get_if<bool>(&b.value)) return *x;
        if (const auto* g = std::get_if<model::GuidValue>(&b.value)) return *g;
        return std::monostate{};
    }
    return std::monostate{};
}

bool BindingSet::operator==(const BindingSet& o) const noexcept
{
    if (m_items.size() != o.m_items.size()) return false;
    for (size_t i = 0; i < m_items.size(); ++i) {
        if (m_items[i].step != o.m_items[i].step || m_items[i].field != o.m_items[i].field ||
            m_items[i].value != o.m_items[i].value)
            return false;
    }
    return true;
}

} // namespace cairn::rules
