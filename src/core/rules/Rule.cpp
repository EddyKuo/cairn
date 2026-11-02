#include "rules/Rule.h"

namespace cairn::rules {

RuleSet::RuleSet(std::vector<Rule> rules, uint32_t generation)
    : m_rules(std::move(rules)), m_generation(generation)
{
    for (uint32_t i = 0; i < m_rules.size(); ++i) {
        const Rule& r = m_rules[i];
        m_byId.emplace(r.id, i);
        if (r.status == model::RuleStatus::Disabled) continue;
        for (size_t t = 0; t < model::kEventTypeCount; ++t)
            if (r.triggerMask.test(t)) m_byType[t].push_back(i);
    }
}

std::span<const uint32_t> RuleSet::RulesFor(model::EventType t) const noexcept
{
    const auto i = static_cast<size_t>(t);
    if (i >= m_byType.size()) return {};
    return {m_byType[i].data(), m_byType[i].size()};
}

const Rule* RuleSet::Find(std::string_view id) const noexcept
{
    auto it = m_byId.find(std::string(id));
    return it == m_byId.end() ? nullptr : &m_rules[it->second];
}

std::optional<uint32_t> RuleSet::IndexOf(std::string_view id) const noexcept
{
    auto it = m_byId.find(std::string(id));
    if (it == m_byId.end()) return std::nullopt;
    return it->second;
}

} // namespace cairn::rules
