#include "rules/Exclusions.h"

#include "model/StringInterner.h"
#include "rules/Rule.h"
#include "rules/TextMatch.h"

namespace cairn::rules {

void ExclusionSet::Reload(std::vector<ExclusionEntry> entries)
{
    m_global.clear();
    m_scoped.clear();
    m_scopedCount = 0;
    for (auto& e : entries) {
        if (!e.enabled || e.value.empty()) continue;
        Entry x{e.id, e.kind, model::ToLowerAscii(e.value), e.expiresTs};
        if (e.scopeRuleId.empty()) {
            m_global.push_back(std::move(x));
        } else {
            m_scoped[e.scopeRuleId].push_back(std::move(x));
            ++m_scopedCount;
        }
    }
}

bool ExclusionSet::Matches(model::ExclusionKind kind, std::string_view v, std::string_view ruleId,
                           const ExclusionSubject& s) noexcept
{
    using K = model::ExclusionKind;
    switch (kind) {
    case K::Path: return !s.image.empty() && EqualsCi(s.image, v);
    case K::PathGlob: return !s.image.empty() && GlobMatchCi(s.image, v);
    case K::Sha256: return !s.sha256.empty() && EqualsCi(s.sha256, v);
    case K::Signer: return !s.signer.empty() && EqualsCi(s.signer, v);
    case K::RuleId: return EqualsCi(ruleId, v);
    case K::CmdlineGlob: return !s.commandLine.empty() && GlobMatchCi(s.commandLine, v);
    }
    return false;
}

std::optional<SuppressionResult> ExclusionSet::IsSuppressed(std::string_view ruleId,
                                                            const std::vector<RuleException>& ruleExceptions,
                                                            const ExclusionSubject& subj, int64_t nowMs) const
{
    auto alive = [&](const Entry& e) { return !e.expiresTs || *e.expiresTs > nowMs; };

    if (auto it = m_scoped.find(std::string(ruleId)); it != m_scoped.end()) {
        for (const auto& e : it->second)
            if (alive(e) && Matches(e.kind, e.value, ruleId, subj)) return SuppressionResult{e.id, "exclusion"};
    }
    for (const auto& ex : ruleExceptions)
        if (Matches(ex.kind, ex.value, ruleId, subj)) return SuppressionResult{std::nullopt, "rule_exception"};
    for (const auto& e : m_global)
        if (alive(e) && Matches(e.kind, e.value, ruleId, subj)) return SuppressionResult{e.id, "exclusion"};
    return std::nullopt;
}

} // namespace cairn::rules
