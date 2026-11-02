// src/core/rules/Exclusions.h                 namespace cairn::rules
// 排除清單（SDD-02 §5.5）。★ 排除在規則「完整命中之後」才評估——可稽核「這條排除擋掉了什麼」，
// 也不會從中間截斷 sequence 比對。
// 比對對象為觸發事件的行為者程序（image / sha256 / signer / command_line）。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "model/Domain.h"

namespace cairn::rules {

struct RuleException;

// DB exclusions 表的一列（svc 填入後交給 AnalysisEngine::ReplaceExclusions）。
struct ExclusionEntry {
    int64_t              id = 0;                    // exclusions.id；0 = 尚未落地（例如規則內建 exceptions）
    model::ExclusionKind kind = model::ExclusionKind::Path;
    std::string          value;                     // 比對時一律不分大小寫
    std::string          scopeRuleId;               // '' = 全域
    std::string          reason;
    std::string          createdBy = "user";        // user | learning_mode | builtin
    bool                 enabled = true;
    std::optional<int64_t> expiresTs;               // Unix ms；nullopt = 永久
};

struct ExclusionSubject {
    std::string_view image;
    std::string_view sha256;
    std::string_view signer;
    std::string_view commandLine;
};

struct SuppressionResult {
    std::optional<int64_t> exclusionId;   // DB id；規則內建 exceptions 為 nullopt
    std::string            source;        // "exclusion" | "rule_exception"
};

class ExclusionSet {
public:
    void Reload(std::vector<ExclusionEntry> entries);

    // 依序：① scope_rule_id == 本規則 ② 規則自帶 exceptions ③ 全域排除。命中回傳抑制來源。
    [[nodiscard]] std::optional<SuppressionResult> IsSuppressed(std::string_view ruleId,
                                                                const std::vector<RuleException>& ruleExceptions,
                                                                const ExclusionSubject& subj, int64_t nowMs) const;

    [[nodiscard]] size_t Size() const noexcept { return m_global.size() + m_scopedCount; }

    // 單一條目是否命中主體（供 exclusions.preview 等工具使用）。
    [[nodiscard]] static bool Matches(model::ExclusionKind kind, std::string_view lowerValue, std::string_view ruleId,
                                      const ExclusionSubject& subj) noexcept;

private:
    struct Entry {
        int64_t              id;
        model::ExclusionKind kind;
        std::string          value;   // 已小寫
        std::optional<int64_t> expiresTs;
    };
    std::vector<Entry>                                  m_global;
    std::unordered_map<std::string, std::vector<Entry>> m_scoped;
    size_t                                              m_scopedCount = 0;
};

} // namespace cairn::rules
