// src/core/rules/Rule.h                       namespace cairn::rules
// 編譯後的規則（不可變）與規則集（SDD-02 §5.1）。
// RuleSet 以 shared_ptr<const RuleSet> 持有，熱重載時原子換手（RCU 風格）。
#pragma once
#include <array>
#include <bitset>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "model/Domain.h"
#include "model/EventType.h"
#include "rules/Expr.h"

namespace cairn::rules {

using EventTypeMask = std::bitset<model::kEventTypeCount>;

inline constexpr size_t kMaxSteps = 4;

struct ThresholdSpec {
    uint32_t               count    = 1;
    int64_t                withinMs = 0;
    std::optional<FieldId> distinctField;
};

struct Step {
    std::string                  id;
    EventTypeMask                types;
    ExprPtr                      where;
    std::optional<ThresholdSpec> threshold;
    std::vector<FieldId>         exports;   // 被後續步驟 equals_ref 引用、需匯出的欄位
};

struct Booster {
    std::string   id;
    EventTypeMask types;
    ExprPtr       where;
    int64_t       scoreMilli = 0;
};

enum class CorrelateBy : uint8_t { ProcessTreeRoot = 0, ProcessGuid };

struct ResponseSpec {
    int                             onScoreGe = 80;   // 40 | 80 | 95
    std::vector<model::ActionKind>  actions;          // C-9 四動作；alert 為隱含
    bool                            requireConfirmation = true;
};

// 規則自帶的例外（YAML exceptions:），語意等同 scope_rule_id = 本規則的排除，但無 DB id。
struct RuleException {
    model::ExclusionKind kind = model::ExclusionKind::Path;
    std::string          value;   // 已小寫
};

struct Rule {
    std::string               id;
    std::string               title;
    std::string               description;
    model::Severity           severity = model::Severity::High;
    model::RuleStatus         status   = model::RuleStatus::DryRun;
    int64_t                   scoreMilli = 0;
    uint32_t                  halfLifeMs = 0;
    bool                      deterministic = false;
    std::vector<uint16_t>     requiresEids;
    std::vector<std::string>  attackIds;
    int64_t                   withinMs = 0;
    CorrelateBy               correlateBy = CorrelateBy::ProcessTreeRoot;
    std::vector<Step>         steps;
    std::vector<Booster>      boosters;
    ResponseSpec              response;
    std::vector<RuleException> exceptions;
    uint64_t                  contentHash = 0;
    std::string               hashHex;      // 16 hex，寫入 rule_hits.rule_hash
    std::string               sourceFile;

    EventTypeMask             triggerMask;  // 所有步驟與 booster 的事件型別聯集

    [[nodiscard]] bool IsSequence() const noexcept { return steps.size() > 1; }
};

class RuleSet {
public:
    RuleSet() = default;
    explicit RuleSet(std::vector<Rule> rules, uint32_t generation = 0);
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;

    // 依 EventType 分桶的規則索引；disabled 規則不建索引（SDD-02 §5.5.2）。
    [[nodiscard]] std::span<const uint32_t> RulesFor(model::EventType t) const noexcept;
    [[nodiscard]] const Rule& At(uint32_t idx) const noexcept { return m_rules[idx]; }
    [[nodiscard]] const Rule* Find(std::string_view id) const noexcept;
    [[nodiscard]] std::optional<uint32_t> IndexOf(std::string_view id) const noexcept;
    [[nodiscard]] size_t Size() const noexcept { return m_rules.size(); }
    [[nodiscard]] uint32_t Generation() const noexcept { return m_generation; }
    [[nodiscard]] const std::vector<Rule>& Rules() const noexcept { return m_rules; }

private:
    std::vector<Rule>                                                   m_rules;
    std::array<std::vector<uint32_t>, model::kEventTypeCount>           m_byType;
    std::unordered_map<std::string, uint32_t>                          m_byId;
    uint32_t                                                            m_generation = 0;
};

} // namespace cairn::rules
