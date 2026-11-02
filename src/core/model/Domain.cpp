#include "model/Domain.h"

#include <array>
#include <utility>

namespace cairn::model {

namespace {
template <class E, size_t N>
std::optional<E> Lookup(const std::array<std::pair<E, std::string_view>, N>& table, std::string_view s) noexcept
{
    for (const auto& [e, name] : table)
        if (name == s) return e;
    return std::nullopt;
}

template <class E, size_t N>
std::string_view Name(const std::array<std::pair<E, std::string_view>, N>& table, E v) noexcept
{
    for (const auto& [e, name] : table)
        if (e == v) return name;
    return table[0].second;
}

constexpr std::array<std::pair<TreeState, std::string_view>, 6> kTreeStates{{
    {TreeState::Benign, "normal"},
    {TreeState::Watched, "watching"},
    {TreeState::Alerted, "alerted"},
    {TreeState::Blocked, "blocked"},
    {TreeState::Resolved, "resolved"},
    {TreeState::Excluded, "excluded"},
}};

constexpr std::array<std::pair<Severity, std::string_view>, 4> kSeverities{{
    {Severity::Low, "low"},
    {Severity::Medium, "medium"},
    {Severity::High, "high"},
    {Severity::Critical, "critical"},
}};

constexpr std::array<std::pair<RuleStatus, std::string_view>, 3> kRuleStatuses{{
    {RuleStatus::Enabled, "enabled"},
    {RuleStatus::DryRun, "dryrun"},
    {RuleStatus::Disabled, "disabled"},
}};

constexpr std::array<std::pair<Verdict, std::string_view>, 3> kVerdicts{{
    {Verdict::TruePositive, "true_positive"},
    {Verdict::FalsePositive, "false_positive"},
    {Verdict::Benign, "benign"},
}};

constexpr std::array<std::pair<AiState, std::string_view>, 6> kAiStates{{
    {AiState::Pending, "pending"},
    {AiState::Ok, "ok"},
    {AiState::Timeout, "timeout"},
    {AiState::SchemaViolation, "schema_violation"},
    {AiState::Unavailable, "unavailable"},
    {AiState::Skipped, "skipped"},
}};

constexpr std::array<std::pair<ActionKind, std::string_view>, 4> kActions{{
    {ActionKind::SuspendProcess, "suspend_process"},
    {ActionKind::TerminateProcessTree, "terminate_process_tree"},
    {ActionKind::QuarantineFile, "quarantine_file"},
    {ActionKind::FirewallBlock, "firewall_block"},
}};

constexpr std::array<std::pair<ExclusionKind, std::string_view>, 6> kExclusionKinds{{
    {ExclusionKind::Path, "path"},
    {ExclusionKind::PathGlob, "path_glob"},
    {ExclusionKind::Sha256, "sha256"},
    {ExclusionKind::Signer, "signer"},
    {ExclusionKind::RuleId, "rule_id"},
    {ExclusionKind::CmdlineGlob, "cmdline_glob"},
}};
} // namespace

std::string_view TreeStateToDb(TreeState s) noexcept { return Name(kTreeStates, s); }

std::string_view SeverityToString(Severity s) noexcept { return Name(kSeverities, s); }
std::optional<Severity> SeverityFromString(std::string_view s) noexcept { return Lookup(kSeverities, s); }

std::string_view RuleStatusToString(RuleStatus s) noexcept { return Name(kRuleStatuses, s); }
std::optional<RuleStatus> RuleStatusFromString(std::string_view s) noexcept { return Lookup(kRuleStatuses, s); }

std::string_view VerdictToString(Verdict v) noexcept { return Name(kVerdicts, v); }
std::optional<Verdict> VerdictFromString(std::string_view s) noexcept { return Lookup(kVerdicts, s); }

std::string_view AiStateToString(AiState s) noexcept { return Name(kAiStates, s); }
std::optional<AiState> AiStateFromString(std::string_view s) noexcept { return Lookup(kAiStates, s); }

std::string_view ActionKindToString(ActionKind a) noexcept { return Name(kActions, a); }
std::optional<ActionKind> ActionKindFromString(std::string_view s) noexcept { return Lookup(kActions, s); }

std::string_view ExclusionKindToString(ExclusionKind k) noexcept { return Name(kExclusionKinds, k); }
std::optional<ExclusionKind> ExclusionKindFromString(std::string_view s) noexcept { return Lookup(kExclusionKinds, s); }

} // namespace cairn::model
