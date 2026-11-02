// src/core/model/Domain.h                     namespace cairn::model
// 跨模組共用的領域列舉與常數（SDD-01 §2.4 L-2：跨模組資料型別一律置於 core.common）。
#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace cairn::model {

// ---- 分數：定點數 milli-point（80 分 = 80000），SDD-02 §4.3.1 ----
inline constexpr int64_t kScoreScale        = 1000;
inline constexpr int64_t kScoreMax          = 100 * kScoreScale;
inline constexpr int64_t kThresholdWatched  = 40 * kScoreScale;
inline constexpr int64_t kThresholdAlerted  = 80 * kScoreScale;
inline constexpr int64_t kThresholdBlocked  = 95 * kScoreScale;
inline constexpr int64_t kHysteresisMilli   = 5 * kScoreScale;

// ---- 程序樹風險狀態（SDD-02 §4.3.3 / §4.4）----
enum class TreeState : uint8_t {
    Benign = 0,   // < 40       DB: normal
    Watched,      // >= 40      DB: watching
    Alerted,      // >= 80      DB: alerted
    Blocked,      // >= 95      DB: blocked
    Resolved,     // 分析師已判定 DB: resolved
    Excluded,     // 命中排除    DB: excluded
};
[[nodiscard]] std::string_view TreeStateToDb(TreeState s) noexcept;

// ---- 告警嚴重度 ----
enum class Severity : uint8_t { Low = 0, Medium, High, Critical };
[[nodiscard]] std::string_view SeverityToString(Severity s) noexcept;
[[nodiscard]] std::optional<Severity> SeverityFromString(std::string_view s) noexcept;

// ---- 規則狀態（三態）----
enum class RuleStatus : uint8_t { Enabled = 0, DryRun, Disabled };
[[nodiscard]] std::string_view RuleStatusToString(RuleStatus s) noexcept;   // enabled | dryrun | disabled
[[nodiscard]] std::optional<RuleStatus> RuleStatusFromString(std::string_view s) noexcept;

// ---- 分析師判定 ----
enum class Verdict : uint8_t { TruePositive = 0, FalsePositive, Benign };
[[nodiscard]] std::string_view VerdictToString(Verdict v) noexcept;         // true_positive | false_positive | benign
[[nodiscard]] std::optional<Verdict> VerdictFromString(std::string_view s) noexcept;

// ---- AI 敘事狀態（alerts.ai_state）----
enum class AiState : uint8_t { Pending = 0, Ok, Timeout, SchemaViolation, Unavailable, Skipped };
[[nodiscard]] std::string_view AiStateToString(AiState s) noexcept;
[[nodiscard]] std::optional<AiState> AiStateFromString(std::string_view s) noexcept;

// ---- 回應動作（CONVENTIONS C-9 權威識別碼，不得新增）----
enum class ActionKind : uint8_t { SuspendProcess = 0, TerminateProcessTree, QuarantineFile, FirewallBlock };
[[nodiscard]] std::string_view ActionKindToString(ActionKind a) noexcept;   // suspend_process | ...
[[nodiscard]] std::optional<ActionKind> ActionKindFromString(std::string_view s) noexcept;
[[nodiscard]] constexpr bool IsReversible(ActionKind a) noexcept { return a != ActionKind::TerminateProcessTree; }
// 風險級 L1/L2/L3（SDD-03 §8.0.1）
[[nodiscard]] constexpr int RiskLevelOf(ActionKind a) noexcept
{
    switch (a) {
    case ActionKind::SuspendProcess: return 1;
    case ActionKind::QuarantineFile: return 2;
    case ActionKind::FirewallBlock: return 2;
    case ActionKind::TerminateProcessTree: return 3;
    }
    return 3;
}

// ---- 排除清單種類（exclusions.kind）----
enum class ExclusionKind : uint8_t { Path = 0, PathGlob, Sha256, Signer, RuleId, CmdlineGlob };
[[nodiscard]] std::string_view ExclusionKindToString(ExclusionKind k) noexcept;
[[nodiscard]] std::optional<ExclusionKind> ExclusionKindFromString(std::string_view s) noexcept;

} // namespace cairn::model
