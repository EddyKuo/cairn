// src/core/rules/RuleCompiler.h               namespace cairn::rules
// YAML → AST 編譯管線（SDD-02 §5.2）。純函式、無狀態，可在任意執行緒（例如 RuleWatcher）執行。
// yaml-cpp 為 PRIVATE 相依：本標頭不暴露任何 yaml-cpp 型別；內部例外一律轉為錯誤（P-2）。
#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "base/Result.h"
#include "rules/Rule.h"

namespace cairn::rules {

struct RuleCompileOutcome {
    std::string         ruleId;      // 解析失敗時可能為空
    std::optional<Rule> rule;        // 成功時有值
    ErrorCode           code = ErrorCode::Ok;
    std::string         error;       // 「檔名:行號 訊息」
    int                 line = 0;
};

// 編譯一份 YAML 文字（可含多個以 --- 分隔的規則文件）。
// 語法錯誤 → 整檔失敗（回傳 Error）；單條規則的 schema / 語意錯誤只讓該條規則失敗（UI 標紅，不影響其他規則）。
[[nodiscard]] Result<std::vector<RuleCompileOutcome>> CompileRuleYaml(std::string_view text,
                                                                     std::string_view sourceFile);

// 解析 "600s" / "10m" → 毫秒。失敗回 nullopt。
[[nodiscard]] std::optional<int64_t> ParseDurationMs(std::string_view s) noexcept;

// 規則 ID 格式 R-T<ATT&CK>-<序號>（CONVENTIONS C-8 原則 3）
[[nodiscard]] bool IsValidRuleId(std::string_view id) noexcept;

// FNV-1a 64-bit
[[nodiscard]] uint64_t Fnv1a64(std::string_view s) noexcept;

} // namespace cairn::rules
