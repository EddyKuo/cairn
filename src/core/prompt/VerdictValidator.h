// src/core/prompt/VerdictValidator.h          namespace cairn::llm
// LLM 輸出的驗證（part2 §2.6.4、SDD-03 §7.5.1 / §7.5.3）。
//   1. 解析 llama-server /completion 回應：取 content；stopped_limit=true 或 JSON 未閉合 → 視同 schema 違規
//   2. JSON Schema（手寫等價檢查，additionalProperties=false、長度以 code point 計）
//   3. 三道白名單：
//      (1) attack_ids 逐項比對 ATT&CK 白名單，剔除個別項；全部被剔除 → schema_violation
//      (2) narrative / recommendation 不得含 URL / 主機名 → 整則作廢
//      (3) 不得含 ≥ 64 字元的 Base64 長串，或 <<< / >>> / ### / system: / <| → 整則作廢
//      key_indicators 命中 (2)(3) 時只剔除該項（它只是輔助顯示，不值得讓整則作廢）
// 所有失敗一律回傳 ErrorCode::LlmSchemaViolation，context 為人可讀原因（寫入日誌與健康度，不給 LLM 看）。
// ★ 驗證結果只影響 alerts.ai_* 顯示欄位；任何路徑都不會碰分數或回應動作。
#pragma once
#include <cstddef>
#include <string>
#include <string_view>

#include "base/Result.h"
#include "model/NarrativeTypes.h"
#include "prompt/AttackCatalog.h"

namespace cairn::llm {

enum class ValidationFailure {
    None = 0,
    NotJson,             // 回應或 content 不是 JSON
    Truncated,           // stopped_limit / 未閉合（n_predict 用盡）
    SchemaViolation,     // 缺欄位、型別錯、長度越界、多餘欄位
    AttackIdsRejected,   // attack_ids 全被白名單剔除
    ForbiddenContent,    // URL / Base64 / 分隔序列
};

struct ValidationReport {
    ValidationFailure failure = ValidationFailure::None;
    std::string       reason;
    size_t            attackIdsRejected     = 0;
    size_t            keyIndicatorsDropped  = 0;
};

[[nodiscard]] std::string_view ValidationFailureName(ValidationFailure f) noexcept;

class VerdictValidator {
public:
    explicit VerdictValidator(const AttackCatalog& catalog = AttackCatalog::Builtin()) : m_catalog(&catalog) {}

    // llama-server /completion 回應體 → 模型產生的 JSON 文字（content 欄位）
    [[nodiscard]] Result<std::string> ExtractCompletionContent(std::string_view responseBody,
                                                               ValidationReport* report = nullptr) const;

    // 模型產生的 JSON 文字 → 驗證後的 NarrativeResult
    [[nodiscard]] Result<model::NarrativeResult> Validate(std::string_view modelJson,
                                                          ValidationReport* report = nullptr) const;

    // 上兩者串接
    [[nodiscard]] Result<model::NarrativeResult> ValidateCompletion(std::string_view responseBody,
                                                                    ValidationReport* report = nullptr) const;

    // 輸出後掃描（可單獨測試）
    [[nodiscard]] static bool ContainsUrl(std::string_view s);
    [[nodiscard]] static bool ContainsBase64Blob(std::string_view s, size_t minRun = 64) noexcept;
    [[nodiscard]] static bool ContainsDelimiter(std::string_view s) noexcept;

private:
    const AttackCatalog* m_catalog;
};

} // namespace cairn::llm
