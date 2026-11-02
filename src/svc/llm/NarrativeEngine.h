// src/svc/llm/NarrativeEngine.h               namespace cairn::llm
// 敘事引擎（SDD-03 §7.1）：唯一的多型點，存在的理由是測試——
// FakeNarrativeEngine / NullNarrativeEngine 可模擬逾時、schema 違規、完全不可用等分支。
//
// LlamaHttpEngine 的一次 Generate：
//   Supervisor.EnsureRunning → PromptBuilder（含 InputSanitizer 四道處理）→ POST /completion（30 s 預算）
//   → VerdictValidator（schema + 三道白名單）→ Supervisor.NotifyActivity
// 錯誤碼（LlmWorker 依此決定 ai_state）：
//   LlmUnavailable → 'unavailable'；LlmTimeout → 'timeout'；Cancelled → 服務停止（不回填）
//   LlmSchemaViolation / LlmHttpError / 其他 → 'schema_violation'
// 非執行緒安全：只在 LlmWorker（T5）上使用。
#pragma once
#include <memory>
#include <stop_token>
#include <string>

#include "base/Result.h"
#include "model/NarrativeTypes.h"
#include "llm/WinHttpClient.h"
#include "prompt/AttackCatalog.h"
#include "prompt/PromptBuilder.h"
#include "prompt/VerdictValidator.h"

namespace cairn::llm {

class LlamaServerSupervisor;

enum class EngineAvailability { Ok, Degraded, Unavailable };

struct GenerateOptions {
    bool reducedContext = false;
};

class INarrativeEngine {
public:
    virtual ~INarrativeEngine() = default;
    [[nodiscard]] virtual Result<model::NarrativeResult> Generate(const model::PromptInput& in,
                                                                  const GenerateOptions& opt,
                                                                  std::stop_token cancel) = 0;
    [[nodiscard]] virtual EngineAvailability Availability() const = 0;
    [[nodiscard]] virtual std::string ModelId() const = 0;
    [[nodiscard]] virtual int RestartsLastHour() const { return 0; }
    [[nodiscard]] virtual std::string Detail() const { return {}; }   // 例如 "backoff: process exited"（不得阻塞）
    virtual void Tick() {}                     // T8：閒置卸載、崩潰偵測
    virtual void RequestManualRestart() {}     // UI「手動重啟本機 AI」
    virtual void CancelCurrent() noexcept {}   // 任意執行緒：中止進行中的推論
};

// 永遠不可用（LLM 停用時注入；也用於「LLM 全掛時系統行為不變」的驗證，SDD-03 §7.7.3）
class NullNarrativeEngine final : public INarrativeEngine {
public:
    Result<model::NarrativeResult> Generate(const model::PromptInput&, const GenerateOptions&, std::stop_token) override
    {
        return MakeError(ErrorCode::LlmUnavailable, "LLM disabled");
    }
    EngineAvailability Availability() const override { return EngineAvailability::Unavailable; }
    std::string ModelId() const override { return {}; }
    std::string Detail() const override { return "disabled"; }
};

class LlamaHttpEngine final : public INarrativeEngine {
public:
    // supervisor 由 ServiceHost 擁有，生命週期必須長於本物件。catalog 同理（AttackCatalog::Builtin() 為靜態）。
    [[nodiscard]] static Result<std::unique_ptr<LlamaHttpEngine>> Create(LlamaServerSupervisor* supervisor,
                                                                         const AttackCatalog* catalog,
                                                                         HttpTimeouts timeouts = {});

    Result<model::NarrativeResult> Generate(const model::PromptInput& in, const GenerateOptions& opt,
                                            std::stop_token cancel) override;
    EngineAvailability Availability() const override;
    std::string ModelId() const override;
    int RestartsLastHour() const override;
    std::string Detail() const override;
    void Tick() override;
    void RequestManualRestart() override;
    void CancelCurrent() noexcept override;

    // 最近一次失敗的 HTTP 狀態碼（健康度指標用）；0 = 無
    [[nodiscard]] uint32_t LastHttpStatus() const noexcept { return m_lastHttpStatus; }

private:
    LlamaHttpEngine(LlamaServerSupervisor* sup, const AttackCatalog* catalog, HttpTimeouts t,
                    std::unique_ptr<WinHttpClient> http)
        : m_sup(sup), m_validator(*catalog), m_timeouts(t), m_http(std::move(http)) {}

    LlamaServerSupervisor*         m_sup;
    PromptBuilder                  m_prompt;
    VerdictValidator               m_validator;
    HttpTimeouts                   m_timeouts;
    std::unique_ptr<WinHttpClient> m_http;
    uint32_t                       m_lastHttpStatus = 0;
};

} // namespace cairn::llm
