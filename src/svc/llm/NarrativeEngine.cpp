#include "llm/NarrativeEngine.h"

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "llm/LlamaServerSupervisor.h"

namespace cairn::llm {

Result<std::unique_ptr<LlamaHttpEngine>> LlamaHttpEngine::Create(LlamaServerSupervisor* supervisor,
                                                                 const AttackCatalog* catalog, HttpTimeouts timeouts)
{
    if (!supervisor || !catalog) return MakeError(ErrorCode::InvalidArgument, "LlamaHttpEngine: supervisor/catalog 為空");
    auto http = WinHttpClient::Create(L"127.0.0.1", supervisor->Port());
    if (!http) return http.GetError();
    return std::unique_ptr<LlamaHttpEngine>(
        new LlamaHttpEngine(supervisor, catalog, timeouts, std::move(http).Value()));
}

Result<model::NarrativeResult> LlamaHttpEngine::Generate(const model::PromptInput& in, const GenerateOptions& opt,
                                                         std::stop_token cancel)
{
    // 冷啟動（最長 60 s）不佔用 30 s 的生成預算（SDD-03 §7.2.5）
    if (auto st = m_sup->EnsureRunning(); !st) return st.GetError();
    if (cancel.stop_requested()) return MakeError(ErrorCode::Cancelled, "cancelled after EnsureRunning");

    PromptOptions popt;
    popt.reducedContext = opt.reducedContext;
    const BuiltPrompt prompt = m_prompt.Build(in, popt);
    const std::string body   = m_prompt.BuildCompletionRequest(prompt, popt);
    if (prompt.reduced)
        spdlog::info("[llm] alert {} prompt 已縮減以符合 context 預算（timeline={} chain={} field={} tokens≈{}）",
                     in.alertId, prompt.timelineIncluded, prompt.chainIncluded, prompt.fieldMaxLen,
                     prompt.estimatedTokens);

    const std::wstring headers = L"Content-Type: application/json\r\nAuthorization: Bearer " +
                                 svc::Utf8ToWide(m_sup->ApiKey()) + L"\r\n";
    auto resp = m_http->Post(L"/completion", body, headers, m_timeouts, cancel);
    if (!resp) {
        if (resp.Code() == ErrorCode::LlmUnavailable) m_sup->ReportConnectionFailure();
        return resp.GetError();
    }
    if (resp.Value().statusCode != 200) {
        m_lastHttpStatus = resp.Value().statusCode;
        // 4xx/5xx（context overflow、grammar 編譯失敗、模型載入中）→ schema_violation（SDD-03 §7.5.3）
        return MakeError(ErrorCode::LlmHttpError, "llama-server HTTP " + std::to_string(resp.Value().statusCode));
    }

    ValidationReport rep;
    auto result = m_validator.ValidateCompletion(resp.Value().body, &rep);
    if (!result) {
        spdlog::warn("[llm] alert {} 輸出未通過驗證: {}", in.alertId, rep.reason);
        return result.GetError();
    }
    if (rep.attackIdsRejected > 0 || rep.keyIndicatorsDropped > 0)
        spdlog::info("[llm] alert {} 剔除 {} 個非白名單 ATT&CK ID、{} 個 key_indicator", in.alertId,
                     rep.attackIdsRejected, rep.keyIndicatorsDropped);
    m_sup->NotifyActivity();
    return result;
}

EngineAvailability LlamaHttpEngine::Availability() const
{
    switch (m_sup->State()) {
    case SupervisorState::Unavailable: return EngineAvailability::Unavailable;
    case SupervisorState::Backoff: return EngineAvailability::Degraded;
    default: return EngineAvailability::Ok;   // Stopped（閒置卸載）仍屬可用：下次需要時冷啟動
    }
}

std::string LlamaHttpEngine::ModelId() const { return m_sup->ModelId(); }
int LlamaHttpEngine::RestartsLastHour() const { return m_sup->RestartsLastHour(); }
std::string LlamaHttpEngine::Detail() const
{
    std::string d = SupervisorStateName(m_sup->State());
    const std::string reason = m_sup->StateReason();
    if (!reason.empty()) d += ": " + reason;
    return d;
}
void LlamaHttpEngine::Tick() { m_sup->Tick(); }
void LlamaHttpEngine::RequestManualRestart() { m_sup->RequestManualRestart(); }
void LlamaHttpEngine::CancelCurrent() noexcept { m_http->CancelActive(); }

} // namespace cairn::llm
