// src/core/model/NarrativeTypes.h             namespace cairn::model
// LLM 敘事層的跨模組型別。
//   AnalysisThread 告警成立 → IAlertSink::OnAlertRaised → svc 投遞 NarrativeRequest 到 T5（僅分數 >= 80）
//   T5 以唯讀 DB 連線組出 PromptInput → core/prompt/PromptBuilder → llama-server → VerdictValidator
// ★ 架構紅線：LLM 永不參與加分或阻擋決策。此檔只描述「事後解釋」所需的輸入，
//   ScoreEngine / AnalysisEngine 不得 include 任何 llm/ 或 prompt/ 標頭（W3 code review 檢查項）。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base/Result.h"
#include "model/Domain.h"
#include "model/GuidValue.h"

namespace cairn::model {

struct NarrativeRequest {
    int64_t alertId    = 0;
    int64_t scoreMilli = 0;       // 佇列滿時踢掉優先度（分數）最低者（SDD-03 §7.7.2）
    int64_t enqueuedTs = 0;
    bool    manual     = false;   // 使用者按「重新生成」
};

// ---- PromptBuilder 的輸入（受信任 vs 不可信 實體分離，part2 §2.6.3）----
struct PromptProcessNode {
    int32_t     depth = 0;
    std::string image;            // ⚠ 不可信
    std::string commandLine;      // ⚠ 不可信
    std::string signer;           // 簽章者字串本身也可能被偽造 → 視為不可信
    std::optional<bool> signatureValid;
    std::string sha256;
};

struct PromptTimelineEvent {
    int64_t     offsetMs = 0;     // 相對第一個事件
    uint16_t    eid      = 0;
    std::string eventType;        // PROCESS_CREATE ...（受信任：由我方列舉產生）
    std::string summary;          // ⚠ 不可信（檔名、網域、命令列片段）
};

struct PromptInput {
    // TRUSTED FACTS —— 由 Cairn 規則引擎產生
    int64_t                  alertId    = 0;
    int64_t                  scoreMilli = 0;
    std::vector<std::string> ruleIds;
    std::vector<std::string> ruleAttackIds;
    std::vector<std::string> actionsTaken;   // C-9 動作名
    int32_t                  treeDepth = 0;
    std::string              hostRole  = "workstation";
    // 結構受信任，字串值不可信
    std::vector<PromptProcessNode>   processChain;
    std::vector<PromptTimelineEvent> timeline;   // 最多 40 筆，最舊在前
};

// 驗證後的 LLM 輸出（part2 §2.6.4 的 schema）
struct NarrativeResult {
    std::vector<std::string> attackIds;
    std::string              narrative;
    std::string              recommendation;
    double                   confidence = 0.0;
    bool                     evasionAttemptDetected = false;
    std::vector<std::string> keyIndicators;
};

// AnalysisEngine 告警成立時的通知（svc 決定送 LLM、Toast 等）。
struct AlertRaised {
    int64_t   alertId    = 0;
    GuidValue rootProcessGuid{};
    int64_t   scoreMilli = 0;
    Severity  severity   = Severity::High;
    TreeState state      = TreeState::Alerted;
    std::string title;
};

class IAlertSink {
public:
    virtual ~IAlertSink() = default;
    virtual void OnAlertRaised(const AlertRaised& a) = 0;   // 非阻塞，於 AnalysisThread 上呼叫
};

// T5 LlmWorker 取得告警脈絡的來源。由 store 的唯讀連線實作（svc/store），LlmWorker 只認識此介面。
// 實作必須可在 T5 上呼叫（每執行緒自有唯讀連線）。
class IAlertContextProvider {
public:
    virtual ~IAlertContextProvider() = default;
    [[nodiscard]] virtual Result<PromptInput> LoadPromptInput(int64_t alertId) = 0;
};

} // namespace cairn::model
