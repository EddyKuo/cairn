// src/svc/response/IResponseAction.h          namespace cairn::response
// 回應動作的三方法契約（SDD-03 §8.1）。可攜標頭。
//   Prepare —— 必須無副作用，只回傳影響清單，可被 UI 反覆呼叫
//   Execute —— 必須冪等地容忍目標已消失（程序已結束、檔案已刪）
//   Revert  —— 不可逆動作回傳 NOT_REVERSIBLE，不得靜默成功
// 執行緒：所有方法只在 ResponseThread（T6）上呼叫（COM 介面不得跨執行緒）。
#pragma once
#include <string>
#include <vector>

#include "base/Result.h"
#include "model/ResponseCommand.h"
#include "response/ResponseTypes.h"

namespace cairn::response {

struct ActionContext {
    int64_t                      alertId = 0;
    model::ActionKind            action = model::ActionKind::SuspendProcess;
    const model::ResponseTarget* target = nullptr;   // 非擁有；呼叫期間有效
    std::string                  reason;
    std::string                  actor;
    bool                         automatic = false;
};

class IResponseAction {
public:
    virtual ~IResponseAction() = default;
    [[nodiscard]] virtual model::ActionKind Kind() const noexcept = 0;

    [[nodiscard]] virtual Result<ActionImpact> Prepare(const ActionContext& ctx) = 0;

    // 執行並把還原所需的參數填進 record（suspended / quarantineIds / firewallRuleName / ip）。
    // 回傳逐目標結果；整體狀態由 ResponseExecutor 以 ComputeStatus 彙總。
    [[nodiscard]] virtual std::vector<TargetOutcome> Execute(const ActionContext& ctx, ActionRecord& record) = 0;

    [[nodiscard]] virtual Result<std::vector<TargetOutcome>> Revert(const ActionRecord& record) = 0;
};

} // namespace cairn::response
