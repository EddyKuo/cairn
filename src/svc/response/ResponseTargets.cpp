// src/svc/response/ResponseTargets.cpp        可攜：目標鍵與顯示標籤
#include "response/ProcessResponder.h"
#include "response/ResponseExecutor.h"
#include "response/ResponseJson.h"

namespace cairn::response {

std::string ProcessKey(const model::ProcessRef& ref)
{
    if (!ref.processGuid.IsNull()) return ref.processGuid.ToString();
    return "pid:" + std::to_string(ref.pid) + "@" + std::to_string(ref.startTsMs);
}

std::string ProcessLabel(const model::ProcessRef& ref)
{
    auto base = BaseNameLower(ref.image);
    if (base.empty()) base = "pid";
    return base + " (" + std::to_string(ref.pid) + ")";
}

std::string TargetKeyOf(model::ActionKind action, const model::ResponseTarget& target)
{
    if (!target.key.empty()) return target.key;
    switch (action) {
    case model::ActionKind::SuspendProcess:
    case model::ActionKind::TerminateProcessTree:
        return target.processes.empty() ? std::string{} : ProcessKey(target.processes.front());
    case model::ActionKind::QuarantineFile:
        return target.filePath ? "file:" + ToLower(*target.filePath) : std::string{};
    case model::ActionKind::FirewallBlock:
        return target.ip ? "ip:" + *target.ip : std::string{};
    }
    return {};
}

} // namespace cairn::response
