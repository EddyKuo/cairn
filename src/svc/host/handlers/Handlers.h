// src/svc/host/handlers/Handlers.h            namespace cairn::host
// 註冊 SDD-03 §9.3.2 的全部 RPC 方法（M0：27 條；/events/stream 為 M1 不註冊）。
#pragma once
#include "host/HandlerContext.h"
#include "rpc/JsonRpcDispatcher.h"

namespace cairn::host {

void RegisterAlertHandlers(rpc::JsonRpcDispatcher& d, const HandlerDeps& deps);      // alerts.* / narrative.* / events.query
void RegisterResponseHandlers(rpc::JsonRpcDispatcher& d, const HandlerDeps& deps);   // response.* / quarantine.list / undo.apply
void RegisterConfigHandlers(rpc::JsonRpcDispatcher& d, const HandlerDeps& deps);     // exclusions.* / rules.*
void RegisterSystemHandlers(rpc::JsonRpcDispatcher& d, const HandlerDeps& deps);     // health / audit / protection / learning / export

inline void RegisterAllHandlers(rpc::JsonRpcDispatcher& d, const HandlerDeps& deps)
{
    RegisterAlertHandlers(d, deps);
    RegisterResponseHandlers(d, deps);
    RegisterConfigHandlers(d, deps);
    RegisterSystemHandlers(d, deps);
}

// 預期註冊的方法數（啟動時檢查，少註冊即記錄錯誤）
inline constexpr size_t kExpectedRpcMethods = 27;

} // namespace cairn::host
