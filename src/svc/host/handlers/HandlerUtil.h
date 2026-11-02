// src/svc/host/handlers/HandlerUtil.h          namespace cairn::host::handlers
// handler 共用的小工具：取唯讀連線、等寫入完成、寫稽核、組 actor 字串。
#pragma once
#include <chrono>
#include <future>
#include <memory>
#include <string>

#include "host/HandlerContext.h"
#include "host/handlers/Convert.h"
#include "rpc/JsonRpcDispatcher.h"
#include "store/ReadOnlyDb.h"

namespace cairn::host::handlers {

using Json = nlohmann::json;
using rpc::RpcContext;
using rpc::RpcOutcome;

inline RpcOutcome Fail(rpc::RpcError e) { return RpcOutcome::Fail(std::move(e)); }
inline RpcOutcome Fail(const Error& e) { return RpcOutcome::Fail(conv::FromError(e)); }
inline RpcOutcome BadParam(std::string msg) { return RpcOutcome::Fail(conv::Err("INVALID_PARAMS", 400, std::move(msg))); }

// 本執行緒的唯讀連線；開不起來時回 SERVICE_UNAVAILABLE。
inline Result<store::ReadOnlyDb*> Reader(const HandlerDeps& d)
{
    store::ReadOnlyDb* db = d.reader ? d.reader() : nullptr;
    if (!db) return MakeError(ErrorCode::ServiceUnavailable, "資料庫唯讀連線無法開啟");
    return db;
}

// 投遞寫入並等待 WriterThread 提交（需要新列 id，或後續動作依賴寫入已落地時使用）。
inline Result<int64_t> WriteAndWait(const HandlerDeps& d, model::WritePayload payload)
{
    auto prom = std::make_shared<std::promise<Result<int64_t>>>();
    auto fut  = prom->get_future();
    model::WriteOp op{std::move(payload), [prom](Result<int64_t> r) {
                          try {
                              prom->set_value(std::move(r));
                          } catch (...) {
                              // 已設定過（不應發生）：忽略
                          }
                      }};
    if (!d.writes->Post(std::move(op))) return MakeError(ErrorCode::QueueFull, "寫入佇列已滿");
    if (fut.wait_for(d.writeTimeout) != std::future_status::ready) {
        return MakeError(ErrorCode::Timeout, "寫入未在時限內完成");
    }
    return fut.get();
}

inline std::string ActorOf(const RpcContext& ctx)
{
    return ctx.clientUser.empty() ? std::string("analyst") : "user:" + ctx.clientUser;
}

// 非阻塞寫稽核（Urgent，不受佇列容量限制）
inline void Audit(const HandlerDeps& d, const RpcContext& ctx, std::string action, std::string eventKind,
                  std::optional<int64_t> alertId, std::string target, Json params, std::string result = "ok",
                  std::optional<std::string> error = std::nullopt)
{
    model::AuditRow a;
    a.ts        = d.clock->NowMs();
    a.actor     = ActorOf(ctx);
    a.action    = std::move(action);
    a.eventKind = std::move(eventKind);
    a.alertId   = alertId;
    a.target    = std::move(target);
    if (!params.is_object()) params = Json::object();
    if (!a.eventKind.empty()) params["event_kind"] = a.eventKind;
    a.paramsJson = params.dump(-1, ' ', false, Json::error_handler_t::replace);
    a.result     = std::move(result);
    a.error      = std::move(error);
    (void)d.writes->Post(model::WriteOp{std::move(a), {}});
}

inline std::string NewToken(const HandlerDeps& d)
{
    if (d.newToken) return d.newToken();
    static std::atomic<uint64_t> n{0};
    return "tok-" + std::to_string(d.clock->NowMs()) + "-" + std::to_string(++n);
}

} // namespace cairn::host::handlers
