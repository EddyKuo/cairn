#include "rpc/JsonRpcDispatcher.h"

#include <exception>

namespace cairn::rpc {

Json RpcError::ToJson() const
{
    Json d = data.is_object() ? data : Json::object();
    d["code"] = appCode;
    return Json{{"code", rpcCode}, {"message", message.empty() ? appCode : message}, {"data", std::move(d)}};
}

void JsonRpcDispatcher::Register(std::string method, RpcHandler handler)
{
    std::unique_lock lk{m_mutex};
    m_handlers[std::move(method)] = std::move(handler);
}

std::vector<std::string> JsonRpcDispatcher::Methods() const
{
    std::shared_lock lk{m_mutex};
    std::vector<std::string> out;
    out.reserve(m_handlers.size());
    for (const auto& [k, _] : m_handlers) out.push_back(k);
    return out;
}

size_t JsonRpcDispatcher::MethodCount() const
{
    std::shared_lock lk{m_mutex};
    return m_handlers.size();
}

namespace {
Json MakeErrorResponse(const Json& id, const RpcError& e)
{
    return Json{{"jsonrpc", "2.0"}, {"id", id}, {"error", e.ToJson()}};
}
} // namespace

Json JsonRpcDispatcher::HandleOne(const Json& req, const RpcContext& ctx, bool& isNotification) const
{
    isNotification = false;
    if (!req.is_object()) {
        return MakeErrorResponse(nullptr, RpcError{kInvalidRequest, "INVALID_REQUEST", "request must be an object", Json::object()});
    }
    const bool hasId = req.contains("id");
    const Json id    = hasId ? req["id"] : Json(nullptr);
    isNotification   = !hasId;

    if (!req.contains("jsonrpc") || req["jsonrpc"] != "2.0" || !req.contains("method") || !req["method"].is_string()) {
        return MakeErrorResponse(id, RpcError{kInvalidRequest, "INVALID_REQUEST", "invalid JSON-RPC 2.0 request", Json::object()});
    }
    if (hasId && !(id.is_number_integer() || id.is_string() || id.is_null())) {
        return MakeErrorResponse(nullptr, RpcError{kInvalidRequest, "INVALID_REQUEST", "invalid id", Json::object()});
    }

    const std::string method = req["method"].get<std::string>();
    Json params = req.contains("params") ? req["params"] : Json::object();
    if (params.is_null()) params = Json::object();
    if (!params.is_object() && !params.is_array()) {
        return MakeErrorResponse(id, RpcError::InvalidParams("params must be object or array"));
    }

    RpcHandler handler;
    {
        std::shared_lock lk{m_mutex};
        auto it = m_handlers.find(method);
        if (it == m_handlers.end()) {
            return MakeErrorResponse(id, RpcError{kMethodNotFound, "METHOD_NOT_FOUND", "method not found: " + method, Json::object()});
        }
        handler = it->second;
    }

    RpcOutcome out;
    try {
        out = handler(params, ctx);
    } catch (const std::exception& ex) {
        out = RpcOutcome::Fail(RpcError::Internal(ex.what()));
    } catch (...) {
        out = RpcOutcome::Fail(RpcError::Internal("unknown exception"));
    }

    if (out.error) return MakeErrorResponse(id, *out.error);
    return Json{{"jsonrpc", "2.0"}, {"id", id}, {"result", out.result ? std::move(*out.result) : Json(nullptr)}};
}

std::optional<std::string> JsonRpcDispatcher::HandleMessage(std::string_view request, const RpcContext& ctx) const
{
    Json req;
    try {
        req = Json::parse(request.begin(), request.end());
    } catch (const std::exception&) {
        return MakeErrorResponse(nullptr, RpcError{kParseError, "PARSE_ERROR", "invalid JSON", Json::object()}).dump();
    }

    // 批次請求（陣列）：M0 的 UI 不使用，但依規範支援
    if (req.is_array()) {
        if (req.empty()) {
            return MakeErrorResponse(nullptr, RpcError{kInvalidRequest, "INVALID_REQUEST", "empty batch", Json::object()}).dump();
        }
        Json out = Json::array();
        for (const auto& r : req) {
            bool notif = false;
            Json resp  = HandleOne(r, ctx, notif);
            if (!notif) out.push_back(std::move(resp));
        }
        if (out.empty()) return std::nullopt;
        return out.dump(-1, ' ', false, Json::error_handler_t::replace);
    }

    bool notif = false;
    Json resp  = HandleOne(req, ctx, notif);
    if (notif) return std::nullopt;
    // error_handler_t::replace：攻擊者可控字串可能含非法 UTF-8，不可讓 dump 丟例外
    return resp.dump(-1, ' ', false, Json::error_handler_t::replace);
}

std::optional<int64_t> GetInt(const Json& params, std::string_view key)
{
    if (!params.is_object()) return std::nullopt;
    auto it = params.find(std::string(key));
    if (it == params.end()) return std::nullopt;
    if (it->is_number_integer()) return it->get<int64_t>();
    if (it->is_string()) {
        try {
            size_t      idx = 0;
            const auto& s   = it->get_ref<const std::string&>();
            const auto  v   = std::stoll(s, &idx);
            if (idx == s.size()) return v;
        } catch (...) {
        }
    }
    return std::nullopt;
}

std::optional<std::string> GetString(const Json& params, std::string_view key)
{
    if (!params.is_object()) return std::nullopt;
    auto it = params.find(std::string(key));
    if (it == params.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

std::optional<bool> GetBool(const Json& params, std::string_view key)
{
    if (!params.is_object()) return std::nullopt;
    auto it = params.find(std::string(key));
    if (it == params.end()) return std::nullopt;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_string()) {
        const auto& s = it->get_ref<const std::string&>();
        if (s == "true" || s == "1") return true;
        if (s == "false" || s == "0") return false;
    }
    return std::nullopt;
}

} // namespace cairn::rpc
