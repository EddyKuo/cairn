// src/svc/rpc/JsonRpcDispatcher.h             namespace cairn::rpc
// JSON-RPC 2.0 分派：method → handler 表。不含 Win32，可在任何平台單元測試。
//
// 錯誤物件格式（與 CairnConsole 的 ApiBridge 對齊，SDD-03 §9.3.4）：
//   {"code": <JSON-RPC 整數碼>, "message": "<人類可讀>", "data": {"code": "<應用層字串碼>", ...}}
//   應用層字串碼為：NOT_FOUND / INVALID_PARAMS / TOKEN_INVALID / TOKEN_EXPIRED /
//   TYPED_CONFIRMATION_MISMATCH / IMPACT_CHANGED / PARTIAL_SUCCESS / ACTION_FAILED / TIMEOUT /
//   SERVICE_UNAVAILABLE / MESSAGE_TOO_LARGE / RESULT_TOO_LARGE / METHOD_NOT_FOUND / INTERNAL
//   UI 端只看 data.code 決定 HTTP 狀態碼。
#pragma once
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace cairn::rpc {

using Json = nlohmann::json;

// JSON-RPC 2.0 標準碼
inline constexpr int kParseError     = -32700;
inline constexpr int kInvalidRequest = -32600;
inline constexpr int kMethodNotFound = -32601;
inline constexpr int kInvalidParams  = -32602;
inline constexpr int kInternalError  = -32603;
inline constexpr int kAppError       = -32000;   // 應用層錯誤一律用此碼 + data.code

struct RpcError {
    int         rpcCode = kAppError;
    std::string appCode = "INTERNAL";   // data.code
    std::string message;
    Json        data = Json::object();  // 額外欄位（例如 PARTIAL_SUCCESS 的逐目標結果）

    [[nodiscard]] Json ToJson() const;

    static RpcError NotFound(std::string msg = "not found") { return {kAppError, "NOT_FOUND", std::move(msg), Json::object()}; }
    static RpcError InvalidParams(std::string msg) { return {kInvalidParams, "INVALID_PARAMS", std::move(msg), Json::object()}; }
    static RpcError Internal(std::string msg) { return {kInternalError, "INTERNAL", std::move(msg), Json::object()}; }
    static RpcError App(std::string appCode, std::string msg, Json data = Json::object())
    {
        return {kAppError, std::move(appCode), std::move(msg), std::move(data)};
    }
};

// handler 的回傳：成功的 result，或錯誤。
struct RpcOutcome {
    std::optional<Json>     result;
    std::optional<RpcError> error;

    static RpcOutcome Ok(Json j) { return RpcOutcome{std::move(j), std::nullopt}; }
    static RpcOutcome Fail(RpcError e) { return RpcOutcome{std::nullopt, std::move(e)}; }
};

// 呼叫端脈絡（Named Pipe 對端資訊），供稽核記錄 actor 用。
struct RpcContext {
    uint32_t    clientPid = 0;
    std::string clientUser;   // DOMAIN\user（ImpersonateNamedPipeClient 取得；取不到為空）
};

using RpcHandler = std::function<RpcOutcome(const Json& params, const RpcContext& ctx)>;

class JsonRpcDispatcher {
public:
    void Register(std::string method, RpcHandler handler);

    // 處理一則請求字串，回傳回應字串。通知（無 id）回傳 nullopt。
    // handler 內的例外一律攔截轉為 INTERNAL（P-2：例外不得跨模組邊界）。
    [[nodiscard]] std::optional<std::string> HandleMessage(std::string_view request, const RpcContext& ctx) const;

    [[nodiscard]] std::vector<std::string> Methods() const;
    [[nodiscard]] size_t MethodCount() const;

private:
    [[nodiscard]] Json HandleOne(const Json& req, const RpcContext& ctx, bool& isNotification) const;

    mutable std::shared_mutex                   m_mutex;
    std::unordered_map<std::string, RpcHandler> m_handlers;
};

// 便利函式：取參數並給出 INVALID_PARAMS 錯誤訊息
[[nodiscard]] std::optional<int64_t> GetInt(const Json& params, std::string_view key);
[[nodiscard]] std::optional<std::string> GetString(const Json& params, std::string_view key);
[[nodiscard]] std::optional<bool> GetBool(const Json& params, std::string_view key);

} // namespace cairn::rpc
