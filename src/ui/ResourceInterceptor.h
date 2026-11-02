// ResourceInterceptor.h —— WebView2 WebResourceRequested 攔截（SDD-03 §9.3；含 SDD 所稱 ApiBridge 的職責）
//   https://cairn.local/api/v1/*  → 路由表 → JSON-RPC（RpcClient）→ HTTP 狀態碼映射（§9.3.4）
//   https://cairn.local/其他       → EmbeddedAssets（RCDATA）
// 不開任何監聽埠（§9.3.1）。本類別是唯一把 RPC 錯誤轉成 HTTP 狀態碼的地方。
//
// 執行緒：
//   - OnWebResourceRequested / CompleteReply：UI 執行緒（STA；COM 介面不可跨執行緒）
//   - HandleApi：任意執行緒（只使用 RpcClient），API 請求以 deferral 交給執行緒池，UI 執行緒不阻塞
#pragma once

#include <nlohmann/json.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace cairn::ui {

class RpcClient;
class EmbeddedAssets;

struct HttpReply {
    int         status = 200;
    std::string body;   // UTF-8 JSON
};

class ResourceInterceptor {
public:
    ResourceInterceptor(std::shared_ptr<RpcClient> rpc, const EmbeddedAssets* assets, HWND notifyWnd);

    // UI 執行緒：由 WebViewHost 的 WebResourceRequested 回呼呼叫
    HRESULT OnWebResourceRequested(ICoreWebView2Environment* env, ICoreWebView2WebResourceRequestedEventArgs* args);

    // UI 執行緒：WM_APP_API_REPLY 的處理（lParam 為 OnWebResourceRequested 配置的待完成工作）
    void CompleteReply(LPARAM pending);

    // 任意執行緒：HTTP 語意 → JSON-RPC → HTTP 回應。path 不含 query；query 為原始 query string（不含 '?'）。
    [[nodiscard]] HttpReply HandleApi(std::string_view method, std::string_view path, std::string_view query,
                                      std::string_view body) const;

    static const wchar_t* SecurityHeaders() noexcept;

private:
    std::shared_ptr<RpcClient> m_rpc;
    const EmbeddedAssets*      m_assets;
    HWND                       m_notifyWnd;
};

// 純函式（DevHttp 與單元測試共用）
std::string PercentDecode(std::string_view s);
nlohmann::json ParseQuery(std::string_view query);
std::string ReasonPhrase(int status);

} // namespace cairn::ui
