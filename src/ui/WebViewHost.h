// WebViewHost.h —— ICoreWebView2Controller 生命週期（SDD-03 §9.2）
//   執行緒：UI 主執行緒（STA）——COM 介面絕不可跨執行緒
//   踩雷點對應：P1 STA（CairnConsoleApp 處理）、P2 回呼存活 token、P3 UserDataFolder、P4 Resize 判空、
//              P5 DPI、P6 ProcessFailed、P7 正式組建關 DevTools、P8 虛擬主機 https://cairn.local
#pragma once

#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <string>

namespace cairn::ui {

class ResourceInterceptor;

enum class HostState : uint8_t { Idle, Creating, Ready, Failed };

enum class HostFailure : uint8_t {
    RuntimeMissing,     // 找不到 WebView2 Runtime
    EnvironmentFailed,  // CreateCoreWebView2Environment 失敗
    ControllerFailed,   // CreateCoreWebView2Controller 失敗
    InitTimeout,        // 10 秒內未就緒
    ProcessCrashed,     // 瀏覽器程序第二次崩潰
};

struct HostCallbacks {
    std::function<void()>                           onReady;
    std::function<void(HostFailure, HRESULT)>       onFailed;
    std::function<void(const nlohmann::json&)>      onWebMessage;   // 已驗證來源為 https://cairn.local
};

class WebViewHost {
public:
    WebViewHost(HWND parent, ResourceInterceptor* interceptor, HostCallbacks cb);
    ~WebViewHost();
    WebViewHost(const WebViewHost&)            = delete;
    WebViewHost& operator=(const WebViewHost&) = delete;

    // 非同步建立；結果經 HostCallbacks 回報。可重複呼叫（「重試」）。
    HRESULT CreateAsync();
    void    Close();
    // 由宿主在 WM_APP_WEBVIEW_FAILED(wParam=2) 時呼叫：關閉並回報 ProcessCrashed
    void    FailCrashed() { Fail(HostFailure::ProcessCrashed, E_FAIL); }

    void Resize(const RECT& rc);
    void SetVisible(bool v);
    void NotifyParentWindowPositionChanged();

    // 宿主 → 前端訊息（例如 {"type":"navigate","path":"/alerts/42"}）
    void PostToPage(const nlohmann::json& msg);

    [[nodiscard]] HostState State() const noexcept { return m_state; }
    [[nodiscard]] std::wstring RuntimeVersion() const;
    [[nodiscard]] ICoreWebView2Environment* Environment() const noexcept { return m_env.get(); }

private:
    HRESULT OnEnvironmentCreated(HRESULT hr, ICoreWebView2Environment* env);
    HRESULT OnControllerCreated(HRESULT hr, ICoreWebView2Controller* controller);
    void    ConfigureSettings();
    void    RegisterHandlers();
    void    Fail(HostFailure f, HRESULT hr);

    HWND                                     m_parent;
    ResourceInterceptor*                     m_interceptor;
    HostCallbacks                            m_cb;
    HostState                                m_state = HostState::Idle;
    std::shared_ptr<int>                     m_alive = std::make_shared<int>(0);   // P2：回呼存活 token
    int                                      m_crashCount = 0;
    std::wstring                             m_lastUrl = L"https://cairn.local/index.html";

    wil::com_ptr<ICoreWebView2Environment>   m_env;
    wil::com_ptr<ICoreWebView2Controller>    m_controller;
    wil::com_ptr<ICoreWebView2>              m_webview;
    EventRegistrationToken                   m_tokResource{}, m_tokNav{}, m_tokNewWin{}, m_tokMsg{}, m_tokFailed{};
};

} // namespace cairn::ui
