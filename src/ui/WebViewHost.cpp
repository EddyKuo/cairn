// WebViewHost.cpp —— 見 WebViewHost.h
#include "pch.h"

#include "WebViewHost.h"

#include "ResourceInterceptor.h"
#include "Utf.h"

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Make;

namespace cairn::ui {

namespace {
constexpr std::wstring_view kAppOrigin = L"https://cairn.local/";
constexpr std::wstring_view kAttackOrigin = L"https://attack.mitre.org/";

bool StartsWithI(std::wstring_view s, std::wstring_view prefix)
{
    return s.size() >= prefix.size() && _wcsnicmp(s.data(), prefix.data(), prefix.size()) == 0;
}

// P3：UserDataFolder 明確指定到 %LOCALAPPDATA%\Cairn\WebView2（預設會寫 EXE 目錄，一般使用者無權限）
std::wstring UserDataFolder()
{
    wil::unique_cotaskmem_string local;
    std::wstring base = L".";
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, local.put())) && local) base = local.get();
    std::wstring dir = base + L"\\Cairn\\WebView2";
    ::SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return dir;
}
} // namespace

WebViewHost::WebViewHost(HWND parent, ResourceInterceptor* interceptor, HostCallbacks cb)
    : m_parent(parent), m_interceptor(interceptor), m_cb(std::move(cb))
{
}

WebViewHost::~WebViewHost()
{
    m_alive.reset();   // 之後到達的非同步回呼一律忽略
    Close();
}

std::wstring WebViewHost::RuntimeVersion() const
{
    wil::unique_cotaskmem_string ver;
    if (SUCCEEDED(::GetAvailableCoreWebView2BrowserVersionString(nullptr, ver.put())) && ver) return ver.get();
    return L"(未安裝)";
}

void WebViewHost::Fail(HostFailure f, HRESULT hr)
{
    m_state = HostState::Failed;
    Close();
    if (m_cb.onFailed) m_cb.onFailed(f, hr);
}

HRESULT WebViewHost::CreateAsync()
{
    if (m_state == HostState::Creating) return S_FALSE;
    Close();
    m_state = HostState::Creating;

    wil::unique_cotaskmem_string ver;
    const HRESULT hrVer = ::GetAvailableCoreWebView2BrowserVersionString(nullptr, ver.put());
    if (FAILED(hrVer) || !ver) {
        Fail(HostFailure::RuntimeMissing, FAILED(hrVer) ? hrVer : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        return hrVer;
    }

    auto options = Make<CoreWebView2EnvironmentOptions>();
    std::weak_ptr<int> alive = m_alive;
    const std::wstring udf = UserDataFolder();
    const HRESULT hr = ::CreateCoreWebView2EnvironmentWithOptions(
        nullptr, udf.c_str(), options.Get(),
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
            [this, alive](HRESULT result, ICoreWebView2Environment* env) -> HRESULT {
                if (alive.expired()) return S_OK;   // P2
                return OnEnvironmentCreated(result, env);
            })
            .Get());
    if (FAILED(hr)) Fail(HostFailure::EnvironmentFailed, hr);
    return hr;
}

HRESULT WebViewHost::OnEnvironmentCreated(HRESULT hr, ICoreWebView2Environment* env)
{
    if (FAILED(hr) || !env) {
        Fail(HostFailure::EnvironmentFailed, FAILED(hr) ? hr : E_FAIL);
        return S_OK;
    }
    m_env = env;
    std::weak_ptr<int> alive = m_alive;
    const HRESULT hr2 = m_env->CreateCoreWebView2Controller(
        m_parent, Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                      [this, alive](HRESULT result, ICoreWebView2Controller* controller) -> HRESULT {
                          if (alive.expired()) return S_OK;
                          return OnControllerCreated(result, controller);
                      })
                      .Get());
    if (FAILED(hr2)) Fail(HostFailure::ControllerFailed, hr2);
    return S_OK;
}

HRESULT WebViewHost::OnControllerCreated(HRESULT hr, ICoreWebView2Controller* controller)
{
    if (FAILED(hr) || !controller) {
        Fail(HostFailure::ControllerFailed, FAILED(hr) ? hr : E_FAIL);
        return S_OK;
    }
    m_controller = controller;
    if (FAILED(m_controller->get_CoreWebView2(m_webview.put())) || !m_webview) {
        Fail(HostFailure::ControllerFailed, E_NOINTERFACE);
        return S_OK;
    }

    ConfigureSettings();
    RegisterHandlers();

    // P4：controller 就緒時主動套用一次目前 client rect
    RECT rc{};
    ::GetClientRect(m_parent, &rc);
    m_controller->put_Bounds(rc);
    m_controller->put_IsVisible(TRUE);

    m_state = HostState::Ready;
    m_webview->Navigate(m_lastUrl.c_str());
    if (m_cb.onReady) m_cb.onReady();
    return S_OK;
}

void WebViewHost::ConfigureSettings()
{
    wil::com_ptr<ICoreWebView2Settings> s;
    if (FAILED(m_webview->get_Settings(s.put())) || !s) return;
#ifdef _DEBUG
    constexpr BOOL kDebug = TRUE;
#else
    constexpr BOOL kDebug = FALSE;   // P7：正式組建關閉 DevTools / 右鍵選單 / 瀏覽器快捷鍵
#endif
    s->put_AreDevToolsEnabled(kDebug);
    s->put_AreDefaultContextMenusEnabled(kDebug);
    s->put_IsStatusBarEnabled(FALSE);
    s->put_IsWebMessageEnabled(TRUE);
    s->put_AreHostObjectsAllowed(FALSE);   // 不注入任何 COM 物件給前端（SDD-03 §9.3.1）
    s->put_IsScriptEnabled(TRUE);
    s->put_AreDefaultScriptDialogsEnabled(TRUE);
    if (auto s3 = s.try_query<ICoreWebView2Settings3>()) s3->put_AreBrowserAcceleratorKeysEnabled(kDebug);
}

void WebViewHost::RegisterHandlers()
{
    std::weak_ptr<int> alive = m_alive;

    // 只攔截本機虛擬主機；外部請求不在 filter 內，會被 CSP 阻擋
    m_webview->AddWebResourceRequestedFilter(L"https://cairn.local/*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);
    m_webview->add_WebResourceRequested(
        Callback<ICoreWebView2WebResourceRequestedEventHandler>(
            [this, alive](ICoreWebView2*, ICoreWebView2WebResourceRequestedEventArgs* args) -> HRESULT {
                if (alive.expired() || !m_env) return S_OK;
                return m_interceptor->OnWebResourceRequested(m_env.get(), args);
            })
            .Get(),
        &m_tokResource);

    // 不允許離開 https://cairn.local/（含 file://、外部網站）
    m_webview->add_NavigationStarting(
        Callback<ICoreWebView2NavigationStartingEventHandler>(
            [](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                wil::unique_cotaskmem_string uri;
                if (SUCCEEDED(args->get_Uri(uri.put())) && uri && !StartsWithI(uri.get(), kAppOrigin)) {
                    args->put_Cancel(TRUE);
                }
                return S_OK;
            })
            .Get(),
        &m_tokNav);

    // window.open / target=_blank：一律不開新 WebView 視窗；ATT&CK 官網交由預設瀏覽器開啟
    m_webview->add_NewWindowRequested(
        Callback<ICoreWebView2NewWindowRequestedEventHandler>(
            [](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                args->put_Handled(TRUE);
                wil::unique_cotaskmem_string uri;
                if (SUCCEEDED(args->get_Uri(uri.put())) && uri && StartsWithI(uri.get(), kAttackOrigin)) {
                    ::ShellExecuteW(nullptr, L"open", uri.get(), nullptr, nullptr, SW_SHOWNORMAL);
                }
                return S_OK;
            })
            .Get(),
        &m_tokNewWin);

    m_webview->add_WebMessageReceived(
        Callback<ICoreWebView2WebMessageReceivedEventHandler>(
            [this, alive](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* args) -> HRESULT {
                if (alive.expired()) return S_OK;
                wil::unique_cotaskmem_string source;
                if (FAILED(args->get_Source(source.put())) || !source || !StartsWithI(source.get(), kAppOrigin)) {
                    return S_OK;   // 只接受本機前端的訊息
                }
                wil::unique_cotaskmem_string raw;
                if (FAILED(args->get_WebMessageAsJson(raw.put())) || !raw) return S_OK;
                auto msg = nlohmann::json::parse(ToUtf8(raw.get()), nullptr, false);
                if (!msg.is_discarded() && msg.is_object() && m_cb.onWebMessage) m_cb.onWebMessage(msg);
                return S_OK;
            })
            .Get(),
        &m_tokMsg);

    // P6：WebView2 程序崩潰。瀏覽器程序退出 → 自動重建一次並回到原路由；第二次才落到原生錯誤畫面
    m_webview->add_ProcessFailed(
        Callback<ICoreWebView2ProcessFailedEventHandler>(
            [this, alive](ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs* args) -> HRESULT {
                if (alive.expired()) return S_OK;
                COREWEBVIEW2_PROCESS_FAILED_KIND kind{};
                args->get_ProcessFailedKind(&kind);
                ::OutputDebugStringW(L"[CairnConsole] WebView2 ProcessFailed\n");
                if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_BROWSER_PROCESS_EXITED) {
                    // 不可在事件回呼內同步重建或關閉（回呼仍持有舊 webview 參照）：投遞到訊息佇列後再做。
                    // wParam：1 = 自動重建一次；2 = 第二次崩潰，改顯示原生錯誤畫面
                    ::PostMessageW(m_parent, WM_APP_WEBVIEW_FAILED, ++m_crashCount >= 2 ? 2 : 1, 0);
                } else if (kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_EXITED ||
                           kind == COREWEBVIEW2_PROCESS_FAILED_KIND_RENDER_PROCESS_UNRESPONSIVE) {
                    if (m_webview) m_webview->Reload();
                }
                return S_OK;
            })
            .Get(),
        &m_tokFailed);
}

void WebViewHost::Close()
{
    if (m_webview) {
        // 記住目前路由（hash route），重建後回到原畫面
        wil::unique_cotaskmem_string src;
        if (SUCCEEDED(m_webview->get_Source(src.put())) && src && StartsWithI(src.get(), kAppOrigin)) m_lastUrl = src.get();
        m_webview->remove_WebResourceRequested(m_tokResource);
        m_webview->remove_NavigationStarting(m_tokNav);
        m_webview->remove_NewWindowRequested(m_tokNewWin);
        m_webview->remove_WebMessageReceived(m_tokMsg);
        m_webview->remove_ProcessFailed(m_tokFailed);
    }
    if (m_controller) m_controller->Close();
    m_webview.reset();
    m_controller.reset();
    if (m_state == HostState::Ready || m_state == HostState::Creating) m_state = HostState::Idle;
}

void WebViewHost::Resize(const RECT& rc)
{
    if (m_controller) m_controller->put_Bounds(rc);   // P4：就緒前判空
}

void WebViewHost::SetVisible(bool v)
{
    if (m_controller) m_controller->put_IsVisible(v ? TRUE : FALSE);
}

void WebViewHost::NotifyParentWindowPositionChanged()
{
    if (m_controller) m_controller->NotifyParentWindowPositionChanged();
}

void WebViewHost::PostToPage(const nlohmann::json& msg)
{
    if (!m_webview) return;
    const std::wstring w = ToWide(msg.dump());
    m_webview->PostWebMessageAsJson(w.c_str());
}

} // namespace cairn::ui
