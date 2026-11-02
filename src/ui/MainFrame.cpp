// MainFrame.cpp —— 見 MainFrame.h
#include "pch.h"

#include "MainFrame.h"

#include "CairnConsole.h"
#include "ResourceInterceptor.h"
#include "RpcClient.h"
#include "Utf.h"

#include <cmath>
#include <fstream>

using nlohmann::json;
using cairn::ui::HostFailure;
using cairn::ui::LinkState;

// DevHttp.cpp（僅 Debug 組建有實作；Release 為空殼並回傳 false）
bool StartDevHttpServer(uint16_t port, cairn::ui::ResourceInterceptor* interceptor);
void StopDevHttpServer();

namespace {

constexpr UINT     kTrayId = 1;
constexpr int      kMinW = 1100, kMinH = 700;      // 低於此寬度 Alert Detail 雙欄被迫堆疊（part3 §3.2.1）
constexpr int      kDefW = 1440, kDefH = 900;
constexpr UINT     kInitTimeoutMs = 10'000;        // controller 建立逾時 → InitTimeout（SDD-03 §9.2.1）
constexpr DWORD    kDwmUseImmersiveDarkMode = 20;  // DWMWA_USE_IMMERSIVE_DARK_MODE

const UINT s_taskbarCreated = ::RegisterWindowMessageW(L"TaskbarCreated");

struct HeartbeatMsg {
    bool       ok = false;
    json       health;
    int        failures = 0;
    LinkState  link = LinkState::Connecting;
};

struct NewAlertsMsg {
    json items;   // AlertSummary[]（risk_score >= 80）
};

int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// %LOCALAPPDATA%\Cairn\ui.log —— 「複製錯誤詳情」會帶上末 50 行
std::wstring UiLogPath()
{
    wil::unique_cotaskmem_string local;
    std::wstring base = L".";
    if (SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, local.put())) && local) base = local.get();
    std::wstring dir = base + L"\\Cairn";
    ::SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return dir + L"\\ui.log";
}

void UiLog(const std::string& line)
{
    SYSTEMTIME st{};
    ::GetLocalTime(&st);
    char ts[64];
    sprintf_s(ts, "%04u-%02u-%02u %02u:%02u:%02u.%03u ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
              st.wSecond, st.wMilliseconds);
    std::ofstream f(UiLogPath(), std::ios::app | std::ios::binary);
    f << ts << line << "\r\n";
}

std::string LastLogLines(size_t n)
{
    std::ifstream f(UiLogPath(), std::ios::binary);
    std::deque<std::string> lines;
    std::string l;
    while (std::getline(f, l)) {
        lines.push_back(l);
        if (lines.size() > n) lines.pop_front();
    }
    std::string out;
    for (auto& x : lines) out += x + "\n";
    return out;
}

std::string HrHex(HRESULT hr)
{
    char buf[16];
    sprintf_s(buf, "0x%08X", static_cast<unsigned>(hr));
    return buf;
}

// 系統匣圖示以程式繪製（不依賴二進位 .ico）：盾牌 + 狀態記號。
// mark：0 無、1 學習期（沙漏角標→黃點）、2 降級（驚嘆號）、3 失聯（叉）
HICON MakeShieldIcon(int size, COLORREF fill, int mark)
{
    BITMAPV5HEADER bi{};
    bi.bV5Size = sizeof(bi);
    bi.bV5Width = size;
    bi.bV5Height = -size;   // top-down
    bi.bV5Planes = 1;
    bi.bV5BitCount = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask = 0x00FF0000;
    bi.bV5GreenMask = 0x0000FF00;
    bi.bV5BlueMask = 0x000000FF;
    bi.bV5AlphaMask = 0xFF000000;
    void* bits = nullptr;
    HDC   dc = ::GetDC(nullptr);
    HBITMAP color = ::CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS, &bits, nullptr, 0);
    ::ReleaseDC(nullptr, dc);
    if (!color || !bits) return nullptr;
    auto* px = static_cast<uint32_t*>(bits);
    const auto argb = [](uint8_t a, uint8_t r, uint8_t g, uint8_t b) {
        // 預乘 alpha
        return (static_cast<uint32_t>(a) << 24) | (static_cast<uint32_t>(r * a / 255) << 16) |
               (static_cast<uint32_t>(g * a / 255) << 8) | static_cast<uint32_t>(b * a / 255);
    };
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            const double u = (x + 0.5) / size, v = (y + 0.5) / size;
            bool in = (v >= 0.08 && v <= 0.55 && u >= 0.15 && u <= 0.85) ||
                      (v > 0.55 && v <= 0.95 && std::abs(u - 0.5) <= 0.35 * (0.95 - v) / 0.40);
            uint32_t c = 0;
            if (in) c = argb(255, GetRValue(fill), GetGValue(fill), GetBValue(fill));
            if (in && mark == 2) {
                if ((u > 0.44 && u < 0.56 && v > 0.20 && v < 0.58) || (u > 0.44 && u < 0.56 && v > 0.66 && v < 0.78))
                    c = argb(255, 255, 255, 255);
            }
            if (mark == 3) {
                const double du = u - 0.5, dv = v - 0.48;
                if (std::abs(du) < 0.26 && std::abs(dv) < 0.26 && (std::abs(du - dv) < 0.075 || std::abs(du + dv) < 0.075))
                    c = argb(255, 0xE0, 0x30, 0x30);
            }
            if (mark == 1) {
                const double du = u - 0.78, dv = v - 0.78;
                const double d = std::sqrt(du * du + dv * dv);
                if (d < 0.20) c = argb(255, 0x20, 0x20, 0x20);
                if (d < 0.15) c = argb(255, 0xF2, 0xC1, 0x4E);
            }
            px[y * size + x] = c;
        }
    }
    HBITMAP mask = ::CreateBitmap(size, size, 1, 1, nullptr);
    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.hbmColor = color;
    ii.hbmMask = mask;
    HICON icon = ::CreateIconIndirect(&ii);
    ::DeleteObject(color);
    ::DeleteObject(mask);
    return icon;
}

std::wstring Trunc(const std::wstring& s, size_t n)
{
    return s.size() <= n ? s : s.substr(0, n - 1) + L"…";
}

} // namespace

IMPLEMENT_DYNAMIC(CMainFrame, CFrameWndEx)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWndEx)
    ON_WM_CREATE()
    ON_WM_SIZE()
    ON_WM_MOVE()
    ON_WM_CLOSE()
    ON_WM_DESTROY()
    ON_WM_GETMINMAXINFO()
    ON_WM_TIMER()
    ON_WM_PAINT()
    ON_WM_ERASEBKGND()
    ON_WM_CTLCOLOR()
    ON_MESSAGE(WM_DPICHANGED, &CMainFrame::OnDpiChanged)
    ON_MESSAGE(WM_APP_API_REPLY, &CMainFrame::OnApiReply)
    ON_MESSAGE(WM_APP_HEARTBEAT, &CMainFrame::OnHeartbeat)
    ON_MESSAGE(WM_APP_NEW_ALERTS, &CMainFrame::OnNewAlerts)
    ON_MESSAGE(WM_APP_TRAY, &CMainFrame::OnTray)
    ON_MESSAGE(WM_APP_WEBVIEW_FAILED, &CMainFrame::OnWebViewFailed)
    ON_REGISTERED_MESSAGE(s_taskbarCreated, &CMainFrame::OnTaskbarCreated)
END_MESSAGE_MAP()

CMainFrame::CMainFrame() = default;

CMainFrame::~CMainFrame()
{
    for (auto& i : m_icons)
        if (i) ::DestroyIcon(i);
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
    if (!CFrameWndEx::PreCreateWindow(cs)) return FALSE;
    // 固定類別名：第二個實例以 FindWindow 找到既有視窗並啟用（part3 §3.2.1 單一實例）
    WNDCLASSW wc{};
    HINSTANCE inst = AfxGetInstanceHandle();
    if (!::GetClassInfoW(inst, kWindowClass, &wc)) {
        wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
        wc.lpfnWndProc = ::DefWindowProcW;
        wc.hInstance = inst;
        wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = nullptr;
        wc.lpszClassName = kWindowClass;
        if (!AfxRegisterClass(&wc)) return FALSE;
    }
    cs.lpszClass = kWindowClass;
    cs.style &= ~FWS_ADDTOTITLE;
    cs.hMenu = nullptr;
    return TRUE;
}

BOOL CMainFrame::CreateMainWindow(uint16_t devHttpPort)
{
    m_devHttpPort = devHttpPort;
    const CRect rc(0, 0, kDefW, kDefH);
    if (!Create(nullptr, L"Cairn", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, rc, nullptr, nullptr, 0, nullptr)) return FALSE;

    // 位置與大小記憶：HKCU\Software\Cairn\UI；落在畫面外時回退至主螢幕置中
    WINDOWPLACEMENT wp{};
    if (theApp.LoadPlacement(wp) && ::MonitorFromRect(&wp.rcNormalPosition, MONITOR_DEFAULTTONULL)) {
        wp.length = sizeof(wp);
        if (wp.showCmd == SW_SHOWMINIMIZED) wp.showCmd = SW_SHOWNORMAL;
        SetWindowPlacement(&wp);
    } else {
        const UINT dpi = ::GetDpiForWindow(m_hWnd);
        const int w = ::MulDiv(kDefW, dpi, 96), h = ::MulDiv(kDefH, dpi, 96);
        MONITORINFO mi{sizeof(mi)};
        ::GetMonitorInfoW(::MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY), &mi);
        const CRect work(mi.rcWork);
        const int cw = std::min(w, work.Width()), ch = std::min(h, work.Height());
        SetWindowPos(nullptr, work.left + (work.Width() - cw) / 2, work.top + (work.Height() - ch) / 2, cw, ch,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        ShowWindow(SW_SHOW);
    }
    return TRUE;
}

int CMainFrame::OnCreate(LPCREATESTRUCT lpcs)
{
    if (CFrameWndEx::OnCreate(lpcs) == -1) return -1;

    m_bgBrush.CreateSolidBrush(RGB(0x0B, 0x0F, 0x14));
    const int small = ::GetSystemMetrics(SM_CXSMICON);
    m_icons[static_cast<int>(TrayState::Protecting)] = MakeShieldIcon(small, RGB(0x2F, 0x81, 0xF7), 0);
    m_icons[static_cast<int>(TrayState::Learning)]   = MakeShieldIcon(small, RGB(0x2F, 0x81, 0xF7), 1);
    m_icons[static_cast<int>(TrayState::Degraded)]   = MakeShieldIcon(small, RGB(0xD2, 0x99, 0x22), 2);
    m_icons[static_cast<int>(TrayState::Gone)]       = MakeShieldIcon(small, RGB(0x8B, 0x94, 0x9E), 3);
    SetIcon(m_icons[0], FALSE);
    SetIcon(MakeShieldIcon(::GetSystemMetrics(SM_CXICON), RGB(0x2F, 0x81, 0xF7), 0), TRUE);

    m_rpc = std::make_shared<cairn::ui::RpcClient>();
    m_interceptor = std::make_unique<cairn::ui::ResourceInterceptor>(m_rpc, &m_assets, m_hWnd);
    AddTrayIcon();

    // 心跳：每 2 秒 health.get（托盤狀態獨立輪詢，不依賴 WebView2，part3 §3.10.1）
    m_heartbeat = std::jthread([this](std::stop_token st) { HeartbeatLoop(st); });

#ifdef _DEBUG
    if (m_devHttpPort != 0) StartDevHttpServer(m_devHttpPort, m_interceptor.get());
#endif

    StartWebView();
    UiLog("CairnConsole started");
    return 0;
}

// ---------------------------------------------------------------------------
// WebView2
// ---------------------------------------------------------------------------
void CMainFrame::StartWebView()
{
    if (!m_host) {
        cairn::ui::HostCallbacks cb;
        cb.onReady = [this] { OnWebViewReady(); };
        cb.onFailed = [this](HostFailure f, HRESULT hr) { OnWebViewFailedCb(f, hr); };
        cb.onWebMessage = [this](const json& m) { OnWebMessage(m); };
        m_host = std::make_unique<cairn::ui::WebViewHost>(m_hWnd, m_interceptor.get(), std::move(cb));
    }
    SetTimer(TIMER_WEBVIEW_INIT, kInitTimeoutMs, nullptr);
    m_host->CreateAsync();
}

void CMainFrame::OnWebViewReady()
{
    KillTimer(TIMER_WEBVIEW_INIT);
    HideNativeError();
    m_retryCount = 0;
    CRect rc;
    GetClientRect(&rc);
    m_host->Resize(rc);
    UiLog("WebView2 ready, runtime " + cairn::ui::ToUtf8(m_host->RuntimeVersion()));
}

void CMainFrame::OnWebViewFailedCb(HostFailure f, HRESULT hr)
{
    KillTimer(TIMER_WEBVIEW_INIT);
    UiLog("WebView2 failed kind=" + std::to_string(static_cast<int>(f)) + " hr=" + HrHex(hr));
    ShowNativeError(f, hr);
}

LRESULT CMainFrame::OnWebViewFailed(WPARAM wParam, LPARAM)
{
    if (!m_host) return 0;
    if (wParam == 1) {
        UiLog("WebView2 browser process exited; rebuilding once");
        StartWebView();   // 自動重建一次並回到原路由
    } else {
        m_host->FailCrashed();
    }
    return 0;
}

void CMainFrame::OnTimer(UINT_PTR id)
{
    if (id == TIMER_WEBVIEW_INIT) {
        KillTimer(TIMER_WEBVIEW_INIT);
        if (m_host && m_host->State() != cairn::ui::HostState::Ready) {
            m_host->Close();
            OnWebViewFailedCb(HostFailure::InitTimeout, HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
        return;
    }
    CFrameWndEx::OnTimer(id);
}

LRESULT CMainFrame::OnApiReply(WPARAM, LPARAM lParam)
{
    if (m_interceptor) m_interceptor->CompleteReply(lParam);
    return 0;
}

void CMainFrame::OnWebMessage(const json& msg)
{
    const std::string type = msg.value("type", std::string{});
    if (type == "theme") {
        ApplyTitleBarTheme(msg.value("value", std::string{}) == "dark");
    } else if (type == "unread") {
        const int n = msg.value("value", 0);
        SetWindowTextW(n > 0 ? (L"Cairn (" + std::to_wstring(n) + L")").c_str() : L"Cairn");
    } else if (type == "openExternal") {
        // 只允許 ATT&CK 官網（AttackTag 的次要動作）；其餘一律拒絕
        const std::wstring url = cairn::ui::ToWide(msg.value("url", std::string{}));
        if (url.rfind(L"https://attack.mitre.org/", 0) == 0) {
            ::ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
    } else if (type == "startService") {
        SHELLEXECUTEINFOW sei{sizeof(sei)};
        sei.lpVerb = L"runas";   // 需提權，會跳 UAC
        sei.lpFile = L"sc.exe";
        sei.lpParameters = L"start CairnAgent";
        sei.nShow = SW_HIDE;
        if (::ShellExecuteExW(&sei)) m_rpc->ResetBackoff();
    } else if (type == "openServices") {
        ::ShellExecuteW(nullptr, L"open", L"services.msc", nullptr, nullptr, SW_SHOWNORMAL);
    }
}

void CMainFrame::ApplyTitleBarTheme(bool dark)
{
    // 前端主題同步至 MFC 非客戶區，避免深色內容配淺色標題列（part3 §3.2.1）
    const BOOL v = dark ? TRUE : FALSE;
    ::DwmSetWindowAttribute(m_hWnd, kDwmUseImmersiveDarkMode, &v, sizeof(v));
    m_bgBrush.DeleteObject();
    m_bgBrush.CreateSolidBrush(dark ? RGB(0x0B, 0x0F, 0x14) : RGB(0xFF, 0xFF, 0xFF));
    Invalidate();
}

// ---------------------------------------------------------------------------
// 視窗行為
// ---------------------------------------------------------------------------
void CMainFrame::OnSize(UINT type, int cx, int cy)
{
    CFrameWndEx::OnSize(type, cx, cy);
    if (m_host) {
        // 最小化時讓 WebView2 不可見 → document.visibilityState=hidden → 前端停止資料輪詢（SDD-03 §9.6）
        m_host->SetVisible(type != SIZE_MINIMIZED);
        m_host->Resize(CRect(0, 0, cx, cy));
    }
    if (m_nativeError) LayoutNativeError();
}

void CMainFrame::OnMove(int x, int y)
{
    CFrameWndEx::OnMove(x, y);
    if (m_host) m_host->NotifyParentWindowPositionChanged();
}

void CMainFrame::OnGetMinMaxInfo(MINMAXINFO* mmi)
{
    const UINT dpi = m_hWnd ? ::GetDpiForWindow(m_hWnd) : 96;
    mmi->ptMinTrackSize.x = ::MulDiv(kMinW, dpi, 96);
    mmi->ptMinTrackSize.y = ::MulDiv(kMinH, dpi, 96);
    CFrameWndEx::OnGetMinMaxInfo(mmi);
}

LRESULT CMainFrame::OnDpiChanged(WPARAM, LPARAM lParam)
{
    // P5：跨螢幕拖曳 → 採用系統建議的矩形；WebView2 自行處理縮放
    const RECT* r = reinterpret_cast<const RECT*>(lParam);
    SetWindowPos(nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
    return 0;
}

void CMainFrame::OnClose()
{
    // ✕ = 最小化至系統匣，不結束程序（P9）。真正結束需由系統匣選單「結束 UI」。
    SavePlacement();
    if (m_host) m_host->SetVisible(false);
    ShowWindow(SW_HIDE);
    if (!m_closeHintShown) {
        m_closeHintShown = true;
        ShowBalloon(L"Cairn 仍在背景執行", L"偵測與回應不受影響。可從系統匣圖示重新開啟主視窗。", {});
    }
}

void CMainFrame::OnDestroy()
{
    KillTimer(TIMER_WEBVIEW_INIT);
#ifdef _DEBUG
    StopDevHttpServer();
#endif
    m_heartbeat.request_stop();
    if (m_heartbeat.joinable()) m_heartbeat.join();
    if (m_trayInitialized) ::Shell_NotifyIconW(NIM_DELETE, &m_nid);
    m_host.reset();
    CFrameWndEx::OnDestroy();
}

void CMainFrame::SavePlacement()
{
    WINDOWPLACEMENT wp{sizeof(wp)};
    if (GetWindowPlacement(&wp) && IsWindowVisible()) theApp.SavePlacement(wp);
}

void CMainFrame::ShowFromTray(const std::string& navigatePath)
{
    if (IsIconic()) ShowWindow(SW_RESTORE);
    else ShowWindow(SW_SHOW);
    if (m_host) m_host->SetVisible(true);
    ::SetForegroundWindow(m_hWnd);
    if (!navigatePath.empty() && m_host) m_host->PostToPage({{"type", "navigate"}, {"path", navigatePath}});
}

void CMainFrame::ExitUi()
{
    const int r = MessageBoxW(L"結束 Cairn 主控台？\n\n結束 UI 不影響 CairnAgent 服務：偵測與回應會繼續在背景執行。\n"
                              L"結束後將不會收到新告警通知，系統匣圖示也會消失。",
                              L"Cairn", MB_OKCANCEL | MB_ICONINFORMATION);
    if (r != IDOK) return;
    SavePlacement();
    DestroyWindow();
}

// ---------------------------------------------------------------------------
// 系統匣（part3 §3.10.1）與 Toast（§3.10.2）
// ---------------------------------------------------------------------------
void CMainFrame::AddTrayIcon()
{
    m_nid = NOTIFYICONDATAW{};
    m_nid.cbSize = sizeof(m_nid);
    m_nid.hWnd = m_hWnd;
    m_nid.uID = kTrayId;
    m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    m_nid.uCallbackMessage = WM_APP_TRAY;
    m_nid.hIcon = m_icons[static_cast<int>(m_trayState)];
    wcscpy_s(m_nid.szTip, L"Cairn — 連線中…");
    m_trayInitialized = ::Shell_NotifyIconW(NIM_ADD, &m_nid) != FALSE;
    m_nid.uVersion = NOTIFYICON_VERSION_4;
    ::Shell_NotifyIconW(NIM_SETVERSION, &m_nid);
}

LRESULT CMainFrame::OnTaskbarCreated(WPARAM, LPARAM)
{
    AddTrayIcon();   // Explorer 重啟後圖示會消失，必須重新加入
    return 0;
}

void CMainFrame::UpdateTray(TrayState s, const std::wstring& tooltip)
{
    m_trayState = s;
    m_nid.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    m_nid.hIcon = m_icons[static_cast<int>(s)];
    wcsncpy_s(m_nid.szTip, tooltip.c_str(), _TRUNCATE);
    if (m_trayInitialized) ::Shell_NotifyIconW(NIM_MODIFY, &m_nid);
    if (m_nativeError) {
        m_errSvc.SetWindowTextW(m_serviceStatusLine.c_str());
    }
}

void CMainFrame::ShowBalloon(const std::wstring& title, const std::wstring& text, const std::string& alertId)
{
    // M0：以 Shell_NotifyIcon 氣球提示實作 Toast（part3 §3.10.2 允許的退回路徑；原生 ToastNotificationManager 需 AUMID 與捷徑註冊）
    m_balloonAlertId = alertId;
    NOTIFYICONDATAW n = m_nid;
    n.uFlags = NIF_INFO;
    wcsncpy_s(n.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(n.szInfo, text.c_str(), _TRUNCATE);
    n.dwInfoFlags = NIIF_INFO | NIIF_RESPECT_QUIET_TIME;
    if (m_trayInitialized) ::Shell_NotifyIconW(NIM_MODIFY, &n);
}

LRESULT CMainFrame::OnTray(WPARAM, LPARAM lParam)
{
    switch (LOWORD(lParam)) {
    case WM_LBUTTONDBLCLK:
    case NIN_SELECT:
    case NIN_KEYSELECT:
        if (m_trayState == TrayState::Learning) ShowFromTray("/settings/exclusions");
        else if (m_trayState == TrayState::Degraded) ShowFromTray("/settings/health");
        else ShowFromTray();
        break;
    case NIN_BALLOONUSERCLICK:
        ShowFromTray(m_balloonAlertId.empty() ? std::string{} : "/alerts/" + m_balloonAlertId);
        break;
    case WM_CONTEXTMENU:
        ShowTrayMenu();
        break;
    default:
        break;
    }
    return 0;
}

void CMainFrame::ShowTrayMenu()
{
    CMenu menu, recent;
    menu.CreatePopupMenu();
    recent.CreatePopupMenu();
    menu.AppendMenuW(MF_STRING, ID_TRAY_OPEN, L"開啟主視窗");
    menu.SetDefaultItem(ID_TRAY_OPEN);
    menu.AppendMenuW(MF_STRING | (m_trayState == TrayState::Gone ? MF_GRAYED : 0), ID_TRAY_PAUSE, L"暫停防護…");
    int i = 0;
    for (const auto& [id, title] : m_recentAlerts) {
        recent.AppendMenuW(MF_STRING, ID_TRAY_RECENT_BASE + i, Trunc(title, 48).c_str());
        if (++i >= 5) break;
    }
    if (i == 0) recent.AppendMenuW(MF_STRING | MF_GRAYED, 0, L"（尚無告警）");
    menu.AppendMenuW(MF_POPUP, reinterpret_cast<UINT_PTR>(recent.Detach()), L"檢視最近告警");
    menu.AppendMenuW(MF_STRING, ID_TRAY_HEALTH, L"服務狀態…");
    if (m_trayState == TrayState::Gone) menu.AppendMenuW(MF_STRING, ID_TRAY_START_SERVICE, L"嘗試啟動服務（需系統管理員）");
    menu.AppendMenuW(MF_SEPARATOR);
    menu.AppendMenuW(MF_STRING, ID_TRAY_EXIT, L"結束 UI");

    POINT pt{};
    ::GetCursorPos(&pt);
    ::SetForegroundWindow(m_hWnd);   // 否則點選單外不會關閉選單
    menu.TrackPopupMenu(TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, this);
    PostMessageW(WM_NULL);
}

BOOL CMainFrame::OnCommand(WPARAM wParam, LPARAM lParam)
{
    const UINT id = LOWORD(wParam);
    switch (id) {
    case ID_TRAY_OPEN: ShowFromTray(); return TRUE;
    case ID_TRAY_PAUSE:
        // 暫停需二次確認並寫入稽核：交給前端的暫停流程（Shell.tsx ProtectionBadge）
        ShowFromTray();
        if (m_host) m_host->PostToPage({{"type", "openPause"}});
        return TRUE;
    case ID_TRAY_HEALTH: ShowFromTray("/settings/health"); return TRUE;
    case ID_TRAY_START_SERVICE: OnWebMessage({{"type", "startService"}}); return TRUE;
    case ID_TRAY_EXIT: ExitUi(); return TRUE;
    case IDC_ERR_INSTALL: InstallWebView2(); return TRUE;
    case IDC_ERR_COPY: CopyErrorDetails(); return TRUE;
    case IDC_ERR_RETRY:
        if (m_retryCount >= 3) {
            // 連續 3 次失敗：重新啟動 CairnConsole（先釋放單一實例 mutex）
            wchar_t self[MAX_PATH * 2]{};
            ::GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
            theApp.ReleaseSingleInstance();
            ::ShellExecuteW(nullptr, L"open", self, nullptr, nullptr, SW_SHOWNORMAL);
            DestroyWindow();
            return TRUE;
        }
        ++m_retryCount;
        StartWebView();   // 不重啟程序，重新呼叫 CreateCoreWebView2Environment
        return TRUE;
    default:
        break;
    }
    if (id >= ID_TRAY_RECENT_BASE && id < ID_TRAY_RECENT_BASE + 5) {
        const size_t idx = id - ID_TRAY_RECENT_BASE;
        if (idx < m_recentAlerts.size()) ShowFromTray("/alerts/" + m_recentAlerts[idx].first);
        return TRUE;
    }
    return CFrameWndEx::OnCommand(wParam, lParam);
}

// ---------------------------------------------------------------------------
// 心跳：背景執行緒，結果以 PostMessage 回 UI 執行緒
// ---------------------------------------------------------------------------
void CMainFrame::HeartbeatLoop(std::stop_token st)
{
    const HWND hwnd = m_hWnd;
    int64_t sinceMs = NowMs() - 60'000;   // 啟動前 1 分鐘內的告警也提示
    int     tick = 0;
    while (!st.stop_requested()) {
        auto hb = std::make_unique<HeartbeatMsg>();
        const auto r = m_rpc->Call("health.get", json::object(), std::chrono::milliseconds(3000));
        hb->ok = r.Ok();
        if (r.Ok()) hb->health = r.result;
        hb->failures = m_rpc->ConsecutiveFailures();
        hb->link = m_rpc->State();
        if (::IsWindow(hwnd) && ::PostMessageW(hwnd, WM_APP_HEARTBEAT, 0, reinterpret_cast<LPARAM>(hb.get()))) hb.release();

        // 每 4 秒查一次新告警（Toast 用）。alerts.list 依時間降冪、僅取分數 >= 80 者通知（§3.10.2）
        if (r.Ok() && (++tick % 2) == 0) {
            char since[40];
            {
                const time_t t = static_cast<time_t>(sinceMs / 1000);
                tm g{};
                gmtime_s(&g, &t);
                sprintf_s(since, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
                          g.tm_hour, g.tm_min, g.tm_sec, static_cast<int>(sinceMs % 1000));
            }
            const auto a = m_rpc->Call("alerts.list", json{{"since", since}, {"sort", "time_desc"}, {"limit", 20}},
                                       std::chrono::milliseconds(3000));
            if (a.Ok() && a.result.is_object() && a.result.contains("items")) {
                auto msg = std::make_unique<NewAlertsMsg>();
                msg->items = json::array();
                for (const auto& it : a.result["items"]) {
                    if (it.value("risk_score", 0) >= 80) msg->items.push_back(it);
                }
                sinceMs = NowMs();
                if (!msg->items.empty() && ::IsWindow(hwnd) &&
                    ::PostMessageW(hwnd, WM_APP_NEW_ALERTS, 0, reinterpret_cast<LPARAM>(msg.get())))
                    msg.release();
            }
        }
        for (int i = 0; i < 20 && !st.stop_requested(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

LRESULT CMainFrame::OnHeartbeat(WPARAM, LPARAM lParam)
{
    std::unique_ptr<HeartbeatMsg> hb{reinterpret_cast<HeartbeatMsg*>(lParam)};
    if (!hb) return 0;

    TrayState    want;
    std::wstring tip;
    if (!hb->ok && hb->failures >= 3) {   // RPC 連續 3 次失敗（約 5 秒）→ 服務失聯
        want = TrayState::Gone;
        tip = L"Cairn — 防護狀態未知\n無法連線至 CairnAgent 服務";
        m_serviceStatusLine = L"服務狀態：✕ 無法連線（防護狀態未知）";
    } else if (!hb->ok) {
        return 0;   // 單次失敗不改變狀態
    } else {
        const json& h = hb->health;
        m_lastHealth = h;
        const auto  res = h.value("resources", json::object());
        const double eps = res.value("events_per_sec", 0.0);
        const double drop = res.value("drop_rate", 0.0);
        const bool  sysmonOk = h.value("sysmon", json::object()).value("installed", false);
        const std::string llm = h.value("llm", json::object()).value("state", std::string("unavailable"));
        const std::string prot = h.value("protection_state", std::string("protecting"));
        const auto  lm = h.value("learning_mode", json::object());
        const int   today = h.value("alerts_today", 0);
        wchar_t rate[32];
        swprintf_s(rate, eps >= 1000 ? L"%.1fk/s" : L"%.0f/s", eps >= 1000 ? eps / 1000 : eps);
        m_serviceStatusLine = std::wstring(L"服務狀態：● 執行中 · 事件 ") + rate + L" · 今日告警 " + std::to_wstring(today);

        if (!sysmonOk || drop > 0.05 || eps <= 0 || llm != "ok" || prot == "paused") {
            want = TrayState::Degraded;
            std::wstring why = !sysmonOk ? L"Sysmon 未執行，僅剩粗粒度事件"
                             : prot == "paused" ? L"防護已暫停"
                             : drop > 0.05 ? L"事件丟包率過高"
                             : eps <= 0 ? L"事件率為 0"
                                        : L"本機 AI 未啟用（偵測不受影響）";
            tip = L"Cairn — 能力降級\n" + why;
        } else if (lm.value("active", false)) {
            want = TrayState::Learning;
            tip = L"Cairn — 學習期 " + std::to_wstring(lm.value("day", 0)) + L"/" + std::to_wstring(lm.value("total_days", 3)) +
                  L" 天\n僅記錄，不執行回應動作";
        } else {
            want = TrayState::Protecting;
            tip = std::wstring(L"Cairn — 防護中\n事件 ") + rate + L" · 今日告警 " + std::to_wstring(today);
        }
        const int unread = h.value("unread_high", 0);
        if (m_host == nullptr || m_host->State() != cairn::ui::HostState::Ready) {
            SetWindowTextW(unread > 0 ? (L"Cairn (" + std::to_wstring(unread) + L")").c_str() : L"Cairn");
        }
    }

    // 遲滯：轉為異常態立即生效；恢復為正常態（防護中／學習期）需連續 3 次健康檢查通過
    const bool wantNormal = want == TrayState::Protecting || want == TrayState::Learning;
    const bool curNormal = m_trayState == TrayState::Protecting || m_trayState == TrayState::Learning;
    if (wantNormal && !curNormal) {
        if (++m_okStreak < 3) return 0;
        m_okStreak = 0;
    } else if (!wantNormal) {
        m_okStreak = 0;
    }

    if (want == TrayState::Degraded && !m_notifiedDegraded) {
        m_notifiedDegraded = true;
        ShowBalloon(L"Cairn 能力降級", tip.substr(tip.find(L'\n') + 1), {});
        UiLog("tray: degraded");
    }
    if (want == TrayState::Gone && !m_notifiedGone) {
        m_notifiedGone = true;
        ShowBalloon(L"Cairn 已停止保護此電腦", L"無法連線至 CairnAgent 服務，在恢復前本機不受保護。", {});
        UiLog("tray: service gone");
    }
    if (wantNormal) {
        m_notifiedDegraded = false;
        m_notifiedGone = false;
    }
    UpdateTray(want, tip);
    return 0;
}

LRESULT CMainFrame::OnNewAlerts(WPARAM, LPARAM lParam)
{
    std::unique_ptr<NewAlertsMsg> m{reinterpret_cast<NewAlertsMsg*>(lParam)};
    if (!m) return 0;
    const int64_t now = NowMs();
    while (!m_toastTimes.empty() && now - m_toastTimes.front() > 60'000) m_toastTimes.pop_front();
    while (!m_toastByTree.empty() && now - m_toastByTree.front().second > 60'000) m_toastByTree.pop_front();

    // items 依時間降冪；由舊到新處理
    for (auto it = m->items.rbegin(); it != m->items.rend(); ++it) {
        const std::string id = it->value("alert_id", std::string{});
        const std::wstring title = cairn::ui::ToWide(it->value("title", std::string{}));
        if (id.empty()) continue;
        if (std::any_of(m_recentAlerts.begin(), m_recentAlerts.end(), [&](auto& p) { return p.first == id; })) continue;
        m_recentAlerts.emplace_front(id, title);
        if (m_recentAlerts.size() > 5) m_recentAlerts.pop_back();

        // 節流：同一程序樹 60 秒最多 1 則；全域每分鐘 3 則，超出合併為「另有 N 則新告警」
        const std::string tree = it->value("root_process_guid", it->value("process_name", std::string{}));
        const bool treeThrottled = std::any_of(m_toastByTree.begin(), m_toastByTree.end(), [&](auto& p) { return p.first == tree; });
        if (treeThrottled || m_toastTimes.size() >= 3) {
            ++m_suppressedToasts;
            continue;
        }
        m_toastTimes.push_back(now);
        m_toastByTree.emplace_back(tree, now);
        // 內文＝程序名 · 分數 · 時間；不放 AI 敘事（§3.10.2）
        const std::wstring proc = cairn::ui::ToWide(it->value("process_name", std::string{}));
        const std::string  time = it->value("time", std::string{});
        const std::wstring hhmmss = time.size() >= 19 ? cairn::ui::ToWide(time.substr(11, 8)) + L" UTC" : L"";
        std::wstring body = proc + L" · 分數 " + std::to_wstring(it->value("risk_score", 0)) + L" · " + hhmmss;
        if (m_suppressedToasts > 0) {
            body += L"\n另有 " + std::to_wstring(m_suppressedToasts) + L" 則新告警";
            m_suppressedToasts = 0;
        }
        ShowBalloon(title, body, id);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 原生錯誤畫面（WebView2 不在時 MFC 自己畫，part3 §3.10.3）
// ---------------------------------------------------------------------------
void CMainFrame::ShowNativeError(HostFailure f, HRESULT hr)
{
    m_nativeError = true;
    m_lastFailure = f;
    m_lastHr = hr;
    if (!m_errTitle.m_hWnd) {
        const UINT dpi = ::GetDpiForWindow(m_hWnd);
        m_fontTitle.CreateFontW(-::MulDiv(22, dpi, 96), 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                                CLEARTYPE_QUALITY, 0, L"Segoe UI");
        m_fontBody.CreateFontW(-::MulDiv(14, dpi, 96), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0,
                               CLEARTYPE_QUALITY, 0, L"Segoe UI");
        const DWORD st = WS_CHILD | SS_CENTER;
        m_errIcon.Create(L"⚠", st, CRect(), this, 0);
        m_errTitle.Create(L"無法載入 Cairn 介面", st, CRect(), this, IDC_ERR_TITLE);
        m_errBody.Create(L"", st, CRect(), this, IDC_ERR_BODY);
        m_errCode.Create(L"", st, CRect(), this, IDC_ERR_CODE);
        m_errSvc.Create(L"", st, CRect(), this, IDC_ERR_SVC);
        m_btnInstall.Create(L"安裝 WebView2…", WS_CHILD | BS_PUSHBUTTON, CRect(), this, IDC_ERR_INSTALL);
        m_btnCopy.Create(L"複製錯誤詳情", WS_CHILD | BS_PUSHBUTTON, CRect(), this, IDC_ERR_COPY);
        m_btnRetry.Create(L"重試", WS_CHILD | BS_PUSHBUTTON, CRect(), this, IDC_ERR_RETRY);
        m_errIcon.SetFont(&m_fontTitle);
        m_errTitle.SetFont(&m_fontTitle);
        for (CWnd* w : std::initializer_list<CWnd*>{&m_errBody, &m_errCode, &m_errSvc, &m_btnInstall, &m_btnCopy, &m_btnRetry})
            w->SetFont(&m_fontBody);
    }
    std::wstring body;
    switch (f) {
    case HostFailure::RuntimeMissing: body = L"找不到 Microsoft Edge WebView2 Runtime。"; break;
    case HostFailure::InitTimeout: body = L"WebView2 初始化逾時（10 秒）。"; break;
    case HostFailure::ProcessCrashed: body = L"WebView2 瀏覽器程序重複異常結束。"; break;
    default: body = L"WebView2 初始化失敗。"; break;
    }
    body += L"\n偵測服務不受影響，仍在背景正常防護。";   // 必要：否則使用者會以為防護整個掛了
    m_errBody.SetWindowTextW(body.c_str());
    m_errCode.SetWindowTextW((L"錯誤代碼：HRESULT " + cairn::ui::ToWide(HrHex(hr))).c_str());
    m_errSvc.SetWindowTextW(m_serviceStatusLine.c_str());
    m_btnRetry.SetWindowTextW(m_retryCount >= 3 ? L"重新啟動 CairnConsole" : L"重試");
    m_btnInstall.ShowWindow(f == HostFailure::RuntimeMissing ? SW_SHOW : SW_HIDE);
    for (CWnd* w : std::initializer_list<CWnd*>{&m_errIcon, &m_errTitle, &m_errBody, &m_errCode, &m_errSvc, &m_btnCopy, &m_btnRetry})
        w->ShowWindow(SW_SHOW);
    LayoutNativeError();
    Invalidate();
}

void CMainFrame::HideNativeError()
{
    if (!m_nativeError) return;
    m_nativeError = false;
    for (CWnd* w : std::initializer_list<CWnd*>{&m_errIcon, &m_errTitle, &m_errBody, &m_errCode, &m_errSvc, &m_btnInstall,
                                                &m_btnCopy, &m_btnRetry})
        if (w->m_hWnd) w->ShowWindow(SW_HIDE);
    Invalidate();
}

void CMainFrame::LayoutNativeError()
{
    if (!m_errTitle.m_hWnd) return;
    CRect rc;
    GetClientRect(&rc);
    const UINT dpi = ::GetDpiForWindow(m_hWnd);
    const auto S = [dpi](int v) { return ::MulDiv(v, dpi, 96); };
    const int w = S(560), x = rc.left + (rc.Width() - w) / 2;
    int y = rc.top + std::max(S(40), (rc.Height() - S(380)) / 2);
    m_errIcon.MoveWindow(x, y, w, S(40)); y += S(48);
    m_errTitle.MoveWindow(x, y, w, S(34)); y += S(46);
    m_errBody.MoveWindow(x, y, w, S(48)); y += S(60);
    m_errCode.MoveWindow(x, y, w, S(22)); y += S(40);
    const int bw = S(180), gap = S(16);
    const bool install = m_btnInstall.IsWindowVisible() != FALSE;
    int bx = install ? x + (w - (bw * 2 + gap)) / 2 : x + (w - bw) / 2;
    if (install) { m_btnInstall.MoveWindow(bx, y, bw, S(32)); bx += bw + gap; }
    m_btnCopy.MoveWindow(bx, y, bw, S(32)); y += S(56);
    m_errSvc.MoveWindow(x, y, w, S(22)); y += S(36);
    m_btnRetry.MoveWindow(x + (w - bw) / 2, y, bw, S(32));
}

void CMainFrame::OnPaint()
{
    CPaintDC dc(this);
    if (m_nativeError) {
        CRect rc;
        GetClientRect(&rc);
        dc.FillRect(&rc, &m_bgBrush);
    }
}

BOOL CMainFrame::OnEraseBkgnd(CDC* dc)
{
    if (!m_nativeError) return TRUE;   // WebView2 填滿客戶區，避免閃爍
    CRect rc;
    GetClientRect(&rc);
    dc->FillRect(&rc, &m_bgBrush);
    return TRUE;
}

HBRUSH CMainFrame::OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor)
{
    if (m_nativeError && ctlColor == CTLCOLOR_STATIC) {
        LOGBRUSH lb{};
        m_bgBrush.GetLogBrush(&lb);
        const bool dark = GetRValue(lb.lbColor) < 0x80;
        dc->SetBkColor(lb.lbColor);
        COLORREF fg = dark ? RGB(0xE6, 0xED, 0xF3) : RGB(0x0D, 0x11, 0x17);
        if (wnd == &m_errIcon) fg = dark ? RGB(0xD2, 0x99, 0x22) : RGB(0x9A, 0x67, 0x00);
        if (wnd == &m_errCode || wnd == &m_errSvc) fg = dark ? RGB(0x8B, 0x94, 0x9E) : RGB(0x6B, 0x72, 0x80);
        dc->SetTextColor(fg);
        return static_cast<HBRUSH>(m_bgBrush.GetSafeHandle());
    }
    return CFrameWndEx::OnCtlColor(dc, wnd, ctlColor);
}

void CMainFrame::CopyErrorDetails()
{
    // HRESULT、Runtime 版本查詢結果、ui.log 末 50 行，一次複製到剪貼簿
    std::string text = "Cairn CairnConsole 錯誤詳情\n";
    text += "HRESULT: " + HrHex(m_lastHr) + "\n";
    text += "Failure: " + std::to_string(static_cast<int>(m_lastFailure)) + "\n";
    text += "WebView2 Runtime: " + cairn::ui::ToUtf8(m_host ? m_host->RuntimeVersion() : L"?") + "\n";
    text += "RPC link: " + cairn::ui::ToUtf8(cairn::ui::LinkStateName(m_rpc->State())) + "\n";
    text += "---- ui.log (last 50 lines) ----\n" + LastLogLines(50);
    const std::wstring w = cairn::ui::ToWide(text);
    if (!OpenClipboard()) return;
    ::EmptyClipboard();
    HGLOBAL h = ::GlobalAlloc(GMEM_MOVEABLE, (w.size() + 1) * sizeof(wchar_t));
    if (h) {
        memcpy(::GlobalLock(h), w.c_str(), (w.size() + 1) * sizeof(wchar_t));
        ::GlobalUnlock(h);
        if (!::SetClipboardData(CF_UNICODETEXT, h)) ::GlobalFree(h);
    }
    ::CloseClipboard();
}

void CMainFrame::InstallWebView2()
{
    // 離線／氣隙環境是目標場景：使用隨產品附帶的 bootstrapper，不只給一個下載連結
    wchar_t self[MAX_PATH * 2]{};
    ::GetModuleFileNameW(nullptr, self, static_cast<DWORD>(std::size(self)));
    std::wstring dir(self);
    dir.resize(dir.find_last_of(L'\\'));
    const std::wstring setup = dir + L"\\redist\\MicrosoftEdgeWebview2Setup.exe";
    if (::GetFileAttributesW(setup.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW((L"找不到 WebView2 安裝程式：\n" + setup + L"\n\n請由 IT 人員安裝 Microsoft Edge WebView2 Runtime。").c_str(),
                    L"Cairn", MB_OK | MB_ICONWARNING);
        return;
    }
    SHELLEXECUTEINFOW sei{sizeof(sei)};
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpFile = setup.c_str();
    sei.nShow = SW_SHOWNORMAL;
    if (!::ShellExecuteExW(&sei) || !sei.hProcess) return;
    // 安裝完成後自動重試
    const HWND hwnd = m_hWnd;
    std::thread([hwnd, proc = sei.hProcess] {
        ::WaitForSingleObject(proc, INFINITE);
        ::CloseHandle(proc);
        ::PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(IDC_ERR_RETRY, BN_CLICKED), 0);
    }).detach();
}
