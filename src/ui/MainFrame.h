// MainFrame.h —— CFrameWndEx 主視窗（part3 §3.2.1 / §3.10；SDD-03 §9.1）
// 宿主層的功能清單是封閉的（part0 §0.3）：視窗、系統匣（四態）、Toast、WebView2 初始化與原生錯誤畫面、RPC 轉接。
// 不做：選單列、工具列、MFC 對話框、任何偵測邏輯、本機快取（part3 §3.10.5）。
#pragma once

#include <nlohmann/json.hpp>

#include <deque>
#include <memory>
#include <string>
#include <thread>

#include "EmbeddedAssets.h"
#include "WebViewHost.h"

namespace cairn::ui {
class RpcClient;
class ResourceInterceptor;
} // namespace cairn::ui

// 系統匣四態（part3 §3.10.1）
enum class TrayState : uint8_t { Protecting, Learning, Degraded, Gone };

class CMainFrame : public CFrameWndEx {
    DECLARE_DYNAMIC(CMainFrame)
public:
    static constexpr const wchar_t* kWindowClass = L"CairnConsoleMainFrame";

    CMainFrame();
    ~CMainFrame() override;

    BOOL CreateMainWindow(uint16_t devHttpPort);
    void ShowFromTray(const std::string& navigatePath = {});

protected:
    BOOL PreCreateWindow(CREATESTRUCT& cs) override;
    BOOL OnCommand(WPARAM wParam, LPARAM lParam) override;

    afx_msg int  OnCreate(LPCREATESTRUCT lpcs);
    afx_msg void OnSize(UINT type, int cx, int cy);
    afx_msg void OnMove(int x, int y);
    afx_msg void OnClose();
    afx_msg void OnDestroy();
    afx_msg void OnGetMinMaxInfo(MINMAXINFO* mmi);
    afx_msg void OnTimer(UINT_PTR id);
    afx_msg void OnPaint();
    afx_msg BOOL OnEraseBkgnd(CDC* dc);
    afx_msg HBRUSH OnCtlColor(CDC* dc, CWnd* wnd, UINT ctlColor);
    afx_msg LRESULT OnDpiChanged(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnApiReply(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnHeartbeat(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnNewAlerts(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnTray(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnWebViewFailed(WPARAM wParam, LPARAM lParam);
    afx_msg LRESULT OnTaskbarCreated(WPARAM wParam, LPARAM lParam);
    DECLARE_MESSAGE_MAP()

private:
    // ---- WebView2 ----
    void StartWebView();
    void OnWebViewReady();
    void OnWebViewFailedCb(cairn::ui::HostFailure f, HRESULT hr);
    void OnWebMessage(const nlohmann::json& msg);

    // ---- 原生錯誤畫面（part3 §3.10.3）----
    void ShowNativeError(cairn::ui::HostFailure f, HRESULT hr);
    void HideNativeError();
    void LayoutNativeError();
    void CopyErrorDetails();
    void InstallWebView2();

    // ---- 系統匣 / Toast ----
    void AddTrayIcon();
    void UpdateTray(TrayState s, const std::wstring& tooltip);
    void ShowBalloon(const std::wstring& title, const std::wstring& text, const std::string& alertId);
    void ShowTrayMenu();
    void ExitUi();

    // ---- 心跳執行緒（不依賴 WebView2：主視窗關閉或前端崩潰時托盤狀態仍須正確）----
    void HeartbeatLoop(std::stop_token st);

    void SavePlacement();
    void ApplyTitleBarTheme(bool dark);

    std::shared_ptr<cairn::ui::RpcClient>            m_rpc;
    cairn::ui::EmbeddedAssets                        m_assets;
    std::unique_ptr<cairn::ui::ResourceInterceptor>  m_interceptor;
    std::unique_ptr<cairn::ui::WebViewHost>          m_host;
    std::jthread                                     m_heartbeat;
    uint16_t                                         m_devHttpPort = 0;

    // 系統匣
    NOTIFYICONDATAW m_nid{};
    HICON           m_icons[4]{};
    TrayState       m_trayState = TrayState::Protecting;
    bool            m_trayInitialized = false;
    int             m_okStreak = 0;
    bool            m_notifiedDegraded = false;
    bool            m_notifiedGone = false;
    bool            m_closeHintShown = false;
    std::string     m_balloonAlertId;
    std::deque<std::pair<std::string, std::wstring>> m_recentAlerts;   // (alert_id, 標題)，最多 5
    std::deque<int64_t> m_toastTimes;                                   // 全域節流：每分鐘 3 則
    std::deque<std::pair<std::string, int64_t>> m_toastByTree;          // 同一程序樹 60 秒 1 則
    int             m_suppressedToasts = 0;
    nlohmann::json  m_lastHealth;
    std::wstring    m_serviceStatusLine = L"服務狀態：查詢中…";

    // 原生錯誤畫面
    bool       m_nativeError = false;
    int        m_retryCount = 0;
    HRESULT    m_lastHr = S_OK;
    cairn::ui::HostFailure m_lastFailure = cairn::ui::HostFailure::RuntimeMissing;
    CStatic    m_errIcon, m_errTitle, m_errBody, m_errCode, m_errSvc;
    CButton    m_btnInstall, m_btnCopy, m_btnRetry;
    CFont      m_fontTitle, m_fontBody;
    CBrush     m_bgBrush;
    UINT       m_taskbarCreatedMsg = 0;
};
