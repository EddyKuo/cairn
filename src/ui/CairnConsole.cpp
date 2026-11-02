// CairnConsole.cpp —— 見 CairnConsole.h
#include "pch.h"

#include "CairnConsole.h"

#include "MainFrame.h"

BEGIN_MESSAGE_MAP(CairnConsoleApp, CWinAppEx)
END_MESSAGE_MAP()

CairnConsoleApp theApp;

namespace {
constexpr wchar_t kMutexName[] = L"Global\\CairnConsole.SingleInstance";
constexpr wchar_t kPlacementSection[] = L"Window";
constexpr wchar_t kPlacementEntry[] = L"Placement";
} // namespace

CairnConsoleApp::CairnConsoleApp()
{
    SetAppID(L"Cairn.CairnConsole.M0");
}

bool CairnConsoleApp::ActivateExistingInstance()
{
    HWND h = ::FindWindowW(CMainFrame::kWindowClass, nullptr);
    if (!h) return false;
    if (::IsIconic(h)) ::ShowWindow(h, SW_RESTORE);
    else ::ShowWindow(h, SW_SHOW);
    ::SetForegroundWindow(h);
    return true;
}

BOOL CairnConsoleApp::InitInstance()
{
    // P1：MFC 需要 STA；WebView2 亦要求 STA
    m_comInitialized = SUCCEEDED(::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED));

    m_singleInstance = ::CreateMutexW(nullptr, FALSE, kMutexName);
    if (m_singleInstance && ::GetLastError() == ERROR_ALREADY_EXISTS) {
        ActivateExistingInstance();
        return FALSE;   // 結束本實例
    }

    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_WIN95_CLASSES};
    ::InitCommonControlsEx(&icc);
    CWinAppEx::InitInstance();

    // HKCU\Software\Cairn\UI（part3 §3.2.1）
    SetRegistryKey(L"Cairn");
    free(const_cast<wchar_t*>(m_pszProfileName));
    m_pszProfileName = _wcsdup(L"UI");

    uint16_t devHttpPort = 0;
#ifdef _DEBUG
    // --dev-http <port>：僅供開發（Vite dev server 經此 proxy 打 /api/v1），Release 不編譯
    for (int i = 1; i + 1 < __argc; ++i) {
        if (wcscmp(__wargv[i], L"--dev-http") == 0) devHttpPort = static_cast<uint16_t>(_wtoi(__wargv[i + 1]));
    }
#endif

    auto* frame = new CMainFrame;
    m_pMainWnd = frame;
    if (!frame->CreateMainWindow(devHttpPort)) {
        m_pMainWnd = nullptr;
        return FALSE;
    }
    frame->UpdateWindow();
    return TRUE;
}

int CairnConsoleApp::ExitInstance()
{
    ReleaseSingleInstance();
    if (m_comInitialized) ::CoUninitialize();
    return CWinAppEx::ExitInstance();
}

void CairnConsoleApp::ReleaseSingleInstance() noexcept
{
    if (m_singleInstance) {
        ::CloseHandle(m_singleInstance);
        m_singleInstance = nullptr;
    }
}

bool CairnConsoleApp::LoadPlacement(WINDOWPLACEMENT& wp)
{
    BYTE* data = nullptr;
    UINT  size = 0;
    if (!GetProfileBinary(kPlacementSection, kPlacementEntry, &data, &size) || !data) return false;
    const bool ok = size == sizeof(WINDOWPLACEMENT);
    if (ok) memcpy(&wp, data, sizeof(wp));
    delete[] data;
    return ok;
}

void CairnConsoleApp::SavePlacement(const WINDOWPLACEMENT& wp)
{
    WriteProfileBinary(kPlacementSection, kPlacementEntry, reinterpret_cast<LPBYTE>(const_cast<WINDOWPLACEMENT*>(&wp)),
                       sizeof(wp));
}
