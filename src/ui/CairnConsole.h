// CairnConsole.h —— CWinAppEx 衍生的應用程式物件（CairnConsoleApp）
//   - COM STA（SDD-03 §9.2.2 P1：MFC 與 WebView2 都要求 STA）
//   - 單一實例：Global\CairnConsole.SingleInstance；第二次啟動時啟用既有視窗後立即結束
//   - UI 偏好：HKCU\Software\Cairn\UI（SetRegistryKey("Cairn") + profile 名稱 "UI"）
//   - 命令列：--dev-http <port>（僅 Debug 組建；Release 以 #ifdef 完全移除）
#pragma once

class CairnConsoleApp : public CWinAppEx {
public:
    CairnConsoleApp();

    BOOL InitInstance() override;
    int  ExitInstance() override;

    bool LoadPlacement(WINDOWPLACEMENT& wp);
    void SavePlacement(const WINDOWPLACEMENT& wp);
    void ReleaseSingleInstance() noexcept;

private:
    static bool ActivateExistingInstance();

    HANDLE m_singleInstance = nullptr;
    bool   m_comInitialized = false;

    DECLARE_MESSAGE_MAP()
};

extern CairnConsoleApp theApp;
