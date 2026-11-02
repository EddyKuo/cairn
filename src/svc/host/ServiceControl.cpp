#include "host/ServiceControl.h"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <thread>

#include <spdlog/spdlog.h>
#include <wil/resource.h>

#include "common/WinUtil.h"

namespace cairn::svc {

namespace {

// ---- SCM 狀態（ServiceMain 與 HandlerEx 共用）----
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
SERVICE_STATUS        g_status{};
std::mutex            g_statusMutex;
wil::unique_event     g_stopRequested;
IServiceBody*         g_body = nullptr;

void ReportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0)
{
    std::lock_guard lk{g_statusMutex};
    g_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState            = state;
    g_status.dwWin32ExitCode           = exitCode == NO_ERROR ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR;
    g_status.dwServiceSpecificExitCode = exitCode;
    g_status.dwWaitHint                = waitHint;
    // 註冊 PRESHUTDOWN：SHUTDOWN 只有 5 秒，本服務的關機流程必然被強殺（SDD-01 §2.5.4）
    g_status.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN) : 0;
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        g_status.dwCheckPoint = 0;
    } else {
        ++g_status.dwCheckPoint;
    }
    if (g_statusHandle) ::SetServiceStatus(g_statusHandle, &g_status);
}

DWORD WINAPI HandlerEx(DWORD control, DWORD, LPVOID, LPVOID)
{
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_PRESHUTDOWN:
        // HandlerEx 只設定停止事件後立即返回；關機序列在 ServiceMain 的執行緒上執行
        ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 30'000);
        g_stopRequested.SetEvent();
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = ::RegisterServiceCtrlHandlerExW(kServiceName, HandlerEx, nullptr);
    if (!g_statusHandle) return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 30'000);
    const ProgressFn startProgress = [](DWORD hint) { ReportStatus(SERVICE_START_PENDING, NO_ERROR, hint); };

    DWORD exitCode = NO_ERROR;
    if (!g_body->Start(startProgress, exitCode)) {
        spdlog::critical("service start failed, exit code {}", exitCode);
        ReportStatus(SERVICE_STOPPED, exitCode ? exitCode : ERROR_BAD_CONFIGURATION);
        return;
    }
    ReportStatus(SERVICE_RUNNING);

    ::WaitForSingleObject(g_stopRequested.get(), INFINITE);

    const ProgressFn stopProgress = [](DWORD hint) { ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, hint); };
    g_body->Stop(stopProgress);
    ReportStatus(SERVICE_STOPPED);
}

std::atomic<bool> g_consoleStop{false};
wil::unique_event g_consoleStopEvent;

BOOL WINAPI ConsoleCtrlHandler(DWORD type)
{
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        g_consoleStop = true;
        g_consoleStopEvent.SetEvent();
        return TRUE;
    default:
        return FALSE;
    }
}

} // namespace

int RunAsService(IServiceBody& body)
{
    g_body = &body;
    g_stopRequested.create(wil::EventOptions::ManualReset);
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr},
    };
    if (!::StartServiceCtrlDispatcherW(table)) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::fwprintf(stderr, L"CairnAgent 不是由 SCM 啟動。開發除錯請用 --console，安裝請用 --install。\n");
        }
        return static_cast<int>(err);
    }
    return 0;
}

int RunInConsole(IServiceBody& body)
{
    g_consoleStopEvent.create(wil::EventOptions::ManualReset);
    ::SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    const ProgressFn progress = [](DWORD) {};

    DWORD exitCode = 0;
    if (!body.Start(progress, exitCode)) {
        std::fwprintf(stderr, L"啟動失敗（exit code %lu），詳見日誌。\n", exitCode);
        return exitCode ? static_cast<int>(exitCode) : 1;
    }
    std::fwprintf(stdout, L"CairnAgent 以主控台模式執行中，按 Ctrl+C 停止。\n");
    ::WaitForSingleObject(g_consoleStopEvent.get(), INFINITE);
    std::fwprintf(stdout, L"正在停止…\n");
    body.Stop(progress);
    return 0;
}

int InstallService()
{
    const auto exe = ExeDir() / L"CairnAgent.exe";
    wil::unique_schandle scm{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager 失敗（%lu）：需以系統管理員身分執行。\n", ::GetLastError());
        return 1;
    }
    const std::wstring cmd = L"\"" + exe.wstring() + L"\"";
    wil::unique_schandle svc{::CreateServiceW(scm.get(), kServiceName, kServiceDisplayName, SERVICE_ALL_ACCESS,
                                              SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                              cmd.c_str(), nullptr, nullptr, nullptr, nullptr /*LocalSystem*/,
                                              nullptr)};
    if (!svc) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            std::fwprintf(stdout, L"服務已存在。\n");
            return 0;
        }
        std::fwprintf(stderr, L"CreateService 失敗（%lu）\n", err);
        return 1;
    }

    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(kServiceDescription)};
    ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

    SERVICE_PRESHUTDOWN_INFO pre{60'000};
    ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_PRESHUTDOWN_INFO, &pre);

    SC_ACTION actions[3] = {{SC_ACTION_RESTART, 60'000}, {SC_ACTION_RESTART, 60'000}, {SC_ACTION_NONE, 0}};
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 24 * 3600;
    fa.cActions      = 3;
    fa.lpsaActions   = actions;
    ::ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    std::fwprintf(stdout, L"已安裝服務 %ls。以 sc.exe start CairnAgent 啟動。\n", kServiceName);
    return 0;
}

int UninstallService()
{
    wil::unique_schandle scm{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) {
        std::fwprintf(stderr, L"OpenSCManager 失敗（%lu）：需以系統管理員身分執行。\n", ::GetLastError());
        return 1;
    }
    wil::unique_schandle svc{::OpenServiceW(scm.get(), kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)};
    if (!svc) {
        std::fwprintf(stdout, L"服務不存在。\n");
        return 0;
    }
    SERVICE_STATUS st{};
    if (::ControlService(svc.get(), SERVICE_CONTROL_STOP, &st)) {
        for (int i = 0; i < 60 && st.dwCurrentState != SERVICE_STOPPED; ++i) {
            ::Sleep(500);
            if (!::QueryServiceStatus(svc.get(), &st)) break;
        }
    }
    if (!::DeleteService(svc.get())) {
        std::fwprintf(stderr, L"DeleteService 失敗（%lu）\n", ::GetLastError());
        return 1;
    }
    std::fwprintf(stdout, L"已移除服務 %ls。\n", kServiceName);
    return 0;
}

} // namespace cairn::svc
