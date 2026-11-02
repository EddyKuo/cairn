// src/svc/host/ServiceControl.h               namespace cairn::svc
// SCM 對接樣板：安裝／移除、ServiceMain、HandlerEx、狀態回報、主控台模式。
// 與偵測邏輯無關；真正的啟停流程在 ServiceHost（IServiceBody 的實作）。
#pragma once
#include <windows.h>

#include <functional>
#include <string>

namespace cairn::svc {

inline constexpr wchar_t kServiceName[]        = L"CairnAgent";
inline constexpr wchar_t kServiceDisplayName[] = L"Cairn Endpoint Agent";
inline constexpr wchar_t kServiceDescription[] = L"Cairn 端點偵測與回應代理程式。停止此服務將關閉所有防護。";

// 啟停進度回報：每完成一個階段呼叫一次，遞增 dwCheckPoint（SDD-01 §2.5.4「dwWaitHint 要誠實」）。
using ProgressFn = std::function<void(DWORD waitHintMs)>;

// 服務本體。Start 在 SERVICE_START_PENDING 期間執行；回傳 false 代表致命錯誤（服務以 exitCode 停止）。
class IServiceBody {
public:
    virtual ~IServiceBody() = default;
    [[nodiscard]] virtual bool Start(const ProgressFn& progress, DWORD& exitCode) = 0;
    virtual void Stop(const ProgressFn& progress) noexcept = 0;
};

// 以 SCM 服務身分執行（StartServiceCtrlDispatcherW）。body 生命週期需涵蓋整個呼叫。
int RunAsService(IServiceBody& body);

// 主控台模式（--console）：開發除錯用，Ctrl+C / Ctrl+Break 觸發停止。
int RunInConsole(IServiceBody& body);

// --install / --uninstall（需系統管理員）。安裝時設定：自動啟動（延遲）、PRESHUTDOWN 逾時 60 秒、
// 失敗時自動重啟（1 分鐘後，最多 3 次）、服務描述。
int InstallService();
int UninstallService();

} // namespace cairn::svc
