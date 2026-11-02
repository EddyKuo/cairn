// src/svc/host/main.cpp —— CairnAgent.exe 進入點
//   CairnAgent.exe              由 SCM 啟動（服務模式）
//   CairnAgent.exe --console    主控台模式（開發除錯；Ctrl+C 停止）
//   CairnAgent.exe --install    安裝服務（需系統管理員）
//   CairnAgent.exe --uninstall  移除服務（需系統管理員）
#include <windows.h>

#include <cstdio>
#include <memory>
#include <string_view>
#include <vector>

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "host/ServiceControl.h"
#include "host/ServiceHost.h"

namespace {

void SetupLogging(bool console)
{
    std::vector<spdlog::sink_ptr> sinks;
    try {
        const auto dir = cairn::svc::DataDir() / L"logs";
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        // 10 MB × 5 份輪替（policy logging.* 的預設值；ServiceHost 讀到設定後只調整等級）
        sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            (dir / L"cairn-svc.log").string(), 10u * 1024 * 1024, 5));
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "日誌檔無法開啟：%s\n", ex.what());
    }
    if (console) sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    auto logger = std::make_shared<spdlog::logger>("cairn", sinks.begin(), sinks.end());
    logger->set_pattern("%Y-%m-%dT%H:%M:%S.%e%z [%l] [t%t] %v");
    logger->flush_on(spdlog::level::warn);
    spdlog::set_default_logger(logger);
    spdlog::set_level(spdlog::level::info);
    spdlog::flush_every(std::chrono::seconds(5));
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    ::SetConsoleOutputCP(CP_UTF8);
    const std::wstring_view arg = argc > 1 ? std::wstring_view(argv[1]) : std::wstring_view{};

    if (arg == L"--install") return cairn::svc::InstallService();
    if (arg == L"--uninstall") return cairn::svc::UninstallService();
    if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
        std::fwprintf(stdout, L"CairnAgent.exe [--console | --install | --uninstall]\n");
        return 0;
    }

    const bool console = arg == L"--console";
    if (!arg.empty() && !console) {
        std::fwprintf(stderr, L"未知參數：%ls（可用：--console / --install / --uninstall）\n", argv[1]);
        return 2;
    }

    SetupLogging(console);
    int rc = 0;
    {
        cairn::host::ServiceHost host;
        rc = console ? cairn::svc::RunInConsole(host) : cairn::svc::RunAsService(host);
    }
    spdlog::shutdown();
    return rc;
}
