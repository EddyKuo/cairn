// src/svc/telemetry/SysmonProbe.h             namespace cairn::telemetry
// Sysmon 服務狀態探測（SDD-01 §3.6：Silent 狀態下以 SCM 主動確認；part2 §2.2.4 的降級判定）。
// 由 Watchdog / health.get 呼叫；可阻塞（SCM 查詢數 ms），不得在 T1/T3 呼叫。
#pragma once
#ifndef _WIN32
#error "SysmonProbe 僅支援 Windows"
#endif

#include <cstdint>
#include <filesystem>
#include <string>

namespace cairn::telemetry {

struct SysmonStatus {
    bool        installed = false;   // 服務存在（Sysmon64 或 Sysmon）
    bool        running   = false;
    std::string serviceName;         // "Sysmon64" | "Sysmon"
    std::string version;             // 檔案版本 "15.15.0.0"；取不到為空
    uint32_t    majorVersion = 0;
    // agent_health.sysmon_state 的值：ok | outdated | missing
    [[nodiscard]] const char* StateString() const noexcept
    {
        if (!installed || !running) return "missing";
        if (majorVersion != 0 && majorVersion < 14) return "outdated";   // part2 §2.2.4：≥ 14 為完整模式
        return "ok";
    }
};

[[nodiscard]] SysmonStatus ProbeSysmon() noexcept;

// config/sysmon.xml 的 SHA256（大寫 hex），供 sysmon_config_hash 組態漂移檢查（SDD-03 §10.3）。
// 讀檔失敗回空字串。
[[nodiscard]] std::string HashFileSha256(const std::filesystem::path& file) noexcept;

} // namespace cairn::telemetry
