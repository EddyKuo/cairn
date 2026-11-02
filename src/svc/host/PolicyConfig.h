// src/svc/host/PolicyConfig.h                 namespace cairn::host
// 讀取 %ProgramData%\Cairn\policy.json（格式見 config/policy.default.json），轉為各模組的設定 struct。
// 可攜（不含 Win32）：路徑中的 %ProgramData% 等環境變數由呼叫端提供的展開函式處理。
//
// 降級原則（SDD-01 §2.6）：設定檔缺失或損毀 → 使用內建預設並繼續；未知欄位忽略並記入 warnings。
#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "base/Result.h"
#include "engine/EnginePolicy.h"

namespace cairn::host {

struct HostConfig {
    engine::EnginePolicy engine{};

    // ---- storage ----
    std::filesystem::path dbPath;
    size_t  writeQueueCapacity = 100'000;
    size_t  batchMaxRows       = 1'000;
    int64_t batchMaxAgeMs      = 200;
    int     busyRetries        = 5;
    int64_t retentionIntervalMs = 3'600'000;
    int64_t eventTtlMs  = 7LL * 86'400'000;
    int64_t alertTtlMs  = 90LL * 86'400'000;
    int64_t healthTtlMs = 30LL * 86'400'000;
    int64_t maxDbBytes  = 4096LL * 1024 * 1024;

    // ---- telemetry ----
    bool    sysmonEnabled          = true;
    bool    powershellEnabled      = true;
    bool    securityFallback       = true;
    int64_t silenceTimeoutMs       = 120'000;
    int64_t resubscribeBackoffMaxMs = 60'000;
    uint32_t maxReconnectAttempts  = 10;
    size_t  analysisQueueCapacity  = 32'768;
    size_t  internerMaxEntries     = 100'000;

    // ---- response ----
    std::chrono::seconds tokenTtl{60};

    // ---- learning ----
    bool    learningEnabled = true;
    int     learningDays    = 3;
    std::vector<std::string> forcedDryrunRules;
    int64_t suggestionMinDryrunHits = 3;

    // ---- llm ----
    bool                  llmEnabled = true;
    std::filesystem::path llamaServerPath;
    std::filesystem::path modelPath;
    std::filesystem::path fallbackModelPath;
    uint16_t              llmPort       = 8080;
    int                   llmCtxSize    = 8192;
    int                   llmGpuLayers  = 999;
    std::chrono::seconds  llmIdleUnload{300};
    int                   llmMaxRestartsPerHour = 3;
    uint64_t              llmJobMemoryBytes = 6ull << 30;
    int64_t               llmMinScoreMilli  = 80'000;
    size_t                llmQueueCapacity  = 32;

    // ---- health / watchdog ----
    int healthSampleSeconds   = 10;
    int watchdogIntervalSeconds = 5;

    // ---- logging ----
    std::string           logLevel = "info";
    std::filesystem::path logFile;
    size_t                logMaxFileBytes = 10u << 20;
    size_t                logMaxFiles     = 5;
    bool                  logPrompts      = false;

    // 解析過程的非致命問題（未知欄位、型別錯誤而採預設值）
    std::vector<std::string> warnings;
};

// 展開 "%ProgramData%" 之類的環境變數。
using EnvExpander = std::function<std::string(std::string_view)>;

// 以 dataDir（%ProgramData%\Cairn）與 exeDir（安裝目錄）為基準的內建預設值。
[[nodiscard]] HostConfig DefaultHostConfig(const std::filesystem::path& dataDir, const std::filesystem::path& exeDir);

// 解析 policy.json 文字。JSON 本身損毀時回錯誤（呼叫端改用 DefaultHostConfig）；
// 個別欄位型別錯誤只記入 warnings 並保留預設值。
[[nodiscard]] Result<HostConfig> ParsePolicyJson(std::string_view jsonText, const std::filesystem::path& dataDir,
                                                 const std::filesystem::path& exeDir, const EnvExpander& expand);

// 讀檔 + 解析；檔案缺失或損毀時寫入內建預設（config/policy.default.json 的內容由呼叫端提供）並回傳預設值。
// fellBack = true 代表採用了內建預設（health 應標示）。
[[nodiscard]] HostConfig LoadPolicyFile(const std::filesystem::path& file, std::string_view builtinDefaultJson,
                                        const std::filesystem::path& dataDir, const std::filesystem::path& exeDir,
                                        const EnvExpander& expand, bool& fellBack);

} // namespace cairn::host
