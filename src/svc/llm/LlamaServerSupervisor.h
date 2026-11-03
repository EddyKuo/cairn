// src/svc/llm/LlamaServerSupervisor.h         namespace cairn::llm
// llama-server.exe 子程序生命週期（part2 §2.6.2、SDD-03 §7.2）。
//   G1 服務死亡時子程序必然一起消失：Job Object + JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE（絕不設 BREAKAWAY_OK）
//      建立順序：CreateJobObject → CreateProcess(CREATE_SUSPENDED) → AssignProcessToJobObject → ResumeThread
//   G2 崩潰自動復原但不無限重啟：退避 min(2^n·5s, 120s)；滑動 1 小時內重啟 > 3 次 → Unavailable（終局）
//   G3 閒置 300 秒卸載（關閉 Job handle → 核心終止子程序、釋放 VRAM）
//   G4 執行檔／模型缺失 → 乾淨降級為 Unavailable，不重試
// 另：
//   - stdout/stderr 以 CreatePipe 接出，專屬讀取執行緒轉入 spdlog（不導流會讓管線寫滿而卡死子程序）
//   - 可繼承 handle 以 PROC_THREAD_ATTRIBUTE_HANDLE_LIST 限定為管線寫端
//   - API key：每次啟動以 BCryptGenRandom 產生，寫入 %ProgramData%\Cairn\llm-api.key（DACL 僅 SYSTEM + Administrators），
//     以 --api-key-file 傳給 llama-server（不放命令列，避免經由程序清單外洩）
//   - ai_model_id = 模型檔 SHA256 前 16 碼（首次啟動時計算，之後快取）
// 執行緒安全：EnsureRunning（T5）、Tick（T8）、Shutdown（ServiceHost）可併發呼叫。
#pragma once
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

#include <wil/resource.h>

#include "base/Result.h"

namespace cairn::llm {

enum class SupervisorState {
    Stopped,      // 尚未啟動、已閒置卸載、或已主動停止（下次 EnsureRunning 會冷啟動）
    Starting,     // 已 CreateProcess，等待 /health 通過
    Running,      // 可接受請求
    Backoff,      // 崩潰後退避中；到期後由下一次 EnsureRunning 重試
    Unavailable,  // 終局：停用／檔案缺失／超過重啟上限。只有 RequestManualRestart() 能解除
};

[[nodiscard]] const char* SupervisorStateName(SupervisorState s) noexcept;

struct SupervisorConfig {
    bool                  enabled = true;
    std::filesystem::path exePath;          // %ProgramFiles%\Cairn\bin\llama-server.exe
    std::filesystem::path modelPath;        // %ProgramData%\Cairn\models\qwen2.5-3b-instruct-q4_k_m.gguf
    std::filesystem::path dataDir;          // %ProgramData%\Cairn（放 llm-api.key）
    uint16_t              port      = 8080;
    int                   ctxSize   = 8192; // ⚠ 不可為 4096（SDD-03 §7.2.2：prompt 3400 + n_predict 512 會 overflow）
    int                   gpuLayers = 999;  // 無獨顯時設 0（Check-Prereqs 依 VRAM 決定）
    int                   threads   = 0;    // 0 = llama-server 自行決定
    std::chrono::seconds  idleUnload{300};
    std::chrono::seconds  healthTimeout{60};   // 冷啟動含模型載入
    int                   maxRestartsPerHour = 3;
    uint64_t              processMemoryLimitBytes = 6ull << 30;   // Job 記憶體保險絲 6 GB
    uint64_t              minModelBytes = 100ull << 20;           // 小於此視為模型檔損毀
};

class LlamaServerSupervisor {
public:
    // 不因檔案缺失而失敗：缺失時物件照常建立但狀態為 Unavailable（health.get 才能顯示原因）。
    [[nodiscard]] static Result<std::unique_ptr<LlamaServerSupervisor>> Create(SupervisorConfig cfg);
    ~LlamaServerSupervisor();
    LlamaServerSupervisor(const LlamaServerSupervisor&)            = delete;
    LlamaServerSupervisor& operator=(const LlamaServerSupervisor&) = delete;

    // T5：每次推論前呼叫。已 Running 則立即返回；需冷啟動時最長阻塞 healthTimeout。
    // 失敗回傳 ErrorCode::LlmUnavailable（context 說明原因：disabled / missing / backoff / restart-limit / health-timeout）。
    // cancel 被觸發（LlmWorker::Stop）時中止冷啟動等待並回傳 ErrorCode::Cancelled——否則服務停止時
    // T5 會卡在 /health 輪詢最長 healthTimeout（ServiceHost 先停 LlmWorker、後呼叫 Shutdown）。
    [[nodiscard]] Status EnsureRunning(std::stop_token cancel = {});

    // T5：推論成功後呼叫，更新閒置計時基準。
    void NotifyActivity() noexcept;

    // T5：推論遇到連線層錯誤時呼叫。若子程序已死 → 退避／終局。
    void ReportConnectionFailure();

    // T8（每 ≤ 30 秒）：偵測子程序意外結束、閒置卸載。使用 try_lock，絕不阻塞 Watchdog。
    void Tick();

    // UI「手動重啟本機 AI」：清除重啟歷史並離開 Unavailable（檔案仍缺失則維持 Unavailable）。
    void RequestManualRestart();

    // 服務停止：中止冷啟動等待、關閉 Job（核心終止子程序）、回收讀取執行緒。冪等。
    void Shutdown() noexcept;

    [[nodiscard]] SupervisorState State() const noexcept { return m_state.load(std::memory_order_acquire); }
    [[nodiscard]] std::string     StateReason() const;
    [[nodiscard]] std::string     ModelId() const;        // 模型 SHA256 前 16 碼；尚未計算時為空
    [[nodiscard]] std::string     ApiKey() const;         // 目前子程序的 API key（Authorization: Bearer）
    [[nodiscard]] uint16_t        Port() const noexcept { return m_cfg.port; }
    [[nodiscard]] int             RestartsLastHour() const;

private:
    explicit LlamaServerSupervisor(SupervisorConfig cfg) : m_cfg(std::move(cfg)) {}

    bool   PreflightLocked();                    // 檔案存在性；失敗 → Unavailable
    Status SpawnLocked();                        // Job → 子程序 → 管線讀取執行緒
    bool   WaitForHealthyLocked(std::stop_token cancel);   // 輪詢 /health
    void   KillLocked() noexcept;                // 關閉 Job、等待結束、回收讀取執行緒
    void   OnCrashLocked(const char* why);       // 記錄重啟並進入 Backoff / Unavailable
    bool   ProcessExitedLocked() const noexcept;
    Status EnsureModelIdLocked();
    Status WriteApiKeyFileLocked();
    std::wstring BuildCommandLine() const;
    void   SetState(SupervisorState s, std::string reason);

    SupervisorConfig            m_cfg;
    // m_mutex：生命週期操作（可能被冷啟動持有長達 healthTimeout）
    // m_infoMutex：只保護下列「給查詢用」的小欄位，讓 health.get / Status() 永不被冷啟動阻塞。
    //   取鎖順序：m_mutex → m_infoMutex（反向禁止）
    mutable std::mutex          m_mutex;
    mutable std::mutex          m_infoMutex;
    std::atomic<SupervisorState> m_state{SupervisorState::Stopped};
    std::string                 m_reason;          // m_infoMutex
    std::atomic<bool>           m_shutdown{false};

    wil::unique_handle          m_job;
    wil::unique_handle          m_process;
    wil::unique_handle          m_stdoutRead;
    std::thread                 m_pumpThread;

    std::deque<std::chrono::steady_clock::time_point> m_restarts;   // 滑動 1 小時視窗（m_infoMutex）
    std::chrono::steady_clock::time_point m_backoffUntil{};
    std::atomic<int64_t>        m_lastActivityMs{0};                // steady 毫秒

    std::string                 m_apiKey;          // m_infoMutex
    std::filesystem::path       m_apiKeyFile;
    std::string                 m_modelId;         // m_infoMutex
};

} // namespace cairn::llm
