// src/svc/response/ResponseExecutor.h         namespace cairn::response
// T6 回應執行器（SDD-03 §8.1 / §8.3 / §8.5、part2 §2.7、part4 W3-1）。標頭可攜（pimpl）。
//
// 執行緒模型：
//   - 專屬 ResponseThread（T6），啟動時 CoInitializeEx(COINIT_APARTMENTTHREADED)
//     （INetFwPolicy2 的 COM 指標與 CNG 檔案 I/O 一律只在 T6 上使用）
//   - 公開方法可由任意執行緒呼叫：同步方法把工作投遞到 T6 並等待結果；
//     Submit()（自動回應，實作 model::IResponseSink）非阻塞，AnalysisThread 可直接呼叫
//   - 動作頻率極低（每小時個位數），序列化的代價為零
//
// 寫入：一律經 model::IWriteSink（T4 是唯一寫者）——
//   AuditRow（action_started / action_completed / action_reverted，params 內含 event_kind 等）、
//   AlertActionAppend（alerts.actions_taken）、ProcessTerminatedByUs（process_tree.is_terminated_by_us）
//
// revert 的鍵：Execute 同步回傳 actionId（"ACT-4821-03"）；audit_log.id 由 WriterThread 非同步配發，
//   以 WriteOp::onDone 取得後回填 ActionRecord（並在 Execute 內最多等待 auditIdWait 讓回應帶上 audit id）。
//   Revert 接受 actionId 或 audit id。
#pragma once
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/IClock.h"
#include "base/Result.h"
#include "model/ResponseCommand.h"
#include "model/WriteOp.h"
#include "response/ResponseTypes.h"

namespace cairn::response {

struct ResponseExecutorConfig {
    std::filesystem::path     dataDir;                      // %ProgramData%\Cairn（其下建立 actions\ 與 quarantine\）
    std::chrono::seconds      tokenTtl{60};                 // part3 §3.8.4
    size_t                    maxTokens = 64;               // SDD-03 §8.3.2
    size_t                    queueCapacity = 256;
    size_t                    maxPendingAutomatic = 256;
    bool                      applyVaultAcl = true;         // 測試以非管理員執行時設 false
    std::chrono::milliseconds auditIdWait{2000};
    std::chrono::milliseconds syncCallTimeout{120'000};     // 終止大型程序樹含逐一等待 2 秒
    std::chrono::milliseconds automaticCoalesce{50};        // 同告警多動作的聚合窗口（以便依序執行）
    bool                      cleanupOrphanFirewallRules = true;
};

struct ExecutorStats {
    uint64_t prepared = 0;
    uint64_t executed = 0;
    uint64_t automaticExecuted = 0;
    uint64_t automaticDropped = 0;   // 自動回應佇列滿而丟棄
    uint64_t rejected = 0;
    uint64_t reverted = 0;
    size_t   pendingTokens = 0;
};

class ResponseExecutor final : public model::IResponseSink {
public:
    // writes 可為 nullptr（測試）；clock 必須長於本物件。
    [[nodiscard]] static Result<std::unique_ptr<ResponseExecutor>>
        Create(ResponseExecutorConfig cfg, model::IWriteSink* writes, const IClock* clock);

    ~ResponseExecutor() override;
    ResponseExecutor(const ResponseExecutor&) = delete;
    ResponseExecutor& operator=(const ResponseExecutor&) = delete;

    // 啟動 T6；動作初始化失敗（例如 ntdll 解析不到）不致命，該動作改回報失敗。
    [[nodiscard]] Status Start();
    // 冪等。停止接收新工作；佇列中尚未執行者回 SERVICE_STOPPING；等待 T6 結束。
    void Stop() noexcept;

    // ---- 兩階段協定（任意執行緒）----
    // 無副作用；回傳影響清單 + confirmation token（L1 也發，但 L1 執行時不強制帶回）。
    [[nodiscard]] Result<PrepareResponse> Prepare(int64_t alertId, model::ActionKind action,
                                                  const model::ResponseTarget& target,
                                                  const std::string& peerSid = {});
    // 拒絕時回傳 Error，context 為 API 碼（見 ResponseJson.h 的 RejectInfoOf）。
    // 執行後即使全部目標失敗也回傳 ExecuteResponse（status=Failed → HTTP 502）。
    [[nodiscard]] Result<ExecuteResponse> Execute(const ExecuteRequest& req);
    [[nodiscard]] Result<RevertResponse> Revert(const RevertRequest& req);

    // ---- 自動回應（AnalysisThread，非阻塞）----
    // 依 §8.5.1 的順序執行同一告警的多個動作；不需 token（觸發條件由 AnalysisEngine 把關：
    // 分數 >= 95 或規則 deterministic: true）。
    void Submit(model::ResponseCommand&& cmd) override;

    // ---- 查詢（任意執行緒）----
    [[nodiscard]] Result<std::vector<QuarantineEntry>> ListQuarantine();
    [[nodiscard]] Result<std::vector<ActionRecord>> ListActions(std::optional<int64_t> alertId = std::nullopt);

    // 由 Watchdog 每 60 秒呼叫（T6 內部亦會定期清理）
    void SweepExpiredTokens();
    [[nodiscard]] ExecutorStats Stats() const;

private:
    struct Impl;
    explicit ResponseExecutor(std::unique_ptr<Impl> impl);
    std::unique_ptr<Impl> m_impl;
};

// 目標鍵（token 綁定用）：target.key 非空則用之；否則依動作推導
//   程序類 → 根程序的 ProcessKey；quarantine → "file:<小寫路徑>"；firewall → "ip:<ip>"
[[nodiscard]] std::string TargetKeyOf(model::ActionKind action, const model::ResponseTarget& target);

} // namespace cairn::response
