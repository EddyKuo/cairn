// src/svc/host/HandlerContext.h               namespace cairn::host
// RPC handlers 的相依。刻意可攜（不含 windows.h）：handler 只做「參數解析 → 呼叫模組 API → 轉成 UI 契約 JSON」，
// 所有需要 Win32 的事（健康度取樣、規則熱重載、LLM 狀態）都經 IHostServices 由 ServiceHost 提供。
//
// 回應形狀的權威：ui-web/src/lib/types.ts（part3 §3.8）。
//   - ID 一律以字串傳入（alert_id / audit_id / exclusion_id / suggestion_id / rule_id / undo_token）
//   - 分數一律 0–100 整數（milli-point ÷ 1000 四捨五入）
//   - 時間一律 RFC3339 UTC 毫秒
//   - result 物件可帶 "_http_status" 覆寫 HTTP 狀態（ApiBridge 回給前端前會移除）
//   - 錯誤：data = {code, http?, details?}
#pragma once
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "base/IClock.h"
#include "base/Result.h"
#include "model/NarrativeTypes.h"
#include "model/WriteOp.h"
#include "rules/RuleLoader.h"

namespace cairn::store {
class ReadOnlyDb;
}
namespace cairn::response {
class ResponseExecutor;
class ConfirmationTokenStore;
} // namespace cairn::response

namespace cairn::host {

class AnalysisTasks;
class HostState;
struct HostConfig;

// ---- 由 ServiceHost 提供的即時狀態（health.get）----
struct LiveHealth {
    int64_t     startedMs = 0;
    std::string hostname;
    std::string serviceVersion = "0.1.0";
    struct Provider {
        std::string name;    // sysmon | powershell | security
        std::string state;   // healthy | silent | reconnecting | failed | stopped
    };
    std::vector<Provider> providers;
    bool        sysmonInstalled = false;
    std::string sysmonVersion;
    std::string sysmonState = "missing";   // ok | outdated | missing
    std::string llmState    = "unavailable";
    std::string llmModelId;
    std::string llmDevice;
    std::string llmDetail;
    double      llmP95Ms = 0;
    double      cpuP95Percent = 0;
    double      ramMb = 0;
    double      diskMb = 0;
    double      eventsPerSec = 0;
    double      dropRate = 0;               // 最近取樣區間 dropped / (ingested + dropped)
    uint64_t    droppedByPriority[4]{};     // Critical, High, Normal, Low（累計）
    double      tier2P95Ms = 0;
    bool        degraded = false;
    std::vector<std::string> degradedReasons;
    struct Anomaly {
        int64_t     ts = 0;
        std::string message;
    };
    std::vector<Anomaly> anomalies24h;
    int         unexpectedTerminations30d = 0;
};

class IHostServices {
public:
    virtual ~IHostServices() = default;

    [[nodiscard]] virtual LiveHealth Health() = 0;

    // 最近一次規則載入報告（rules.list 的中繼資料）
    [[nodiscard]] virtual std::vector<rules::RuleInfo> RuleInfos() = 0;
    // rules.setStatus：持久化覆寫 → 重新載入規則 → 在 AnalysisThread 上 ReplaceRuleSet
    [[nodiscard]] virtual Result<rules::RuleInfo> SetRuleStatus(const std::string& ruleId, model::RuleStatus s) = 0;

    // 從 DB 重讀 exclusions（+ 內建 YAML）並在 AnalysisThread 上 ReplaceExclusions。寫入已提交後才呼叫。
    [[nodiscard]] virtual Status ReloadExclusions() = 0;

    // narrative.regenerate：交給 LlmWorker。回傳是否被接受。
    [[nodiscard]] virtual bool EnqueueNarrative(const model::NarrativeRequest& req, bool reducedContext) = 0;

    // protection.pause / resume；learning.finish（同步套用到引擎與持久狀態）
    [[nodiscard]] virtual Status SetProtectionPaused(bool paused, int64_t untilMs, const std::string& reason) = 0;
    [[nodiscard]] virtual Status FinishLearning() = 0;
};

// ---- undo token（verdict / exclusions.add / L1 suspend 的「復原」按鈕）----
struct UndoEntry {
    enum class Kind { RemoveExclusion, RevertAction };
    Kind        kind = Kind::RemoveExclusion;
    int64_t     exclusionId = 0;
    std::string actionId;
    int64_t     alertId = 0;
    int64_t     expiresAt = 0;
};

class UndoStore {
public:
    explicit UndoStore(const IClock& clock, std::chrono::seconds ttl = std::chrono::seconds{30})
        : m_clock(clock), m_ttl(ttl) {}

    // 回傳 token 與到期時間（Unix ms）
    std::pair<std::string, int64_t> Issue(UndoEntry e, const std::string& token);
    [[nodiscard]] std::optional<UndoEntry> Take(const std::string& token);   // 一次性
    void Sweep();
    [[nodiscard]] std::chrono::seconds Ttl() const noexcept { return m_ttl; }

private:
    const IClock&        m_clock;
    std::chrono::seconds m_ttl;
    std::mutex           m_mutex;
    std::unordered_map<std::string, UndoEntry> m_entries;
};

struct HandlerDeps {
    IHostServices*                    host      = nullptr;   // 必填
    model::IWriteSink*                writes    = nullptr;   // 必填
    response::ResponseExecutor*       responses = nullptr;   // 可為空（回應模組啟動失敗）
    AnalysisTasks*                    analysis  = nullptr;   // 必填
    HostState*                        state     = nullptr;   // 必填
    const HostConfig*                 config    = nullptr;   // 必填
    const IClock*                     clock     = nullptr;   // 必填
    response::ConfirmationTokenStore* tokens    = nullptr;   // protection.pause / response.revert 的確認 token
    UndoStore*                        undo      = nullptr;
    // 每個 RPC worker 執行緒自有的唯讀連線（thread_local，由 ServiceHost 實作）
    std::function<store::ReadOnlyDb*()> reader;
    // 產生不可預測的 token 字串（BCryptGenRandom；測試可注入）
    std::function<std::string()> newToken;
    std::chrono::milliseconds analysisTimeout{2000};
    std::chrono::milliseconds writeTimeout{5000};
};

} // namespace cairn::host
