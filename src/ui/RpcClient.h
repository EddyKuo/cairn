// RpcClient.h —— Named Pipe JSON-RPC 2.0 客戶端（SDD-03 §9.1 / §9.4.2 / §9.5.1）
//   管線：\\.\pipe\Cairn\rpc；框架：4-byte little-endian 長度前綴 + UTF-8 JSON；單一訊息上限 1 MiB
//   執行緒：any（內部 mutex 序列化；一條連線同時只有一個請求在途）
//   本類別自行實作框架編解碼，不依賴 svc 的程式碼（ui.host 只依賴 core.common）。
#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace cairn::ui {

// 連線狀態機（SDD-03 §9.5.1）
enum class LinkState : uint8_t {
    Connecting,
    Connected,
    Degraded,     // 連續 2 次逾時
    Retrying,     // 退避中：1s,2s,4s,8s,15s,30s(封頂)
    ServiceGone,  // 累計失敗 > 20 次且 SCM 回報服務未執行
};

const wchar_t* LinkStateName(LinkState s) noexcept;

struct RpcOutcome {
    enum class Kind : uint8_t {
        Ok,
        RpcError,   // 伺服器回傳 JSON-RPC error 物件
        LinkDown,   // 管線無法連線／已斷開／退避中（對外一律 SERVICE_UNAVAILABLE）
        Timeout,    // 超過呼叫逾時（對外 RPC_TIMEOUT）
        Protocol,   // 回應格式錯誤、id 不符、訊息過大
    };
    Kind           kind = Kind::LinkDown;
    nlohmann::json result;       // Kind::Ok
    int            code = 0;     // Kind::RpcError：JSON-RPC 數值碼
    std::string    message;
    nlohmann::json data;         // Kind::RpcError：error.data（含業務碼 code / http / details）

    [[nodiscard]] bool Ok() const noexcept { return kind == Kind::Ok; }
};

class RpcClient {
public:
    static constexpr uint32_t kMaxMessageBytes = 1u << 20;   // 1 MiB（SDD-03 §9.4.2）

    RpcClient();
    ~RpcClient();
    RpcClient(const RpcClient&)            = delete;
    RpcClient& operator=(const RpcClient&) = delete;

    // 阻塞呼叫。可由任意執行緒呼叫；UI 執行緒絕不可直接呼叫（WebView2 回呼以 deferral 轉到背景）。
    [[nodiscard]] RpcOutcome Call(const std::string& method, const nlohmann::json& params,
                                  std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    [[nodiscard]] LinkState State() const noexcept { return m_state.load(); }
    [[nodiscard]] int ConsecutiveFailures() const noexcept { return m_consecutiveFailures.load(); }

    // 使用者按「重新連線」：清除退避與 ServiceGone，下一次 Call 立即嘗試。
    void ResetBackoff();

    // 框架編解碼（純函式，供單元測試與 DevHttp 共用）
    static std::string EncodeFrame(const std::string& payload);
    // 回傳負值表示需要更多資料；回傳 -2 表示長度超限。
    static int64_t DecodeLength(const unsigned char header[4]) noexcept;

private:
    bool EnsureConnectedLocked(std::chrono::milliseconds timeout);
    void DisconnectLocked() noexcept;
    bool WriteAllLocked(const void* data, uint32_t len, std::chrono::milliseconds timeout);
    bool ReadAllLocked(void* data, uint32_t len, std::chrono::milliseconds timeout, bool* timedOut);
    void NoteFailure(bool timeout);
    void NoteSuccess();
    bool QueryServiceRunning() const noexcept;

    std::mutex            m_mutex;
    HANDLE                m_pipe = INVALID_HANDLE_VALUE;
    HANDLE                m_ioEvent = nullptr;
    std::atomic<int64_t>  m_nextId{1};
    std::atomic<LinkState> m_state{LinkState::Connecting};
    std::atomic<int>      m_consecutiveFailures{0};
    int                   m_consecutiveTimeouts = 0;
    int                   m_totalFailures = 0;
    int                   m_backoffIndex = 0;
    std::chrono::steady_clock::time_point m_retryAt{};
};

} // namespace cairn::ui
