// src/svc/telemetry/EvtChannelSource.h        namespace cairn::telemetry
// Windows Event Log 通道訂閱（EvtSubscribe push 模式），實作 IEventSource。
// 同一個類別以三組設定實例化：Sysmon/Operational、PowerShell/Operational（4104）、Security（4688）。
// 設計依據：part2 §2.2.3、SDD-01 §3.2.2–3.2.3、§3.6。
//
// 回呼（OS 執行緒，可重入、可併發）三條禁令：
//   1. 不得阻塞 —— 只做 EvtRender + UTF-16→UTF-8 + Push；所有鎖一律 Try*，取不到就跳過
//   2. 不得重入 Event Log 訂閱 API（EvtSubscribe / EvtClose(訂閱)）—— 重訂閱交給 Watchdog
//   3. 不得保存 hEvent —— 回呼返回後 OS 即關閉它
//
// 書籤：回呼執行緒以 TryAcquireSRWLockExclusive 更新 EVT_HANDLE 書籤；每 1,000 事件或 5 秒渲染成 XML
//       字串暫存。維護執行緒呼叫 PersistBookmark() 取走字串寫檔（永不觸碰 EVT_HANDLE 以外的書籤狀態）。
#pragma once
#ifndef _WIN32
#error "EvtChannelSource 僅支援 Windows"
#endif

#include <windows.h>
#include <winevt.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>

#include "base/IEventSource.h"
#include "telemetry/BookmarkStore.h"

namespace cairn::telemetry {

// wil 沒有內建 EVT_HANDLE 的 RAII，自行定義（SDD-01 §3.2.2）。
struct EvtHandleDeleter {
    void operator()(EVT_HANDLE h) const noexcept
    {
        if (h) ::EvtClose(h);
    }
};
using UniqueEvtHandle = std::unique_ptr<std::remove_pointer_t<EVT_HANDLE>, EvtHandleDeleter>;

class EvtChannelSource final : public IEventSource {
public:
    struct Config {
        std::string            name;          // "sysmon" | "powershell" | "security"（書籤檔名、健康度顯示）
        model::EventSourceKind kind = model::EventSourceKind::Sysmon;
        std::wstring           channel;       // L"Microsoft-Windows-Sysmon/Operational"
        std::wstring           xpathQuery;    // 在 OS 層過濾，別把不要的事件收進來
        BookmarkStore*         bookmarks = nullptr;   // 非擁有；nullptr = 不持久化書籤
        bool     startAtOldestWithoutBookmark = false; // 無書籤時是否補讀既有事件（預設只收新事件）
        int64_t  silentThresholdMs     = 120'000;      // part2 §2.2.3 silence_timeout
        uint32_t maxReconnectAttempts  = 10;           // SDD-01 §3.6：重試 10 次仍失敗 → Failed
        uint32_t bookmarkRenderEvery   = 1'000;        // 每 N 事件渲染一次書籤 XML
        int64_t  bookmarkRenderEveryMs = 5'000;        // 或每 5 秒
    };

    // 三個預設設定（xpath 與 part2 §2.2.1 的 EID 清單一致）
    [[nodiscard]] static Config SysmonConfig(BookmarkStore* bookmarks);
    [[nodiscard]] static Config PowerShellConfig(BookmarkStore* bookmarks);
    [[nodiscard]] static Config SecurityConfig(BookmarkStore* bookmarks);

    [[nodiscard]] static Result<std::unique_ptr<EvtChannelSource>> Create(Config cfg);

    ~EvtChannelSource() override;
    EvtChannelSource(const EvtChannelSource&) = delete;
    EvtChannelSource& operator=(const EvtChannelSource&) = delete;

    // ---- IEventSource ----
    // 通道不存在時：Sysmon 回 SysmonNotInstalled，其餘回 ChannelNotFound（win32 = 15007）。
    [[nodiscard]] Status Start(IRawEventSink* sink) override;
    void Stop() noexcept override;
    [[nodiscard]] SourceHealth GetHealth() const noexcept override;
    [[nodiscard]] std::string_view Name() const noexcept override { return m_cfg.name; }
    [[nodiscard]] int64_t LastEventSteadyMs() const noexcept override { return m_lastEventSteadyMs.load(std::memory_order_relaxed); }
    // 由 Watchdog（T8）以指數退避呼叫；絕不可在回呼中呼叫。
    [[nodiscard]] Status Resubscribe() override;

    // ---- 維護執行緒介面 ----
    // 把回呼渲染好的最新書籤 XML 寫檔。每 5 秒由 Watchdog 呼叫；Stop() 也會在最後呼叫一次。
    void PersistBookmark() noexcept;
    // 書籤失效（通道被清空 / 輪替過快）時置位；Watchdog 取走後產生 channel_cleared 健康度告警。
    [[nodiscard]] bool TakeChannelClearedFlag() noexcept { return m_channelCleared.exchange(false); }
    [[nodiscard]] uint64_t RenderFailures() const noexcept { return m_renderFailures.load(std::memory_order_relaxed); }
    [[nodiscard]] uint64_t EventCount() const noexcept { return m_eventCount.load(std::memory_order_relaxed); }
    [[nodiscard]] uint32_t ReconnectAttempts() const noexcept { return m_reconnectAttempts.load(std::memory_order_relaxed); }
    [[nodiscard]] DWORD LastSubscriptionError() const noexcept { return m_lastError.load(std::memory_order_relaxed); }

private:
    explicit EvtChannelSource(Config cfg) noexcept;

    static DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext,
                                             EVT_HANDLE hEvent) noexcept;
    DWORD HandleEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) noexcept;
    void  UpdateBookmark(EVT_HANDLE hEvent) noexcept;
    [[nodiscard]] std::string RenderBookmarkXml() noexcept;   // 呼叫端須持有 m_bookmarkLock（exclusive）

    [[nodiscard]] Status Subscribe();
    void CloseSubscriptionAndWait() noexcept;

    Config          m_cfg;
    IRawEventSink*  m_sink = nullptr;     // 非擁有
    std::mutex      m_ctrlMutex;          // 序列化 Start / Stop / Resubscribe（控制執行緒間）
    UniqueEvtHandle m_subscription;

    // 書籤：EVT_HANDLE 只在持有 m_bookmarkLock（exclusive）時操作
    SRWLOCK         m_bookmarkLock = SRWLOCK_INIT;
    UniqueEvtHandle m_bookmark;
    bool            m_bookmarkHasPosition = false;   // 書籤是否已指向某筆事件（載入或更新過）
    uint32_t        m_sinceRender = 0;
    int64_t         m_lastRenderSteadyMs = 0;
    std::string     m_pendingBookmarkXml;            // 待落地的最新書籤（受 m_bookmarkLock 保護）

    // in-flight 回呼：回呼取 shared（Try），Stop / Resubscribe 取 exclusive 等待歸零
    SRWLOCK         m_inflightLock = SRWLOCK_INIT;

    std::atomic<bool>         m_stopping{false};
    std::atomic<SourceHealth> m_health{SourceHealth::Stopped};
    std::atomic<uint64_t>     m_eventCount{0};
    std::atomic<uint64_t>     m_renderFailures{0};
    std::atomic<int64_t>      m_lastEventSteadyMs{0};
    std::atomic<int64_t>      m_startedSteadyMs{0};
    std::atomic<uint32_t>     m_reconnectAttempts{0};
    std::atomic<DWORD>        m_lastError{ERROR_SUCCESS};
    std::atomic<bool>         m_channelCleared{false};
};

} // namespace cairn::telemetry
