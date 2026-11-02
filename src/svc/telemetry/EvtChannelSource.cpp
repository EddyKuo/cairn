#include "telemetry/EvtChannelSource.h"

#include <chrono>
#include <vector>

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "telemetry/EventXml.h"

#pragma comment(lib, "wevtapi.lib")

namespace cairn::telemetry {

namespace {

int64_t SteadyNowMs() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// 不可恢復：通道根本不存在（Sysmon 被移除）。其餘一律視為可恢復，交給 Watchdog 退避重試。
bool IsUnrecoverable(DWORD status) noexcept
{
    return status == ERROR_EVT_CHANNEL_NOT_FOUND || status == ERROR_EVT_INVALID_CHANNEL_PATH ||
           status == ERROR_EVT_INVALID_QUERY;
}

// 書籤指向的事件已不存在（通道被清空 / 輪替過快）。
bool IsStaleBookmark(DWORD status) noexcept
{
    return status == ERROR_NOT_FOUND || status == ERROR_EVT_QUERY_RESULT_STALE ||
           status == ERROR_EVT_QUERY_RESULT_INVALID_POSITION;
}

} // namespace

// ------------------------------------------------------------------ 預設設定

EvtChannelSource::Config EvtChannelSource::SysmonConfig(BookmarkStore* bookmarks)
{
    Config c;
    c.name    = "sysmon";
    c.kind    = model::EventSourceKind::Sysmon;
    c.channel = L"Microsoft-Windows-Sysmon/Operational";
    // part2 §2.2.1 啟用的 EID；在 OS 層過濾，避免白付 EvtRender 的序列化成本
    c.xpathQuery =
        L"*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=7 or EventID=8 or EventID=10 or "
        L"EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=15 or EventID=17 or "
        L"EventID=18 or EventID=22 or EventID=23 or EventID=25 or EventID=26)]]";
    c.bookmarks = bookmarks;
    return c;
}

EvtChannelSource::Config EvtChannelSource::PowerShellConfig(BookmarkStore* bookmarks)
{
    Config c;
    c.name       = "powershell";
    c.kind       = model::EventSourceKind::PowerShell;
    c.channel    = L"Microsoft-Windows-PowerShell/Operational";
    c.xpathQuery = L"*[System[(EventID=4104)]]";
    c.bookmarks  = bookmarks;
    // PowerShell 通道在閒置機器上可能數小時無事件 —— 靜默不代表失效，放寬門檻
    c.silentThresholdMs = 24LL * 3600 * 1000;
    return c;
}

EvtChannelSource::Config EvtChannelSource::SecurityConfig(BookmarkStore* bookmarks)
{
    Config c;
    c.name       = "security";
    c.kind       = model::EventSourceKind::SecurityLog;
    c.channel    = L"Security";
    c.xpathQuery = L"*[System[(EventID=4688)]]";
    c.bookmarks  = bookmarks;
    return c;
}

// ------------------------------------------------------------------ 建立 / 解構

EvtChannelSource::EvtChannelSource(Config cfg) noexcept : m_cfg(std::move(cfg)) {}

Result<std::unique_ptr<EvtChannelSource>> EvtChannelSource::Create(Config cfg)
{
    if (cfg.channel.empty() || cfg.xpathQuery.empty())
        return MakeError(ErrorCode::InvalidArgument, "EvtChannelSource: empty channel/query");

    auto self = std::unique_ptr<EvtChannelSource>(new EvtChannelSource(std::move(cfg)));

    // 書籤：有落地檔則還原（重啟續讀），否則建立空書籤
    std::optional<std::string> saved;
    if (self->m_cfg.bookmarks) saved = self->m_cfg.bookmarks->Load(self->m_cfg.name);
    if (saved) {
        const std::wstring wxml = svc::Utf8ToWide(*saved);
        self->m_bookmark.reset(::EvtCreateBookmark(wxml.c_str()));
        if (self->m_bookmark) {
            self->m_bookmarkHasPosition = true;
        } else {
            spdlog::warn("[{}] 書籤檔損毀（{}），改由新事件開始", self->m_cfg.name, ::GetLastError());
            if (self->m_cfg.bookmarks) self->m_cfg.bookmarks->Remove(self->m_cfg.name);
        }
    }
    if (!self->m_bookmark) {
        self->m_bookmark.reset(::EvtCreateBookmark(nullptr));
        if (!self->m_bookmark) return svc::Win32Error(ErrorCode::SubscribeFailed, "EvtCreateBookmark");
    }
    return self;
}

EvtChannelSource::~EvtChannelSource()
{
    Stop();
}

// ------------------------------------------------------------------ 訂閱控制

Status EvtChannelSource::Start(IRawEventSink* sink)
{
    if (!sink) return MakeError(ErrorCode::InvalidArgument, "EvtChannelSource::Start: null sink");
    std::lock_guard lk{m_ctrlMutex};
    if (m_subscription) return MakeError(ErrorCode::AlreadyExists, "EvtChannelSource already started");
    m_sink = sink;
    m_stopping.store(false, std::memory_order_release);
    m_startedSteadyMs.store(SteadyNowMs(), std::memory_order_relaxed);
    Status st = Subscribe();
    if (st) {
        m_health.store(SourceHealth::Healthy, std::memory_order_release);
        m_reconnectAttempts.store(0, std::memory_order_relaxed);
    } else {
        m_health.store(SourceHealth::Failed, std::memory_order_release);
    }
    return st;
}

Status EvtChannelSource::Subscribe()
{
    // 呼叫端持有 m_ctrlMutex，且沒有任何 in-flight 回呼（舊訂閱已關閉並等待完畢）。
    auto subscribeWith = [this](DWORD flags, EVT_HANDLE bookmark) -> EVT_HANDLE {
        return ::EvtSubscribe(/*session*/ nullptr, /*signal*/ nullptr, m_cfg.channel.c_str(),
                              m_cfg.xpathQuery.c_str(), bookmark, this, &EvtChannelSource::SubscriptionCallback,
                              flags);
    };

    EVT_HANDLE h = nullptr;
    if (m_bookmarkHasPosition) {
        // ★ Strict：書籤指向的事件不存在時直接失敗，而不是默默從頭或從尾開始 —— 才能偵測到通道被清空
        h = subscribeWith(EvtSubscribeStartAfterBookmark | EvtSubscribeStrict, m_bookmark.get());
        if (!h) {
            const DWORD err = ::GetLastError();
            if (!IsStaleBookmark(err) && !IsUnrecoverable(err)) {
                m_lastError.store(err, std::memory_order_relaxed);
                return svc::Win32Error(ErrorCode::SubscribeFailed, "EvtSubscribe(after bookmark)", err);
            }
            if (IsStaleBookmark(err)) {
                // 通道被清空（wevtutil cl 是攻擊者反鑑識手法）或輪替過快：期間事件確定遺失
                spdlog::warn("[{}] 書籤失效（{}），通道可能已被清空；改由新事件開始", m_cfg.name, err);
                m_channelCleared.store(true, std::memory_order_release);
                AcquireSRWLockExclusive(&m_bookmarkLock);
                m_bookmark.reset(::EvtCreateBookmark(nullptr));
                m_bookmarkHasPosition = false;
                m_pendingBookmarkXml.clear();
                ReleaseSRWLockExclusive(&m_bookmarkLock);
                if (m_cfg.bookmarks) m_cfg.bookmarks->Remove(m_cfg.name);
            } else {
                m_lastError.store(err, std::memory_order_relaxed);
                return MakeWin32Error(m_cfg.kind == model::EventSourceKind::Sysmon ? ErrorCode::SysmonNotInstalled
                                                                                    : ErrorCode::ChannelNotFound,
                                      err, "EvtSubscribe: channel not found");
            }
        }
    }
    if (!h) {
        const DWORD flags = m_cfg.startAtOldestWithoutBookmark ? EvtSubscribeStartAtOldestRecord
                                                               : EvtSubscribeToFutureEvents;
        h = subscribeWith(flags, nullptr);
        if (!h) {
            const DWORD err = ::GetLastError();
            m_lastError.store(err, std::memory_order_relaxed);
            if (err == ERROR_EVT_CHANNEL_NOT_FOUND || err == ERROR_EVT_INVALID_CHANNEL_PATH) {
                return MakeWin32Error(m_cfg.kind == model::EventSourceKind::Sysmon ? ErrorCode::SysmonNotInstalled
                                                                                    : ErrorCode::ChannelNotFound,
                                      err, "EvtSubscribe: channel not found");
            }
            return svc::Win32Error(ErrorCode::SubscribeFailed, "EvtSubscribe", err);
        }
    }
    m_subscription.reset(h);
    m_lastError.store(ERROR_SUCCESS, std::memory_order_relaxed);
    spdlog::info("[{}] 訂閱成功（bookmark={}）", m_cfg.name, m_bookmarkHasPosition);
    return Ok();
}

void EvtChannelSource::CloseSubscriptionAndWait() noexcept
{
    // 1) EvtClose 訂閱（不在回呼中呼叫 —— 呼叫端是控制執行緒）
    m_subscription.reset();
    // 2) 等待所有 in-flight 回呼結束：回呼持有 shared，此處取 exclusive 即代表歸零。
    //    wevtapi 不保證 EvtClose 之後回呼不再被呼叫（SDD-01 §3.2.1 的 ⚠），所以這一步不可省。
    AcquireSRWLockExclusive(&m_inflightLock);
    ReleaseSRWLockExclusive(&m_inflightLock);
}

void EvtChannelSource::Stop() noexcept
{
    std::lock_guard lk{m_ctrlMutex};
    if (m_stopping.exchange(true, std::memory_order_acq_rel) && !m_subscription) return;
    CloseSubscriptionAndWait();
    m_health.store(SourceHealth::Stopped, std::memory_order_release);
    // 此後不會再有回呼：渲染最終書籤並落地（服務重啟後由此續讀）
    AcquireSRWLockExclusive(&m_bookmarkLock);
    if (m_bookmarkHasPosition) m_pendingBookmarkXml = RenderBookmarkXml();
    ReleaseSRWLockExclusive(&m_bookmarkLock);
    PersistBookmark();
}

Status EvtChannelSource::Resubscribe()
{
    std::lock_guard lk{m_ctrlMutex};
    if (!m_sink) return MakeError(ErrorCode::NotInitialized, "Resubscribe before Start");
    if (m_stopping.load(std::memory_order_acquire) && !m_subscription && m_health.load() == SourceHealth::Stopped)
        return MakeError(ErrorCode::Cancelled, "source stopped");

    const uint32_t attempt = m_reconnectAttempts.fetch_add(1, std::memory_order_relaxed) + 1;
    m_health.store(SourceHealth::Reconnecting, std::memory_order_release);

    // 關閉舊訂閱時暫時擋住回呼推送，避免與新訂閱重疊投遞（重疊只會造成重複，但仍避免）
    m_stopping.store(true, std::memory_order_release);
    CloseSubscriptionAndWait();
    m_stopping.store(false, std::memory_order_release);

    Status st = Subscribe();
    if (st) {
        m_reconnectAttempts.store(0, std::memory_order_relaxed);
        m_health.store(SourceHealth::Healthy, std::memory_order_release);
        m_startedSteadyMs.store(SteadyNowMs(), std::memory_order_relaxed);
        spdlog::info("[{}] 重訂閱成功（第 {} 次嘗試）", m_cfg.name, attempt);
        return st;
    }
    spdlog::warn("[{}] 重訂閱失敗（第 {} 次）：{}", m_cfg.name, attempt, st.GetError().ToString());
    m_health.store(attempt >= m_cfg.maxReconnectAttempts ? SourceHealth::Failed : SourceHealth::Reconnecting,
                   std::memory_order_release);
    return st;
}

SourceHealth EvtChannelSource::GetHealth() const noexcept
{
    const SourceHealth h = m_health.load(std::memory_order_acquire);
    if (h != SourceHealth::Healthy) return h;
    // 訂閱成功不代表有事件在流（Sysmon 被停用時只會安靜地收不到事件，SDD-01 §3.6）
    const int64_t now  = SteadyNowMs();
    int64_t       last = m_lastEventSteadyMs.load(std::memory_order_relaxed);
    if (last == 0) last = m_startedSteadyMs.load(std::memory_order_relaxed);
    if (last != 0 && now - last > m_cfg.silentThresholdMs) return SourceHealth::Silent;
    return h;
}

// ------------------------------------------------------------------ OS 回呼（T1）

DWORD WINAPI EvtChannelSource::SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext,
                                                    EVT_HANDLE hEvent) noexcept
{
    auto* self = static_cast<EvtChannelSource*>(userContext);
    return self ? self->HandleEvent(action, hEvent) : ERROR_SUCCESS;
}

DWORD EvtChannelSource::HandleEvent(EVT_SUBSCRIBE_NOTIFY_ACTION action, EVT_HANDLE hEvent) noexcept
{
    // in-flight 計數：取不到 shared 代表 Stop / Resubscribe 正在等待 —— 立刻返回，絕不阻塞
    if (!TryAcquireSRWLockShared(&m_inflightLock)) return ERROR_SUCCESS;
    struct Release {
        SRWLOCK* l;
        ~Release() { ReleaseSRWLockShared(l); }
    } release{&m_inflightLock};

    if (m_stopping.load(std::memory_order_acquire)) return ERROR_SUCCESS;

    if (action == EvtSubscribeActionError) {
        // hEvent 此時是 DWORD 錯誤碼而非事件控制代碼
        const auto status = static_cast<DWORD>(reinterpret_cast<uintptr_t>(hEvent));
        m_lastError.store(status, std::memory_order_relaxed);
        if (IsStaleBookmark(status)) m_channelCleared.store(true, std::memory_order_release);
        // 可恢復者（含 SUBSCRIPTION_CANCELLED / RPC_S_SERVER_UNAVAILABLE / QUERY_RESULT_STALE）絕不直接進 Failed：
        // 那等於從此不再收任何事件。標記 Reconnecting，由 Watchdog 以指數退避重訂閱。
        m_health.store(IsUnrecoverable(status) ? SourceHealth::Failed : SourceHealth::Reconnecting,
                       std::memory_order_release);
        return ERROR_SUCCESS;
    }
    if (action != EvtSubscribeActionDeliver || !hEvent) return ERROR_SUCCESS;

    // 1) EvtRender → thread_local 緩衝（回呼可併發，緩衝不可是成員）
    thread_local std::vector<wchar_t> buf(8192);
    DWORD used = 0, props = 0;
    if (!::EvtRender(nullptr, hEvent, EvtRenderEventXml, static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                     buf.data(), &used, &props)) {
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || used > 4u * 1024 * 1024) {
            m_renderFailures.fetch_add(1, std::memory_order_relaxed);
            return ERROR_SUCCESS;   // 只丟這一筆，絕不讓回呼失敗（回傳非 0 會使訂閱被取消）
        }
        buf.resize(used / sizeof(wchar_t) + 1);
        if (!::EvtRender(nullptr, hEvent, EvtRenderEventXml, static_cast<DWORD>(buf.size() * sizeof(wchar_t)),
                         buf.data(), &used, &props)) {
            m_renderFailures.fetch_add(1, std::memory_order_relaxed);
            return ERROR_SUCCESS;
        }
    }
    size_t chars = used / sizeof(wchar_t);
    while (chars > 0 && buf[chars - 1] == L'\0') --chars;
    const std::wstring_view xml{buf.data(), chars};

    // 2) 優先級必須在入佇列「之前」決定（分級丟棄發生在 Push 當下）
    model::RawEvent ev;
    ev.kind     = m_cfg.kind;
    ev.recvTime = std::chrono::steady_clock::now();
    ev.eventId  = PeekEventIdW(xml);
    ev.priority = PriorityOfEid(ev.eventId);
    ev.xml      = svc::WideToUtf8(xml);   // 唯一一次配置

    // 3) Push：滿了就丟（計數由 ring buffer 維護）。絕不重試、絕不 sleep。
    (void)m_sink->Push(std::move(ev));

    m_eventCount.fetch_add(1, std::memory_order_relaxed);
    m_lastEventSteadyMs.store(SteadyNowMs(), std::memory_order_relaxed);
    if (m_health.load(std::memory_order_relaxed) != SourceHealth::Healthy)
        m_health.store(SourceHealth::Healthy, std::memory_order_release);

    // 4) 書籤（非阻塞：取不到鎖就跳過這一筆，下一筆會把位置推得更新）
    UpdateBookmark(hEvent);
    return ERROR_SUCCESS;
}

void EvtChannelSource::UpdateBookmark(EVT_HANDLE hEvent) noexcept
{
    if (!m_cfg.bookmarks) return;
    if (!TryAcquireSRWLockExclusive(&m_bookmarkLock)) return;
    if (m_bookmark && ::EvtUpdateBookmark(m_bookmark.get(), hEvent)) {
        m_bookmarkHasPosition = true;
        const int64_t now = SteadyNowMs();
        if (++m_sinceRender >= m_cfg.bookmarkRenderEvery || now - m_lastRenderSteadyMs >= m_cfg.bookmarkRenderEveryMs) {
            std::string xml = RenderBookmarkXml();
            if (!xml.empty()) m_pendingBookmarkXml = std::move(xml);
            m_sinceRender        = 0;
            m_lastRenderSteadyMs = now;
        }
    }
    ReleaseSRWLockExclusive(&m_bookmarkLock);
}

std::string EvtChannelSource::RenderBookmarkXml() noexcept
{
    if (!m_bookmark) return {};
    DWORD used = 0, props = 0;
    ::EvtRender(nullptr, m_bookmark.get(), EvtRenderBookmark, 0, nullptr, &used, &props);
    if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0) return {};
    std::vector<wchar_t> b(used / sizeof(wchar_t) + 1);
    if (!::EvtRender(nullptr, m_bookmark.get(), EvtRenderBookmark, static_cast<DWORD>(b.size() * sizeof(wchar_t)),
                     b.data(), &used, &props)) {
        return {};
    }
    size_t chars = used / sizeof(wchar_t);
    while (chars > 0 && b[chars - 1] == L'\0') --chars;
    return svc::WideToUtf8(std::wstring_view{b.data(), chars});
}

void EvtChannelSource::PersistBookmark() noexcept
{
    if (!m_cfg.bookmarks) return;
    std::string xml;
    // 維護執行緒可以阻塞（短暫），回呼那一側是 Try，不會因此卡住
    AcquireSRWLockExclusive(&m_bookmarkLock);
    xml.swap(m_pendingBookmarkXml);
    ReleaseSRWLockExclusive(&m_bookmarkLock);
    if (xml.empty()) return;
    if (Status st = m_cfg.bookmarks->Save(m_cfg.name, xml); !st) {
        spdlog::warn("[{}] 書籤落地失敗：{}", m_cfg.name, st.GetError().ToString());
        // 放回，下次再試（除非已有更新的版本）
        AcquireSRWLockExclusive(&m_bookmarkLock);
        if (m_pendingBookmarkXml.empty()) m_pendingBookmarkXml = std::move(xml);
        ReleaseSRWLockExclusive(&m_bookmarkLock);
    }
}

} // namespace cairn::telemetry
