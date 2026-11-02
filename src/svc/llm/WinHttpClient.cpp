#include "llm/WinHttpClient.h"

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"

namespace cairn::llm {

namespace {

bool IsLoopbackHost(std::wstring_view h) noexcept
{
    return h == L"127.0.0.1" || h == L"localhost" || h == L"::1" || h == L"[::1]";
}

Error MapWinHttpError(DWORD err, bool timedOut, bool cancelled, std::string_view ctx)
{
    if (cancelled) return MakeWin32Error(ErrorCode::Cancelled, err, std::string(ctx) + ": cancelled");
    if (timedOut) return MakeWin32Error(ErrorCode::LlmTimeout, err, std::string(ctx) + ": total budget exceeded");
    switch (err) {
    case ERROR_WINHTTP_TIMEOUT:
        return MakeWin32Error(ErrorCode::LlmTimeout, err, std::string(ctx) + ": ERROR_WINHTTP_TIMEOUT");
    case ERROR_WINHTTP_CANNOT_CONNECT:
    case ERROR_WINHTTP_CONNECTION_ERROR:
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        return MakeWin32Error(ErrorCode::LlmUnavailable, err, std::string(ctx) + ": cannot connect");
    case ERROR_WINHTTP_OPERATION_CANCELLED:
    case ERROR_INVALID_HANDLE:
        // handle 被他執行緒關閉但旗標尚未可見的極窄窗口：視為取消
        return MakeWin32Error(ErrorCode::Cancelled, err, std::string(ctx) + ": handle closed");
    default:
        return svc::Win32Error(ErrorCode::LlmHttpError, ctx, err);
    }
}

} // namespace

Result<std::unique_ptr<WinHttpClient>> WinHttpClient::Create(std::wstring host, uint16_t port)
{
    if (!IsLoopbackHost(host))
        return MakeError(ErrorCode::InvalidArgument, "WinHttpClient: 只允許 loopback 主機（設定可能遭竄改）");

    std::unique_ptr<WinHttpClient> c{new WinHttpClient()};
    // WINHTTP_ACCESS_TYPE_NO_PROXY：loopback 不經任何系統 proxy
    c->m_session.reset(::WinHttpOpen(L"CairnAgent/0.1", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0));
    if (!c->m_session) return svc::Win32Error(ErrorCode::LlmUnavailable, "WinHttpOpen");

    c->m_connect.reset(::WinHttpConnect(c->m_session.get(), host.c_str(), static_cast<INTERNET_PORT>(port), 0));
    if (!c->m_connect) return svc::Win32Error(ErrorCode::LlmUnavailable, "WinHttpConnect");
    return c;
}

WinHttpClient::~WinHttpClient()
{
    std::lock_guard lk{m_reqMutex};
    CloseActiveLocked();
}

void WinHttpClient::CloseActiveLocked() noexcept
{
    if (m_activeRequest) {
        ::WinHttpCloseHandle(m_activeRequest);
        m_activeRequest = nullptr;
    }
}

void WinHttpClient::CancelActive() noexcept
{
    std::lock_guard lk{m_reqMutex};
    if (m_activeRequest) {
        m_cancelled.store(true, std::memory_order_release);
        CloseActiveLocked();
    }
}

void CALLBACK WinHttpClient::OnBudgetTimer(PVOID param, BOOLEAN /*timerOrWaitFired*/)
{
    auto* self = static_cast<WinHttpClient*>(param);
    std::lock_guard lk{self->m_reqMutex};
    if (self->m_activeRequest) {
        self->m_timedOut.store(true, std::memory_order_release);
        self->CloseActiveLocked();
    }
}

Result<HttpResponse> WinHttpClient::Send(std::wstring_view verb, std::wstring_view path, std::string_view body,
                                         std::wstring_view extraHeaders, const HttpTimeouts& t,
                                         std::stop_token cancel)
{
    if (body.size() > 0xFFFFFFFFull) return MakeError(ErrorCode::InvalidArgument, "WinHttpClient: body 過大");
    if (cancel.stop_requested()) return MakeError(ErrorCode::Cancelled, "WinHttpClient: cancelled before send");

    m_timedOut.store(false, std::memory_order_relaxed);
    m_cancelled.store(false, std::memory_order_relaxed);

    const std::wstring verbStr(verb);
    const std::wstring pathStr(path);
    HINTERNET req = ::WinHttpOpenRequest(m_connect.get(), verbStr.c_str(), pathStr.c_str(), nullptr,
                                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) return svc::Win32Error(ErrorCode::LlmHttpError, "WinHttpOpenRequest");
    {
        std::lock_guard lk{m_reqMutex};
        m_activeRequest = req;
    }

    // 收尾：先刪計時器（會等待進行中的 callback 結束，且不可持有 m_reqMutex，否則與 callback 互鎖），
    // 再於鎖內關閉 handle（若已被他執行緒關閉則為 no-op）。
    HANDLE budgetTimer = nullptr;
    auto cleanup = wil::scope_exit([&] {
        if (budgetTimer) ::DeleteTimerQueueTimer(nullptr, budgetTimer, INVALID_HANDLE_VALUE);
        std::lock_guard lk{m_reqMutex};
        if (m_activeRequest == req) CloseActiveLocked();
    });

    // 取消：任意執行緒觸發 stop_token → 關閉 handle → 阻塞中的 WinHTTP 呼叫立即以錯誤返回
    std::stop_callback onCancel{cancel, [this] { CancelActive(); }};

    ::WinHttpSetTimeouts(req, t.resolveMs, t.connectMs, t.sendMs, t.receiveMs);

    if (t.totalBudget.count() > 0) {
        if (!::CreateTimerQueueTimer(&budgetTimer, nullptr, &WinHttpClient::OnBudgetTimer, this,
                                     static_cast<DWORD>(t.totalBudget.count()), 0, WT_EXECUTEONLYONCE)) {
            budgetTimer = nullptr;
            spdlog::warn("[llm] CreateTimerQueueTimer 失敗（{}），僅以 receive 逾時兜底", ::GetLastError());
        }
    }

    auto fail = [&](std::string_view ctx) -> Error {
        const DWORD err = ::GetLastError();
        return MapWinHttpError(err, m_timedOut.load(std::memory_order_acquire),
                               m_cancelled.load(std::memory_order_acquire) || cancel.stop_requested(), ctx);
    };

    const std::wstring headers(extraHeaders);
    const BOOL sent = ::WinHttpSendRequest(
        req, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
        headers.empty() ? 0 : static_cast<DWORD>(-1L),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()), 0);
    if (!sent) return fail("WinHttpSendRequest");

    if (!::WinHttpReceiveResponse(req, nullptr)) return fail("WinHttpReceiveResponse");

    HttpResponse resp;
    DWORD status = 0;
    DWORD size   = sizeof(status);
    if (!::WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                               &status, &size, WINHTTP_NO_HEADER_INDEX))
        return fail("WinHttpQueryHeaders");
    resp.statusCode = status;

    for (;;) {
        if (m_timedOut.load(std::memory_order_acquire) || m_cancelled.load(std::memory_order_acquire))
            return MapWinHttpError(ERROR_WINHTTP_OPERATION_CANCELLED, m_timedOut.load(), m_cancelled.load(),
                                   "WinHttpReadData");
        DWORD avail = 0;
        if (!::WinHttpQueryDataAvailable(req, &avail)) return fail("WinHttpQueryDataAvailable");
        if (avail == 0) break;
        if (resp.body.size() + avail > kMaxBodyBytes)
            return MakeError(ErrorCode::LlmHttpError, "WinHttpClient: 回應超過 4 MB 上限");
        const size_t old = resp.body.size();
        resp.body.resize(old + avail);
        DWORD read = 0;
        if (!::WinHttpReadData(req, resp.body.data() + old, avail, &read)) return fail("WinHttpReadData");
        resp.body.resize(old + read);
        if (read == 0) break;
    }
    return resp;
}

} // namespace cairn::llm
