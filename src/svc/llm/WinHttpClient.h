// src/svc/llm/WinHttpClient.h                 namespace cairn::llm
// 對 127.0.0.1 的極簡同步 HTTP/1.1 客戶端（part2 §2.6.5、SDD-03 §7.4）。
//   - session / connect handle 建立一次、跨請求重用
//   - 分階段逾時：resolve 1s / connect 2s / send 5s / receive 30s（WinHttpSetTimeouts，設在 request handle 上）
//   - receive 逾時是「兩次資料到達的間隔」不是總時長 → 另以 Timer Queue 計時器實作總時長看門狗，
//     到期由計時器執行緒 WinHttpCloseHandle 中止進行中的請求
//   - 取消：std::stop_callback 在任意執行緒關閉 request handle（同步 WinHTTP 唯一可靠的中止手段）
// 執行緒親和性：Send() 一次只能有一條執行緒呼叫（LlmWorker）；CancelActive() 可由任意執行緒呼叫。
#pragma once
#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <string_view>

#include <wil/resource.h>

#include "base/Result.h"

namespace cairn::llm {

struct HttpTimeouts {
    int resolveMs = 1'000;
    int connectMs = 2'000;
    int sendMs    = 5'000;
    int receiveMs = 30'000;
    std::chrono::milliseconds totalBudget{30'000};   // 0 = 不設總時長
};

struct HttpResponse {
    uint32_t    statusCode = 0;
    std::string body;
};

class WinHttpClient {
public:
    static constexpr size_t kMaxBodyBytes = 4u * 1024u * 1024u;

    // host 必須是 loopback；非 loopback 一律拒絕（設定被竄改指向外部主機時及早失敗）
    [[nodiscard]] static Result<std::unique_ptr<WinHttpClient>> Create(std::wstring host, uint16_t port);
    ~WinHttpClient();
    WinHttpClient(const WinHttpClient&)            = delete;
    WinHttpClient& operator=(const WinHttpClient&) = delete;

    // 錯誤碼對應：
    //   ErrorCode::Cancelled      —— stop_token 被觸發或 CancelActive()
    //   ErrorCode::LlmTimeout     —— 總時長看門狗或 WinHTTP 階段逾時
    //   ErrorCode::LlmUnavailable —— 連線層失敗（子程序未啟動／已死）
    //   ErrorCode::LlmHttpError   —— 其餘 WinHTTP 錯誤、回應過大
    // HTTP 非 200 不算錯誤：回傳 HttpResponse 由呼叫端判斷 statusCode。
    [[nodiscard]] Result<HttpResponse> Send(std::wstring_view verb, std::wstring_view path, std::string_view body,
                                            std::wstring_view extraHeaders, const HttpTimeouts& t,
                                            std::stop_token cancel = {});

    [[nodiscard]] Result<HttpResponse> Post(std::wstring_view path, std::string_view body,
                                            std::wstring_view extraHeaders, const HttpTimeouts& t,
                                            std::stop_token cancel = {})
    {
        return Send(L"POST", path, body, extraHeaders, t, std::move(cancel));
    }

    [[nodiscard]] Result<HttpResponse> Get(std::wstring_view path, std::wstring_view extraHeaders,
                                           const HttpTimeouts& t, std::stop_token cancel = {})
    {
        return Send(L"GET", path, {}, extraHeaders, t, std::move(cancel));
    }

    // 任意執行緒：中止進行中的請求（Watchdog / 服務停止）。無請求時為 no-op。
    void CancelActive() noexcept;

private:
    WinHttpClient() = default;
    static void CALLBACK OnBudgetTimer(PVOID param, BOOLEAN timerOrWaitFired);
    void CloseActiveLocked() noexcept;

    wil::unique_winhttp_hinternet m_session;
    wil::unique_winhttp_hinternet m_connect;

    std::mutex        m_reqMutex;                 // 保護 m_activeRequest（T5 建立/釋放 vs 他執行緒關閉）
    HINTERNET         m_activeRequest = nullptr;
    std::atomic<bool> m_timedOut{false};
    std::atomic<bool> m_cancelled{false};
};

} // namespace cairn::llm
