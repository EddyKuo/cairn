// RpcClient.cpp —— 見 RpcClient.h
#include "pch.h"

#include "RpcClient.h"

namespace cairn::ui {

namespace {
constexpr wchar_t kPipeName[] = LR"(\\.\pipe\Cairn\rpc)";
constexpr int kBackoffSec[]   = {1, 2, 4, 8, 15, 30};

// 驗證管線對端確實是 CairnAgent.exe（防同名管線搶佔的第二道防線；第一道是伺服器端的
// FILE_FLAG_FIRST_PIPE_INSTANCE）。無法開啟對端程序（權限不足）時不阻擋，僅記錄。
bool VerifyServer(HANDLE pipe)
{
    ULONG pid = 0;
    if (!::GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) return true;
    wil::unique_handle proc{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!proc) return true;
    wchar_t path[MAX_PATH * 2]{};
    DWORD   n = static_cast<DWORD>(std::size(path));
    if (!::QueryFullProcessImageNameW(proc.get(), 0, path, &n)) return true;
    const wchar_t* name = ::PathFindFileNameW(path);
    if (_wcsicmp(name, L"CairnAgent.exe") != 0) {
        ::OutputDebugStringW(L"[CairnConsole] 管線對端不是 CairnAgent.exe，拒絕連線\n");
        return false;
    }
    return true;
}
} // namespace

const wchar_t* LinkStateName(LinkState s) noexcept
{
    switch (s) {
    case LinkState::Connecting: return L"Connecting";
    case LinkState::Connected: return L"Connected";
    case LinkState::Degraded: return L"Degraded";
    case LinkState::Retrying: return L"Retrying";
    case LinkState::ServiceGone: return L"ServiceGone";
    }
    return L"?";
}

RpcClient::RpcClient()
{
    m_ioEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

RpcClient::~RpcClient()
{
    std::lock_guard lk{m_mutex};
    DisconnectLocked();
    if (m_ioEvent) ::CloseHandle(m_ioEvent);
}

std::string RpcClient::EncodeFrame(const std::string& payload)
{
    const auto n = static_cast<uint32_t>(payload.size());
    std::string out;
    out.reserve(4 + payload.size());
    out.push_back(static_cast<char>(n & 0xFF));
    out.push_back(static_cast<char>((n >> 8) & 0xFF));
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    out.push_back(static_cast<char>((n >> 24) & 0xFF));
    out.append(payload);
    return out;
}

int64_t RpcClient::DecodeLength(const unsigned char h[4]) noexcept
{
    const uint32_t n = static_cast<uint32_t>(h[0]) | (static_cast<uint32_t>(h[1]) << 8) |
                       (static_cast<uint32_t>(h[2]) << 16) | (static_cast<uint32_t>(h[3]) << 24);
    if (n > kMaxMessageBytes) return -2;
    return static_cast<int64_t>(n);
}

void RpcClient::ResetBackoff()
{
    std::lock_guard lk{m_mutex};
    m_backoffIndex = 0;
    m_totalFailures = 0;
    m_retryAt = {};
    m_state = LinkState::Connecting;
}

void RpcClient::DisconnectLocked() noexcept
{
    if (m_pipe != INVALID_HANDLE_VALUE) {
        ::CancelIoEx(m_pipe, nullptr);
        ::CloseHandle(m_pipe);
        m_pipe = INVALID_HANDLE_VALUE;
    }
}

bool RpcClient::QueryServiceRunning() const noexcept
{
    wil::unique_schandle scm{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) return true;   // 查不到就不斷言服務已死
    wil::unique_schandle svc{::OpenServiceW(scm.get(), L"CairnAgent", SERVICE_QUERY_STATUS)};
    if (!svc) return false;  // 服務未安裝
    SERVICE_STATUS st{};
    if (!::QueryServiceStatus(svc.get(), &st)) return true;
    return st.dwCurrentState == SERVICE_RUNNING || st.dwCurrentState == SERVICE_START_PENDING;
}

bool RpcClient::EnsureConnectedLocked(std::chrono::milliseconds timeout)
{
    if (m_pipe != INVALID_HANDLE_VALUE) return true;

    // 退避中：快速失敗，不打擾服務
    if (m_retryAt != std::chrono::steady_clock::time_point{} && std::chrono::steady_clock::now() < m_retryAt) {
        return false;
    }

    for (int attempt = 0; attempt < 2; ++attempt) {
        HANDLE h = ::CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE;
            ::SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
            if (!VerifyServer(h)) {
                ::CloseHandle(h);
                return false;
            }
            m_pipe = h;
            return true;
        }
        const DWORD err = ::GetLastError();
        if (err == ERROR_PIPE_BUSY && attempt == 0) {
            const auto waitMs = static_cast<DWORD>(std::min<int64_t>(timeout.count(), 1000));
            if (::WaitNamedPipeW(kPipeName, waitMs)) continue;
        }
        return false;
    }
    return false;
}

bool RpcClient::WriteAllLocked(const void* data, uint32_t len, std::chrono::milliseconds timeout)
{
    const auto* p = static_cast<const char*>(data);
    uint32_t    done = 0;
    while (done < len) {
        OVERLAPPED ov{};
        ov.hEvent = m_ioEvent;
        ::ResetEvent(m_ioEvent);
        DWORD n = 0;
        if (!::WriteFile(m_pipe, p + done, len - done, &n, &ov)) {
            if (::GetLastError() != ERROR_IO_PENDING) return false;
            if (::WaitForSingleObject(m_ioEvent, static_cast<DWORD>(timeout.count())) != WAIT_OBJECT_0) {
                ::CancelIoEx(m_pipe, &ov);
                ::GetOverlappedResult(m_pipe, &ov, &n, TRUE);
                return false;
            }
            if (!::GetOverlappedResult(m_pipe, &ov, &n, FALSE)) return false;
        }
        if (n == 0) return false;
        done += n;
    }
    return true;
}

bool RpcClient::ReadAllLocked(void* data, uint32_t len, std::chrono::milliseconds timeout, bool* timedOut)
{
    auto*      p = static_cast<char*>(data);
    uint32_t   done = 0;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    *timedOut = false;
    while (done < len) {   // Byte 模式管線不保證一次讀完，迴圈讀至滿 len
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            *timedOut = true;
            return false;
        }
        OVERLAPPED ov{};
        ov.hEvent = m_ioEvent;
        ::ResetEvent(m_ioEvent);
        DWORD n = 0;
        if (!::ReadFile(m_pipe, p + done, len - done, &n, &ov)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_IO_PENDING) return false;   // ERROR_BROKEN_PIPE 等
            if (::WaitForSingleObject(m_ioEvent, static_cast<DWORD>(left.count())) != WAIT_OBJECT_0) {
                ::CancelIoEx(m_pipe, &ov);
                ::GetOverlappedResult(m_pipe, &ov, &n, TRUE);
                *timedOut = true;
                return false;
            }
            if (!::GetOverlappedResult(m_pipe, &ov, &n, FALSE)) return false;
        }
        if (n == 0) return false;
        done += n;
    }
    return true;
}

void RpcClient::NoteFailure(bool timeout)
{
    m_consecutiveFailures.fetch_add(1);
    ++m_totalFailures;
    if (timeout) {
        ++m_consecutiveTimeouts;
        // 連續 2 次逾時 → Degraded；連續 5 次 → Retrying（SDD-03 §9.5.1）
        if (m_consecutiveTimeouts >= 5) {
            m_state = LinkState::Retrying;
        } else if (m_consecutiveTimeouts >= 2) {
            m_state = LinkState::Degraded;
            return;
        } else {
            return;
        }
    }
    // 斷線／連不上：進入退避
    m_retryAt = std::chrono::steady_clock::now() + std::chrono::seconds(kBackoffSec[m_backoffIndex]);
    if (m_backoffIndex + 1 < static_cast<int>(std::size(kBackoffSec))) ++m_backoffIndex;
    if (m_totalFailures > 20 && !QueryServiceRunning()) {
        m_state = LinkState::ServiceGone;
    } else {
        m_state = LinkState::Retrying;
    }
}

void RpcClient::NoteSuccess()
{
    m_consecutiveFailures = 0;
    m_consecutiveTimeouts = 0;
    m_totalFailures = 0;
    m_backoffIndex = 0;
    m_retryAt = {};
    m_state = LinkState::Connected;
}

RpcOutcome RpcClient::Call(const std::string& method, const nlohmann::json& params, std::chrono::milliseconds timeout)
{
    std::lock_guard lk{m_mutex};
    RpcOutcome out;

    if (!EnsureConnectedLocked(timeout)) {
        if (m_retryAt == std::chrono::steady_clock::time_point{} || std::chrono::steady_clock::now() >= m_retryAt) {
            NoteFailure(false);
        } else {
            m_consecutiveFailures.fetch_add(1);
        }
        out.kind = RpcOutcome::Kind::LinkDown;
        out.message = "pipe not connected";
        return out;
    }

    const int64_t  id = m_nextId.fetch_add(1);
    nlohmann::json req = {{"jsonrpc", "2.0"}, {"id", id}, {"method", method},
                          {"params", params.is_null() ? nlohmann::json::object() : params}};
    const std::string payload = req.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (payload.size() > kMaxMessageBytes) {
        out.kind = RpcOutcome::Kind::Protocol;
        out.message = "request too large";
        return out;
    }
    const std::string frame = EncodeFrame(payload);

    if (!WriteAllLocked(frame.data(), static_cast<uint32_t>(frame.size()), timeout)) {
        DisconnectLocked();
        NoteFailure(false);
        out.kind = RpcOutcome::Kind::LinkDown;
        out.message = "pipe write failed";
        return out;
    }

    unsigned char hdr[4]{};
    bool          timedOut = false;
    if (!ReadAllLocked(hdr, 4, timeout, &timedOut)) {
        // 逾時後連線上可能仍有遲到的回應，為避免錯配下一個請求，一律斷線重連
        DisconnectLocked();
        NoteFailure(timedOut);
        out.kind = timedOut ? RpcOutcome::Kind::Timeout : RpcOutcome::Kind::LinkDown;
        out.message = timedOut ? "rpc timeout" : "pipe read failed";
        return out;
    }
    const int64_t len = DecodeLength(hdr);
    if (len < 0) {
        // 不讀 body：攻擊者可用 4 bytes 標頭誘使我們配置任意記憶體
        DisconnectLocked();
        out.kind = RpcOutcome::Kind::Protocol;
        out.message = "response too large";
        return out;
    }
    std::string body(static_cast<size_t>(len), '\0');
    if (len > 0 && !ReadAllLocked(body.data(), static_cast<uint32_t>(len), timeout, &timedOut)) {
        DisconnectLocked();
        NoteFailure(timedOut);
        out.kind = timedOut ? RpcOutcome::Kind::Timeout : RpcOutcome::Kind::LinkDown;
        return out;
    }

    nlohmann::json resp = nlohmann::json::parse(body, nullptr, false);
    if (resp.is_discarded() || !resp.is_object() || resp.value("id", nlohmann::json()) != nlohmann::json(id)) {
        DisconnectLocked();
        out.kind = RpcOutcome::Kind::Protocol;
        out.message = "malformed response";
        return out;
    }
    NoteSuccess();
    if (auto it = resp.find("error"); it != resp.end() && it->is_object()) {
        out.kind = RpcOutcome::Kind::RpcError;
        out.code = it->value("code", -32603);
        out.message = it->value("message", std::string{});
        out.data = it->value("data", nlohmann::json::object());
        return out;
    }
    out.kind = RpcOutcome::Kind::Ok;
    out.result = resp.value("result", nlohmann::json());
    return out;
}

} // namespace cairn::ui
