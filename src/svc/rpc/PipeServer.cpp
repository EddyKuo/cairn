#include "rpc/PipeServer.h"

#include <sddl.h>

#include <algorithm>
#include <span>

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "rpc/Framing.h"

namespace cairn::rpc {

Result<wil::unique_handle> CreatePipeInstance(bool first, uint32_t maxInstances)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(kPipeSddl, SDDL_REVISION_1, &psd, nullptr)) {
        return svc::Win32Error(ErrorCode::PipeBusy, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    }
    wil::unique_hlocal sdOwner{psd};
    SECURITY_ATTRIBUTES sa{sizeof(sa), psd, FALSE};

    DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (first) openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;   // ← 防搶佔

    wil::unique_handle h{::CreateNamedPipeW(kPipeName, openMode,
                                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                            maxInstances, 64 * 1024, 64 * 1024, 0, &sa)};
    if (!h || h.get() == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        (void)h.release();
        return svc::Win32Error(ErrorCode::PipeBusy, first ? "CreateNamedPipe(first instance)" : "CreateNamedPipe", err);
    }
    return h;
}

Result<std::unique_ptr<PipeServer>> PipeServer::Start(const JsonRpcDispatcher* dispatcher, PipeServerOptions opts)
{
    if (!dispatcher) return MakeError(ErrorCode::InvalidArgument, "PipeServer::Start: dispatcher is null");
    // 第一個實例在呼叫端執行緒上同步建立：搶佔失敗必須讓服務啟動失敗，而不是背景默默重試。
    auto first = CreatePipeInstance(true, opts.maxInstances);
    if (!first) return first.GetError();

    std::unique_ptr<PipeServer> srv{new PipeServer(dispatcher, opts)};
    for (uint32_t i = 0; i < opts.workerThreads; ++i) srv->m_workers.emplace_back([p = srv.get()] { p->WorkerLoop(); });
    srv->m_acceptThread = std::thread([p = srv.get(), h = std::move(first).Value()]() mutable { p->AcceptLoop(std::move(h)); });
    return srv;
}

PipeServer::PipeServer(const JsonRpcDispatcher* dispatcher, PipeServerOptions opts)
    : m_dispatcher(dispatcher), m_opts(opts)
{
    m_stopEvent.create(wil::EventOptions::ManualReset);
}

PipeServer::~PipeServer() { Stop(); }

void PipeServer::Stop() noexcept
{
    if (m_stopping.exchange(true)) {
        // 已在停止中；仍確保 join（解構路徑）
    }
    m_stopEvent.SetEvent();
    // 在 m_qMutex 下「經過」一次再 notify：避免 worker 已檢查完述詞、尚未進入 wait 時錯過喚醒而永久阻塞（join 卡死）
    { std::lock_guard lk{m_qMutex}; }
    m_qCv.notify_all();
    if (m_acceptThread.joinable()) m_acceptThread.join();
    for (auto& t : m_workers)
        if (t.joinable()) t.join();
    m_workers.clear();
    std::lock_guard lk{m_qMutex};
    m_pending.clear();
}

void PipeServer::AcceptLoop(wil::unique_handle instance)
{
    while (!m_stopping.load()) {
        if (!instance) {
            auto next = CreatePipeInstance(false, m_opts.maxInstances);
            if (!next) {
                spdlog::error("rpc: {}", next.GetError().ToString());
                // 實例數達上限等暫時性錯誤：稍候重試，可被停止訊號中斷
                if (::WaitForSingleObject(m_stopEvent.get(), 500) == WAIT_OBJECT_0) return;
                continue;
            }
            instance = std::move(next).Value();
        }

        wil::unique_event ev{wil::EventOptions::ManualReset};
        OVERLAPPED ov{};
        ov.hEvent = ev.get();

        const BOOL ok  = ::ConnectNamedPipe(instance.get(), &ov);
        const DWORD err = ok ? ERROR_SUCCESS : ::GetLastError();

        if (err == ERROR_IO_PENDING) {
            HANDLE waits[2]{ev.get(), m_stopEvent.get()};
            const DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0) {
                ::CancelIoEx(instance.get(), &ov);
                DWORD dummy = 0;
                ::GetOverlappedResult(instance.get(), &ov, &dummy, TRUE);   // 等取消完成，OVERLAPPED 才可釋放
                return;
            }
            DWORD dummy = 0;
            if (!::GetOverlappedResult(instance.get(), &ov, &dummy, FALSE)) {
                instance.reset();
                continue;
            }
        } else if (err != ERROR_SUCCESS && err != ERROR_PIPE_CONNECTED) {
            spdlog::warn("rpc: ConnectNamedPipe failed err={}", err);
            instance.reset();
            continue;
        }

        {
            std::lock_guard lk{m_qMutex};
            m_pending.push_back(std::move(instance));
        }
        m_qCv.notify_one();
        instance.reset();
    }
}

void PipeServer::WorkerLoop()
{
    for (;;) {
        wil::unique_handle pipe;
        {
            std::unique_lock lk{m_qMutex};
            m_qCv.wait(lk, [&] { return m_stopping.load() || !m_pending.empty(); });
            if (m_stopping.load()) return;
            pipe = std::move(m_pending.front());
            m_pending.pop_front();
        }
        ++m_active;
        Serve(std::move(pipe));
        --m_active;
    }
}

namespace {
RpcContext QueryClientContext(HANDLE pipe)
{
    RpcContext ctx;
    ULONG pid = 0;
    if (::GetNamedPipeClientProcessId(pipe, &pid)) ctx.clientPid = pid;

    // 以模擬身分取得對端使用者名稱，供稽核記錄的 actor 使用
    if (::ImpersonateNamedPipeClient(pipe)) {
        wil::unique_handle token;
        if (::OpenThreadToken(::GetCurrentThread(), TOKEN_QUERY, TRUE, token.put())) {
            DWORD need = 0;
            ::GetTokenInformation(token.get(), TokenUser, nullptr, 0, &need);
            std::vector<uint8_t> buf(need);
            if (need && ::GetTokenInformation(token.get(), TokenUser, buf.data(), need, &need)) {
                auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
                wchar_t name[256]{}, domain[256]{};
                DWORD nlen = 256, dlen = 256;
                SID_NAME_USE use{};
                if (::LookupAccountSidW(nullptr, tu->User.Sid, name, &nlen, domain, &dlen, &use)) {
                    ctx.clientUser = svc::WideToUtf8(std::wstring(domain) + L"\\" + name);
                }
            }
        }
        ::RevertToSelf();
    }
    return ctx;
}
} // namespace

bool PipeServer::ReadSome(HANDLE pipe, std::vector<uint8_t>& buf, DWORD& got)
{
    wil::unique_event ev{wil::EventOptions::ManualReset};
    OVERLAPPED ov{};
    ov.hEvent = ev.get();
    got = 0;
    if (!::ReadFile(pipe, buf.data(), static_cast<DWORD>(buf.size()), nullptr, &ov)) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_MORE_DATA) {
            // Byte 模式不應發生；仍視為成功讀到部分資料
        } else if (err != ERROR_IO_PENDING) {
            return false;
        }
    }
    HANDLE waits[2]{ev.get(), m_stopEvent.get()};
    const DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, m_opts.readIdleTimeoutMs);
    if (w != WAIT_OBJECT_0) {
        // 逾時（半開連線）或停止訊號：取消並等待取消完成
        ::CancelIoEx(pipe, &ov);
        ::GetOverlappedResult(pipe, &ov, &got, TRUE);
        return false;
    }
    if (!::GetOverlappedResult(pipe, &ov, &got, FALSE)) {
        return ::GetLastError() == ERROR_MORE_DATA;
    }
    return got > 0;
}

bool PipeServer::WriteAll(HANDLE pipe, const std::string& data)
{
    size_t off = 0;
    while (off < data.size()) {
        wil::unique_event ev{wil::EventOptions::ManualReset};
        OVERLAPPED ov{};
        ov.hEvent = ev.get();
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(data.size() - off, 64 * 1024));
        if (!::WriteFile(pipe, data.data() + off, chunk, nullptr, &ov) && ::GetLastError() != ERROR_IO_PENDING) {
            return false;
        }
        HANDLE waits[2]{ev.get(), m_stopEvent.get()};
        if (::WaitForMultipleObjects(2, waits, FALSE, m_opts.readIdleTimeoutMs) != WAIT_OBJECT_0) {
            DWORD dummy = 0;
            ::CancelIoEx(pipe, &ov);
            ::GetOverlappedResult(pipe, &ov, &dummy, TRUE);
            return false;
        }
        DWORD wrote = 0;
        if (!::GetOverlappedResult(pipe, &ov, &wrote, FALSE) || wrote == 0) return false;
        off += wrote;
    }
    return true;
}

void PipeServer::Serve(wil::unique_handle pipe)
{
    // ImpersonateNamedPipeClient 必須在自管線讀到資料之後才能成功（否則 ERROR_CANNOT_IMPERSONATE），
    // 因此對端脈絡延後到第一次讀取成功後才查詢。
    RpcContext ctx;
    bool ctxReady = false;
    FrameDecoder dec;
    std::vector<uint8_t> buf(64 * 1024);

    while (!m_stopping.load()) {
        DWORD got = 0;
        if (!ReadSome(pipe.get(), buf, got)) break;
        if (!ctxReady) {
            ctx      = QueryClientContext(pipe.get());
            ctxReady = true;
        }
        dec.Feed(std::span<const uint8_t>(buf.data(), got));

        for (;;) {
            auto msg = dec.Next();
            if (dec.GetState() == FrameDecoder::State::TooLarge) {
                const auto err = Json{{"jsonrpc", "2.0"}, {"id", nullptr},
                                      {"error", RpcError::App("MESSAGE_TOO_LARGE", "message exceeds 1 MiB").ToJson()}};
                if (auto f = EncodeFrame(err.dump())) (void)WriteAll(pipe.get(), *f);
                ::FlushFileBuffers(pipe.get());
                ::DisconnectNamedPipe(pipe.get());
                return;   // 關閉連線
            }
            if (!msg) break;

            auto resp = m_dispatcher->HandleMessage(*msg, ctx);
            ++m_served;
            if (!resp) continue;   // 通知，無回應
            auto frame = EncodeFrame(*resp);
            if (!frame) {
                const auto err = Json{{"jsonrpc", "2.0"}, {"id", nullptr},
                                      {"error", RpcError::App("RESULT_TOO_LARGE", "result exceeds 1 MiB; narrow the query").ToJson()}};
                frame = EncodeFrame(err.dump());
            }
            if (!frame || !WriteAll(pipe.get(), *frame)) {
                ::DisconnectNamedPipe(pipe.get());
                return;
            }
        }
    }
    ::DisconnectNamedPipe(pipe.get());
}

} // namespace cairn::rpc
