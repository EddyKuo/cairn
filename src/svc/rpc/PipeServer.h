// src/svc/rpc/PipeServer.h                    namespace cairn::rpc
// Named Pipe JSON-RPC 伺服器（T7 RpcServerThreadPool：1 accept + 4 worker，SDD-03 §9.4）。
//   名稱  \\.\pipe\Cairn\rpc
//   SDDL  D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)
//   第一個實例帶 FILE_FLAG_FIRST_PIPE_INSTANCE（防搶佔；失敗即中止服務啟動）
//   PIPE_REJECT_REMOTE_CLIENTS、FILE_FLAG_OVERLAPPED（accept 可被停止訊號中斷）
#pragma once
#ifndef _WIN32
#error "PipeServer 僅支援 Windows"
#endif

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include <wil/resource.h>

#include "base/Result.h"
#include "rpc/JsonRpcDispatcher.h"

namespace cairn::rpc {

inline constexpr wchar_t kPipeName[] = LR"(\\.\pipe\Cairn\rpc)";
inline constexpr wchar_t kPipeSddl[] = L"D:(A;;GA;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;IU)";

struct PipeServerOptions {
    uint32_t workerThreads   = 4;
    uint32_t maxInstances    = 8;
    uint32_t readIdleTimeoutMs = 30'000;   // 30 秒無資料即關閉連線
};

class PipeServer {
public:
    // dispatcher 必須在 PipeServer 解構前保持有效。
    // 建立第一個管線實例失敗（例如名稱已被搶佔）時回錯誤 —— 服務必須中止啟動。
    [[nodiscard]] static Result<std::unique_ptr<PipeServer>> Start(const JsonRpcDispatcher* dispatcher,
                                                                   PipeServerOptions opts = {});
    ~PipeServer();
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    // 冪等。取消 accept 與所有連線，等待 worker 結束。
    void Stop() noexcept;

    [[nodiscard]] uint64_t RequestsServed() const noexcept { return m_served.load(); }
    [[nodiscard]] uint32_t ActiveSessions() const noexcept { return m_active.load(); }

private:
    PipeServer(const JsonRpcDispatcher* dispatcher, PipeServerOptions opts);

    void AcceptLoop(wil::unique_handle firstInstance);
    void WorkerLoop();
    void Serve(wil::unique_handle pipe);
    [[nodiscard]] bool ReadSome(HANDLE pipe, std::vector<uint8_t>& buf, DWORD& got);
    [[nodiscard]] bool WriteAll(HANDLE pipe, const std::string& data);

    const JsonRpcDispatcher* m_dispatcher;
    PipeServerOptions        m_opts;
    wil::unique_event        m_stopEvent;
    std::atomic<bool>        m_stopping{false};
    std::atomic<uint64_t>    m_served{0};
    std::atomic<uint32_t>    m_active{0};

    std::thread              m_acceptThread;
    std::vector<std::thread> m_workers;
    std::mutex               m_qMutex;
    std::condition_variable  m_qCv;
    std::deque<wil::unique_handle> m_pending;
};

// 建立管線實例（first = 是否帶 FILE_FLAG_FIRST_PIPE_INSTANCE）。
[[nodiscard]] Result<wil::unique_handle> CreatePipeInstance(bool first, uint32_t maxInstances);

} // namespace cairn::rpc
