#include "llm/LlamaServerSupervisor.h"

#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <vector>

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "llm/WinHttpClient.h"

namespace cairn::llm {

namespace {

using SteadyClock = std::chrono::steady_clock;

int64_t SteadyNowMs() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(SteadyClock::now().time_since_epoch()).count();
}

std::string ToHex(const uint8_t* p, size_t n)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    return s;
}

// 只允許 SYSTEM 與 Administrators 讀寫（D:P = protected，不繼承父目錄 ACE）
constexpr wchar_t kKeyFileSddl[] = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)";

// llama-server 的 stdout/stderr → spdlog。管線寫端關閉（子程序結束）時 ReadFile 失敗而退出。
void PumpChildOutput(HANDLE readEnd)
{
    std::string pending;
    char        buf[4096];
    for (;;) {
        DWORD n = 0;
        if (!::ReadFile(readEnd, buf, sizeof(buf), &n, nullptr) || n == 0) break;
        pending.append(buf, n);
        size_t nl;
        while ((nl = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.size() > 512) line.resize(512);
            if (!line.empty()) spdlog::debug("[llama-server] {}", line);
        }
        if (pending.size() > 64 * 1024) pending.clear();   // 無換行的異常輸出，避免無限成長
    }
    if (!pending.empty()) spdlog::debug("[llama-server] {}", pending.substr(0, 512));
}

} // namespace

const char* SupervisorStateName(SupervisorState s) noexcept
{
    switch (s) {
    case SupervisorState::Stopped: return "stopped";
    case SupervisorState::Starting: return "starting";
    case SupervisorState::Running: return "running";
    case SupervisorState::Backoff: return "backoff";
    case SupervisorState::Unavailable: return "unavailable";
    }
    return "unknown";
}

Result<std::unique_ptr<LlamaServerSupervisor>> LlamaServerSupervisor::Create(SupervisorConfig cfg)
{
    if (cfg.port == 0) return MakeError(ErrorCode::InvalidArgument, "SupervisorConfig.port 不可為 0");
    if (cfg.ctxSize < 4096) return MakeError(ErrorCode::InvalidArgument, "SupervisorConfig.ctxSize 過小");
    if (cfg.dataDir.empty()) cfg.dataDir = svc::DataDir();

    std::unique_ptr<LlamaServerSupervisor> s{new LlamaServerSupervisor(std::move(cfg))};
    s->m_apiKeyFile = s->m_cfg.dataDir / L"llm-api.key";
    {
        std::lock_guard lk{s->m_mutex};
        (void)s->PreflightLocked();
    }
    return s;
}

LlamaServerSupervisor::~LlamaServerSupervisor()
{
    Shutdown();
}

void LlamaServerSupervisor::SetState(SupervisorState s, std::string reason)
{
    {
        std::lock_guard ik{m_infoMutex};
        m_reason = std::move(reason);
    }
    m_state.store(s, std::memory_order_release);
}

std::string LlamaServerSupervisor::StateReason() const
{
    std::lock_guard ik{m_infoMutex};
    return m_reason;
}

std::string LlamaServerSupervisor::ModelId() const
{
    std::lock_guard ik{m_infoMutex};
    return m_modelId;
}

std::string LlamaServerSupervisor::ApiKey() const
{
    std::lock_guard ik{m_infoMutex};
    return m_apiKey;
}

int LlamaServerSupervisor::RestartsLastHour() const
{
    std::lock_guard ik{m_infoMutex};
    const auto cutoff = SteadyClock::now() - std::chrono::hours(1);
    return static_cast<int>(std::count_if(m_restarts.begin(), m_restarts.end(), [&](auto t) { return t >= cutoff; }));
}

void LlamaServerSupervisor::NotifyActivity() noexcept
{
    m_lastActivityMs.store(SteadyNowMs(), std::memory_order_relaxed);
}

bool LlamaServerSupervisor::PreflightLocked()
{
    std::error_code ec;
    if (!m_cfg.enabled) {
        SetState(SupervisorState::Unavailable, "disabled");
        return false;
    }
    if (m_cfg.exePath.empty() || !std::filesystem::is_regular_file(m_cfg.exePath, ec)) {
        SetState(SupervisorState::Unavailable, "missing-executable: " + svc::WideToUtf8(m_cfg.exePath.wstring()));
        return false;
    }
    const auto size = std::filesystem::file_size(m_cfg.modelPath, ec);
    if (m_cfg.modelPath.empty() || ec || size < m_cfg.minModelBytes) {
        SetState(SupervisorState::Unavailable, "missing-model: " + svc::WideToUtf8(m_cfg.modelPath.wstring()));
        return false;
    }
    if (m_state.load() == SupervisorState::Unavailable) SetState(SupervisorState::Stopped, "");
    return true;
}

Status LlamaServerSupervisor::EnsureModelIdLocked()
{
    {
        std::lock_guard ik{m_infoMutex};
        if (!m_modelId.empty()) return Ok();
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return MakeError(ErrorCode::LlmUnavailable, "BCryptOpenAlgorithmProvider(SHA256)");
    auto closeAlg = wil::scope_exit([&] { ::BCryptCloseAlgorithmProvider(alg, 0); });

    BCRYPT_HASH_HANDLE hash = nullptr;
    if (!BCRYPT_SUCCESS(::BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0)))
        return MakeError(ErrorCode::LlmUnavailable, "BCryptCreateHash");
    auto closeHash = wil::scope_exit([&] { ::BCryptDestroyHash(hash); });

    wil::unique_hfile f{::CreateFileW(m_cfg.modelPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (!f) return svc::Win32Error(ErrorCode::LlmUnavailable, "CreateFile(model)");

    std::vector<uint8_t> buf(1u << 20);
    for (;;) {
        if (m_shutdown.load(std::memory_order_acquire)) return MakeError(ErrorCode::Cancelled, "model hash: shutdown");
        DWORD n = 0;
        if (!::ReadFile(f.get(), buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr))
            return svc::Win32Error(ErrorCode::LlmUnavailable, "ReadFile(model)");
        if (n == 0) break;
        if (!BCRYPT_SUCCESS(::BCryptHashData(hash, buf.data(), n, 0)))
            return MakeError(ErrorCode::LlmUnavailable, "BCryptHashData");
    }
    uint8_t digest[32]{};
    if (!BCRYPT_SUCCESS(::BCryptFinishHash(hash, digest, sizeof(digest), 0)))
        return MakeError(ErrorCode::LlmUnavailable, "BCryptFinishHash");
    const std::string id = ToHex(digest, sizeof(digest)).substr(0, 16);
    {
        std::lock_guard ik{m_infoMutex};
        m_modelId = id;
    }
    spdlog::info("[llm] model id = {}", id);
    return Ok();
}

Status LlamaServerSupervisor::WriteApiKeyFileLocked()
{
    uint8_t rnd[32]{};
    if (!BCRYPT_SUCCESS(::BCryptGenRandom(nullptr, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        return MakeError(ErrorCode::LlmUnavailable, "BCryptGenRandom");
    const std::string key = ToHex(rnd, sizeof(rnd));
    ::SecureZeroMemory(rnd, sizeof(rnd));
    {
        std::lock_guard ik{m_infoMutex};
        m_apiKey = key;
    }

    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(kKeyFileSddl, SDDL_REVISION_1, &sd, nullptr))
        return svc::Win32Error(ErrorCode::LlmUnavailable, "ConvertStringSecurityDescriptor");
    auto freeSd = wil::scope_exit([&] { ::LocalFree(sd); });
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};

    // CREATE_ALWAYS 對既有檔案不會套用新的 DACL → 先刪除再以 CREATE_NEW 建立
    ::DeleteFileW(m_apiKeyFile.c_str());
    wil::unique_hfile f{::CreateFileW(m_apiKeyFile.c_str(), GENERIC_WRITE, 0, &sa, CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!f) return svc::Win32Error(ErrorCode::LlmUnavailable, "CreateFile(llm-api.key)");
    DWORD written = 0;
    if (!::WriteFile(f.get(), key.data(), static_cast<DWORD>(key.size()), &written, nullptr) ||
        written != key.size())
        return svc::Win32Error(ErrorCode::LlmUnavailable, "WriteFile(llm-api.key)");
    return Ok();
}

std::wstring LlamaServerSupervisor::BuildCommandLine() const
{
    // 對齊 part2 §2.6.2 / SDD-03 §7.2.3；--api-key-file 取代 --api-key（金鑰不出現在命令列）
    auto quote = [](const std::wstring& s) { return L"\"" + s + L"\""; };
    std::wstring cmd = quote(m_cfg.exePath.wstring());
    cmd += L" -m " + quote(m_cfg.modelPath.wstring());
    cmd += L" --host 127.0.0.1 --port " + std::to_wstring(m_cfg.port);
    cmd += L" --api-key-file " + quote(m_apiKeyFile.wstring());
    cmd += L" --ctx-size " + std::to_wstring(m_cfg.ctxSize);
    cmd += L" --n-gpu-layers " + std::to_wstring(m_cfg.gpuLayers);
    if (m_cfg.threads > 0) cmd += L" --threads " + std::to_wstring(m_cfg.threads);
    cmd += L" --parallel 1 --no-webui --timeout 60";
    return cmd;
}

Status LlamaServerSupervisor::SpawnLocked()
{
    KillLocked();   // 清掉任何殘留

    if (auto st = EnsureModelIdLocked(); !st) return st;
    if (auto st = WriteApiKeyFileLocked(); !st) return st;

    // 1) Job：KILL_ON_JOB_CLOSE + 記憶體保險絲。⚠ 絕不設 JOB_OBJECT_LIMIT_BREAKAWAY_OK
    m_job.reset(::CreateJobObjectW(nullptr, nullptr));
    if (!m_job) return svc::Win32Error(ErrorCode::LlmUnavailable, "CreateJobObject");
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li{};
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    li.ProcessMemoryLimit               = static_cast<SIZE_T>(m_cfg.processMemoryLimitBytes);
    if (!::SetInformationJobObject(m_job.get(), JobObjectExtendedLimitInformation, &li, sizeof(li)))
        return svc::Win32Error(ErrorCode::LlmUnavailable, "SetInformationJobObject");

    // 2) 管線：只有寫端可繼承
    SECURITY_ATTRIBUTES pipeSa{sizeof(pipeSa), nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!::CreatePipe(&rd, &wr, &pipeSa, 0)) return svc::Win32Error(ErrorCode::LlmUnavailable, "CreatePipe");
    wil::unique_handle readEnd{rd};
    wil::unique_handle writeEnd{wr};
    ::SetHandleInformation(readEnd.get(), HANDLE_FLAG_INHERIT, 0);

    // 3) 以 PROC_THREAD_ATTRIBUTE_HANDLE_LIST 限定子程序只繼承管線寫端
    SIZE_T attrSize = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    std::vector<uint8_t> attrBuf(attrSize);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
    if (!::InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize))
        return svc::Win32Error(ErrorCode::LlmUnavailable, "InitializeProcThreadAttributeList");
    auto delAttrs = wil::scope_exit([&] { ::DeleteProcThreadAttributeList(attrs); });
    HANDLE inheritList[1] = {writeEnd.get()};
    if (!::UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritList, sizeof(inheritList),
                                     nullptr, nullptr))
        return svc::Win32Error(ErrorCode::LlmUnavailable, "UpdateProcThreadAttribute");

    STARTUPINFOEXW si{};
    si.StartupInfo.cb          = sizeof(si);
    si.StartupInfo.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.StartupInfo.wShowWindow = SW_HIDE;
    si.StartupInfo.hStdInput   = nullptr;
    si.StartupInfo.hStdOutput  = writeEnd.get();
    si.StartupInfo.hStdError   = writeEnd.get();
    si.lpAttributeList         = attrs;

    std::wstring cmdline = BuildCommandLine();
    const std::wstring workDir = m_cfg.exePath.parent_path().wstring();
    PROCESS_INFORMATION pi{};
    // bInheritHandles 必須為 TRUE，否則子程序拿不到管線寫端（HANDLE_LIST 已把範圍限定在寫端）
    if (!::CreateProcessW(m_cfg.exePath.c_str(), cmdline.data(), nullptr, nullptr, TRUE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                          workDir.c_str(), &si.StartupInfo, &pi))
        return svc::Win32Error(ErrorCode::LlmUnavailable, "CreateProcess(llama-server)");
    wil::unique_handle proc{pi.hProcess};
    wil::unique_handle thread{pi.hThread};

    // 4) 指派到 Job —— 必須在 ResumeThread 之前
    if (!::AssignProcessToJobObject(m_job.get(), proc.get())) {
        const DWORD err = ::GetLastError();
        ::TerminateProcess(proc.get(), 1);
        return svc::Win32Error(ErrorCode::LlmUnavailable, "AssignProcessToJobObject", err);
    }
    // 5) 放行
    if (::ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
        const DWORD err = ::GetLastError();
        m_job.reset();   // KILL_ON_JOB_CLOSE
        return svc::Win32Error(ErrorCode::LlmUnavailable, "ResumeThread", err);
    }

    // 父程序關閉自己的寫端：子程序結束時讀端才會得到 EOF，讀取執行緒才會退出
    writeEnd.reset();
    m_process    = std::move(proc);
    m_stdoutRead = std::move(readEnd);
    HANDLE pumpHandle = m_stdoutRead.get();
    m_pumpThread = std::thread([pumpHandle] { PumpChildOutput(pumpHandle); });

    SetState(SupervisorState::Starting, "");
    spdlog::info("[llm] llama-server 已啟動 pid={} port={}", pi.dwProcessId, m_cfg.port);
    return Ok();
}

bool LlamaServerSupervisor::ProcessExitedLocked() const noexcept
{
    return !m_process || ::WaitForSingleObject(m_process.get(), 0) == WAIT_OBJECT_0;
}

bool LlamaServerSupervisor::WaitForHealthyLocked(std::stop_token cancel)
{
    auto http = WinHttpClient::Create(L"127.0.0.1", m_cfg.port);
    if (!http) return false;
    HttpTimeouts t;
    t.connectMs = 500;
    t.sendMs = 1'000;
    t.receiveMs = 2'000;
    t.totalBudget = std::chrono::milliseconds(3'000);
    const std::wstring auth = L"Authorization: Bearer " + svc::Utf8ToWide(ApiKey()) + L"\r\n";

    const auto deadline = SteadyClock::now() + m_cfg.healthTimeout;
    while (SteadyClock::now() < deadline) {
        if (m_shutdown.load(std::memory_order_acquire) || cancel.stop_requested()) return false;
        if (ProcessExitedLocked()) return false;
        auto r = http.Value()->Get(L"/health", auth, t, cancel);
        if (r && r.Value().statusCode == 200) return true;   // 載入中為 503
        ::Sleep(500);
    }
    return false;
}

void LlamaServerSupervisor::KillLocked() noexcept
{
    m_job.reset();   // ← KILL_ON_JOB_CLOSE：核心終止 Job 內所有程序
    if (m_process) {
        if (::WaitForSingleObject(m_process.get(), 5'000) != WAIT_OBJECT_0) ::TerminateProcess(m_process.get(), 1);
        m_process.reset();
    }
    if (m_pumpThread.joinable()) {
        // 子程序已死 → 寫端全數關閉 → ReadFile 回 EOF。保險起見再取消同步 I/O。
        ::CancelSynchronousIo(m_pumpThread.native_handle());
        m_pumpThread.join();
    }
    m_stdoutRead.reset();
}

void LlamaServerSupervisor::OnCrashLocked(const char* why)
{
    KillLocked();
    const auto now = SteadyClock::now();
    int n = 0;
    {
        std::lock_guard ik{m_infoMutex};
        while (!m_restarts.empty() && m_restarts.front() < now - std::chrono::hours(1)) m_restarts.pop_front();
        m_restarts.push_back(now);
        n = static_cast<int>(m_restarts.size());
    }
    if (n > m_cfg.maxRestartsPerHour) {
        SetState(SupervisorState::Unavailable, std::string("restart-limit: ") + why);
        spdlog::error("[llm] llama-server 1 小時內失敗 {} 次（{}），停用本機 AI 直到手動重啟", n, why);
        return;
    }
    const auto delay = std::min<std::chrono::seconds>(std::chrono::seconds(5LL << std::min(n, 10)), std::chrono::seconds(120));
    m_backoffUntil = now + delay;
    SetState(SupervisorState::Backoff, std::string("backoff: ") + why);
    spdlog::warn("[llm] llama-server 失敗（{}），{} 秒後重試（第 {} 次）", why, delay.count(), n);
}

Status LlamaServerSupervisor::EnsureRunning(std::stop_token cancel)
{
    if (m_shutdown.load(std::memory_order_acquire)) return MakeError(ErrorCode::LlmUnavailable, "shutdown");
    std::lock_guard lk{m_mutex};

    switch (m_state.load()) {
    case SupervisorState::Unavailable:
        return MakeError(ErrorCode::LlmUnavailable, StateReason());
    case SupervisorState::Running:
        if (!ProcessExitedLocked()) return Ok();
        OnCrashLocked("process exited");
        return MakeError(ErrorCode::LlmUnavailable, StateReason());
    case SupervisorState::Backoff:
        if (SteadyClock::now() < m_backoffUntil) return MakeError(ErrorCode::LlmUnavailable, StateReason());
        break;
    case SupervisorState::Stopped:
    case SupervisorState::Starting:
        break;
    }

    if (!PreflightLocked()) return MakeError(ErrorCode::LlmUnavailable, StateReason());
    if (auto st = SpawnLocked(); !st) {
        if (st.Code() == ErrorCode::Cancelled) return MakeError(ErrorCode::LlmUnavailable, "shutdown");
        spdlog::error("[llm] 啟動 llama-server 失敗: {}", st.GetError().ToString());
        OnCrashLocked("spawn failed");
        return MakeError(ErrorCode::LlmUnavailable, StateReason());
    }
    if (!WaitForHealthyLocked(cancel)) {
        if (m_shutdown.load()) {
            KillLocked();
            return MakeError(ErrorCode::LlmUnavailable, "shutdown");
        }
        if (cancel.stop_requested()) {   // 呼叫端停止（服務關機）：不算崩潰、不計入重啟次數
            KillLocked();
            SetState(SupervisorState::Stopped, "cancelled");
            return MakeError(ErrorCode::Cancelled, "cold start cancelled");
        }
        OnCrashLocked("health-timeout");
        return MakeError(ErrorCode::LlmUnavailable, StateReason());
    }
    SetState(SupervisorState::Running, "");
    NotifyActivity();
    return Ok();
}

void LlamaServerSupervisor::ReportConnectionFailure()
{
    std::lock_guard lk{m_mutex};
    if (m_state.load() == SupervisorState::Running && ProcessExitedLocked()) OnCrashLocked("connection lost");
}

void LlamaServerSupervisor::Tick()
{
    std::unique_lock lk{m_mutex, std::try_to_lock};
    if (!lk.owns_lock()) return;   // T5 正在冷啟動；不阻塞 Watchdog
    if (m_state.load() != SupervisorState::Running) return;
    if (ProcessExitedLocked()) {
        OnCrashLocked("process exited");
        return;
    }
    const int64_t idleMs = SteadyNowMs() - m_lastActivityMs.load(std::memory_order_relaxed);
    if (idleMs >= std::chrono::duration_cast<std::chrono::milliseconds>(m_cfg.idleUnload).count()) {
        KillLocked();
        SetState(SupervisorState::Stopped, "idle-unloaded");
        spdlog::info("[llm] llama-server 閒置 {} 秒，已卸載以釋放 VRAM", idleMs / 1000);
    }
}

void LlamaServerSupervisor::RequestManualRestart()
{
    std::lock_guard lk{m_mutex};
    {
        std::lock_guard ik{m_infoMutex};
        m_restarts.clear();
    }
    m_backoffUntil = {};
    KillLocked();
    SetState(SupervisorState::Stopped, "manual-restart");
    (void)PreflightLocked();
}

void LlamaServerSupervisor::Shutdown() noexcept
{
    m_shutdown.store(true, std::memory_order_release);   // 先中止冷啟動等待，再取鎖
    std::lock_guard lk{m_mutex};
    KillLocked();
    if (m_state.load() != SupervisorState::Unavailable) SetState(SupervisorState::Stopped, "shutdown");
}

} // namespace cairn::llm
