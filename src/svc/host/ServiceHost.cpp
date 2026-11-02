#include "host/ServiceHost.h"

#include <bcrypt.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <future>
#include <cstdio>
#include <limits>
#include <sstream>
#include <unordered_map>

#include <spdlog/spdlog.h>

#include "common/WinUtil.h"
#include "host/handlers/Convert.h"
#include "host/handlers/Handlers.h"
#include "llm/NarrativeEngine.h"
#include "prompt/AttackCatalog.h"
#include "telemetry/ProcessSnapshot.h"
#include "telemetry/SysmonProbe.h"
#include "tree/ProcessNode.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

namespace cairn::host {

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {

constexpr int64_t kForever = std::numeric_limits<int64_t>::max();

int64_t SteadyNowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

std::string ExpandEnv(std::string_view s)
{
    const std::wstring w = svc::Utf8ToWide(s);
    const DWORD n = ::ExpandEnvironmentStringsW(w.c_str(), nullptr, 0);
    if (n == 0) return std::string(s);
    std::wstring out(n, L'\0');
    ::ExpandEnvironmentStringsW(w.c_str(), out.data(), n);
    while (!out.empty() && out.back() == L'\0') out.pop_back();
    return svc::WideToUtf8(out);
}

std::array<uint8_t, 16> Random16()
{
    std::array<uint8_t, 16> b{};
    ::BCryptGenRandom(nullptr, b.data(), static_cast<ULONG>(b.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return b;
}

std::string RandomTokenHex()
{
    static constexpr char kHex[] = "0123456789abcdef";
    const auto b = Random16();
    std::string s;
    s.reserve(32);
    for (auto x : b) {
        s.push_back(kHex[x >> 4]);
        s.push_back(kHex[x & 0xF]);
    }
    return s;
}

std::string HostName()
{
    wchar_t buf[256]{};
    DWORD n = 256;
    if (::GetComputerNameExW(ComputerNameDnsHostname, buf, &n)) return svc::WideToUtf8(std::wstring(buf, n));
    return "localhost";
}

// 記錄用：path → UTF-8（path::string() 在 Windows 上經 ANSI code page，非 ASCII 路徑會丟例外）
std::string U8(const fs::path& p)
{
    return svc::WideToUtf8(p.wstring());
}

std::string SourceHealthName(telemetry::SourceHealth h)
{
    switch (h) {
    case telemetry::SourceHealth::Stopped: return "stopped";
    case telemetry::SourceHealth::Healthy: return "healthy";
    case telemetry::SourceHealth::Silent: return "silent";
    case telemetry::SourceHealth::Reconnecting: return "reconnecting";
    case telemetry::SourceHealth::Failed: return "failed";
    }
    return "unknown";
}

double Percentile(std::vector<double> v, double p)
{
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t idx = static_cast<size_t>(std::min<double>(v.size() - 1, std::ceil(p * v.size()) - 1));
    return v[idx];
}

} // namespace

ServiceHost::ServiceHost() = default;

ServiceHost::~ServiceHost()
{
    if (!m_stopped.load()) Stop([](DWORD) {});
}

bool ServiceHost::LearningActiveNow() const
{
    return m_state && m_state->LearningActive(m_clock.NowMs(), m_cfg.learningDays, m_cfg.learningEnabled);
}

// ============================================================ 啟動（SDD-01 §2.6）

bool ServiceHost::Start(const svc::ProgressFn& progress, DWORD& exitCode)
{
    m_startedMs = m_clock.NowMs();
    m_dataDir   = svc::DataDir();
    m_exeDir    = svc::ExeDir();
    m_hostname  = HostName();
    m_interner  = std::make_unique<model::StringInterner>();
    m_dispatcher = std::make_unique<rpc::JsonRpcDispatcher>();

    // 1) ★ 第一步：Named Pipe 第一實例 = 單一實例鎖（先於任何對 cairn.db 的開啟）
    {
        auto pipe = rpc::PipeServer::Start(m_dispatcher.get());
        if (!pipe) {
            spdlog::critical("Named Pipe 建立失敗（另一個實例正在執行，或名稱被搶佔）：{}", pipe.GetError().ToString());
            exitCode = ERROR_SERVICE_ALREADY_RUNNING;
            return false;
        }
        m_pipe = std::move(pipe).Value();
    }
    progress(30'000);

    // 2) 設定（降級：缺失或損毀 → 內建預設）
    if (auto s = LoadConfig(); !s) spdlog::warn("設定載入問題：{}", s.GetError().ToString());
    m_state = std::make_unique<HostState>(m_dataDir / "state.json");
    if (auto s = m_state->Load(m_clock.NowMs()); !s) spdlog::warn("state.json：{}", s.GetError().ToString());
    progress(30'000);

    // 3) 資料庫（開庫 / migrate / spill 重放；損毀時 WriterThread 會自行改名重建）
    if (auto s = OpenStore(); !s) {
        spdlog::critical("資料庫無法開啟：{}", s.GetError().ToString());
        exitCode = ERROR_DATABASE_FAILURE;
        return false;
    }
    progress(30'000);

    // 4) 規則（全部失敗 = 致命：沒有規則的 EDR 比明確失敗更危險）
    if (auto s = LoadRules(/*initial*/ true); !s) {
        spdlog::critical("規則載入失敗，服務不啟動：{}", s.GetError().ToString());
        exitCode = ERROR_BAD_CONFIGURATION;
        return false;
    }
    SeedBuiltinExclusions();
    progress(30'000);

    // 5) 回應執行器（AnalysisEngine 的 IResponseSink）
    CreateResponder();

    // 6) 分析引擎（SetNextIds、既存程序快照）
    if (auto s = CreateEngine(); !s) {
        spdlog::critical("AnalysisEngine 建立失敗：{}", s.GetError().ToString());
        exitCode = ERROR_BAD_CONFIGURATION;
        return false;
    }
    progress(30'000);

    // 7) LLM（不在 START_PENDING 期間探活：冷啟動交給 T5 的 EnsureRunning）
    CreateLlm();

    // 8) RPC handlers（管線早已開啟；在此之前的請求會得到 METHOD_NOT_FOUND）
    RegisterRpc();

    // 9) 執行緒：Analysis 必須先於事件訂閱（訂閱一開事件即湧入）。佇列在執行緒啟動前建立（避免跨執行緒讀寫指標）
    m_analysisQueue  = std::make_unique<BlockingQueue<model::NormalizedEvent>>(m_cfg.analysisQueueCapacity);
    m_analysisThread = std::jthread([this](std::stop_token st) { AnalysisLoop(st); });
    m_analysisStarted = true;

    // 10) 事件來源（Sysmon 缺席 → Security 4688 備援，降級不致命）
    if (auto s = StartTelemetry(); !s) {
        spdlog::error("事件管線啟動失敗（降級執行）：{}", s.GetError().ToString());
        AddAnomaly("事件管線啟動失敗：" + s.GetError().context);
    }
    m_maintThread = std::jthread([this](std::stop_token st) { MaintenanceLoop(st); });

    spdlog::info("CairnAgent 已啟動：規則 {} 條、Sysmon {}、LLM {}", RuleInfos().size(),
                 m_sysmonMissing ? "缺席（4688 備援）" : "正常", m_cfg.llmEnabled ? "啟用" : "停用");
    return true;
}

Status ServiceHost::LoadConfig()
{
    m_rulesDir = m_dataDir / "rules";
    std::error_code ec;
    if (!fs::exists(m_rulesDir, ec)) {
        // 開發期：安裝前直接從執行檔旁或 repo 的 rules/ 讀
        for (const auto& c : {m_exeDir / "rules", m_exeDir / ".." / ".." / ".." / "rules"}) {
            if (fs::exists(c, ec)) {
                m_rulesDir = fs::weakly_canonical(c, ec);
                break;
            }
        }
    }
    m_cfg = LoadPolicyFile(m_dataDir / "policy.json", EmbeddedDefaultPolicy(), m_dataDir, m_exeDir, ExpandEnv,
                           m_policyFellBack);
    for (const auto& w : m_cfg.warnings) spdlog::warn("policy：{}", w);
    if (auto lvl = spdlog::level::from_str(m_cfg.logLevel); lvl != spdlog::level::off || m_cfg.logLevel == "off") {
        spdlog::set_level(lvl);
    }
    if (m_policyFellBack) AddAnomaly("policy.json 缺失或損毀，已使用內建預設");
    return Ok();
}

Status ServiceHost::OpenStore()
{
    store::WriterConfig wc;
    wc.dbPath        = m_cfg.dbPath;
    wc.queueCapacity = m_cfg.writeQueueCapacity;
    wc.batchMaxRows  = m_cfg.batchMaxRows;
    wc.batchMaxAgeMs = m_cfg.batchMaxAgeMs;
    wc.busyRetries   = m_cfg.busyRetries;
    wc.retention.intervalMs  = m_cfg.retentionIntervalMs;
    wc.retention.eventTtlMs  = m_cfg.eventTtlMs;
    wc.retention.alertTtlMs  = m_cfg.alertTtlMs;
    wc.retention.healthTtlMs = m_cfg.healthTtlMs;
    wc.retention.maxDbBytes  = m_cfg.maxDbBytes;
    CAIRN_TRY(m_writer, store::WriterThread::Create(wc, *m_interner, m_clock));
    CAIRN_CHECK(m_writer->Start());
    if (m_writer->UncleanStart()) AddAnomaly("上次服務未正常結束（已偵測並復原）");

    // 唯讀連線必須在 Writer 建好 schema 之後才開
    CAIRN_TRY(m_maintDb, store::ReadOnlyDb::Open(m_cfg.dbPath));
    CAIRN_TRY(m_llmDb, store::ReadOnlyDb::Open(m_cfg.dbPath));
    return Ok();
}

Status ServiceHost::LoadRules(bool initial)
{
    rules::RuleLoadOptions opts;
    {
        std::lock_guard lk{m_rulesMutex};
        opts.generation = ++m_ruleGeneration;
    }
    const bool learning = LearningActiveNow();
    opts.overrides = ComposeRuleOverrides(m_state->Snapshot(), m_cfg.forcedDryrunRules, learning);

    auto r = rules::LoadRuleDirectory(m_rulesDir, *m_interner, opts);
    if (!r) {
        AddAnomaly("規則載入失敗：" + r.GetError().context);
        return r.GetError();   // 呼叫端保留舊規則集
    }
    auto report = std::move(r).Value();
    for (const auto& fe : report.fileErrors) spdlog::error("規則檔錯誤：{}", fe);
    for (const auto& ri : report.rules)
        if (!ri.loadError.empty()) spdlog::error("規則 {} 載入失敗：{}", ri.id, ri.loadError);
    if (report.failed > 0) AddAnomaly(std::to_string(report.failed) + " 條規則載入失敗（其餘照常生效）");
    spdlog::info("規則載入：成功 {} 條、失敗 {} 條（{}）", report.loaded, report.failed, U8(m_rulesDir));

    {
        std::lock_guard lk{m_rulesMutex};
        m_ruleInfos = report.rules;
        m_ruleSig   = RuleDirSignature();
    }
    if (!initial) {
        auto rs = report.ruleSet;
        m_tasks.Post([rs](engine::AnalysisEngine& e) { e.ReplaceRuleSet(rs); });
    } else if (m_engine) {
        m_engine->ReplaceRuleSet(report.ruleSet);
    } else {
        // 引擎尚未建立：CreateEngine 會重新取用（暫存於 m_ruleInfos 以外的 ruleSet）
        m_tasks.Post([rs = report.ruleSet](engine::AnalysisEngine& e) { e.ReplaceRuleSet(rs); });
    }
    return Ok();
}

void ServiceHost::SeedBuiltinExclusions()
{
    if (m_state->Snapshot().builtinExclusionsSeeded) return;
    const fs::path file = m_rulesDir / "exclusions.default.yaml";
    auto r = rules::LoadExclusionsYaml(file);
    if (!r) {
        spdlog::warn("內建排除清單無法載入（{}）：{}", U8(file), r.GetError().ToString());
        return;
    }
    size_t ok = 0;
    // 最後一筆附完成回呼並等待：CreateEngine 緊接著從 DB 讀排除清單，必須看得到這些列
    //（ExclusionInsert 為 Urgent，WriterThread 依序提交，等最後一筆即可）
    auto done = std::make_shared<std::promise<void>>();
    auto fut  = done->get_future();
    const size_t total = r.Value().size();
    size_t i = 0;
    for (const auto& e : r.Value()) {
        model::ExclusionInsert ins;
        ins.kind        = e.kind;
        ins.value       = e.value;
        ins.scopeRuleId = e.scopeRuleId;
        ins.reason      = e.reason;
        ins.createdBy   = "builtin";
        ins.createdTs   = m_clock.NowMs();
        ins.expiresTs   = e.expiresTs;
        model::WriteCompletion cb;
        if (++i == total) cb = [done](Result<int64_t>) { done->set_value(); };
        if (m_writer->Post(model::WriteOp{std::move(ins), std::move(cb)})) ++ok;
    }
    if (total > 0 && fut.wait_for(5s) != std::future_status::ready) {
        spdlog::warn("內建排除寫入逾時；引擎稍後於下次排除清單變更時才會載入它們");
    }
    (void)m_state->MarkBuiltinExclusionsSeeded();
    spdlog::info("首次安裝：已寫入 {} 條內建排除", ok);
}

std::vector<rules::ExclusionEntry> ServiceHost::ReadExclusionsFromDb(store::ReadOnlyDb& db)
{
    std::vector<rules::ExclusionEntry> out;
    auto r = db.ListExclusions(m_clock.NowMs(), /*includeDisabled*/ false);
    if (!r) {
        spdlog::warn("讀取排除清單失敗：{}", r.GetError().ToString());
        return out;
    }
    for (const auto& e : r.Value())
        if (auto x = conv::ToEngineExclusion(e)) out.push_back(std::move(*x));
    return out;
}

Status ServiceHost::CreateEngine()
{
    engine::EnginePolicy pol = m_cfg.engine;
    pol.learningMode = LearningActiveNow();
    m_engineLearning = pol.learningMode;

    engine::AnalysisEngine::Deps deps;
    deps.interner  = m_interner.get();
    deps.writes    = m_writer.get();
    deps.alerts    = this;
    deps.responses = m_responses.get();   // 可為空 = 不自動回應
    deps.clock     = &m_clock;
    CAIRN_TRY(m_engine, engine::AnalysisEngine::Create(deps, pol));

    // ID 配發：顯式指定（SDD-02 §5.4）
    CAIRN_TRY(auto ids, m_maintDb->QueryMaxIds());
    m_engine->SetNextIds(ids.nextEventId, ids.nextAlertId);

    // 先前投遞的 ReplaceRuleSet（LoadRules 在引擎建立前執行）
    m_tasks.Drain(*m_engine);
    m_engine->ReplaceExclusions(ReadExclusionsFromDb(*m_maintDb));
    if (m_state->Paused(m_clock.NowMs())) m_engine->SetProtectionPaused(true);

    // 既存程序快照（part2 §2.4.1）：服務啟動前已在跑的程序也要有樹
    if (auto snap = telemetry::TakeProcessSnapshot()) {
        const auto& procs = snap.Value();
        std::unordered_map<uint32_t, const telemetry::SnapshotProcess*> byPid;
        for (const auto& p : procs) byPid[p.pid] = &p;
        std::vector<tree::SnapshotProcess> seed;
        seed.reserve(procs.size());
        for (const auto& p : procs) {
            tree::SnapshotProcess s;
            s.guid      = p.syntheticGuid;
            s.pid       = p.pid;
            s.parentPid = p.parentPid;
            s.image     = p.imagePath.empty() ? p.exeName : p.imagePath;
            s.startMs   = p.createMs;
            s.synthetic = true;
            // PID 重用防護：父程序的建立時間必須早於子程序
            if (auto it = byPid.find(p.parentPid); it != byPid.end() && it->second->pid != p.pid &&
                                                   (p.createMs == 0 || it->second->createMs <= p.createMs)) {
                s.parentGuid = it->second->syntheticGuid;
            }
            seed.push_back(std::move(s));
        }
        m_engine->SeedProcesses(seed);
        spdlog::info("既存程序快照：{} 個", seed.size());
    } else {
        spdlog::warn("程序快照失敗：{}", snap.GetError().ToString());
    }
    if (m_pipeline) m_pipeline->SetNextSeq(static_cast<uint64_t>(ids.nextEventId));
    return Ok();
}

void ServiceHost::CreateResponder()
{
    response::ResponseExecutorConfig rc;
    rc.dataDir  = m_dataDir;
    rc.tokenTtl = m_cfg.tokenTtl;
    auto r = response::ResponseExecutor::Create(rc, m_writer.get(), &m_clock);
    if (!r) {
        spdlog::error("ResponseExecutor 建立失敗（回應動作停用，偵測照常）：{}", r.GetError().ToString());
        AddAnomaly("回應執行器無法啟動：" + r.GetError().context);
    } else {
        m_responses = std::move(r).Value();
        if (auto s = m_responses->Start(); !s) {
            spdlog::error("ResponseExecutor 啟動失敗：{}", s.GetError().ToString());
            m_responses.reset();
        }
    }
    m_tokens = std::make_unique<response::ConfirmationTokenStore>(m_clock, Random16, 64, m_cfg.tokenTtl);
    m_undo   = std::make_unique<UndoStore>(m_clock);
}

void ServiceHost::CreateLlm()
{
    std::unique_ptr<llm::INarrativeEngine> narrative;
    if (m_cfg.llmEnabled) {
        llm::SupervisorConfig sc;
        sc.enabled   = true;
        sc.exePath   = m_cfg.llamaServerPath;
        std::error_code ec;
        sc.modelPath = (!fs::exists(m_cfg.modelPath, ec) && fs::exists(m_cfg.fallbackModelPath, ec)) ? m_cfg.fallbackModelPath
                                                                                                   : m_cfg.modelPath;
        sc.dataDir   = m_dataDir;
        sc.port      = m_cfg.llmPort;
        sc.ctxSize   = m_cfg.llmCtxSize;
        sc.gpuLayers = m_cfg.llmGpuLayers;
        sc.idleUnload = m_cfg.llmIdleUnload;
        sc.maxRestartsPerHour      = m_cfg.llmMaxRestartsPerHour;
        sc.processMemoryLimitBytes = m_cfg.llmJobMemoryBytes;
        if (auto sup = llm::LlamaServerSupervisor::Create(sc)) {
            m_llamaSup = std::move(sup).Value();
            if (auto eng = llm::LlamaHttpEngine::Create(m_llamaSup.get(), &llm::AttackCatalog::Builtin())) {
                narrative = std::move(eng).Value();
            } else {
                spdlog::error("LlamaHttpEngine 建立失敗：{}", eng.GetError().ToString());
            }
        } else {
            spdlog::error("LlamaServerSupervisor 建立失敗：{}", sup.GetError().ToString());
        }
    }
    if (!narrative) narrative = std::make_unique<llm::NullNarrativeEngine>();

    llm::LlmWorkerConfig wc;
    wc.enabled       = m_cfg.llmEnabled;
    wc.queueCapacity = m_cfg.llmQueueCapacity;
    wc.minScoreMilli = m_cfg.llmMinScoreMilli;
    if (auto w = llm::LlmWorker::Create(wc, std::move(narrative), m_llmDb.get(), m_writer.get())) {
        m_llm = std::move(w).Value();
        if (auto s = m_llm->Start(); !s) {
            spdlog::error("LlmWorker 啟動失敗：{}", s.GetError().ToString());
            m_llm.reset();
        }
    } else {
        spdlog::error("LlmWorker 建立失敗：{}", w.GetError().ToString());
    }
}

store::ReadOnlyDb* ServiceHost::ThreadReader()
{
    // 每個 RPC worker 執行緒一條唯讀連線（SQLITE_THREADSAFE=2：連線不可跨執行緒共用）
    thread_local std::unique_ptr<store::ReadOnlyDb> tl;
    thread_local int64_t lastFailMs = 0;
    if (!tl) {
        const int64_t now = m_clock.NowMs();
        if (now - lastFailMs < 1000) return nullptr;   // 開庫失敗時節流重試
        auto r = store::ReadOnlyDb::Open(m_cfg.dbPath);
        if (!r) {
            lastFailMs = now;
            spdlog::warn("RPC 唯讀連線開啟失敗：{}", r.GetError().ToString());
            return nullptr;
        }
        tl = std::move(r).Value();
    }
    return tl.get();
}

void ServiceHost::RegisterRpc()
{
    HandlerDeps d;
    d.host      = this;
    d.writes    = m_writer.get();
    d.responses = m_responses.get();
    d.analysis  = &m_tasks;
    d.state     = m_state.get();
    d.config    = &m_cfg;
    d.clock     = &m_clock;
    d.tokens    = m_tokens.get();
    d.undo      = m_undo.get();
    d.reader    = [this] { return ThreadReader(); };
    d.newToken  = [] { return RandomTokenHex(); };
    RegisterAllHandlers(*m_dispatcher, d);
    const size_t n = m_dispatcher->MethodCount();
    if (n != kExpectedRpcMethods) spdlog::error("RPC 方法數 {}，預期 {}", n, kExpectedRpcMethods);
    else spdlog::info("RPC：已註冊 {} 條方法", n);
}

Status ServiceHost::StartTelemetry()
{
    m_bookmarks = std::make_unique<telemetry::BookmarkStore>(m_dataDir / "bookmarks");
    m_pipeline  = std::make_unique<telemetry::EventPipeline>(*m_interner, *m_analysisQueue);
    if (m_engine) {
        // seq 與 events.id 同起點，方便除錯時對照
        auto ids = m_maintDb->QueryMaxIds();
        if (ids) m_pipeline->SetNextSeq(static_cast<uint64_t>(ids.Value().nextEventId));
    }

    const auto sysmon = telemetry::ProbeSysmon();
    m_sysmonMissing   = !(sysmon.installed && sysmon.running);

    auto add = [&](telemetry::EvtChannelSource::Config c) {
        c.silentThresholdMs    = m_cfg.silenceTimeoutMs;
        c.maxReconnectAttempts = m_cfg.maxReconnectAttempts;
        auto s = telemetry::EvtChannelSource::Create(std::move(c));
        if (!s) {
            spdlog::warn("事件來源建立失敗：{}", s.GetError().ToString());
            return false;
        }
        m_sources.push_back(s.Value().get());
        m_pipeline->AddSource(std::move(s).Value());
        return true;
    };

    if (m_cfg.sysmonEnabled && !m_sysmonMissing) add(telemetry::EvtChannelSource::SysmonConfig(m_bookmarks.get()));
    if (m_cfg.powershellEnabled) add(telemetry::EvtChannelSource::PowerShellConfig(m_bookmarks.get()));
    if (m_sysmonMissing) {
        AddAnomaly("Sysmon 未安裝或未執行：偵測覆蓋率大幅下降，已改用 Security 4688 備援");
        if (m_cfg.securityFallback) add(telemetry::EvtChannelSource::SecurityConfig(m_bookmarks.get()));
    }
    m_sourceWatch.assign(m_sources.size(), SourceWatch{});

    CAIRN_CHECK(m_pipeline->Start());
    for (const auto& r : m_pipeline->StartResults()) {
        if (!r.status) {
            spdlog::error("事件來源 {} 啟動失敗：{}", r.name, r.status.GetError().ToString());
            AddAnomaly("事件來源 " + r.name + " 啟動失敗");
            if (r.name == "sysmon" && m_cfg.securityFallback) m_sysmonMissing = true;
        }
    }
    {
        std::lock_guard lk{m_healthMutex};
        m_live.sysmonInstalled = sysmon.installed;
        m_live.sysmonVersion   = sysmon.version;
        m_live.sysmonState     = sysmon.StateString();
    }
    return Ok();
}

// ============================================================ T3：AnalysisThread

void ServiceHost::AnalysisLoop(std::stop_token st)
{
    int64_t lastTick = 0;
    for (;;) {
        m_tasks.Drain(*m_engine);

        auto* q = m_analysisQueue.get();   // Start() 在啟動本執行緒前建立，之後不變
        size_t n = 0;
        if (q) {
            // 一次最多處理 256 筆再回頭看任務與定時器，避免 RPC 任務在高事件率下餓死
            while (n < 256) {
                auto ev = n == 0 ? q->PopFor(50ms, st) : q->TryPop();
                if (!ev) break;
                m_engine->OnEvent(std::move(*ev));
                ++n;
            }
            m_eventsAnalyzed.fetch_add(n, std::memory_order_relaxed);
        } else {
            std::this_thread::sleep_for(20ms);
        }

        const int64_t now = m_clock.NowMs();
        if (now - lastTick >= 1000) {
            m_engine->OnTick(now);
            lastTick = now;
        }

        // 停止：上游（Normalizer）已停，排空分析佇列與任務後才離開
        if (st.stop_requested() && (!q || q->Size() == 0) && m_tasks.Pending() == 0 && n == 0) break;
    }
    // 最後一次 tick，讓分數快照落地
    m_tasks.Drain(*m_engine);
    m_engine->OnTick(m_clock.NowMs());
}

void ServiceHost::OnAlertRaised(const model::AlertRaised& a)
{
    if (!m_llm) return;
    if (a.scoreMilli < m_cfg.llmMinScoreMilli) return;
    model::NarrativeRequest req;
    req.alertId    = a.alertId;
    req.scoreMilli = a.scoreMilli;
    req.enqueuedTs = m_clock.NowMs();
    (void)m_llm->Enqueue(req);   // 非阻塞；滿載時 LlmWorker 自行以 skipped 回填
}

// ============================================================ T8：MaintenanceThread（Watchdog）

void ServiceHost::MaintenanceLoop(std::stop_token st)
{
    std::mutex              m;
    std::condition_variable_any cv;
    int64_t lastWatch = 0, lastSample = 0, lastSlow = 0;
    while (!st.stop_requested()) {
        const int64_t steady = SteadyNowMs();
        const int64_t now    = m_clock.NowMs();
        try {
            if (steady - lastWatch >= m_cfg.watchdogIntervalSeconds * 1000LL) {
                lastWatch = steady;
                WatchSources(steady);
                if (m_llm) m_llm->Tick();
                if (m_tokens) m_tokens->SweepExpired();
                if (m_responses) m_responses->SweepExpiredTokens();
                if (m_undo) m_undo->Sweep();
                CheckRuleDirectory(steady);
                CheckPolicyTimers(now);
            }
            if (steady - lastSample >= m_cfg.healthSampleSeconds * 1000LL) {
                lastSample = steady;
                SampleHealth(now);
            }
            if (steady - lastSlow >= 60'000) {   // 每分鐘：Sysmon 狀態
                lastSlow = steady;
                const auto s = telemetry::ProbeSysmon();
                std::lock_guard lk{m_healthMutex};
                if (m_live.sysmonState != s.StateString() && m_live.sysmonState == "ok") {
                    m_anomalies.push_back({now, std::string("Sysmon 狀態變為 ") + s.StateString()});
                }
                m_live.sysmonInstalled = s.installed;
                m_live.sysmonVersion   = s.version;
                m_live.sysmonState     = s.StateString();
            }
        } catch (const std::exception& ex) {
            spdlog::error("MaintenanceThread 例外：{}", ex.what());
        }
        std::unique_lock lk{m};
        cv.wait_for(lk, st, 1s, [] { return false; });
    }
}

void ServiceHost::WatchSources(int64_t steadyNow)
{
    for (size_t i = 0; i < m_sources.size(); ++i) {
        auto* s = m_sources[i];
        s->PersistBookmark();   // 每 5 秒落地書籤（重啟續讀）
        if (s->TakeChannelClearedFlag()) {
            // 事件記錄被清除 = 典型反鑑識行為（T1070.001），必須留下稽核
            AddAnomaly(std::string("事件通道 ") + std::string(s->Name()) + " 被清除");
            model::AuditRow a;
            a.ts        = m_clock.NowMs();
            a.actor     = "system";
            a.action    = "channel_cleared";
            a.eventKind = "channel_cleared";
            a.target    = std::string(s->Name());
            a.result    = "ok";
            (void)m_writer->Post(model::WriteOp{std::move(a), {}});
        }
        const auto h     = s->GetHealth();
        const int64_t last = s->LastEventSteadyMs();
        const bool silent = h == telemetry::SourceHealth::Silent ||
                            (h == telemetry::SourceHealth::Healthy && last > 0 && steadyNow - last > m_cfg.silenceTimeoutMs);
        const bool broken = h == telemetry::SourceHealth::Reconnecting || h == telemetry::SourceHealth::Failed;
        auto& w = m_sourceWatch[i];
        if ((silent || broken) && steadyNow >= w.nextAttemptSteadyMs) {
            spdlog::warn("事件來源 {} 狀態 {}，重新訂閱", s->Name(), SourceHealthName(h));
            if (auto r = s->Resubscribe(); r) {
                w.backoffMs = 5'000;
            } else {
                spdlog::error("重新訂閱 {} 失敗：{}", s->Name(), r.GetError().ToString());
                w.backoffMs = std::min<int64_t>(w.backoffMs * 2, m_cfg.resubscribeBackoffMaxMs);
            }
            w.nextAttemptSteadyMs = steadyNow + w.backoffMs;
        }
    }
}

void ServiceHost::SampleHealth(int64_t nowMs)
{
    // ---- CPU（本程序；所有核心合計後除以核心數）----
    FILETIME ct{}, et{}, kt{}, ut{};
    double cpu = 0.0;
    if (::GetProcessTimes(::GetCurrentProcess(), &ct, &et, &kt, &ut)) {
        auto to64 = [](const FILETIME& f) { return (static_cast<uint64_t>(f.dwHighDateTime) << 32) | f.dwLowDateTime; };
        const uint64_t total = to64(kt) + to64(ut);
        const int64_t wall   = SteadyNowMs();
        if (m_lastCpuWallMs > 0 && wall > m_lastCpuWallMs) {
            SYSTEM_INFO si{};
            ::GetSystemInfo(&si);
            const double cpuMs = static_cast<double>(total - m_lastCpuTime100ns) / 10'000.0;
            cpu = 100.0 * cpuMs / static_cast<double>(wall - m_lastCpuWallMs) / std::max<DWORD>(1, si.dwNumberOfProcessors);
        }
        m_lastCpuTime100ns = total;
        m_lastCpuWallMs    = wall;
    }
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    double privMb = 0.0;
    if (::GetProcessMemoryInfo(::GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        privMb = static_cast<double>(pmc.PrivateUsage) / (1024.0 * 1024.0);
    }
    double dbMb = 0.0;
    if (auto b = m_maintDb->DatabaseBytes()) dbMb = static_cast<double>(b.Value()) / (1024.0 * 1024.0);

    telemetry::PipelineStats ps{};
    if (m_pipeline) ps = m_pipeline->Stats();

    // 引擎統計：經 AnalysisThread 取（逾時不阻塞健康度取樣）
    engine::EngineStats es{};
    if (auto r = m_tasks.Run([](engine::AnalysisEngine& e) { return e.Stats(); }, 500ms)) es = r.Value();

    llm::LlmStatus ls{};
    if (m_llm) ls = m_llm->Status();

    const auto ws = m_writer->Stats();

    model::HealthRow row;
    row.ts             = nowMs;
    row.eventsIngested = static_cast<int64_t>(ps.ingested);
    row.eventsDropped  = static_cast<int64_t>(ps.droppedTotal + ws.queueDropped);
    row.eventsFiltered = static_cast<int64_t>(es.suppressedHits);
    row.queueDepth     = static_cast<int64_t>(ps.rawQueueDepth);
    row.cpuPercent     = cpu;
    row.privateBytesMb = privMb;
    row.dbSizeMb       = dbMb;
    {
        std::lock_guard lk{m_healthMutex};
        row.sysmonState = m_live.sysmonState;
    }
    row.llmState   = m_cfg.llmEnabled ? (ls.state.empty() ? "unavailable" : ls.state) : "unavailable";
    row.tier2P95Ms = es.tier2P95Ms;
    if (ls.p95Ms > 0) row.llmP95Ms = ls.p95Ms;
    (void)m_writer->Post(model::WriteOp{row, {}});

    // ---- LiveHealth 快取（RPC health.get 讀）----
    std::lock_guard lk{m_healthMutex};
    m_cpuSamples.push_back(cpu);
    while (m_cpuSamples.size() > 360) m_cpuSamples.pop_front();
    const double dtS = m_lastSampleMs > 0 ? (nowMs - m_lastSampleMs) / 1000.0 : 0.0;
    const uint64_t dIn  = ps.ingested >= m_lastIngested ? ps.ingested - m_lastIngested : 0;
    const uint64_t dDrop = ps.droppedTotal >= m_lastDropped ? ps.droppedTotal - m_lastDropped : 0;
    m_lastIngested = ps.ingested;
    m_lastDropped  = ps.droppedTotal;
    m_lastSampleMs = nowMs;

    m_live.startedMs     = m_startedMs;
    m_live.hostname      = m_hostname;
    m_live.providers.clear();
    for (auto* s : m_sources) m_live.providers.push_back({std::string(s->Name()), SourceHealthName(s->GetHealth())});
    m_live.llmState      = row.llmState;
    m_live.llmModelId    = ls.modelId;
    m_live.llmDevice     = m_cfg.llmGpuLayers > 0 ? "gpu" : "cpu";
    m_live.llmDetail     = ls.supervisorDetail;
    m_live.llmP95Ms      = ls.p95Ms;
    m_live.cpuP95Percent = Percentile(std::vector<double>(m_cpuSamples.begin(), m_cpuSamples.end()), 0.95);
    m_live.ramMb         = privMb;
    m_live.diskMb        = dbMb;
    m_live.eventsPerSec  = dtS > 0 ? static_cast<double>(dIn) / dtS : 0.0;
    m_live.dropRate      = (dIn + dDrop) > 0 ? static_cast<double>(dDrop) / static_cast<double>(dIn + dDrop) : 0.0;
    for (size_t i = 0; i < 4; ++i) m_live.droppedByPriority[i] = ps.droppedByPriority[i];
    m_live.tier2P95Ms    = es.tier2P95Ms;

    m_live.degradedReasons.clear();
    if (m_sysmonMissing) m_live.degradedReasons.push_back("sysmon_missing");
    if (ps.internerSaturated) m_live.degradedReasons.push_back("interner_saturated");
    if (ws.degraded) m_live.degradedReasons.push_back("db_write_degraded");
    if (es.degraded) m_live.degradedReasons.push_back("process_tree_limits");
    if (ps.droppedByPriority[0] + ps.droppedByPriority[1] > 0) m_live.degradedReasons.push_back("high_priority_drops");
    if (m_policyFellBack) m_live.degradedReasons.push_back("policy_default");
    {
        std::lock_guard rl{m_rulesMutex};
        for (const auto& r : m_ruleInfos)
            if (!r.loadError.empty()) {
                m_live.degradedReasons.push_back("rule_load_errors");
                break;
            }
    }
    m_live.degraded = !m_live.degradedReasons.empty();

    while (!m_anomalies.empty() && m_anomalies.front().ts < nowMs - 86'400'000) m_anomalies.pop_front();
    m_live.anomalies24h.assign(m_anomalies.begin(), m_anomalies.end());
}

std::string ServiceHost::RuleDirSignature() const
{
    std::ostringstream ss;
    std::error_code    ec;
    std::vector<std::string> parts;
    for (fs::directory_iterator it(m_rulesDir, ec), end; !ec && it != end; it.increment(ec)) {
        const auto& p = it->path();
        const auto ext = U8(p.extension());
        if (ext != ".yaml" && ext != ".yml") continue;
        const auto t  = fs::last_write_time(p, ec).time_since_epoch().count();
        const auto sz = fs::file_size(p, ec);
        parts.push_back(U8(p.filename()) + ":" + std::to_string(t) + ":" + std::to_string(sz));
    }
    std::sort(parts.begin(), parts.end());
    for (const auto& s : parts) ss << s << '|';
    return ss.str();
}

void ServiceHost::CheckRuleDirectory(int64_t steadyNow)
{
    // 輪詢 mtime + 2 秒 debounce（part2 §2.4.2；比 ReadDirectoryChangesW 簡單且不需額外執行緒）
    const std::string sig = RuleDirSignature();
    std::string current;
    {
        std::lock_guard lk{m_rulesMutex};
        current = m_ruleSig;
    }
    if (sig == current) {
        m_pendingRuleSig.clear();
        return;
    }
    if (sig != m_pendingRuleSig) {
        m_pendingRuleSig      = sig;
        m_pendingRuleSigSince = steadyNow;
        return;
    }
    if (steadyNow - m_pendingRuleSigSince < 2'000) return;
    m_pendingRuleSig.clear();
    spdlog::info("規則目錄變更，熱重載");
    if (auto s = LoadRules(/*initial*/ false); !s) {
        // 失敗保留舊規則集，但記住新簽章避免每 5 秒重試同一份壞檔
        std::lock_guard lk{m_rulesMutex};
        m_ruleSig = sig;
    }
}

void ServiceHost::CheckPolicyTimers(int64_t nowMs)
{
    // 定時暫停到期
    if (m_state->ExpirePauseIfDue(nowMs)) {
        m_tasks.Post([](engine::AnalysisEngine& e) { e.SetProtectionPaused(false); });
        AddAnomaly("暫停防護已到期，自動恢復");
    }
    // 學習期屆滿：關閉學習模式並重載規則（解除強制 dry-run）
    const bool learning = LearningActiveNow();
    if (m_engineLearning && !learning) {
        m_engineLearning = false;
        m_tasks.Post([](engine::AnalysisEngine& e) { e.SetLearningMode(false); });
        (void)LoadRules(/*initial*/ false);
        AddAnomaly("學習期結束，自動回應與完整規則集已生效");
    }
}

void ServiceHost::AddAnomaly(std::string message)
{
    spdlog::warn("異常：{}", message);
    std::lock_guard lk{m_healthMutex};
    m_anomalies.push_back({m_clock.NowMs(), std::move(message)});
    while (m_anomalies.size() > 200) m_anomalies.pop_front();
}

// ============================================================ IHostServices

LiveHealth ServiceHost::Health()
{
    std::lock_guard lk{m_healthMutex};
    LiveHealth h = m_live;
    h.startedMs  = m_startedMs;
    h.hostname   = m_hostname;
    if (h.providers.empty())
        for (auto* s : m_sources) h.providers.push_back({std::string(s->Name()), SourceHealthName(s->GetHealth())});
    return h;
}

std::vector<rules::RuleInfo> ServiceHost::RuleInfos()
{
    std::lock_guard lk{m_rulesMutex};
    return m_ruleInfos;
}

Result<rules::RuleInfo> ServiceHost::SetRuleStatus(const std::string& ruleId, model::RuleStatus s)
{
    {
        std::lock_guard lk{m_rulesMutex};
        const bool known = std::any_of(m_ruleInfos.begin(), m_ruleInfos.end(), [&](const auto& r) { return r.id == ruleId; });
        if (!known) return MakeError(ErrorCode::NotFound, "規則不存在：" + ruleId);
    }
    CAIRN_CHECK(m_state->SetRuleOverride(ruleId, s));
    CAIRN_CHECK(LoadRules(/*initial*/ false));
    std::lock_guard lk{m_rulesMutex};
    for (const auto& r : m_ruleInfos)
        if (r.id == ruleId) return r;
    return MakeError(ErrorCode::NotFound, "規則重載後不存在：" + ruleId);
}

Status ServiceHost::ReloadExclusions()
{
    store::ReadOnlyDb* db = ThreadReader();
    if (!db) return MakeError(ErrorCode::ServiceUnavailable, "唯讀連線不可用");
    auto entries = ReadExclusionsFromDb(*db);
    return m_tasks.RunVoid([entries = std::move(entries)](engine::AnalysisEngine& e) mutable {
        e.ReplaceExclusions(std::move(entries));
    }, 2s);
}

bool ServiceHost::EnqueueNarrative(const model::NarrativeRequest& req, bool reducedContext)
{
    if (!m_llm) return false;
    const auto r = m_llm->Enqueue(req, reducedContext);
    return r == llm::EnqueueResult::Accepted || r == llm::EnqueueResult::EvictedLowest || r == llm::EnqueueResult::Duplicate;
}

Status ServiceHost::SetProtectionPaused(bool paused, int64_t untilMs, const std::string& reason)
{
    CAIRN_CHECK(m_state->SetPause(paused ? untilMs : 0, reason));
    return m_tasks.RunVoid([paused](engine::AnalysisEngine& e) { e.SetProtectionPaused(paused); }, 2s);
}

Status ServiceHost::FinishLearning()
{
    CAIRN_CHECK(m_state->FinishLearning());
    m_engineLearning = false;
    CAIRN_CHECK(m_tasks.RunVoid([](engine::AnalysisEngine& e) { e.SetLearningMode(false); }, 2s));
    return LoadRules(/*initial*/ false);   // 解除學習期強制 dry-run
}

// ============================================================ 關機（SDD-01 §2.5.4）

void ServiceHost::Stop(const svc::ProgressFn& progress) noexcept
{
    if (m_stopped.exchange(true)) return;
    spdlog::info("CairnAgent 停止中…");

    // 階段 1：維護執行緒最先停（它會用到 Writer 與唯讀連線）
    if (m_maintThread.joinable()) {
        m_maintThread.request_stop();
        m_maintThread.join();
    }
    progress(30'000);

    // 階段 1：RPC —— 必須先於任何下游工作者（卡在 ResponseExecutor 的 RPC 執行緒會讓 join 掛住）
    if (m_pipe) m_pipe->Stop();
    progress(30'000);

    // 階段 1：關上水龍頭（Stop 阻塞至 in-flight 回呼結束）
    if (m_pipeline) m_pipeline->StopSources();
    for (auto* s : m_sources) s->PersistBookmark();
    progress(30'000);

    // 階段 2：Normalizer 排空 → Analysis 排空
    if (m_pipeline) m_pipeline->StopNormalizer();
    if (m_analysisThread.joinable()) {
        m_analysisThread.request_stop();
        m_analysisThread.join();
    }
    m_tasks.Close();
    progress(30'000);

    // 階段 3：慢速工作者 —— LLM 可粗暴中止；回應動作不可半途中止（給它做完當前這一個）
    if (m_llm) m_llm->Stop();
    progress(30'000);
    if (m_responses) m_responses->Stop();
    progress(30'000);

    // 階段 4：最後才停寫入者（COMMIT 最後一批 → wal_checkpoint(TRUNCATE) → close）
    m_maintDb.reset();
    m_llmDb.reset();
    if (m_writer) m_writer->Stop();
    progress(30'000);

    // 階段 5：子程序（Job Object 關閉 → llama-server 被 OS 終止）
    if (m_llamaSup) m_llamaSup->Shutdown();
    spdlog::info("CairnAgent 已停止");
    spdlog::default_logger()->flush();
}

} // namespace cairn::host
