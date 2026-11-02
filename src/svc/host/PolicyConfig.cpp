#include "host/PolicyConfig.h"

#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

namespace cairn::host {

using nlohmann::json;
namespace fs = std::filesystem;

HostConfig DefaultHostConfig(const fs::path& dataDir, const fs::path& exeDir)
{
    HostConfig c;
    c.dbPath            = dataDir / "cairn.db";
    c.llamaServerPath   = exeDir / "llama" / "llama-server.exe";
    c.modelPath         = dataDir / "models" / "qwen2.5-3b-instruct-q4_k_m.gguf";
    c.fallbackModelPath = dataDir / "models" / "qwen2.5-1.5b-instruct-q4_k_m.gguf";
    c.logFile           = dataDir / "logs" / "cairn-svc.log";
    c.forcedDryrunRules = {"R-T1574-001", "R-T1543-001", "R-T1053-001", "R-T1071-001"};
    // demo 預設關閉自動回應（part1 §5）；與 config/policy.default.json 一致
    c.engine.autoResponseEnabled = false;
    return c;
}

namespace {

// 依路徑取得子節點；任何一層不存在或型別不符回傳 nullptr。
const json* At(const json& root, std::initializer_list<const char*> path)
{
    const json* cur = &root;
    for (const char* k : path) {
        if (!cur->is_object()) return nullptr;
        auto it = cur->find(k);
        if (it == cur->end()) return nullptr;
        cur = &*it;
    }
    return cur;
}

class Reader {
public:
    Reader(const json& root, std::vector<std::string>& warnings) : m_root(root), m_warn(warnings) {}

    template <class T>
    void Num(std::initializer_list<const char*> path, T& out, double scale = 1.0)
    {
        const json* v = At(m_root, path);
        if (!v) return;
        if (!v->is_number()) {
            Warn(path, "應為數字");
            return;
        }
        const double d = v->get<double>() * scale;
        if (d < 0) {
            Warn(path, "不得為負數");
            return;
        }
        out = static_cast<T>(d);
    }

    void Bool(std::initializer_list<const char*> path, bool& out)
    {
        const json* v = At(m_root, path);
        if (!v) return;
        if (!v->is_boolean()) {
            Warn(path, "應為布林值");
            return;
        }
        out = v->get<bool>();
    }

    void Str(std::initializer_list<const char*> path, std::string& out)
    {
        const json* v = At(m_root, path);
        if (!v) return;
        if (!v->is_string()) {
            Warn(path, "應為字串");
            return;
        }
        out = v->get<std::string>();
    }

    void Path(std::initializer_list<const char*> path, fs::path& out, const EnvExpander& expand)
    {
        std::string s;
        Str(path, s);
        if (s.empty()) return;
        const std::string e = expand ? expand(s) : s;
        out = fs::path(std::u8string(e.begin(), e.end()));   // UTF-8 → path（Windows 上不經 ANSI code page）
    }

    void StrList(std::initializer_list<const char*> path, std::vector<std::string>& out)
    {
        const json* v = At(m_root, path);
        if (!v) return;
        if (!v->is_array()) {
            Warn(path, "應為字串陣列");
            return;
        }
        std::vector<std::string> tmp;
        for (const auto& e : *v) {
            if (!e.is_string()) {
                Warn(path, "陣列元素應為字串");
                return;
            }
            tmp.push_back(e.get<std::string>());
        }
        out = std::move(tmp);
    }

private:
    void Warn(std::initializer_list<const char*> path, const char* why)
    {
        std::string p;
        for (const char* k : path) {
            if (!p.empty()) p += '.';
            p += k;
        }
        m_warn.push_back(p + "：" + why + "，採用預設值");
    }

    const json&               m_root;
    std::vector<std::string>& m_warn;
};

} // namespace

Result<HostConfig> ParsePolicyJson(std::string_view jsonText, const fs::path& dataDir, const fs::path& exeDir,
                                   const EnvExpander& expand)
{
    json root = json::parse(jsonText.begin(), jsonText.end(), nullptr, /*allow_exceptions*/ false,
                            /*ignore_comments*/ true);
    if (root.is_discarded() || !root.is_object()) {
        return MakeError(ErrorCode::InvalidArgument, "policy.json 不是合法的 JSON 物件");
    }

    HostConfig c = DefaultHostConfig(dataDir, exeDir);
    Reader r{root, c.warnings};

    // ---- response / engine ----
    r.Bool({"response", "auto_response_enabled"}, c.engine.autoResponseEnabled);
    int64_t ttlS = c.tokenTtl.count();
    r.Num({"response", "confirmation_token_ttl_seconds"}, ttlS);
    c.tokenTtl = std::chrono::seconds{ttlS > 0 ? ttlS : 60};

    r.Bool({"engine", "blocked_default_actions"}, c.engine.blockedDefaultActions);
    r.StrList({"engine", "never_target_images"}, c.engine.neverTargetImages);
    r.Num({"engine", "max_evidence_events_per_alert"}, c.engine.maxEvidenceEventsPerAlert);
    r.Num({"engine", "sequence_expire_slack_ms"}, c.engine.sequenceExpireSlackMs);

    r.Num({"process_tree", "max_nodes"}, c.engine.treeLimits.maxNodes);
    r.Num({"process_tree", "max_trees"}, c.engine.treeLimits.maxTrees);
    r.Num({"process_tree", "max_orphans_pending"}, c.engine.treeLimits.maxOrphansPending);
    r.Num({"process_tree", "orphan_grace_ms"}, c.engine.treeLimits.orphanGraceMs);
    r.Num({"process_tree", "retention_after_exit_minutes"}, c.engine.treeLimits.retentionAfterExitMs, 60'000.0);
    r.Num({"process_tree", "resolved_retention_minutes"}, c.engine.resolvedRetentionMs, 60'000.0);
    r.StrList({"process_tree", "boundary_images"}, c.engine.treeBoundaryImages);

    // ---- learning ----
    r.Bool({"learning_mode", "enabled"}, c.learningEnabled);
    r.Num({"learning_mode", "total_days"}, c.learningDays);
    r.StrList({"learning_mode", "forced_dryrun_rules"}, c.forcedDryrunRules);
    r.Num({"learning_mode", "suggestion_min_dryrun_hits"}, c.suggestionMinDryrunHits);

    // ---- telemetry ----
    r.Bool({"telemetry", "sources", "sysmon"}, c.sysmonEnabled);
    r.Bool({"telemetry", "sources", "powershell_4104"}, c.powershellEnabled);
    r.Bool({"telemetry", "sources", "security_4688_fallback"}, c.securityFallback);
    r.Num({"telemetry", "silence_timeout_seconds"}, c.silenceTimeoutMs, 1000.0);
    r.Num({"telemetry", "resubscribe_backoff_max_seconds"}, c.resubscribeBackoffMaxMs, 1000.0);
    r.Num({"telemetry", "max_reconnect_attempts"}, c.maxReconnectAttempts);
    r.Num({"telemetry", "analysis_queue_capacity"}, c.analysisQueueCapacity);
    r.Num({"telemetry", "interner_max_entries"}, c.internerMaxEntries);

    // ---- storage ----
    r.Path({"storage", "db_path"}, c.dbPath, expand);
    r.Num({"storage", "write_queue_capacity"}, c.writeQueueCapacity);
    r.Num({"storage", "batch_max_rows"}, c.batchMaxRows);
    r.Num({"storage", "batch_max_age_ms"}, c.batchMaxAgeMs);
    r.Num({"storage", "busy_retries"}, c.busyRetries);
    r.Num({"storage", "retention_interval_minutes"}, c.retentionIntervalMs, 60'000.0);
    r.Num({"storage", "events_retention_days"}, c.eventTtlMs, 86'400'000.0);
    r.Num({"storage", "alerts_retention_days"}, c.alertTtlMs, 86'400'000.0);
    r.Num({"storage", "health_retention_days"}, c.healthTtlMs, 86'400'000.0);
    r.Num({"storage", "max_db_size_mb"}, c.maxDbBytes, 1024.0 * 1024.0);

    // ---- llm ----
    r.Bool({"llm", "enabled"}, c.llmEnabled);
    r.Path({"llm", "server_path"}, c.llamaServerPath, expand);
    r.Path({"llm", "model_path"}, c.modelPath, expand);
    r.Path({"llm", "fallback_model_path"}, c.fallbackModelPath, expand);
    r.Num({"llm", "port"}, c.llmPort);
    r.Num({"llm", "ctx_size"}, c.llmCtxSize);
    r.Num({"llm", "gpu_layers"}, c.llmGpuLayers);
    int64_t idle = c.llmIdleUnload.count();
    r.Num({"llm", "idle_unload_seconds"}, idle);
    c.llmIdleUnload = std::chrono::seconds{idle};
    r.Num({"llm", "max_restarts_per_hour"}, c.llmMaxRestartsPerHour);
    r.Num({"llm", "job_memory_limit_mb"}, c.llmJobMemoryBytes, 1024.0 * 1024.0);
    r.Num({"llm", "min_score_for_narrative"}, c.llmMinScoreMilli, 1000.0);
    r.Num({"llm", "queue_capacity"}, c.llmQueueCapacity);
    if (c.llmCtxSize < 8192) {
        c.warnings.push_back("llm.ctx_size < 8192 會使 prompt 溢出（SDD-03 §7.2.2），已改為 8192");
        c.llmCtxSize = 8192;
    }

    // ---- health ----
    r.Num({"health", "sample_interval_seconds"}, c.healthSampleSeconds);
    r.Num({"health", "watchdog_interval_seconds"}, c.watchdogIntervalSeconds);
    if (c.healthSampleSeconds <= 0) c.healthSampleSeconds = 10;
    if (c.watchdogIntervalSeconds <= 0) c.watchdogIntervalSeconds = 5;

    // ---- logging ----
    r.Str({"logging", "level"}, c.logLevel);
    r.Path({"logging", "file"}, c.logFile, expand);
    r.Num({"logging", "max_file_mb"}, c.logMaxFileBytes, 1024.0 * 1024.0);
    r.Num({"logging", "max_files"}, c.logMaxFiles);
    r.Bool({"logging", "log_prompts"}, c.logPrompts);

    // 未知的頂層欄位：向前相容，只記錄
    static const char* kKnown[] = {"$comment", "format",  "scoring", "response", "learning_mode", "protection",
                                   "telemetry", "process_tree", "storage", "llm", "health", "ui",
                                   "logging", "engine"};
    for (auto it = root.begin(); it != root.end(); ++it) {
        bool known = false;
        for (const char* k : kKnown)
            if (it.key() == k) known = true;
        if (!known) c.warnings.push_back("未知的頂層欄位 " + it.key() + "（已忽略）");
    }
    return c;
}

HostConfig LoadPolicyFile(const fs::path& file, std::string_view builtinDefaultJson, const fs::path& dataDir,
                          const fs::path& exeDir, const EnvExpander& expand, bool& fellBack)
{
    fellBack = false;
    std::string text;
    {
        std::ifstream in(file, std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            text = ss.str();
        }
    }
    if (!text.empty()) {
        // UTF-8 BOM
        if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
            static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF) {
            text.erase(0, 3);
        }
        if (auto r = ParsePolicyJson(text, dataDir, exeDir, expand)) return std::move(r).Value();
    }

    // 缺失或損毀：寫入內建預設（損毀檔先保留為 .corrupt）並使用之
    fellBack = true;
    std::error_code ec;
    if (fs::exists(file, ec)) fs::rename(file, fs::path(file).concat(".corrupt"), ec);
    fs::create_directories(file.parent_path(), ec);
    if (!builtinDefaultJson.empty()) {
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(builtinDefaultJson.data(), static_cast<std::streamsize>(builtinDefaultJson.size()));
        if (auto r = ParsePolicyJson(builtinDefaultJson, dataDir, exeDir, expand)) {
            HostConfig c = std::move(r).Value();
            c.warnings.push_back("policy.json 缺失或損毀，已寫入內建預設");
            return c;
        }
    }
    HostConfig c = DefaultHostConfig(dataDir, exeDir);
    c.warnings.push_back("policy.json 缺失或損毀，使用程式內建預設");
    return c;
}

} // namespace cairn::host
