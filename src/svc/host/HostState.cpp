#include "host/HostState.h"

#include <fstream>
#include <limits>
#include <sstream>

#include <nlohmann/json.hpp>

namespace cairn::host {

using nlohmann::json;
namespace fs = std::filesystem;

namespace {
constexpr int64_t kDayMs   = 86'400'000;
constexpr int64_t kForever = std::numeric_limits<int64_t>::max();
} // namespace

std::string HostState::Serialize(const HostStateData& d)
{
    json ov = json::object();
    for (const auto& [k, v] : d.ruleOverrides) ov[k] = std::string(model::RuleStatusToString(v));
    json j{{"format", 1},
           {"install_ts", d.installTs},
           {"learning_finished", d.learningFinished},
           {"rule_overrides", std::move(ov)},
           // until_reboot 不持久化：重開機即解除（part3 §3.8.1 端點 19 的語意）
           {"paused_until_ms", d.pausedUntilMs == kForever ? 0 : d.pausedUntilMs},
           {"pause_reason", d.pausedUntilMs == kForever ? std::string{} : d.pauseReason},
           {"builtin_exclusions_seeded", d.builtinExclusionsSeeded}};
    return j.dump(2);
}

Result<HostStateData> HostState::Deserialize(std::string_view text)
{
    const json j = json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return MakeError(ErrorCode::InvalidArgument, "state.json 損毀");
    HostStateData d;
    d.installTs        = j.value("install_ts", int64_t{0});
    d.learningFinished = j.value("learning_finished", false);
    d.pausedUntilMs    = j.value("paused_until_ms", int64_t{0});
    d.pauseReason      = j.value("pause_reason", std::string{});
    d.builtinExclusionsSeeded = j.value("builtin_exclusions_seeded", false);
    if (auto it = j.find("rule_overrides"); it != j.end() && it->is_object()) {
        for (auto o = it->begin(); o != it->end(); ++o) {
            if (!o->is_string()) continue;
            if (auto s = model::RuleStatusFromString(o->get<std::string>())) d.ruleOverrides[o.key()] = *s;
        }
    }
    return d;
}

Status HostState::Load(int64_t nowMs)
{
    std::lock_guard lk{m_mutex};
    std::string text;
    {
        std::ifstream in(m_file, std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            text = ss.str();
        }
    }
    if (!text.empty()) {
        if (auto r = Deserialize(text)) {
            m_data = std::move(r).Value();
            if (m_data.installTs <= 0) m_data.installTs = nowMs;
            return Ok();
        }
        std::error_code ec;
        fs::rename(m_file, fs::path(m_file).concat(".corrupt"), ec);
    }
    m_data           = HostStateData{};
    m_data.installTs = nowMs;
    return SaveLocked();
}

HostStateData HostState::Snapshot() const
{
    std::lock_guard lk{m_mutex};
    return m_data;
}

Status HostState::SetRuleOverride(const std::string& ruleId, model::RuleStatus s)
{
    std::lock_guard lk{m_mutex};
    m_data.ruleOverrides[ruleId] = s;
    return SaveLocked();
}

Status HostState::FinishLearning()
{
    std::lock_guard lk{m_mutex};
    m_data.learningFinished = true;
    return SaveLocked();
}

Status HostState::MarkBuiltinExclusionsSeeded()
{
    std::lock_guard lk{m_mutex};
    m_data.builtinExclusionsSeeded = true;
    return SaveLocked();
}

Status HostState::SetPause(int64_t untilMs, std::string reason)
{
    std::lock_guard lk{m_mutex};
    m_data.pausedUntilMs = untilMs;
    m_data.pauseReason   = untilMs ? std::move(reason) : std::string{};
    return SaveLocked();
}

bool HostState::ExpirePauseIfDue(int64_t nowMs)
{
    std::lock_guard lk{m_mutex};
    if (m_data.pausedUntilMs == 0 || m_data.pausedUntilMs == kForever || nowMs < m_data.pausedUntilMs) return false;
    m_data.pausedUntilMs = 0;
    m_data.pauseReason.clear();
    (void)SaveLocked();
    return true;
}

bool HostState::LearningActive(int64_t nowMs, int totalDays, bool enabled) const
{
    std::lock_guard lk{m_mutex};
    if (!enabled || m_data.learningFinished || totalDays <= 0) return false;
    return nowMs < m_data.installTs + static_cast<int64_t>(totalDays) * kDayMs;
}

int HostState::LearningDay(int64_t nowMs) const
{
    std::lock_guard lk{m_mutex};
    if (nowMs <= m_data.installTs) return 1;
    return static_cast<int>((nowMs - m_data.installTs) / kDayMs) + 1;
}

bool HostState::Paused(int64_t nowMs) const
{
    std::lock_guard lk{m_mutex};
    return m_data.pausedUntilMs != 0 && nowMs < m_data.pausedUntilMs;
}

Status HostState::SaveLocked() const
{
    std::error_code ec;
    fs::create_directories(m_file.parent_path(), ec);
    const fs::path tmp = fs::path(m_file).concat(".tmp");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return MakeError(ErrorCode::IoError, "state.json: 無法寫入暫存檔");
        const std::string s = Serialize(m_data);
        out.write(s.data(), static_cast<std::streamsize>(s.size()));
        if (!out) return MakeError(ErrorCode::IoError, "state.json: 寫入失敗");
    }
    fs::rename(tmp, m_file, ec);   // 同一磁碟區內為原子替換
    if (ec) return MakeError(ErrorCode::IoError, "state.json: 改名失敗 " + ec.message());
    return Ok();
}

rules::StatusOverrides ComposeRuleOverrides(const HostStateData& state, const std::vector<std::string>& forcedDryrun,
                                            bool learningActive)
{
    rules::StatusOverrides o;
    if (learningActive)
        for (const auto& id : forcedDryrun) o[id] = model::RuleStatus::DryRun;
    for (const auto& [id, st] : state.ruleOverrides) o[id] = st;
    return o;
}

} // namespace cairn::host
