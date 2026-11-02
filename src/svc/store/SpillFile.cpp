#include "store/SpillFile.h"

#include <algorithm>
#include <chrono>
#include <fstream>

#include <nlohmann/json.hpp>

namespace cairn::store {

using nlohmann::json;

namespace {

json GuidJson(const model::GuidValue& g) { return g.IsNull() ? json(nullptr) : json(g.ToString()); }

model::GuidValue GuidFrom(const json& j)
{
    if (!j.is_string()) return {};
    return model::GuidValue::Parse(j.get<std::string>()).value_or(model::GuidValue{});
}

template <class T>
json Opt(const std::optional<T>& v)
{
    return v ? json(*v) : json(nullptr);
}

template <class T>
std::optional<T> OptFrom(const json& j, const char* key)
{
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return std::nullopt;
    return it->get<T>();
}

json HitJson(const model::RuleHitRow& h)
{
    return json{{"ts", h.ts},
                {"rule_id", h.ruleId},
                {"root", GuidJson(h.rootProcessGuid)},
                {"event_id", Opt(h.eventId)},
                {"alert_id", Opt(h.alertId)},
                {"delta", h.scoreDeltaMilli},
                {"dryrun", h.dryrun},
                {"suppressed", h.suppressed},
                {"suppressed_by", Opt(h.suppressedBy)},
                {"rule_hash", h.ruleHash}};
}

model::RuleHitRow HitFrom(const json& j)
{
    model::RuleHitRow h;
    h.ts              = j.value("ts", int64_t{0});
    h.ruleId          = j.value("rule_id", std::string{});
    h.rootProcessGuid = GuidFrom(j.value("root", json(nullptr)));
    h.eventId         = OptFrom<int64_t>(j, "event_id");
    h.alertId         = OptFrom<int64_t>(j, "alert_id");
    h.scoreDeltaMilli = j.value("delta", int64_t{0});
    h.dryrun          = j.value("dryrun", false);
    h.suppressed      = j.value("suppressed", false);
    h.suppressedBy    = OptFrom<int64_t>(j, "suppressed_by");
    h.ruleHash        = j.value("rule_hash", std::string{});
    return h;
}

} // namespace

std::string SerializeSpill(const SpillRecord& rec)
{
    json j;
    if (const auto* a = std::get_if<model::AlertRow>(&rec)) {
        json events = json::array();
        for (const auto& e : a->events)
            events.push_back({{"event_id", e.eventId}, {"step", Opt(e.stepIndex)}, {"role", e.role}});
        json hits = json::array();
        for (const auto& h : a->hits) hits.push_back(HitJson(h));
        j = {{"type", "alert"},
             {"id", a->id},
             {"ts", a->ts},
             {"root", GuidJson(a->rootProcessGuid)},
             {"trigger", a->triggerProcessGuid ? GuidJson(*a->triggerProcessGuid) : json(nullptr)},
             {"severity", std::string(model::SeverityToString(a->severity))},
             {"score", a->scoreAtTriggerMilli},
             {"rule_ids", a->ruleIds},
             {"attack_ids", a->attackIds},
             {"title", a->title},
             {"summary", a->summary},
             {"ai_state", std::string(model::AiStateToString(a->aiState))},
             {"events", events},
             {"hits", hits}};
    } else {
        const auto& r = std::get<model::AuditRow>(rec);
        j = {{"type", "audit"},
             {"ts", r.ts},
             {"actor", r.actor},
             {"action", r.action},
             {"event_kind", r.eventKind},
             {"alert_id", Opt(r.alertId)},
             {"target", r.target},
             {"params", r.paramsJson},
             {"result", r.result},
             {"error", Opt(r.error)}};
    }
    return j.dump(-1, ' ', false, json::error_handler_t::replace);
}

Result<SpillRecord> DeserializeSpill(std::string_view line)
{
    const json j = json::parse(line, nullptr, /*allow_exceptions*/ false);
    if (!j.is_object()) return MakeError(ErrorCode::InvalidArgument, "spill: malformed line");
    try {
        const std::string type = j.value("type", std::string{});
        if (type == "alert") {
            model::AlertRow a;
            a.id                  = j.value("id", int64_t{0});
            a.ts                  = j.value("ts", int64_t{0});
            a.rootProcessGuid     = GuidFrom(j.value("root", json(nullptr)));
            if (j.contains("trigger") && j["trigger"].is_string()) a.triggerProcessGuid = GuidFrom(j["trigger"]);
            a.severity            = model::SeverityFromString(j.value("severity", std::string{"high"})).value_or(model::Severity::High);
            a.scoreAtTriggerMilli = j.value("score", int64_t{0});
            a.ruleIds             = j.value("rule_ids", std::vector<std::string>{});
            a.attackIds           = j.value("attack_ids", std::vector<std::string>{});
            a.title               = j.value("title", std::string{});
            a.summary             = j.value("summary", std::string{});
            a.aiState             = model::AiStateFromString(j.value("ai_state", std::string{"pending"})).value_or(model::AiState::Pending);
            for (const auto& e : j.value("events", json::array())) {
                model::AlertEventLink l;
                l.eventId   = e.value("event_id", int64_t{0});
                l.stepIndex = OptFrom<int32_t>(e, "step");
                l.role      = e.value("role", std::string{"evidence"});
                a.events.push_back(std::move(l));
            }
            for (const auto& h : j.value("hits", json::array())) a.hits.push_back(HitFrom(h));
            if (a.id == 0) return MakeError(ErrorCode::InvalidArgument, "spill: alert without id");
            return SpillRecord{std::move(a)};
        }
        if (type == "audit") {
            model::AuditRow r;
            r.ts         = j.value("ts", int64_t{0});
            r.actor      = j.value("actor", std::string{});
            r.action     = j.value("action", std::string{});
            r.eventKind  = j.value("event_kind", std::string{});
            r.alertId    = OptFrom<int64_t>(j, "alert_id");
            r.target     = j.value("target", std::string{});
            r.paramsJson = j.value("params", std::string{"{}"});
            r.result     = j.value("result", std::string{});
            r.error      = OptFrom<std::string>(j, "error");
            return SpillRecord{std::move(r)};
        }
    } catch (const std::exception& ex) {
        return MakeError(ErrorCode::InvalidArgument, std::string("spill: ") + ex.what());
    }
    return MakeError(ErrorCode::InvalidArgument, "spill: unknown record type");
}

SpillFile::SpillFile(std::filesystem::path dir) : m_dir(std::move(dir))
{
    std::error_code ec;
    std::filesystem::create_directories(m_dir, ec);
}

Status SpillFile::Append(const SpillRecord& rec)
{
    if (m_current.empty()) {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
        m_current = m_dir / ("spill-" + std::to_string(ms) + ".jsonl");
    }
    std::ofstream out(m_current, std::ios::binary | std::ios::app);
    if (!out) return MakeError(ErrorCode::IoError, "spill: open failed");
    const std::string line = SerializeSpill(rec);
    out.write(line.data(), static_cast<std::streamsize>(line.size()));
    out.put('\n');
    out.flush();
    if (!out) return MakeError(ErrorCode::IoError, "spill: write failed");
    return Ok();
}

bool SpillFile::HasPending() const
{
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(m_dir, ec))
        if (e.path().extension() == ".jsonl") return true;
    return false;
}

Result<size_t> SpillFile::Replay(const std::function<bool(const SpillRecord&)>& apply)
{
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(m_dir, ec))
        if (e.path().extension() == ".jsonl") files.push_back(e.path());
    std::sort(files.begin(), files.end());

    size_t applied = 0;
    for (const auto& f : files) {
        std::ifstream in(f, std::ios::binary);
        if (!in) continue;
        bool        allOk = true;
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            auto rec = DeserializeSpill(line);
            if (!rec) continue;   // 壞行：略過（不能因一行損毀而永遠卡住整個檔案）
            if (!apply(rec.Value())) {
                allOk = false;
                break;
            }
            ++applied;
        }
        in.close();
        if (!allOk) break;   // 保留此檔與之後的檔，下次再補（順序不可亂：稽核鏈依序）
        std::filesystem::remove(f, ec);
        if (f == m_current) m_current.clear();
    }
    return applied;
}

} // namespace cairn::store
