#include "store/ReadOnlyDb.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <map>
#include <set>
#include <unordered_map>
#include <variant>

#include <nlohmann/json.hpp>

#include "store/Sha256.h"

namespace cairn::store {

namespace {

using Param = std::variant<int64_t, std::string>;
constexpr int64_t kDayMs = 86'400'000;
constexpr auto    kQueryBudget = std::chrono::milliseconds(2000);

// 每個公開方法的查詢上限（SDD-02 §6.5 長查詢保護）
struct DeadlineScope {
    SqliteDb& db;
    explicit DeadlineScope(SqliteDb& d) : db(d) { db.SetQueryDeadline(kQueryBudget); }
    ~DeadlineScope() { db.SetQueryDeadline(std::chrono::milliseconds(0)); }
};

void BindAll(Stmt& st, const std::vector<Param>& ps)
{
    int i = 1;
    for (const auto& p : ps) {
        if (const auto* v = std::get_if<int64_t>(&p)) st.Bind(i, *v);
        else st.BindText(i, std::get<std::string>(p));
        ++i;
    }
}

std::vector<std::string> ParseJsonStringArray(const std::string& s)
{
    std::vector<std::string> out;
    const auto j = nlohmann::json::parse(s, nullptr, false);
    if (!j.is_array()) return out;
    for (const auto& e : j)
        if (e.is_string()) out.push_back(e.get<std::string>());
    return out;
}

// LIKE 的萬用字元跳脫（ESCAPE '\'）
std::string LikeContains(std::string_view q)
{
    std::string out = "%";
    for (char c : q) {
        char lc = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        if (lc == '%' || lc == '_' || lc == '\\') out.push_back('\\');
        out.push_back(lc);
    }
    out.push_back('%');
    return out;
}

std::string Placeholders(size_t n)
{
    std::string s;
    for (size_t i = 0; i < n; ++i) s += (i ? ",?" : "?");
    return s;
}

// events 的欄位清單（ReadEvent 依此順序讀取）
constexpr std::string_view kEventCols =
    "e.id,e.ts,e.source,e.source_event_id,e.event_type,e.priority,e.process_guid,e.parent_process_guid,"
    "e.root_process_guid,e.pid,e.image,e.parent_image,e.command_line,e.parent_command_line,e.user_name,"
    "e.integrity_level,e.sha256,e.signature_signer,e.signature_valid,e.target_process_guid,e.target_image,"
    "e.granted_access,e.target_filename,e.registry_path,e.registry_details,e.dest_ip,e.dest_port,e.dest_hostname,"
    "e.query_name,e.query_results,e.pipe_name,e.script_block,e.score_delta";
constexpr int kEventColCount = 33;

EventRecord ReadEvent(const Stmt& st, int o = 0)
{
    EventRecord e;
    e.id                = st.Int64(o + 0);
    e.ts                = st.Int64(o + 1);
    e.source            = st.Text(o + 2);
    e.sourceEventId     = static_cast<int32_t>(st.Int64(o + 3));
    e.eventType         = st.Text(o + 4);
    e.priority          = static_cast<int32_t>(st.Int64(o + 5));
    e.processGuid       = st.OptText(o + 6);
    e.parentProcessGuid = st.OptText(o + 7);
    e.rootProcessGuid   = st.OptText(o + 8);
    e.pid               = static_cast<uint32_t>(st.Int64(o + 9));
    e.image             = st.OptText(o + 10);
    e.parentImage       = st.OptText(o + 11);
    e.commandLine       = st.OptText(o + 12);
    e.parentCommandLine = st.OptText(o + 13);
    e.userName          = st.OptText(o + 14);
    e.integrityLevel    = st.OptText(o + 15);
    e.sha256            = st.OptText(o + 16);
    e.signer            = st.OptText(o + 17);
    if (auto v = st.OptInt64(o + 18)) e.signatureValid = (*v != 0);
    e.targetProcessGuid = st.OptText(o + 19);
    e.targetImage       = st.OptText(o + 20);
    e.grantedAccess     = st.OptInt64(o + 21);
    e.targetFilename    = st.OptText(o + 22);
    e.registryPath      = st.OptText(o + 23);
    e.registryDetails   = st.OptText(o + 24);
    e.destIp            = st.OptText(o + 25);
    e.destPort          = st.OptInt64(o + 26);
    e.destHostname      = st.OptText(o + 27);
    e.queryName         = st.OptText(o + 28);
    e.queryResults      = st.OptText(o + 29);
    e.pipeName          = st.OptText(o + 30);
    e.scriptBlock       = st.OptText(o + 31);
    e.scoreDeltaMilli   = st.Int64(o + 32);
    return e;
}

constexpr std::string_view kNodeCols =
    "p.process_guid,p.parent_process_guid,p.root_process_guid,p.pid,p.image,p.command_line,p.user_name,"
    "p.integrity_level,p.sha256,p.signature_signer,p.signature_valid,p.start_ts,p.end_ts,p.event_count,"
    "p.is_terminated_by_us";

ProcessNodeRecord ReadNode(const Stmt& st, int o = 0)
{
    ProcessNodeRecord n;
    n.processGuid       = st.Text(o + 0);
    n.parentProcessGuid = st.OptText(o + 1);
    n.rootProcessGuid   = st.Text(o + 2);
    n.pid               = static_cast<uint32_t>(st.Int64(o + 3));
    n.image             = st.OptText(o + 4);
    n.commandLine       = st.OptText(o + 5);
    n.userName          = st.OptText(o + 6);
    n.integrityLevel    = st.OptText(o + 7);
    n.sha256            = st.OptText(o + 8);
    n.signer            = st.OptText(o + 9);
    if (auto v = st.OptInt64(o + 10)) n.signatureValid = (*v != 0);
    n.startTs           = st.Int64(o + 11);
    n.endTs             = st.OptInt64(o + 12);
    n.eventCount        = st.Int64(o + 13);
    n.terminatedByUs    = st.Int64(o + 14) != 0;
    n.placeholder       = (n.pid == 0);
    return n;
}

constexpr std::string_view kAlertCols =
    "a.id,a.ts,a.root_process_guid,a.trigger_process_guid,a.severity,a.score_at_trigger,a.rule_ids,a.attack_ids,"
    "a.title,a.summary,a.ai_state,a.ai_narrative,a.ai_recommendation,a.ai_confidence,a.ai_attack_ids,a.ai_model_id,"
    "a.ai_latency_ms,a.actions_taken,a.analyst_verdict,a.analyst_note,a.verdict_ts";

AlertRecord ReadAlert(const Stmt& st)
{
    AlertRecord a;
    a.id                  = st.Int64(0);
    a.ts                  = st.Int64(1);
    a.rootProcessGuid     = st.Text(2);
    a.triggerProcessGuid  = st.OptText(3);
    a.severity            = st.Text(4);
    a.scoreAtTriggerMilli = st.Int64(5);
    a.ruleIds             = ParseJsonStringArray(st.Text(6));
    if (auto v = st.OptText(7)) a.attackIds = ParseJsonStringArray(*v);
    a.title               = st.Text(8);
    a.summary             = st.OptText(9);
    a.aiState             = st.Text(10);
    a.aiNarrative         = st.OptText(11);
    a.aiRecommendation    = st.OptText(12);
    a.aiConfidence        = st.OptDouble(13);
    if (auto v = st.OptText(14)) a.aiAttackIds = ParseJsonStringArray(*v);
    a.aiModelId           = st.OptText(15);
    a.aiLatencyMs         = st.OptInt64(16);
    a.actionsTakenJson    = st.Text(17);
    a.analystVerdict      = st.OptText(18);
    a.analystNote         = st.OptText(19);
    a.verdictTs           = st.OptInt64(20);
    return a;
}

RuleHitRecord ReadHit(const Stmt& st)
{
    RuleHitRecord h;
    h.id              = st.Int64(0);
    h.ts              = st.Int64(1);
    h.ruleId          = st.Text(2);
    h.rootProcessGuid = st.Text(3);
    h.eventId         = st.OptInt64(4);
    h.alertId         = st.OptInt64(5);
    h.scoreDeltaMilli = st.Int64(6);
    h.dryrun          = st.Int64(7) != 0;
    h.suppressed      = st.Int64(8) != 0;
    h.suppressedBy    = st.OptInt64(9);
    h.ruleHash        = st.Text(10);
    return h;
}

AuditRecord ReadAudit(const Stmt& st)
{
    AuditRecord a;
    a.id         = st.Int64(0);
    a.ts         = st.Int64(1);
    a.actor      = st.Text(2);
    a.action     = st.Text(3);
    a.eventKind  = st.Text(4);
    a.alertId    = st.OptInt64(5);
    a.target     = st.OptText(6);
    a.paramsJson = st.Text(7);
    a.result     = st.Text(8);
    a.error      = st.OptText(9);
    a.prevHash   = st.Text(10);
    a.rowHash    = st.Text(11);
    return a;
}
constexpr std::string_view kAuditCols =
    "id,ts,actor,action,event_kind,alert_id,target,params,result,error,prev_hash,row_hash";

std::string Utf8Prefix(const std::string& s, size_t maxBytes)
{
    if (s.size() <= maxBytes) return s;
    size_t cut = maxBytes;
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
    return s.substr(0, cut) + "…";
}

constexpr std::string_view kStatusExpr =
    "(CASE WHEN a.analyst_verdict IS NOT NULL THEN 'resolved'"
    " WHEN s.state = 'blocked' THEN 'auto_blocked' ELSE 'pending' END)";

} // namespace

std::string BaseName(std::string_view path)
{
    const size_t p = path.find_last_of("\\/");
    return std::string(p == std::string_view::npos ? path : path.substr(p + 1));
}

std::string SummarizeEvent(const EventRecord& e)
{
    auto v = [](const std::optional<std::string>& s) { return s ? *s : std::string{}; };
    const std::string img = BaseName(v(e.image));
    const std::string& t = e.eventType;
    if (t == "PROCESS_CREATE" || t == "SECURITY_PROCESS_CREATE") {
        std::string s = BaseName(v(e.parentImage)) + " -> " + img;
        if (e.commandLine) s += " | " + *e.commandLine;
        return s;
    }
    if (t == "NETWORK_CONNECT") {
        std::string s = img + " -> " + v(e.destIp);
        if (e.destPort) s += ":" + std::to_string(*e.destPort);
        if (e.destHostname) s += " (" + *e.destHostname + ")";
        return s;
    }
    if (t == "DNS_QUERY") return img + " ? " + v(e.queryName);
    if (t == "REMOTE_THREAD" || t == "PROCESS_ACCESS") {
        std::string s = img + " -> " + BaseName(v(e.targetImage));
        if (e.grantedAccess) {
            char buf[24];
            std::snprintf(buf, sizeof(buf), " (access 0x%llX)", static_cast<unsigned long long>(*e.grantedAccess));
            s += buf;
        }
        return s;
    }
    if (t == "REGISTRY_SET" || t == "REGISTRY_ADD" || t == "REGISTRY_RENAME") {
        std::string s = img + " " + v(e.registryPath);
        if (e.registryDetails) s += " = " + *e.registryDetails;
        return s;
    }
    if (t == "FILE_CREATE" || t == "FILE_DELETE" || t == "FILE_STREAM_HASH" || t == "IMAGE_LOAD")
        return img + " " + v(e.targetFilename);
    if (t == "PIPE_CREATE" || t == "PIPE_CONNECT") return img + " " + v(e.pipeName);
    if (t == "SCRIPT_BLOCK") {
        std::string sb = v(e.scriptBlock);
        if (sb.size() > 300) sb.resize(300);
        return "pid " + std::to_string(e.pid) + " script: " + sb;
    }
    if (t == "PROCESS_TAMPERING") return img + " image tampering";
    if (t == "PROCESS_TERMINATE") return img + " exited";
    return img;
}

Result<std::unique_ptr<ReadOnlyDb>> ReadOnlyDb::Open(const std::filesystem::path& dbPath)
{
    CAIRN_TRY(auto db, SqliteDb::Open(dbPath, ConnRole::Reader));
    return std::unique_ptr<ReadOnlyDb>(new ReadOnlyDb(std::move(db)));
}

// ======================================================================= alerts

Result<AlertListResult> ReadOnlyDb::ListAlerts(const AlertListFilter& f, int64_t nowMs)
{
    DeadlineScope ds{*m_db};
    AlertListResult res;
    const int limit = std::clamp(f.limit, 1, 200);

    std::string where = " WHERE 1=1";
    std::vector<Param> ps;
    if (!f.severities.empty()) {
        where += " AND a.severity IN (" + Placeholders(f.severities.size()) + ")";
        for (const auto& s : f.severities) ps.emplace_back(s);
    }
    if (!f.statuses.empty()) {
        where += " AND " + std::string(kStatusExpr) + " IN (" + Placeholders(f.statuses.size()) + ")";
        for (const auto& s : f.statuses) ps.emplace_back(s);
    }
    if (f.since) { where += " AND a.ts >= ?"; ps.emplace_back(*f.since); }
    if (f.until) { where += " AND a.ts <= ?"; ps.emplace_back(*f.until); }
    if (!f.q.empty()) {
        where += " AND (lower(a.title) LIKE ? ESCAPE '\\' OR lower(p.image) LIKE ? ESCAPE '\\'"
                 " OR lower(a.rule_ids) LIKE ? ESCAPE '\\')";
        const std::string like = LikeContains(f.q);
        ps.emplace_back(like);
        ps.emplace_back(like);
        ps.emplace_back(like);
    }
    if (f.hasNarrative) where += *f.hasNarrative ? " AND a.ai_state = 'ok'" : " AND a.ai_state != 'ok'";
    if (f.blockedOnly) where += " AND s.state = 'blocked'";

    const std::string from =
        " FROM alerts a"
        " LEFT JOIN scores s ON s.root_process_guid = a.root_process_guid"
        " LEFT JOIN process_tree p ON p.process_guid = COALESCE(a.trigger_process_guid, a.root_process_guid)"
        " LEFT JOIN process_tree pp ON pp.process_guid = p.parent_process_guid";

    // total_matched（不含 cursor 條件）
    {
        CAIRN_TRY(auto st, m_db->Prepare("SELECT COUNT(*)" + from + where + ";"));
        BindAll(st, ps);
        CAIRN_TRY(bool row, st.Step());
        if (row) res.stats.totalMatched = st.Int64(0);
    }

    // keyset cursor："t:<ts>:<id>" 或 "r:<score>:<id>"
    std::string page = where;
    std::vector<Param> pps = ps;
    const bool byRisk = f.sort == AlertSort::RiskDesc;
    if (f.cursor) {
        const auto& c = *f.cursor;
        const size_t a = c.find(':'), b = c.rfind(':');
        if (c.size() > 4 && a == 1 && b > a && (c[0] == 't' || c[0] == 'r')) {
            try {
                const int64_t k  = std::stoll(c.substr(a + 1, b - a - 1));
                const int64_t id = std::stoll(c.substr(b + 1));
                page += byRisk ? " AND (a.score_at_trigger < ? OR (a.score_at_trigger = ? AND a.id < ?))"
                               : " AND (a.ts < ? OR (a.ts = ? AND a.id < ?))";
                pps.emplace_back(k);
                pps.emplace_back(k);
                pps.emplace_back(id);
            } catch (...) {
                return MakeError(ErrorCode::InvalidArgument, "invalid cursor");
            }
        } else {
            return MakeError(ErrorCode::InvalidArgument, "invalid cursor");
        }
    }
    const std::string order = byRisk ? " ORDER BY a.score_at_trigger DESC, a.id DESC" : " ORDER BY a.ts DESC, a.id DESC";
    const std::string sql = "SELECT a.id,a.ts,a.severity,a.score_at_trigger,a.title,a.root_process_guid,"
                            "a.trigger_process_guid,a.rule_ids,a.ai_state,a.analyst_verdict,"
                            "COALESCE(s.state,'normal'),json_array_length(a.actions_taken),p.image,pp.image," +
                            std::string(kStatusExpr) +
                            ",CASE WHEN a.ai_state = 'ok' THEN a.ai_narrative END,"
                            "EXISTS(SELECT 1 FROM audit_log al WHERE al.alert_id = a.id AND al.action = 'exclusion_add')" +
                            from + page + order + " LIMIT ?;";
    pps.emplace_back(static_cast<int64_t>(limit + 1));
    {
        CAIRN_TRY(auto st, m_db->Prepare(sql));
        BindAll(st, pps);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            AlertSummary s;
            s.id                  = st.Int64(0);
            s.ts                  = st.Int64(1);
            s.severity            = st.Text(2);
            s.scoreAtTriggerMilli = st.Int64(3);
            s.title               = st.Text(4);
            s.rootProcessGuid     = st.Text(5);
            s.triggerProcessGuid  = st.OptText(6);
            s.ruleIds             = ParseJsonStringArray(st.Text(7));
            s.aiState             = st.Text(8);
            s.analystVerdict      = st.OptText(9);
            s.scoreState          = st.Text(10);
            s.actionsCount        = static_cast<int>(st.Int64(11));
            s.imagePath           = st.OptText(12).value_or("");
            s.processName         = BaseName(s.imagePath);
            s.parentName          = BaseName(st.OptText(13).value_or(""));
            s.status              = st.Text(14);
            if (auto n = st.OptText(15)) s.narrativePreview = Utf8Prefix(*n, 120);
            s.exclusionCreated    = st.Int64(16) != 0;
            res.items.push_back(std::move(s));
        }
    }
    const bool hasMore = static_cast<int>(res.items.size()) > limit;
    if (hasMore) res.items.resize(static_cast<size_t>(limit));
    // 程序鏈摘要（每頁最多 200 列 × 8 層的索引查詢；列表雙行列所需，part3 §3.8.5）
    for (auto& item : res.items) {
        CAIRN_TRY(auto chain, LoadChain(item.triggerProcessGuid.value_or(item.rootProcessGuid), item.rootProcessGuid, 8));
        for (size_t i = 0; i < chain.size(); ++i) {
            ChainItem c;
            c.name  = BaseName(chain[i].image.value_or(""));
            c.pid   = chain[i].pid;
            c.depth = static_cast<int32_t>(i);
            CAIRN_TRY(c.scoreDeltaMilli, ProcessScore(chain[i].processGuid));
            item.processChain.push_back(std::move(c));
        }
    }
    if (res.items.size() == static_cast<size_t>(limit) && res.stats.totalMatched > 0 && hasMore) {
        const auto& last = res.items.back();
        res.nextCursor = (byRisk ? "r:" + std::to_string(last.scoreAtTriggerMilli) : "t:" + std::to_string(last.ts)) +
                         ":" + std::to_string(last.id);
    }

    // 全域統計（不受篩選影響）
    {
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT"
                               " SUM(CASE WHEN analyst_verdict IS NULL THEN 1 ELSE 0 END),"
                               " SUM(CASE WHEN analyst_verdict IS NULL AND severity = 'critical' THEN 1 ELSE 0 END),"
                               " SUM(CASE WHEN ts >= ?1 THEN 1 ELSE 0 END),"
                               " SUM(CASE WHEN ts >= ?2 AND analyst_verdict = 'false_positive' THEN 1 ELSE 0 END),"
                               " SUM(CASE WHEN ts >= ?2 AND analyst_verdict IS NOT NULL THEN 1 ELSE 0 END)"
                               " FROM alerts;"));
        st.Bind(1, nowMs - kDayMs).Bind(2, nowMs - 30 * kDayMs);
        CAIRN_TRY(bool row, st.Step());
        if (row) {
            res.stats.pending  = st.Int64(0);
            res.stats.critical = st.Int64(1);
            res.stats.today    = st.Int64(2);
            const int64_t fp = st.Int64(3), judged = st.Int64(4);
            res.stats.falsePositiveRate = judged > 0 ? static_cast<double>(fp) / static_cast<double>(judged) : 0.0;
        }
    }
    {
        CAIRN_TRY(auto obs, m_db->QueryInt64("SELECT COUNT(*) FROM scores WHERE state = 'watching';"));
        res.stats.observing = obs.value_or(0);
    }
    return res;
}

Result<std::optional<AlertRecord>> ReadOnlyDb::GetAlertRecord(int64_t alertId)
{
    DeadlineScope ds{*m_db};
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kAlertCols) + " FROM alerts a WHERE a.id = ?1;"));
    st.Bind(1, alertId);
    CAIRN_TRY(bool row, st.Step());
    if (!row) return std::optional<AlertRecord>{};
    return std::optional<AlertRecord>{ReadAlert(st)};
}

Result<std::optional<std::string>> ReadOnlyDb::AlertRoot(int64_t alertId)
{
    DeadlineScope ds{*m_db};
    CAIRN_TRY(auto st, m_db->Prepare("SELECT root_process_guid FROM alerts WHERE id = ?1;"));
    st.Bind(1, alertId);
    CAIRN_TRY(bool row, st.Step());
    if (!row) return std::optional<std::string>{};
    return std::optional<std::string>{st.Text(0)};
}

Result<std::vector<int64_t>> ReadOnlyDb::AlertsForRoot(const std::string& rootGuid)
{
    DeadlineScope ds{*m_db};
    std::vector<int64_t> out;
    CAIRN_TRY(auto st, m_db->Prepare("SELECT id FROM alerts WHERE root_process_guid = ?1 ORDER BY id;"));
    st.BindText(1, rootGuid);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        out.push_back(st.Int64(0));
    }
    return out;
}

Result<std::vector<ProcessNodeRecord>> ReadOnlyDb::LoadChain(const std::string& fromGuid, const std::string& rootGuid,
                                                             size_t maxDepth)
{
    std::vector<ProcessNodeRecord> chain;
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kNodeCols) + " FROM process_tree p WHERE p.process_guid = ?1;"));
    std::set<std::string> seen;
    std::string cur = fromGuid;
    while (!cur.empty() && chain.size() < maxDepth && !seen.count(cur)) {
        seen.insert(cur);
        st.BindText(1, cur);
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        ProcessNodeRecord n = ReadNode(st);
        ::sqlite3_reset(st.Raw());
        const bool atRoot = (n.processGuid == rootGuid);
        cur = (atRoot || !n.parentProcessGuid) ? std::string{} : *n.parentProcessGuid;
        chain.push_back(std::move(n));
    }
    std::reverse(chain.begin(), chain.end());   // 根在前
    return chain;
}

Result<int64_t> ReadOnlyDb::ProcessScore(const std::string& processGuid)
{
    CAIRN_TRY(auto st, m_db->Prepare("SELECT IFNULL(SUM(rh.score_delta),0) FROM events e JOIN rule_hits rh ON rh.event_id = e.id"
                                     " WHERE e.process_guid = ?1 AND rh.dryrun = 0 AND rh.suppressed = 0;"));
    st.BindText(1, processGuid);
    CAIRN_TRY(bool row, st.Step());
    return row ? st.Int64(0) : int64_t{0};
}

Result<std::vector<ProcessNodeRecord>> ReadOnlyDb::GetProcessSubtree(const std::string& rootGuid)
{
    DeadlineScope ds{*m_db};
    std::vector<ProcessNodeRecord> nodes;
    // SDD-02 §6.5 的核心查詢：遞迴 CTE 一次撈整棵樹，ix_ptree_parent 使每層為索引掃描
    const std::string sql =
        "WITH RECURSIVE subtree(process_guid, depth) AS ("
        "  SELECT process_guid, 0 FROM process_tree WHERE process_guid = ?1"
        "  UNION ALL"
        "  SELECT c.process_guid, s.depth + 1 FROM process_tree c JOIN subtree s"
        "    ON c.parent_process_guid = s.process_guid AND c.process_guid != s.process_guid"
        "  WHERE s.depth < 64"
        ") SELECT " + std::string(kNodeCols) + ", s.depth,"
        " (SELECT COUNT(*) FROM process_tree k WHERE k.parent_process_guid = p.process_guid)"
        " FROM process_tree p JOIN subtree s USING(process_guid) ORDER BY p.start_ts, s.depth LIMIT 2000;";
    CAIRN_TRY(auto st, m_db->Prepare(sql));
    st.BindText(1, rootGuid);
    std::unordered_map<std::string, size_t> index;
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        ProcessNodeRecord n = ReadNode(st);
        n.depth      = static_cast<int32_t>(st.Int64(15));
        n.childCount = st.Int64(16);
        if (index.count(n.processGuid)) continue;   // 自參照環的防呆
        index[n.processGuid] = nodes.size();
        nodes.push_back(std::move(n));
    }
    // 每個程序被哪些規則命中、累計多少分（以觸發事件的程序歸屬）
    CAIRN_TRY(auto hs, m_db->Prepare("SELECT e.process_guid, rh.rule_id, SUM(rh.score_delta)"
                                     " FROM rule_hits rh JOIN events e ON e.id = rh.event_id"
                                     " WHERE rh.root_process_guid = ?1 AND rh.suppressed = 0"
                                     " GROUP BY e.process_guid, rh.rule_id;"));
    hs.BindText(1, rootGuid);
    for (;;) {
        CAIRN_TRY(bool row, hs.Step());
        if (!row) break;
        auto it = index.find(hs.Text(0));
        if (it == index.end()) continue;
        auto& n = nodes[it->second];
        n.ruleIds.push_back(hs.Text(1));
        n.scoreDeltaMilli += hs.Int64(2);
    }
    return nodes;
}

Result<std::vector<TimelineEntry>> ReadOnlyDb::LoadTimeline(int64_t alertId, int limit)
{
    std::vector<TimelineEntry> out;
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kEventCols) +
                                     ", ae.step_index, ae.role FROM alert_events ae JOIN events e ON e.id = ae.event_id"
                                     " WHERE ae.alert_id = ?1 ORDER BY e.ts, e.id LIMIT ?2;"));
    st.Bind(1, alertId).Bind(2, static_cast<int64_t>(limit));
    std::unordered_map<int64_t, size_t> index;
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        TimelineEntry t;
        t.event = ReadEvent(st);
        if (auto v = st.OptInt64(kEventColCount)) t.stepIndex = static_cast<int32_t>(*v);
        t.role = st.Text(kEventColCount + 1);
        index[t.event.id] = out.size();
        out.push_back(std::move(t));
    }
    CAIRN_TRY(auto hs, m_db->Prepare("SELECT rh.event_id, rh.rule_id, rh.score_delta, rh.dryrun, rh.suppressed"
                                     " FROM rule_hits rh JOIN alert_events ae ON ae.event_id = rh.event_id"
                                     " WHERE ae.alert_id = ?1 ORDER BY rh.id;"));
    hs.Bind(1, alertId);
    for (;;) {
        CAIRN_TRY(bool row, hs.Step());
        if (!row) break;
        auto it = index.find(hs.Int64(0));
        if (it == index.end()) continue;
        out[it->second].hits.push_back(HitBrief{hs.Text(1), hs.Int64(2), hs.Int64(3) != 0, hs.Int64(4) != 0});
    }
    return out;
}

Result<std::vector<RuleHitRecord>> ReadOnlyDb::HitsForAlert(int64_t alertId)
{
    DeadlineScope ds{*m_db};
    std::vector<RuleHitRecord> out;
    // 告警本身的命中 + 同一棵樹在告警前 1 小時到後 5 分鐘內未掛告警的命中（含 dryrun / suppressed —— 誤報排查的關鍵資料）
    CAIRN_TRY(auto st, m_db->Prepare(
                           "SELECT rh.id,rh.ts,rh.rule_id,rh.root_process_guid,rh.event_id,rh.alert_id,rh.score_delta,"
                           "rh.dryrun,rh.suppressed,rh.suppressed_by,rh.rule_hash FROM rule_hits rh, alerts a"
                           " WHERE a.id = ?1 AND (rh.alert_id = a.id OR (rh.alert_id IS NULL"
                           "   AND rh.root_process_guid = a.root_process_guid"
                           "   AND rh.ts BETWEEN a.ts - 3600000 AND a.ts + 300000))"
                           " ORDER BY rh.ts, rh.id LIMIT 1000;"));
    st.Bind(1, alertId);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        out.push_back(ReadHit(st));
    }
    return out;
}

Result<std::optional<AlertDetail>> ReadOnlyDb::GetAlert(int64_t alertId)
{
    CAIRN_TRY(auto rec, GetAlertRecord(alertId));
    if (!rec) return std::optional<AlertDetail>{};
    DeadlineScope ds{*m_db};
    AlertDetail d;
    d.alert = std::move(*rec);
    {
        CAIRN_TRY(auto st, m_db->Prepare("SELECT root_process_guid,score,peak_score,shadow_score,last_update_ts,"
                                         "first_hit_ts,state FROM scores WHERE root_process_guid = ?1;"));
        st.BindText(1, d.alert.rootProcessGuid);
        CAIRN_TRY(bool row, st.Step());
        if (row) {
            ScoreRecord s;
            s.rootProcessGuid = st.Text(0);
            s.scoreMilli      = st.Int64(1);
            s.peakMilli       = st.Int64(2);
            s.shadowMilli     = st.Int64(3);
            s.lastUpdateTs    = st.Int64(4);
            s.firstHitTs      = st.Int64(5);
            s.state           = st.Text(6);
            d.score           = std::move(s);
        }
    }
    CAIRN_TRY(d.processTree, GetProcessSubtree(d.alert.rootProcessGuid));
    m_db->SetQueryDeadline(kQueryBudget);
    CAIRN_TRY(d.timeline, LoadTimeline(alertId, 500));
    CAIRN_TRY(d.hits, HitsForAlert(alertId));
    m_db->SetQueryDeadline(kQueryBudget);
    {
        // 處置目標：樹中程序映像（非佔位）＋ 落地檔
        std::set<std::string> files;
        for (const auto& n : d.processTree)
            if (!n.placeholder && n.image && !n.image->empty() && files.insert(*n.image).second)
                d.availableTargets.files.push_back({*n.image});
        CAIRN_TRY(auto fs, m_db->Prepare("SELECT DISTINCT target_filename FROM events WHERE root_process_guid = ?1"
                                         " AND event_type IN ('FILE_CREATE','FILE_STREAM_HASH') AND target_filename IS NOT NULL"
                                         " LIMIT 50;"));
        fs.BindText(1, d.alert.rootProcessGuid);
        for (;;) {
            CAIRN_TRY(bool row, fs.Step());
            if (!row) break;
            std::string path = fs.Text(0);
            if (const auto colon = path.find(':', 2); colon != std::string::npos) path.resize(colon);   // 去掉 ADS 後綴
            if (files.insert(path).second) d.availableTargets.files.push_back({path});
        }
        CAIRN_TRY(auto ns, m_db->Prepare("SELECT DISTINCT dest_ip, dest_port FROM events WHERE root_process_guid = ?1"
                                         " AND event_type = 'NETWORK_CONNECT' AND dest_ip IS NOT NULL LIMIT 50;"));
        ns.BindText(1, d.alert.rootProcessGuid);
        for (;;) {
            CAIRN_TRY(bool row, ns.Step());
            if (!row) break;
            d.availableTargets.ips.push_back({ns.Text(0), ns.OptInt64(1)});
        }
    }
    {
        CAIRN_TRY(auto as, m_db->Prepare("SELECT " + std::string(kAuditCols) +
                                         " FROM audit_log WHERE alert_id = ?1 ORDER BY id LIMIT 500;"));
        as.Bind(1, alertId);
        for (;;) {
            CAIRN_TRY(bool row, as.Step());
            if (!row) break;
            d.audits.push_back(ReadAudit(as));
        }
    }
    return std::optional<AlertDetail>{std::move(d)};
}

// ======================================================================= events

Result<EventPage> ReadOnlyDb::QueryEvents(const EventQuery& q)
{
    DeadlineScope ds{*m_db};
    EventPage page;
    const int limit = std::clamp(q.limit, 1, 1000);
    std::string where = " WHERE 1=1";
    std::vector<Param> ps;
    if (q.from) { where += " AND e.ts >= ?"; ps.emplace_back(*q.from); }
    if (q.to) { where += " AND e.ts <= ?"; ps.emplace_back(*q.to); }
    if (q.processGuid) {
        where += " AND (e.process_guid = ? OR e.root_process_guid = ?)";
        ps.emplace_back(*q.processGuid);
        ps.emplace_back(*q.processGuid);
    }
    if (q.eventType) { where += " AND e.event_type = ?"; ps.emplace_back(*q.eventType); }
    if (q.textContains && !q.textContains->empty()) {
        // 四個獨立的位置參數（不與具名參數混用）
        where += " AND (lower(e.image) LIKE ? ESCAPE '\\' OR lower(e.command_line) LIKE ? ESCAPE '\\'"
                 " OR lower(e.target_filename) LIKE ? ESCAPE '\\' OR lower(e.query_name) LIKE ? ESCAPE '\\')";
        const std::string like = LikeContains(*q.textContains);
        for (int i = 0; i < 4; ++i) ps.emplace_back(like);
    }
    if (q.beforeId) { where += " AND e.id < ?"; ps.emplace_back(*q.beforeId); }
    ps.emplace_back(static_cast<int64_t>(limit + 1));
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kEventCols) + " FROM events e" + where +
                                     " ORDER BY e.id DESC LIMIT ?;"));
    BindAll(st, ps);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        page.items.push_back(ReadEvent(st));
    }
    if (static_cast<int>(page.items.size()) > limit) {
        page.items.resize(static_cast<size_t>(limit));
        page.nextBeforeId = page.items.back().id;
    }
    return page;
}

// ======================================================================= exclusions

Result<std::vector<ExclusionRecord>> ReadOnlyDb::ListExclusions(int64_t nowMs, bool includeDisabled)
{
    DeadlineScope ds{*m_db};
    std::vector<ExclusionRecord> out;
    CAIRN_TRY(auto st, m_db->Prepare(
                           "SELECT x.id,x.kind,x.value,x.scope_rule_id,x.reason,x.created_by,x.created_ts,x.expires_ts,"
                           "x.enabled,x.hit_count,x.last_hit_ts,"
                           " (SELECT COUNT(*) FROM rule_hits rh WHERE rh.suppressed_by = x.id AND rh.ts >= ?1)"
                           " FROM exclusions x WHERE (?2 = 1 OR x.enabled = 1) ORDER BY x.id;"));
    st.Bind(1, nowMs - 30 * kDayMs).Bind(2, static_cast<int64_t>(includeDisabled ? 1 : 0));
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        ExclusionRecord x;
        x.id                 = st.Int64(0);
        x.kind               = st.Text(1);
        x.value              = st.Text(2);
        x.scopeRuleId        = st.Text(3);
        x.reason             = st.OptText(4);
        x.createdBy          = st.Text(5);
        x.createdTs          = st.Int64(6);
        x.expiresTs          = st.OptInt64(7);
        x.enabled            = st.Int64(8) != 0;
        x.hitCount           = st.Int64(9);
        x.lastHitTs          = st.OptInt64(10);
        x.suppressedCount30d = st.Int64(11);
        out.push_back(std::move(x));
    }
    return out;
}

Result<ExclusionPreview> ReadOnlyDb::PreviewExclusion(const std::string& kind, const std::string& value,
                                                      const std::string& scopeRuleId, int64_t nowMs)
{
    DeadlineScope ds{*m_db};
    ExclusionPreview pv;
    std::string cond;
    if (kind == "rule_id") cond = "a.rule_ids LIKE '%\"' || ?2 || '\"%'";
    else if (kind == "path") cond = "EXISTS(SELECT 1 FROM process_tree p WHERE p.root_process_guid = a.root_process_guid AND lower(p.image) = lower(?2))";
    else if (kind == "path_glob") cond = "EXISTS(SELECT 1 FROM process_tree p WHERE p.root_process_guid = a.root_process_guid AND lower(p.image) GLOB lower(?2))";
    else if (kind == "sha256") cond = "EXISTS(SELECT 1 FROM process_tree p WHERE p.root_process_guid = a.root_process_guid AND upper(p.sha256) = upper(?2))";
    else if (kind == "signer") cond = "EXISTS(SELECT 1 FROM process_tree p WHERE p.root_process_guid = a.root_process_guid AND lower(p.signature_signer) = lower(?2))";
    else if (kind == "cmdline_glob") cond = "EXISTS(SELECT 1 FROM process_tree p WHERE p.root_process_guid = a.root_process_guid AND lower(p.command_line) GLOB lower(?2))";
    else return MakeError(ErrorCode::InvalidArgument, "unknown exclusion kind: " + kind);

    CAIRN_TRY(auto st, m_db->Prepare("SELECT a.id, a.analyst_verdict FROM alerts a WHERE a.ts >= ?1 AND " + cond +
                                     " AND (?3 = '' OR a.rule_ids LIKE '%\"' || ?3 || '\"%')"
                                     " ORDER BY a.ts DESC LIMIT 10000;"));
    st.Bind(1, nowMs - 30 * kDayMs).BindText(2, value).BindText(3, scopeRuleId);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        ++pv.wouldSuppressCount;
        if (st.OptText(1).value_or("") == "true_positive") ++pv.previouslyTruePositiveCount;
        if (pv.sampleAlertIds.size() < 5) pv.sampleAlertIds.push_back(st.Int64(0));
    }
    return pv;
}

Result<std::vector<ExclusionSuggestion>> ReadOnlyDb::ExclusionSuggestions(int64_t nowMs, int64_t minDryrunHits)
{
    DeadlineScope ds{*m_db};
    const int64_t since = nowMs - 30 * kDayMs;

    std::set<std::string> dismissed;
    {
        CAIRN_TRY(auto st, m_db->Prepare("SELECT suggestion_id FROM dismissed_suggestions;"));
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            dismissed.insert(st.Text(0));
        }
    }
    std::set<std::string> existing;   // "kind|value|scope"
    {
        CAIRN_TRY(auto st, m_db->Prepare("SELECT kind, lower(value), scope_rule_id FROM exclusions WHERE enabled = 1;"));
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            existing.insert(st.Text(0) + "|" + st.Text(1) + "|" + st.Text(2));
        }
    }

    std::map<std::string, ExclusionSuggestion> byKey;
    auto upsert = [&](const std::string& img, const std::string& rule, const std::string& source, int64_t count,
                      std::optional<int64_t> alertId) {
        const std::string key = "path|" + img + "|" + rule;
        if (existing.count(key)) return;
        const std::string sid = Sha256Hex(key).substr(0, 16);
        if (dismissed.count(sid)) return;
        auto& s = byKey[key];
        if (s.suggestionId.empty()) {
            s.suggestionId = sid;
            s.value        = img;
            s.scopeRuleId  = rule;
            s.source       = source;
            s.affectedRuleIds.push_back(rule);
        } else if (source == "false_positive") {
            s.source = source;   // 分析師判定的誤報優先於 dryrun 統計
        }
        s.triggeredCount += count;
        if (alertId && s.sampleAlertIds.size() < 5) s.sampleAlertIds.push_back(*alertId);
    };

    // (a) 分析師判定為誤報的告警：以觸發程序映像 × 規則分組
    {
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT lower(p.image), je.value, a.id FROM alerts a, json_each(a.rule_ids) je"
                               " JOIN process_tree p ON p.process_guid = COALESCE(a.trigger_process_guid, a.root_process_guid)"
                               " WHERE a.analyst_verdict = 'false_positive' AND a.ts >= ?1 AND p.image IS NOT NULL"
                               " ORDER BY a.ts DESC LIMIT 5000;"));
        st.Bind(1, since);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            upsert(st.Text(0), st.Text(1), "false_positive", 1, st.Int64(2));
        }
    }
    // (b) dryrun 規則的高頻命中（學習期的主要來源）
    {
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT lower(COALESCE(e.image, p.image)) AS img, rh.rule_id, COUNT(*)"
                               " FROM rule_hits rh LEFT JOIN events e ON e.id = rh.event_id"
                               " LEFT JOIN process_tree p ON p.process_guid = rh.root_process_guid"
                               " WHERE rh.dryrun = 1 AND rh.suppressed = 0 AND rh.ts >= ?1"
                               " GROUP BY img, rh.rule_id HAVING img IS NOT NULL AND COUNT(*) >= ?2"
                               " ORDER BY COUNT(*) DESC LIMIT 200;"));
        st.Bind(1, since).Bind(2, minDryrunHits);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            upsert(st.Text(0), st.Text(1), "dryrun", st.Int64(2), std::nullopt);
        }
    }

    std::vector<ExclusionSuggestion> out;
    out.reserve(byKey.size());
    for (auto& [k, v] : byKey) out.push_back(std::move(v));
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.triggeredCount > b.triggeredCount; });
    return out;
}

// ======================================================================= rules

Result<std::vector<RuleStats>> ReadOnlyDb::RuleStatsAll(int64_t nowMs)
{
    DeadlineScope ds{*m_db};
    const int64_t since = nowMs - 30 * kDayMs;
    std::map<std::string, RuleStats> m;
    {
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT rule_id,"
                               " SUM(CASE WHEN dryrun = 0 AND suppressed = 0 THEN 1 ELSE 0 END),"
                               " SUM(CASE WHEN dryrun = 1 THEN 1 ELSE 0 END), SUM(suppressed)"
                               " FROM rule_hits WHERE ts >= ?1 GROUP BY rule_id;"));
        st.Bind(1, since);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            auto& r         = m[st.Text(0)];
            r.hits30d       = st.Int64(1);
            r.dryrunHits30d = st.Int64(2);
            r.suppressed30d = st.Int64(3);
        }
    }
    {
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT je.value, COUNT(*),"
                               " SUM(CASE WHEN a.analyst_verdict = 'false_positive' THEN 1 ELSE 0 END)"
                               " FROM alerts a, json_each(a.rule_ids) je WHERE a.ts >= ?1 GROUP BY je.value;"));
        st.Bind(1, since);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            auto& r       = m[st.Text(0)];
            r.alerts30d   = st.Int64(1);
            r.fpAlerts30d = st.Int64(2);
        }
    }
    {
        // 「若啟用這條 dry-run 規則會多幾則告警」：shadow >= 80 但實際 peak < 80 的樹
        CAIRN_TRY(auto st, m_db->Prepare(
                               "SELECT rh.rule_id, COUNT(DISTINCT rh.root_process_guid)"
                               " FROM rule_hits rh JOIN scores s ON s.root_process_guid = rh.root_process_guid"
                               " WHERE rh.dryrun = 1 AND rh.ts >= ?1 AND s.shadow_score >= 80000 AND s.peak_score < 80000"
                               " GROUP BY rh.rule_id;"));
        st.Bind(1, since);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            m[st.Text(0)].shadowAlerts30d = st.Int64(1);
        }
    }
    std::vector<RuleStats> out;
    out.reserve(m.size());
    for (auto& [id, r] : m) {
        r.ruleId = id;
        out.push_back(std::move(r));
    }
    return out;
}

// ======================================================================= audit


Result<AuditPage> ReadOnlyDb::ListAudit(const AuditQuery& q)
{
    DeadlineScope ds{*m_db};
    AuditPage page;
    const int limit = std::clamp(q.limit, 1, 1000);
    std::string where = " WHERE 1=1";
    std::vector<Param> ps;
    if (q.from) { where += " AND ts >= ?"; ps.emplace_back(*q.from); }
    if (q.to) { where += " AND ts <= ?"; ps.emplace_back(*q.to); }
    if (!q.actions.empty()) {
        where += " AND action IN (" + Placeholders(q.actions.size()) + ")";
        for (const auto& a : q.actions) ps.emplace_back(a);
    }
    if (q.actor) { where += " AND actor = ?"; ps.emplace_back(*q.actor); }
    if (q.q && !q.q->empty()) {
        where += " AND (lower(target) LIKE ? ESCAPE '\\' OR lower(params) LIKE ? ESCAPE '\\')";
        const std::string like = LikeContains(*q.q);
        ps.emplace_back(like);
        ps.emplace_back(like);
    }
    if (q.beforeId) { where += " AND id < ?"; ps.emplace_back(*q.beforeId); }
    ps.emplace_back(static_cast<int64_t>(limit + 1));
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kAuditCols) + " FROM audit_log" + where +
                                     " ORDER BY id DESC LIMIT ?;"));
    BindAll(st, ps);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        page.items.push_back(ReadAudit(st));
    }
    if (static_cast<int>(page.items.size()) > limit) {
        page.items.resize(static_cast<size_t>(limit));
        page.nextBeforeId = page.items.back().id;
    }
    return page;
}

Result<std::optional<AuditRecord>> ReadOnlyDb::GetAudit(int64_t auditId)
{
    DeadlineScope ds{*m_db};
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kAuditCols) + " FROM audit_log WHERE id = ?1;"));
    st.Bind(1, auditId);
    CAIRN_TRY(bool row, st.Step());
    if (!row) return std::optional<AuditRecord>{};
    return std::optional<AuditRecord>{ReadAudit(st)};
}

Result<ChainReport> ReadOnlyDb::VerifyAudit(int64_t fromId, int64_t toId)
{
    // 全鏈驗證可能超過 2 秒查詢上限：給 30 秒（由 GET /audit?verify=true 明確觸發）
    m_db->SetQueryDeadline(std::chrono::milliseconds(30'000));
    auto r = VerifyAuditChain(*m_db, fromId, toId);
    m_db->SetQueryDeadline(std::chrono::milliseconds(0));
    return r;
}

Result<ChainReport> ReadOnlyDb::VerifyRecentAudit(int64_t lastN)
{
    CAIRN_TRY(auto maxId, m_db->QueryInt64("SELECT MAX(id) FROM audit_log;"));
    const int64_t last = maxId.value_or(0);
    if (last == 0) return ChainReport{};
    return VerifyAudit(std::max<int64_t>(1, last - lastN + 1), 0);
}

// ======================================================================= health

namespace {
constexpr std::string_view kHealthCols =
    "id,ts,events_ingested,events_dropped,events_filtered,queue_depth,cpu_percent,private_bytes_mb,db_size_mb,"
    "sysmon_state,llm_state,tier2_p95_ms,llm_p95_ms";
HealthRecord ReadHealth(const Stmt& st)
{
    HealthRecord h;
    h.id             = st.Int64(0);
    h.ts             = st.Int64(1);
    h.eventsIngested = st.Int64(2);
    h.eventsDropped  = st.Int64(3);
    h.eventsFiltered = st.Int64(4);
    h.queueDepth     = st.Int64(5);
    h.cpuPercent     = st.Double(6);
    h.privateBytesMb = st.Double(7);
    h.dbSizeMb       = st.Double(8);
    h.sysmonState    = st.Text(9);
    h.llmState       = st.Text(10);
    h.tier2P95Ms     = st.OptDouble(11);
    h.llmP95Ms       = st.OptDouble(12);
    return h;
}
} // namespace

Result<std::optional<HealthRecord>> ReadOnlyDb::LatestHealth()
{
    DeadlineScope ds{*m_db};
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kHealthCols) + " FROM agent_health ORDER BY ts DESC, id DESC LIMIT 1;"));
    CAIRN_TRY(bool row, st.Step());
    if (!row) return std::optional<HealthRecord>{};
    return std::optional<HealthRecord>{ReadHealth(st)};
}

Result<std::vector<HealthRecord>> ReadOnlyDb::HealthSince(int64_t sinceMs, int limit)
{
    DeadlineScope ds{*m_db};
    std::vector<HealthRecord> out;
    CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kHealthCols) +
                                     " FROM agent_health WHERE ts >= ?1 ORDER BY ts LIMIT ?2;"));
    st.Bind(1, sinceMs).Bind(2, static_cast<int64_t>(std::clamp(limit, 1, 20000)));
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        out.push_back(ReadHealth(st));
    }
    return out;
}

Result<int64_t> ReadOnlyDb::DatabaseBytes()
{
    CAIRN_TRY(auto pages, m_db->QueryInt64("PRAGMA page_count;"));
    CAIRN_TRY(auto size, m_db->QueryInt64("PRAGMA page_size;"));
    return pages.value_or(0) * size.value_or(4096);
}

Result<MaxIds> ReadOnlyDb::QueryMaxIds()
{
    DeadlineScope ds{*m_db};
    MaxIds m;
    // events 為 AUTOINCREMENT：sqlite_sequence 記錄曾配發過的最大值（即使該列已被刪除），避免重用 id
    CAIRN_TRY(auto ev, m_db->QueryInt64(
                           "SELECT MAX(IFNULL((SELECT MAX(id) FROM events),0),"
                           " IFNULL((SELECT seq FROM sqlite_sequence WHERE name = 'events'),0));"));
    m.nextEventId = ev.value_or(0) + 1;
    // alerts 不是 AUTOINCREMENT：90 天 retention 後 MAX(id) 可能倒退，故一併參考 audit_log / rule_hits 的弱關聯
    CAIRN_TRY(auto al, m_db->QueryInt64(
                           "SELECT MAX(IFNULL((SELECT MAX(id) FROM alerts),0),"
                           " IFNULL((SELECT MAX(alert_id) FROM audit_log),0),"
                           " IFNULL((SELECT MAX(alert_id) FROM rule_hits),0));"));
    m.nextAlertId = al.value_or(0) + 1;
    return m;
}

// ======================================================================= IAlertContextProvider

Result<model::PromptInput> ReadOnlyDb::LoadPromptInput(int64_t alertId)
{
    CAIRN_TRY(auto rec, GetAlertRecord(alertId));
    if (!rec) return MakeError(ErrorCode::NotFound, "alert not found: " + std::to_string(alertId));
    DeadlineScope ds{*m_db};
    const AlertRecord& a = *rec;

    model::PromptInput in;
    in.alertId       = a.id;
    in.scoreMilli    = a.scoreAtTriggerMilli;
    in.ruleIds       = a.ruleIds;
    in.ruleAttackIds = a.attackIds;
    {
        const auto acts = nlohmann::json::parse(a.actionsTakenJson, nullptr, false);
        if (acts.is_array())
            for (const auto& x : acts)
                if (x.is_object() && x.contains("action") && x["action"].is_string())
                    in.actionsTaken.push_back(x["action"].get<std::string>());
    }

    // 程序鏈：由觸發程序往上走到樹根（最多 16 層），根在前
    {
        CAIRN_TRY(auto chain, LoadChain(a.triggerProcessGuid.value_or(a.rootProcessGuid), a.rootProcessGuid, 16));
        for (size_t i = 0; i < chain.size(); ++i) {
            const auto& n = chain[i];
            model::PromptProcessNode p;
            p.depth          = static_cast<int32_t>(i);
            p.image          = n.image.value_or("");
            p.commandLine    = n.commandLine.value_or("");
            p.signer         = n.signer.value_or("");
            p.signatureValid = n.signatureValid;
            p.sha256         = n.sha256.value_or("");
            in.processChain.push_back(std::move(p));
        }
    }
    {
        // 樹深度：以子樹查詢計算（受 64 層上限保護）
        auto sub = GetProcessSubtree(a.rootProcessGuid);
        if (sub) {
            int32_t maxd = 0;
            for (const auto& n : sub.Value()) maxd = std::max(maxd, n.depth);
            in.treeDepth = maxd;
        }
        m_db->SetQueryDeadline(kQueryBudget);
    }

    // 時間軸：最多 40 筆、最舊在前。告警證據不足 40 筆時以同一棵樹在告警時間前後的事件補足。
    std::vector<EventRecord> events;
    {
        CAIRN_TRY(auto tl, LoadTimeline(alertId, 500));
        for (auto& t : tl) events.push_back(std::move(t.event));
    }
    if (events.size() < 40) {
        std::set<int64_t> have;
        for (const auto& e : events) have.insert(e.id);
        CAIRN_TRY(auto st, m_db->Prepare("SELECT " + std::string(kEventCols) +
                                         " FROM events e WHERE e.root_process_guid = ?1 AND e.ts <= ?2"
                                         " ORDER BY e.ts DESC, e.id DESC LIMIT 80;"));
        st.BindText(1, a.rootProcessGuid).Bind(2, a.ts + 60'000);
        for (;;) {
            CAIRN_TRY(bool row, st.Step());
            if (!row) break;
            EventRecord e = ReadEvent(st);
            if (!have.count(e.id)) events.push_back(std::move(e));
        }
    }
    std::sort(events.begin(), events.end(), [](const EventRecord& x, const EventRecord& y) {
        return x.ts != y.ts ? x.ts < y.ts : x.id < y.id;
    });
    if (events.size() > 40) events.erase(events.begin(), events.end() - 40);   // 保留最接近告警的 40 筆
    const int64_t t0 = events.empty() ? 0 : events.front().ts;
    for (const auto& e : events) {
        model::PromptTimelineEvent t;
        t.offsetMs  = e.ts - t0;
        t.eid       = static_cast<uint16_t>(e.sourceEventId);
        t.eventType = e.eventType;
        t.summary   = SummarizeEvent(e);
        in.timeline.push_back(std::move(t));
    }
    return in;
}

} // namespace cairn::store
