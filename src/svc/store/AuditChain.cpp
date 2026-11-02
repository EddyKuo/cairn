#include "store/AuditChain.h"

#include <nlohmann/json.hpp>

#include "store/Sha256.h"

namespace cairn::store {

std::string CanonicalAuditJson(const AuditFields& f)
{
    // ordered_json：鍵的順序即插入順序 —— 這就是「固定欄位順序」的實作
    nlohmann::ordered_json j;
    j["ts"]         = f.ts;
    j["actor"]      = f.actor;
    j["action"]     = f.action;
    j["event_kind"] = f.eventKind;
    j["alert_id"]   = f.alertId ? nlohmann::ordered_json(*f.alertId) : nlohmann::ordered_json(nullptr);
    j["target"]     = f.target ? nlohmann::ordered_json(*f.target) : nlohmann::ordered_json(nullptr);
    j["params"]     = f.params;   // 以字串原樣納入（不重新序列化，避免鍵順序差異）
    j["result"]     = f.result;
    j["error"]      = f.error ? nlohmann::ordered_json(*f.error) : nlohmann::ordered_json(nullptr);
    j["prev_hash"]  = f.prevHash;
    return j.dump(-1, ' ', false, nlohmann::ordered_json::error_handler_t::replace);
}

std::string ComputeAuditRowHash(const AuditFields& f)
{
    std::string buf;
    const std::string canon = CanonicalAuditJson(f);
    buf.reserve(f.prevHash.size() + canon.size());
    buf.append(f.prevHash).append(canon);
    return Sha256Hex(buf);
}

std::string DeriveEventKind(const model::AuditRow& row)
{
    try {
        const auto p = nlohmann::json::parse(row.paramsJson, nullptr, /*allow_exceptions*/ false);
        if (p.is_object()) {
            if (auto it = p.find("event_kind"); it != p.end() && it->is_string()) return it->get<std::string>();
        }
    } catch (...) {
        // parse 已關閉例外；保險起見仍吞掉（P-2：例外不得跨模組邊界）
    }
    const std::string& a = row.action;
    if (a == "suspend_process" || a == "terminate_process_tree" || a == "quarantine_file" || a == "firewall_block")
        return "action_completed";
    if (a.find("revert") != std::string::npos || a == "restore") return "action_reverted";
    return a;
}

Status AuditChain::Load()
{
    CAIRN_TRY(auto st, m_db.Prepare("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1;"));
    CAIRN_TRY(bool row, st.Step());
    m_lastHash = row ? st.Text(0) : std::string(kGenesisHash);
    return Ok();
}

Result<int64_t> AuditChain::Append(const model::AuditRow& row)
{
    AuditFields f;
    f.ts        = row.ts;
    f.actor     = row.actor;
    f.action    = row.action;
    f.eventKind = DeriveEventKind(row);
    f.alertId   = row.alertId;
    if (!row.target.empty()) f.target = row.target;
    f.params    = row.paramsJson.empty() ? std::string("{}") : row.paramsJson;
    f.result    = row.result;
    f.error     = row.error;
    f.prevHash  = m_lastHash;
    const std::string hash = ComputeAuditRowHash(f);
    if (hash.empty()) return MakeError(ErrorCode::IoError, "audit: sha256 failed");

    CAIRN_TRY(auto st, m_db.Prepare(
                           "INSERT INTO audit_log(ts,actor,action,event_kind,alert_id,target,params,result,error,"
                           "prev_hash,row_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?);"));
    st.Bind(1, f.ts).BindText(2, f.actor).BindText(3, f.action).BindText(4, f.eventKind).BindOpt(5, f.alertId)
        .BindOpt(6, f.target).BindText(7, f.params).BindText(8, f.result).BindOpt(9, f.error)
        .BindText(10, f.prevHash).BindText(11, hash);
    CAIRN_CHECK(st.Run());
    m_lastHash = hash;
    return m_db.LastInsertRowId();
}

Result<ChainReport> VerifyAuditChain(SqliteDb& db, int64_t fromId, int64_t toId)
{
    ChainReport rep;
    std::string prev(kGenesisHash);
    int64_t     expectId = fromId < 1 ? 1 : fromId;

    if (expectId > 1) {
        CAIRN_TRY(auto ps, db.Prepare("SELECT id,row_hash FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT 1;"));
        ps.Bind(1, expectId);
        CAIRN_TRY(bool row, ps.Step());
        if (row) {
            prev     = ps.Text(1);
            expectId = ps.Int64(0) + 1;
        } else {
            expectId = 1;
        }
    }

    CAIRN_TRY(auto st, db.Prepare("SELECT id,ts,actor,action,event_kind,alert_id,target,params,result,error,prev_hash,"
                                  "row_hash FROM audit_log WHERE id >= ? AND (? = 0 OR id <= ?) ORDER BY id;"));
    st.Bind(1, expectId).Bind(2, toId).Bind(3, toId);
    for (;;) {
        CAIRN_TRY(bool row, st.Step());
        if (!row) break;
        const int64_t id = st.Int64(0);
        // id 缺口：AUTOINCREMENT 保證 id 不重用（回滾的交易也不消耗序號），缺口代表該列被刪除
        if (id != expectId) {
            rep.valid         = false;
            rep.firstBrokenId = expectId;
            rep.detail        = "gap: id " + std::to_string(expectId) + " missing (deleted?)";
            return rep;
        }

        AuditFields f;
        f.ts        = st.Int64(1);
        f.actor     = st.Text(2);
        f.action    = st.Text(3);
        f.eventKind = st.Text(4);
        f.alertId   = st.OptInt64(5);
        f.target    = st.OptText(6);
        f.params    = st.Text(7);
        f.result    = st.Text(8);
        f.error     = st.OptText(9);
        f.prevHash  = st.Text(10);
        const std::string stored = st.Text(11);

        if (f.prevHash != prev) {
            rep.valid = false;
            rep.firstBrokenId = id;
            rep.detail = "row " + std::to_string(id) + ": prev_hash does not match previous row";
            return rep;
        }
        if (ComputeAuditRowHash(f) != stored) {
            rep.valid = false;
            rep.firstBrokenId = id;
            rep.detail = "row " + std::to_string(id) + ": row_hash mismatch";
            return rep;
        }
        prev = stored;
        expectId = id + 1;
        ++rep.verifiedCount;
    }
    return rep;
}

} // namespace cairn::store
