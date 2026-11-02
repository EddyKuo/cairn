#include "store/WriteDao.h"

#include <nlohmann/json.hpp>

#include "base/IClock.h"

namespace cairn::store {

using model::ResolveField;

std::string GuidText(const model::GuidValue& g)
{
    return g.IsNull() ? std::string{} : g.ToString();
}

std::string ToJsonArray(const std::vector<std::string>& v)
{
    return nlohmann::json(v).dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

Status InsertEvent(SqliteDb& db, const model::StringInterner& in, const model::EventRow& r)
{
    static constexpr std::string_view kSql =
        "INSERT INTO events(id,ts,source,source_event_id,event_type,priority,process_guid,parent_process_guid,"
        "root_process_guid,pid,image,parent_image,command_line,parent_command_line,user_name,integrity_level,"
        "sha256,signature_signer,signature_valid,target_process_guid,target_image,granted_access,target_filename,"
        "registry_path,registry_details,dest_ip,dest_port,dest_hostname,query_name,query_results,pipe_name,"
        "script_block,score_delta,raw_json) VALUES("
        "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,"
        "?29,?30,?31,?32,?33,?34) ON CONFLICT(id) DO NOTHING;";
    CAIRN_TRY(auto st, db.Prepare(kSql));
    const auto& e = r.ev;
    const std::string pg   = GuidText(e.processGuid);
    const std::string ppg  = GuidText(e.parentProcessGuid);
    const std::string root = GuidText(r.rootProcessGuid);
    const std::string tpg  = e.targetProcessGuid ? GuidText(*e.targetProcessGuid) : std::string{};
    const std::string_view targetImage =
        e.targetImage ? ResolveField(in, *e.targetImage, e.targetImageFallback)
                      : (e.targetImageFallback ? std::string_view{*e.targetImageFallback} : std::string_view{});

    // 本函式內所有字串來源（r、in）的生命週期涵蓋 step，可用 SQLITE_STATIC 省下複製（part2 §2.3.3）
    st.Bind(1, r.id)
        .Bind(2, ToUnixMs(e.time))
        .BindTextStatic(3, model::SourceKindToString(e.source))
        .Bind(4, static_cast<int64_t>(e.sourceEventId))
        .BindTextStatic(5, model::EventTypeToString(e.type))
        .Bind(6, static_cast<int64_t>(e.priority));
    st.BindTextOrNull(7, pg).BindTextOrNull(8, ppg).BindTextOrNull(9, root);
    st.Bind(10, static_cast<int64_t>(e.pid));
    const auto image  = ResolveField(in, e.image, e.imageFallback);
    const auto pimage = ResolveField(in, e.parentImage, e.parentImageFallback);
    const auto user   = ResolveField(in, e.user, std::nullopt);
    const auto signer = ResolveField(in, e.signer, e.signerFallback);
    image.empty() ? st.BindNull(11) : st.BindTextStatic(11, image);
    pimage.empty() ? st.BindNull(12) : st.BindTextStatic(12, pimage);
    e.commandLine.empty() ? st.BindNull(13) : st.BindTextStatic(13, e.commandLine);
    e.parentCommandLine.empty() ? st.BindNull(14) : st.BindTextStatic(14, e.parentCommandLine);
    user.empty() ? st.BindNull(15) : st.BindTextStatic(15, user);
    st.BindTextOrNull(16, e.integrityLevel).BindTextOrNull(17, e.sha256);
    signer.empty() ? st.BindNull(18) : st.BindTextStatic(18, signer);
    st.BindOpt(19, e.signatureValid);
    st.BindTextOrNull(20, tpg);
    targetImage.empty() ? st.BindNull(21) : st.BindTextStatic(21, targetImage);
    st.BindOpt(22, e.grantedAccess)
        .BindOpt(23, e.targetFilename)
        .BindOpt(24, e.registryPath)
        .BindOpt(25, e.registryDetails)
        .BindOpt(26, e.destinationIp)
        .BindOpt(27, e.destinationPort)
        .BindOpt(28, e.destinationHostname)
        .BindOpt(29, e.queryName)
        .BindOpt(30, e.queryResults)
        .BindOpt(31, e.pipeName)
        .BindOpt(32, e.scriptBlock)
        .Bind(33, r.scoreDeltaMilli)
        .BindOpt(34, e.rawXml);
    return st.Run();
}

Status UpsertProcess(SqliteDb& db, const model::ProcessRow& r)
{
    static constexpr std::string_view kSql =
        "INSERT INTO process_tree(process_guid,parent_process_guid,root_process_guid,depth,pid,image,command_line,"
        "user_name,integrity_level,sha256,signature_signer,signature_valid,start_ts,end_ts,event_count)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        " ON CONFLICT(process_guid) DO UPDATE SET"
        "  parent_process_guid = COALESCE(excluded.parent_process_guid, parent_process_guid),"
        "  root_process_guid   = excluded.root_process_guid,"
        "  depth               = excluded.depth,"
        "  pid                 = CASE WHEN excluded.pid != 0 THEN excluded.pid ELSE pid END,"
        "  image               = COALESCE(excluded.image, image),"
        "  command_line        = COALESCE(excluded.command_line, command_line),"
        "  user_name           = COALESCE(excluded.user_name, user_name),"
        "  integrity_level     = COALESCE(excluded.integrity_level, integrity_level),"
        "  sha256              = COALESCE(excluded.sha256, sha256),"
        "  signature_signer    = COALESCE(excluded.signature_signer, signature_signer),"
        "  signature_valid     = COALESCE(excluded.signature_valid, signature_valid),"
        "  start_ts            = CASE WHEN pid = 0 THEN excluded.start_ts ELSE MIN(start_ts, excluded.start_ts) END,"
        "  end_ts              = COALESCE(excluded.end_ts, end_ts),"
        "  event_count         = MAX(event_count, excluded.event_count);";
    CAIRN_TRY(auto st, db.Prepare(kSql));
    st.BindText(1, GuidText(r.processGuid))
        .BindTextOrNull(2, GuidText(r.parentProcessGuid))
        .BindText(3, GuidText(r.rootProcessGuid.IsNull() ? r.processGuid : r.rootProcessGuid))
        .Bind(4, static_cast<int64_t>(r.depth))
        .Bind(5, static_cast<int64_t>(r.pid))
        .BindTextOrNull(6, r.image)
        .BindTextOrNull(7, r.commandLine)
        .BindTextOrNull(8, r.userName)
        .BindTextOrNull(9, r.integrityLevel)
        .BindTextOrNull(10, r.sha256)
        .BindTextOrNull(11, r.signatureSigner)
        .BindOpt(12, r.signatureValid)
        .Bind(13, r.startTs)
        .BindOpt(14, r.endTs)
        .Bind(15, static_cast<int64_t>(r.eventCount));
    return st.Run();
}

Status UpdateProcessEnd(SqliteDb& db, const model::ProcessEndUpdate& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE process_tree SET end_ts = ?1 WHERE process_guid = ?2;"));
    st.Bind(1, r.endTs).BindText(2, GuidText(r.processGuid));
    return st.Run();
}

Status MarkTerminatedByUs(SqliteDb& db, const model::ProcessTerminatedByUs& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE process_tree SET is_terminated_by_us = 1 WHERE process_guid = ?1;"));
    st.BindText(1, GuidText(r.processGuid));
    return st.Run();
}

Status UpsertScore(SqliteDb& db, const model::ScoreRow& r)
{
    const std::string root = GuidText(r.rootProcessGuid);
    if (root.empty()) return MakeError(ErrorCode::InvalidArgument, "score without root guid");
    {
        // FK：scores.root_process_guid → process_tree。樹根尚無節點列時插入佔位（pid=0 標示佔位）
        CAIRN_TRY(auto ph, db.Prepare("INSERT INTO process_tree(process_guid,root_process_guid,pid,start_ts)"
                                      " VALUES(?1,?1,0,?2) ON CONFLICT(process_guid) DO NOTHING;"));
        ph.BindText(1, root).Bind(2, r.firstHitTs);
        CAIRN_CHECK(ph.Run());
    }
    static constexpr std::string_view kSql =
        "INSERT INTO scores(root_process_guid,score,peak_score,shadow_score,last_update_ts,first_hit_ts,state)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7)"
        " ON CONFLICT(root_process_guid) DO UPDATE SET"
        "  score = excluded.score, peak_score = MAX(peak_score, excluded.peak_score),"
        "  shadow_score = excluded.shadow_score, last_update_ts = excluded.last_update_ts,"
        "  first_hit_ts = MIN(first_hit_ts, excluded.first_hit_ts), state = excluded.state;";
    CAIRN_TRY(auto st, db.Prepare(kSql));
    st.BindText(1, root)
        .Bind(2, r.scoreMilli)
        .Bind(3, r.peakMilli)
        .Bind(4, r.shadowMilli)
        .Bind(5, r.lastUpdateTs)
        .Bind(6, r.firstHitTs)
        .BindTextStatic(7, model::TreeStateToDb(r.state));
    return st.Run();
}

Status InsertRuleHit(SqliteDb& db, const model::RuleHitRow& r)
{
    static constexpr std::string_view kSql =
        "INSERT INTO rule_hits(ts,rule_id,root_process_guid,event_id,alert_id,score_delta,dryrun,suppressed,"
        "suppressed_by,rule_hash) VALUES(?1,?2,?3,"
        " (SELECT id FROM events WHERE id = ?4),"
        " (SELECT id FROM alerts WHERE id = ?5),"
        " ?6,?7,?8,"
        " (SELECT id FROM exclusions WHERE id = ?9),"
        " ?10);";
    CAIRN_TRY(auto st, db.Prepare(kSql));
    st.Bind(1, r.ts)
        .BindText(2, r.ruleId)
        .BindText(3, GuidText(r.rootProcessGuid))
        .BindOpt(4, r.eventId)
        .BindOpt(5, r.alertId)
        .Bind(6, r.scoreDeltaMilli)
        .BindBool(7, r.dryrun)
        .BindBool(8, r.suppressed)
        .BindOpt(9, r.suppressedBy)
        .BindText(10, r.ruleHash);
    return st.Run();
}

Result<int64_t> InsertAlert(SqliteDb& db, const model::AlertRow& r)
{
    static constexpr std::string_view kSql =
        "INSERT INTO alerts(id,ts,root_process_guid,trigger_process_guid,severity,score_at_trigger,rule_ids,"
        "attack_ids,title,summary,ai_state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
        " ON CONFLICT(id) DO NOTHING;";
    {
        CAIRN_TRY(auto st, db.Prepare(kSql));
        st.Bind(1, r.id)
            .Bind(2, r.ts)
            .BindText(3, GuidText(r.rootProcessGuid))
            .BindTextOrNull(4, r.triggerProcessGuid ? GuidText(*r.triggerProcessGuid) : std::string{})
            .BindTextStatic(5, model::SeverityToString(r.severity))
            .Bind(6, r.scoreAtTriggerMilli)
            .BindText(7, ToJsonArray(r.ruleIds))
            .BindText(8, ToJsonArray(r.attackIds))
            .BindText(9, r.title.empty() ? std::string("（未命名告警）") : r.title)   // title 永不為空（UI 在 LLM 全掛時仍須可用）
            .BindTextOrNull(10, r.summary)
            .BindTextStatic(11, model::AiStateToString(r.aiState));
        CAIRN_CHECK(st.Run());
    }
    for (const auto& link : r.events) {
        CAIRN_TRY(auto st, db.Prepare("INSERT OR IGNORE INTO alert_events(alert_id,event_id,step_index,role)"
                                      " SELECT ?1,?2,?3,?4 WHERE EXISTS(SELECT 1 FROM events WHERE id = ?2);"));
        // OR IGNORE 只吞 PK 衝突（同一事件重複連結），不是 REPLACE，不會觸發 CASCADE
        st.Bind(1, r.id).Bind(2, link.eventId).BindOpt(3, link.stepIndex).BindText(4, link.role);
        CAIRN_CHECK(st.Run());
    }
    for (auto hit : r.hits) {
        if (!hit.alertId) hit.alertId = r.id;
        CAIRN_CHECK(InsertRuleHit(db, hit));
    }
    return r.id;
}

Status UpdateNarrative(SqliteDb& db, const model::AlertNarrativeUpdate& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE alerts SET ai_state=?1, ai_narrative=?2, ai_recommendation=?3,"
                                  " ai_confidence=?4, ai_attack_ids=?5, ai_model_id=?6, ai_latency_ms=?7 WHERE id=?8;"));
    st.BindTextStatic(1, model::AiStateToString(r.aiState))
        .BindOpt(2, r.narrative)
        .BindOpt(3, r.recommendation)
        .BindOpt(4, r.confidence);
    r.aiAttackIds.empty() ? st.BindNull(5) : st.BindText(5, ToJsonArray(r.aiAttackIds));
    st.BindOpt(6, r.modelId).BindOpt(7, r.latencyMs).Bind(8, r.alertId);
    return st.Run();
}

Status UpdateVerdict(SqliteDb& db, const model::AlertVerdictUpdate& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE alerts SET analyst_verdict=?1, analyst_note=?2, verdict_ts=?3 WHERE id=?4;"));
    st.BindTextStatic(1, model::VerdictToString(r.verdict)).BindTextOrNull(2, r.note).Bind(3, r.ts).Bind(4, r.alertId);
    return st.Run();
}

Status AppendAlertAction(SqliteDb& db, const model::AlertActionAppend& r)
{
    // json(?) 會驗證輸入；非法 JSON 時以字串形式附加，絕不丟掉「做了什麼」的紀錄
    CAIRN_TRY(auto st, db.Prepare(
                           "UPDATE alerts SET actions_taken = json_insert(COALESCE(actions_taken,'[]'), '$[#]',"
                           " CASE WHEN json_valid(?1) THEN json(?1) ELSE ?1 END) WHERE id = ?2;"));
    st.BindText(1, r.actionJson).Bind(2, r.alertId);
    return st.Run();
}

Result<int64_t> InsertExclusion(SqliteDb& db, const model::ExclusionInsert& r)
{
    static constexpr std::string_view kSql =
        "INSERT INTO exclusions(kind,value,scope_rule_id,reason,created_by,created_ts,expires_ts,enabled)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,1)"
        " ON CONFLICT(kind,value,scope_rule_id) DO UPDATE SET"
        "  enabled = 1, reason = COALESCE(excluded.reason, reason), expires_ts = excluded.expires_ts"
        " RETURNING id;";
    CAIRN_TRY(auto st, db.Prepare(kSql));
    st.BindTextStatic(1, model::ExclusionKindToString(r.kind))
        .BindText(2, r.value)
        .BindText(3, r.scopeRuleId)
        .BindTextOrNull(4, r.reason)
        .BindText(5, r.createdBy.empty() ? std::string("user") : r.createdBy)
        .Bind(6, r.createdTs)
        .BindOpt(7, r.expiresTs);
    CAIRN_TRY(bool row, st.Step());
    if (!row) return MakeError(ErrorCode::DbQueryFailed, "exclusion insert returned no id");
    const int64_t id = st.Int64(0);
    // RETURNING：必須把語句跑到 DONE 才算完成寫入
    for (;;) {
        CAIRN_TRY(bool more, st.Step());
        if (!more) break;
    }
    return id;
}

Status RemoveExclusion(SqliteDb& db, const model::ExclusionRemove& r)
{
    CAIRN_TRY(auto st, db.Prepare("DELETE FROM exclusions WHERE id = ?1;"));
    st.Bind(1, r.id);
    CAIRN_CHECK(st.Run());
    if (db.Changes() == 0) return MakeError(ErrorCode::NotFound, "exclusion not found");
    return Ok();
}

Status SetExclusionEnabled(SqliteDb& db, const model::ExclusionSetEnabled& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE exclusions SET enabled = ?1 WHERE id = ?2;"));
    st.BindBool(1, r.enabled).Bind(2, r.id);
    CAIRN_CHECK(st.Run());
    if (db.Changes() == 0) return MakeError(ErrorCode::NotFound, "exclusion not found");
    return Ok();
}

Status IncrementExclusionHits(SqliteDb& db, const model::ExclusionHitIncrement& r)
{
    CAIRN_TRY(auto st, db.Prepare("UPDATE exclusions SET hit_count = hit_count + ?1,"
                                  " last_hit_ts = MAX(COALESCE(last_hit_ts, 0), ?2) WHERE id = ?3;"));
    st.Bind(1, static_cast<int64_t>(r.count)).Bind(2, r.ts).Bind(3, r.id);
    return st.Run();
}

Status DismissSuggestion(SqliteDb& db, const model::SuggestionDismiss& r)
{
    if (r.suggestionId.empty()) return MakeError(ErrorCode::InvalidArgument, "DismissSuggestion: empty id");
    CAIRN_TRY(auto st, db.Prepare("INSERT INTO dismissed_suggestions(suggestion_id, dismissed_ts) VALUES(?1, ?2)"
                                  " ON CONFLICT(suggestion_id) DO UPDATE SET dismissed_ts = excluded.dismissed_ts;"));
    st.BindText(1, r.suggestionId).Bind(2, r.ts);
    return st.Run();
}

Status InsertHealth(SqliteDb& db, const model::HealthRow& r)
{
    CAIRN_TRY(auto st, db.Prepare(
                           "INSERT INTO agent_health(ts,events_ingested,events_dropped,events_filtered,queue_depth,"
                           "cpu_percent,private_bytes_mb,db_size_mb,sysmon_state,llm_state,tier2_p95_ms,llm_p95_ms)"
                           " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12);"));
    st.Bind(1, r.ts)
        .Bind(2, r.eventsIngested)
        .Bind(3, r.eventsDropped)
        .Bind(4, r.eventsFiltered)
        .Bind(5, r.queueDepth)
        .Bind(6, r.cpuPercent)
        .Bind(7, r.privateBytesMb)
        .Bind(8, r.dbSizeMb)
        .BindText(9, r.sysmonState)
        .BindText(10, r.llmState)
        .BindOpt(11, r.tier2P95Ms)
        .BindOpt(12, r.llmP95Ms);
    return st.Run();
}

} // namespace cairn::store
