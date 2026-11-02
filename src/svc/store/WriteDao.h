// src/svc/store/WriteDao.h                    namespace cairn::store
// 各 WriteOp payload 的 SQL 寫入（無狀態函式群；只在 WriterThread 的寫連線上呼叫）。
//
// FK 防呆（foreign_keys=ON 下，單筆失敗不可拖垮整批）：
//   - rule_hits 的 event_id / alert_id / suppressed_by 以子查詢取值：參照的列不存在（被背壓丟掉或已 retention）
//     時自動寫 NULL，而不是讓 INSERT 失敗。
//   - alert_events 只在 events 有該列時插入（INSERT ... SELECT ... WHERE EXISTS）。
//   - scores 的 root 若尚無 process_tree 列（孤兒樹根、EID 1 被丟）先插入佔位節點，再 upsert 分數。
//   - 一律 upsert（ON CONFLICT DO UPDATE），禁止 INSERT OR REPLACE：REPLACE 會先 DELETE 衝突列並
//     觸發 scores 的 ON DELETE CASCADE，靜默刪掉該樹的分數（SDD-02 §6.3.1）。
//
// ★ 可攜程式碼。
#pragma once
#include "base/Result.h"
#include "model/StringInterner.h"
#include "model/WriteOp.h"
#include "store/SqliteDb.h"

namespace cairn::store {

[[nodiscard]] std::string GuidText(const model::GuidValue& g);   // null GUID → 空字串（綁定時轉 NULL）

[[nodiscard]] Status InsertEvent(SqliteDb& db, const model::StringInterner& in, const model::EventRow& r);
[[nodiscard]] Status UpsertProcess(SqliteDb& db, const model::ProcessRow& r);
[[nodiscard]] Status UpdateProcessEnd(SqliteDb& db, const model::ProcessEndUpdate& r);
[[nodiscard]] Status MarkTerminatedByUs(SqliteDb& db, const model::ProcessTerminatedByUs& r);
[[nodiscard]] Status UpsertScore(SqliteDb& db, const model::ScoreRow& r);
[[nodiscard]] Status InsertRuleHit(SqliteDb& db, const model::RuleHitRow& r);
// 告警本體 + alert_events + 構成告警的 rule_hits。呼叫端負責 Safe 交易。
[[nodiscard]] Result<int64_t> InsertAlert(SqliteDb& db, const model::AlertRow& r);
[[nodiscard]] Status UpdateNarrative(SqliteDb& db, const model::AlertNarrativeUpdate& r);
[[nodiscard]] Status UpdateVerdict(SqliteDb& db, const model::AlertVerdictUpdate& r);
[[nodiscard]] Status AppendAlertAction(SqliteDb& db, const model::AlertActionAppend& r);
[[nodiscard]] Result<int64_t> InsertExclusion(SqliteDb& db, const model::ExclusionInsert& r);
[[nodiscard]] Status RemoveExclusion(SqliteDb& db, const model::ExclusionRemove& r);
[[nodiscard]] Status SetExclusionEnabled(SqliteDb& db, const model::ExclusionSetEnabled& r);
[[nodiscard]] Status IncrementExclusionHits(SqliteDb& db, const model::ExclusionHitIncrement& r);
[[nodiscard]] Status InsertHealth(SqliteDb& db, const model::HealthRow& r);

// JSON 陣列文字（rule_ids / attack_ids / ai_attack_ids 欄位）
[[nodiscard]] std::string ToJsonArray(const std::vector<std::string>& v);

} // namespace cairn::store
