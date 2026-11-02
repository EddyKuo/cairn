// src/svc/store/AuditChain.h                  namespace cairn::store
// audit_log 的 append-only 雜湊鏈（part2 §2.3.2、SDD-03 §8.6）。
//   row_hash = SHA256(prev_hash || canonical_json(本列除 row_hash 外欄位))
//   第一列 prev_hash = 64 個 '0'
//
// 只由 WriterThread（T4）持有並寫入；VerifyAuditChain 可在任何連線（含唯讀）執行。
// canonical_json：欄位順序固定、無空白、NULL 序列化為 null、非法 UTF-8 以 U+FFFD 取代。
// ★ 寫入與驗證必須用同一個 CanonicalJson，否則鏈永遠驗不過。
//
// 誠實揭露：鏈能偵測「竄改或刪除其中一列」，不能偵測「整段截斷後重建整條鏈」（M1 以外部錨點補）。
#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "base/Result.h"
#include "model/WriteOp.h"
#include "store/SqliteDb.h"

namespace cairn::store {

inline constexpr std::string_view kGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

struct AuditFields {
    int64_t                    ts = 0;
    std::string                actor;
    std::string                action;
    std::string                eventKind;
    std::optional<int64_t>     alertId;
    std::optional<std::string> target;
    std::string                params = "{}";
    std::string                result;
    std::optional<std::string> error;
    std::string                prevHash;
};

[[nodiscard]] std::string CanonicalAuditJson(const AuditFields& f);
[[nodiscard]] std::string ComputeAuditRowHash(const AuditFields& f);   // SHA256(prev_hash || canonical)

// AuditRow 沒有 event_kind 欄位：若 paramsJson 帶 "event_kind" 字串則採用，否則依 action 推導
// （C-9 動作名 → action_completed；*_revert / restore → action_reverted；其餘 = action 本身）。
[[nodiscard]] std::string DeriveEventKind(const model::AuditRow& row);

class AuditChain {
public:
    explicit AuditChain(SqliteDb& writer) noexcept : m_db(writer) {}

    // 啟動時讀最後一列的 row_hash；表為空則為創世雜湊。
    [[nodiscard]] Status Load();

    // INSERT 一列並推進鏈尾。呼叫端負責交易邊界（Safe 交易）。
    // ★ 只在 INSERT 成功後推進 m_lastHash —— 失敗重試仍接在正確的前一列之後。
    [[nodiscard]] Result<int64_t> Append(const model::AuditRow& row);

    [[nodiscard]] const std::string& LastHash() const noexcept { return m_lastHash; }

    // 交易回滾後呼叫：把鏈尾還原為 DB 中真正的最後一列。
    [[nodiscard]] Status Reload() { return Load(); }

private:
    SqliteDb&   m_db;
    std::string m_lastHash{kGenesisHash};
};

struct ChainReport {
    bool        valid         = true;
    int64_t     firstBrokenId = 0;   // 0 = 無斷點
    std::string detail;              // "row 1093: row_hash mismatch" | "gap: id 1094 missing"
    int64_t     verifiedCount = 0;
};

// 驗證 [fromId, toId]（toId = 0 表示到最後）。fromId > 1 時以前一列的 row_hash 作為起點。
[[nodiscard]] Result<ChainReport> VerifyAuditChain(SqliteDb& db, int64_t fromId = 1, int64_t toId = 0);

} // namespace cairn::store
