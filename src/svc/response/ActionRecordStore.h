// src/svc/response/ActionRecordStore.h        namespace cairn::response
// 動作紀錄的持久化：%ProgramData%\Cairn\actions\{actionId}.json。可攜程式碼。
//
// 為什麼不放 DB：WriterThread 是唯一寫者（part2 §2.3.3），T6 若要讀回自己的動作參數
// 就得等寫入佇列 flush 再開唯讀連線，且 DB 損毀重建時還原資訊會一併消失。
// 動作頻率極低（每小時個位數），每筆一個小 JSON 檔是最簡單且可人工檢視的作法。
//
// revert 的鍵與 audit_log.id 的對應：
//   - actionId（"ACT-{alertId:04}-{nn}"）在 Execute 當下由本類別配發，同步回給 RPC，是 revert 的主鍵
//   - audit_log.id 由 WriterThread 非同步配發；ResponseExecutor 以 WriteOp::onDone 取得後
//     投遞回 T6，呼叫 SetAuditId(actionId, id) 寫回此檔。
//   - Revert 也接受 audit id：FindByAuditId 線性掃描（紀錄數極少）。
//
// 執行緒：僅 ResponseThread（T6）呼叫，不加鎖。
#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "base/Result.h"
#include "response/ResponseTypes.h"

namespace cairn::response {

class ActionRecordStore {
public:
    explicit ActionRecordStore(std::filesystem::path dir);

    [[nodiscard]] Status EnsureDir();

    // "ACT-0142-01"、"ACT-0142-02" ...（同一告警的第 n 個動作）
    [[nodiscard]] std::string NextActionId(int64_t alertId) const;

    // 原子寫入：先寫 .tmp 再 rename 覆蓋
    [[nodiscard]] Status Save(const ActionRecord& r);
    [[nodiscard]] Result<ActionRecord> Load(const std::string& actionId) const;
    [[nodiscard]] Result<ActionRecord> FindByAuditId(int64_t auditId) const;
    // 接受 actionId 或十進位 audit id 字串
    [[nodiscard]] Result<ActionRecord> Resolve(const std::string& actionIdOrAuditId) const;
    [[nodiscard]] std::vector<ActionRecord> List() const;

    [[nodiscard]] const std::filesystem::path& Dir() const noexcept { return m_dir; }

private:
    [[nodiscard]] std::filesystem::path PathOf(const std::string& actionId) const;
    std::filesystem::path m_dir;
};

// actionId 只允許 [A-Za-z0-9-]，防止以 "..\\" 之類的字串逃出目錄。
[[nodiscard]] bool IsValidActionId(std::string_view id) noexcept;

} // namespace cairn::response
