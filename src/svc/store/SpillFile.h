// src/svc/store/SpillFile.h                   namespace cairn::store
// DB 不可用時，alerts / audit_log 的降級落地（SDD-02 §6.4 錯誤路徑、§6.7.2 步驟 2c）。
// 位置：%ProgramData%\Cairn\spill\spill-{unixms}.jsonl，一行一筆，WriterThread 啟動或 DB 恢復後補入。
// 「我們終止了你的程序」這件事，在任何情況下都必須有紀錄 —— 這是信任問題不是效能問題。
//
// ★ 可攜程式碼。
#pragma once
#include <filesystem>
#include <functional>
#include <string>
#include <variant>
#include <vector>

#include "base/Result.h"
#include "model/WriteOp.h"

namespace cairn::store {

using SpillRecord = std::variant<model::AlertRow, model::AuditRow>;

[[nodiscard]] std::string SerializeSpill(const SpillRecord& rec);
[[nodiscard]] Result<SpillRecord> DeserializeSpill(std::string_view line);

class SpillFile {
public:
    explicit SpillFile(std::filesystem::path dir);

    // 追加一筆並 flush（每筆都落地：spill 只在 DB 已失效時發生，頻率極低）
    [[nodiscard]] Status Append(const SpillRecord& rec);

    // 依檔名（時間）順序讀出全部記錄。回呼回傳 false 代表補入失敗：保留該檔供下次重試。
    // 全部成功的檔案會被刪除。回傳成功補入的筆數。
    [[nodiscard]] Result<size_t> Replay(const std::function<bool(const SpillRecord&)>& apply);

    [[nodiscard]] bool HasPending() const;

private:
    std::filesystem::path m_dir;
    std::filesystem::path m_current;
};

} // namespace cairn::store
