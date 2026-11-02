// src/core/prompt/AttackCatalog.h             namespace cairn::llm
// ATT&CK Enterprise 技術 ID 白名單（SDD-03 §7.5.1 第 1 道白名單）。
// LLM 輸出的 attack_ids 逐項比對，不在清單內者剔除；全部被剔除則 ai_state='schema_violation'。
//
// 來源：
//   1. Builtin()：編譯期內嵌的清單（Enterprise v15/v16 時期的技術與子技術 ID）。
//      ⚠ 內嵌清單由人工整理，子技術以「連號區間」表示，可能包含少數已棄用或不存在的編號
//        （寬鬆方向的誤差：最多讓一個不存在的 ID 通過，不會讓真實 ID 被剔除）。
//   2. FromJson()：隨產品打包的 attack-techniques.json（%ProgramFiles%\Cairn\data\），
//      由 MITRE STIX（enterprise-attack.json）抽出 external_id 產生。存在時應優先使用。
#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "base/Result.h"

namespace cairn::llm {

class AttackCatalog {
public:
    // 內嵌清單（程序生命週期內唯一實例，執行緒安全的唯讀物件）
    [[nodiscard]] static const AttackCatalog& Builtin();

    // 接受 ["T1059","T1059.001",...] 或 {"techniques":[...]}。格式不符的項目略過；結果為空則回錯誤。
    [[nodiscard]] static Result<AttackCatalog> FromJson(std::string_view json);

    // 由 ID 清單直接建立（測試用）
    [[nodiscard]] static AttackCatalog FromIds(const std::vector<std::string>& ids);

    // ^T\d{4}(\.\d{3})?$
    [[nodiscard]] static bool IsWellFormed(std::string_view id) noexcept;

    [[nodiscard]] bool Contains(std::string_view id) const;

    // 保留格式正確且在清單內者；去重並維持原順序。
    [[nodiscard]] std::vector<std::string> Filter(const std::vector<std::string>& ids) const;

    [[nodiscard]] size_t Size() const noexcept { return m_ids.size(); }

private:
    AttackCatalog() = default;
    std::unordered_set<std::string> m_ids;
};

} // namespace cairn::llm
