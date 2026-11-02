// src/svc/host/HostState.h                    namespace cairn::host
// 服務的持久狀態（%ProgramData%\Cairn\state.json）：不屬於事件資料、但需跨重啟保存者。
//   - installTs / learningFinished：學習期（安裝後 N 天，part3 §3.10.1）
//   - ruleOverrides：rules.setStatus 的覆寫（YAML 檔不改，覆寫另存）
//   - pausedUntilMs：protection.pause 的定時暫停（until_reboot 只存在記憶體，重開機自然解除）
// 可攜、執行緒安全（mutex）。寫檔採「寫暫存檔再改名」避免斷電留下半個檔。
#pragma once
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "base/Result.h"
#include "model/Domain.h"
#include "rules/RuleLoader.h"

namespace cairn::host {

struct HostStateData {
    int64_t installTs        = 0;
    bool    learningFinished = false;
    std::unordered_map<std::string, model::RuleStatus> ruleOverrides;
    int64_t pausedUntilMs    = 0;      // 0 = 未暫停；INT64_MAX = 直到重開機（不持久化）
    std::string pauseReason;
    bool    builtinExclusionsSeeded = false;   // rules/exclusions.default.yaml 是否已寫入 DB（只在首次安裝寫一次）
};

class HostState {
public:
    explicit HostState(std::filesystem::path file) : m_file(std::move(file)) {}

    // 讀檔；不存在時以 nowMs 為安裝時間建立新狀態並寫檔。
    [[nodiscard]] Status Load(int64_t nowMs);
    [[nodiscard]] HostStateData Snapshot() const;

    [[nodiscard]] Status SetRuleOverride(const std::string& ruleId, model::RuleStatus s);
    [[nodiscard]] Status FinishLearning();
    [[nodiscard]] Status MarkBuiltinExclusionsSeeded();
    [[nodiscard]] Status SetPause(int64_t untilMs, std::string reason);   // 0 = 解除
    [[nodiscard]] bool   ExpirePauseIfDue(int64_t nowMs);                 // 到期則解除並回傳 true

    // 學習期是否進行中、第幾天（1 起算）
    [[nodiscard]] bool LearningActive(int64_t nowMs, int totalDays, bool enabled) const;
    [[nodiscard]] int  LearningDay(int64_t nowMs) const;
    [[nodiscard]] bool Paused(int64_t nowMs) const;

    // 純函式：序列化 / 反序列化（測試用）
    [[nodiscard]] static std::string Serialize(const HostStateData& d);
    [[nodiscard]] static Result<HostStateData> Deserialize(std::string_view text);

private:
    [[nodiscard]] Status SaveLocked() const;

    std::filesystem::path m_file;
    mutable std::mutex    m_mutex;
    HostStateData         m_data;
};

// 規則狀態覆寫的合成：學習期強制 dry-run 的規則（policy learning_mode.forced_dryrun_rules）為底，
// 使用者以 rules.setStatus 設定的覆寫優先（使用者的明確意圖高於預設政策）。
[[nodiscard]] rules::StatusOverrides ComposeRuleOverrides(const HostStateData& state,
                                                         const std::vector<std::string>& forcedDryrun,
                                                         bool learningActive);

} // namespace cairn::host
