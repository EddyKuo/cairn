// src/core/rules/RuleLoader.h                 namespace cairn::rules
// 規則目錄載入、逐條錯誤報告、狀態覆寫（rules.setStatus）、排除清單 YAML 載入。
// 「絕不因規則語法錯誤讓防護停擺」：單條規則失敗只讓該條缺席；整批為零才回傳 NoRulesLoaded，
// 呼叫端（svc）此時必須保留舊 RuleSet。
#pragma once
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/Result.h"
#include "model/StringInterner.h"
#include "rules/Exclusions.h"
#include "rules/Rule.h"

namespace cairn::rules {

// rules.list 所需的每條規則中繼資料
struct RuleInfo {
    std::string              id;
    std::string              title;
    std::string              severity;        // low | medium | high | critical
    std::string              status;          // enabled | dryrun | disabled（已套用覆寫）
    std::string              declaredStatus;  // YAML 檔內宣告的狀態
    int                      score = 0;       // 顯示分（1–100）
    std::vector<std::string> attackIds;
    std::vector<uint16_t>    requiresEids;
    bool                     deterministic = false;
    std::string              contentHash;     // 16 hex
    std::string              sourceFile;
    std::string              loadError;       // 空字串 = 載入成功
};

struct RuleLoadReport {
    std::shared_ptr<const RuleSet> ruleSet;   // 只含成功編譯的規則
    std::vector<RuleInfo>          rules;     // 含失敗者（loadError 非空）
    std::vector<std::string>       fileErrors;// 整檔語法錯誤
    size_t                         loaded = 0;
    size_t                         failed = 0;
};

using StatusOverrides = std::unordered_map<std::string, model::RuleStatus>;

struct RuleLoadOptions {
    uint32_t        generation = 0;
    StatusOverrides overrides;            // rules.setStatus 持久化的覆寫（由 svc 保存）
    bool            forceDryRun = false;  // 7 天 dry-run 誤報基準（part4 §4.5.3）：enabled 一律降為 dryrun
};

// 載入目錄下所有 *.yaml / *.yml，略過以 "_" 或 "exclusions" 開頭的檔案。
// interner 目前保留給規則常數駐留的後續最佳化（M0 以小寫字串比對）。
[[nodiscard]] Result<RuleLoadReport> LoadRuleDirectory(const std::filesystem::path& dir,
                                                       model::StringInterner& interner,
                                                       const RuleLoadOptions& opts = {});

// 測試與工具用：從記憶體中的 (檔名, YAML 文字) 載入。
[[nodiscard]] Result<RuleLoadReport> LoadRuleTexts(const std::vector<std::pair<std::string, std::string>>& files,
                                                   model::StringInterner& interner,
                                                   const RuleLoadOptions& opts = {});

// 套用覆寫至狀態（供 rules.setStatus 預覽；實際生效需重新 LoadRuleDirectory 並 ReplaceRuleSet）。
[[nodiscard]] model::RuleStatus EffectiveStatus(const std::string& ruleId, model::RuleStatus declared,
                                                const RuleLoadOptions& opts) noexcept;

// 排除清單 YAML（rules/exclusions.default.yaml）。回傳的條目 id = 0、createdBy = "builtin"；
// svc 安裝時寫入 DB exclusions 表取得 id 後，再以 DB 內容呼叫 AnalysisEngine::ReplaceExclusions。
[[nodiscard]] Result<std::vector<ExclusionEntry>> LoadExclusionsYaml(const std::filesystem::path& file);
[[nodiscard]] Result<std::vector<ExclusionEntry>> ParseExclusionsYaml(std::string_view text);

} // namespace cairn::rules
