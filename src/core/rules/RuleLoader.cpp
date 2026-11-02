#include "rules/RuleLoader.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "rules/RuleCompiler.h"

namespace cairn::rules {

namespace {

RuleInfo InfoOf(const Rule& r, model::RuleStatus declared)
{
    RuleInfo i;
    i.id             = r.id;
    i.title          = r.title;
    i.severity       = std::string(model::SeverityToString(r.severity));
    i.status         = std::string(model::RuleStatusToString(r.status));
    i.declaredStatus = std::string(model::RuleStatusToString(declared));
    i.score          = static_cast<int>(r.scoreMilli / model::kScoreScale);
    i.attackIds      = r.attackIds;
    i.requiresEids   = r.requiresEids;
    i.deterministic  = r.deterministic;
    i.contentHash    = r.hashHex;
    i.sourceFile     = r.sourceFile;
    return i;
}

bool IsRuleFile(const std::filesystem::path& p)
{
    const auto ext  = model::ToLowerAscii(p.extension().string());
    const auto name = model::ToLowerAscii(p.filename().string());
    if (ext != ".yaml" && ext != ".yml") return false;
    if (name.rfind("_", 0) == 0 || name.rfind("exclusions", 0) == 0) return false;
    return true;
}

} // namespace

model::RuleStatus EffectiveStatus(const std::string& ruleId, model::RuleStatus declared,
                                  const RuleLoadOptions& opts) noexcept
{
    model::RuleStatus s = declared;
    if (auto it = opts.overrides.find(ruleId); it != opts.overrides.end()) s = it->second;
    if (opts.forceDryRun && s == model::RuleStatus::Enabled) s = model::RuleStatus::DryRun;
    return s;
}

Result<RuleLoadReport> LoadRuleTexts(const std::vector<std::pair<std::string, std::string>>& files,
                                     model::StringInterner& /*interner*/, const RuleLoadOptions& opts)
{
    RuleLoadReport report;
    std::vector<Rule> rules;
    std::unordered_set<std::string> seen;

    for (const auto& [name, text] : files) {
        auto compiled = CompileRuleYaml(text, name);
        if (!compiled) {
            report.fileErrors.push_back(compiled.GetError().context);
            ++report.failed;
            continue;
        }
        for (auto& o : compiled.Value()) {
            if (!o.rule) {
                RuleInfo bad;
                bad.id         = o.ruleId;
                bad.sourceFile = name;
                bad.loadError  = o.error;
                bad.status     = "disabled";
                report.rules.push_back(std::move(bad));
                ++report.failed;
                continue;
            }
            Rule r = std::move(*o.rule);
            if (!seen.insert(r.id).second) {
                RuleInfo dup = InfoOf(r, r.status);
                dup.loadError = name + " 規則 id 重複：" + r.id;
                report.rules.push_back(std::move(dup));
                ++report.failed;
                continue;
            }
            const model::RuleStatus declared = r.status;
            r.status = EffectiveStatus(r.id, declared, opts);
            report.rules.push_back(InfoOf(r, declared));
            rules.push_back(std::move(r));
            ++report.loaded;
        }
    }

    std::sort(report.rules.begin(), report.rules.end(),
              [](const RuleInfo& a, const RuleInfo& b) { return a.id < b.id; });

    if (rules.empty()) {
        std::string ctx = "沒有任何規則成功載入";
        if (!report.fileErrors.empty()) ctx += "：" + report.fileErrors.front();
        else
            for (const auto& i : report.rules)
                if (!i.loadError.empty()) {
                    ctx += "：" + i.loadError;
                    break;
                }
        return MakeError(ErrorCode::NoRulesLoaded, ctx);
    }
    report.ruleSet = std::make_shared<const RuleSet>(std::move(rules), opts.generation);
    return report;
}

Result<RuleLoadReport> LoadRuleDirectory(const std::filesystem::path& dir, model::StringInterner& interner,
                                         const RuleLoadOptions& opts)
{
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec))
        return MakeError(ErrorCode::NotFound, "規則目錄不存在：" + dir.string());

    std::vector<std::filesystem::path> paths;
    for (const auto& de : std::filesystem::directory_iterator(dir, ec)) {
        if (de.is_regular_file(ec) && IsRuleFile(de.path())) paths.push_back(de.path());
    }
    if (ec) return MakeError(ErrorCode::IoError, "列舉規則目錄失敗：" + ec.message());
    std::sort(paths.begin(), paths.end());   // 決定性順序

    std::vector<std::pair<std::string, std::string>> files;
    for (const auto& p : paths) {
        std::ifstream in(p, std::ios::binary);
        if (!in) return MakeError(ErrorCode::IoError, "無法讀取規則檔：" + p.string());
        std::ostringstream ss;
        ss << in.rdbuf();
        files.emplace_back(p.filename().string(), ss.str());
    }
    return LoadRuleTexts(files, interner, opts);
}

Result<std::vector<ExclusionEntry>> ParseExclusionsYaml(std::string_view text)
{
    try {
        const YAML::Node root = YAML::Load(std::string(text));
        const YAML::Node list = root.IsMap() ? root["exclusions"] : root;
        std::vector<ExclusionEntry> out;
        if (!list) return out;
        if (!list.IsSequence()) return MakeError(ErrorCode::RuleSchemaViolation, "exclusions 需為陣列");
        for (const auto& n : list) {
            if (!n.IsMap() || !n["kind"] || !n["value"])
                return MakeError(ErrorCode::RuleSchemaViolation,
                                 "exclusion 需有 kind 與 value（第 " + std::to_string(n.Mark().line + 1) + " 行）");
            auto kind = model::ExclusionKindFromString(model::ToLowerAscii(n["kind"].as<std::string>()));
            if (!kind)
                return MakeError(ErrorCode::RuleSchemaViolation,
                                 "未知的 exclusion kind（第 " + std::to_string(n.Mark().line + 1) + " 行）");
            ExclusionEntry e;
            e.kind      = *kind;
            e.value     = n["value"].as<std::string>();
            e.createdBy = "builtin";
            if (n["scope_rule_id"]) e.scopeRuleId = n["scope_rule_id"].as<std::string>();
            if (n["reason"]) e.reason = n["reason"].as<std::string>();
            out.push_back(std::move(e));
        }
        return out;
    } catch (const YAML::Exception& e) {
        return MakeError(ErrorCode::RuleParseError, "exclusions YAML 第 " + std::to_string(e.mark.line + 1) + " 行：" + e.msg);
    }
}

Result<std::vector<ExclusionEntry>> LoadExclusionsYaml(const std::filesystem::path& file)
{
    std::ifstream in(file, std::ios::binary);
    if (!in) return MakeError(ErrorCode::NotFound, "無法讀取排除清單：" + file.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ParseExclusionsYaml(ss.str());
}

} // namespace cairn::rules
