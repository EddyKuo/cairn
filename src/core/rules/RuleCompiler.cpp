#include "rules/RuleCompiler.h"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <unordered_map>

namespace cairn::rules {

namespace {

// 編譯期錯誤：以內部例外傳遞，於 CompileOne 邊界轉為 RuleCompileOutcome（P-2）。
struct CompileError {
    ErrorCode   code;
    std::string message;
    int         line;
};

[[noreturn]] void Fail(ErrorCode code, const std::string& msg, const YAML::Node& at)
{
    const int line = at.IsDefined() ? static_cast<int>(at.Mark().line) + 1 : 0;
    throw CompileError{code, msg, line};
}

[[noreturn]] void FailSchema(const std::string& msg, const YAML::Node& at)
{
    Fail(ErrorCode::RuleSchemaViolation, msg, at);
}

std::string Scalar(const YAML::Node& n, const char* key)
{
    if (!n.IsScalar()) FailSchema(std::string("'") + key + "' 必須是純量", n);
    return n.as<std::string>();
}

std::optional<int64_t> ParseInt(const std::string& s) noexcept
{
    if (s.empty()) return std::nullopt;
    size_t i   = 0;
    bool   neg = false;
    if (s[0] == '-') {
        neg = true;
        i   = 1;
    }
    int base = 10;
    if (s.size() > i + 2 && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        base = 16;
        i += 2;
    }
    if (i >= s.size()) return std::nullopt;
    int64_t v = 0;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (base == 16 && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (base == 16 && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return std::nullopt;
        if (v > (INT64_MAX - d) / base) return std::nullopt;
        v = v * base + d;
    }
    return neg ? -v : v;
}

std::optional<bool> ParseBool(const std::string& s) noexcept
{
    const std::string l = model::ToLowerAscii(s);
    if (l == "true" || l == "yes" || l == "1") return true;
    if (l == "false" || l == "no" || l == "0") return false;
    return std::nullopt;
}

// 事件型別名稱（含文件中出現過的別名）→ 遮罩
EventTypeMask ParseEventTypes(const YAML::Node& n)
{
    EventTypeMask m;
    auto add = [&](const std::string& raw, const YAML::Node& at) {
        const std::string s = [&] {
            std::string u = raw;
            for (auto& c : u) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            return u;
        }();
        static const std::unordered_map<std::string, std::vector<model::EventType>> kAliases{
            {"REG_SET", {model::EventType::RegistrySet}},
            {"REGISTRY_EVENT", {model::EventType::RegistryAdd, model::EventType::RegistrySet,
                                model::EventType::RegistryRename}},
            {"CREATE_REMOTE_THREAD", {model::EventType::CreateRemoteThread}},
            {"PROCESS_TERMINATED", {model::EventType::ProcessTerminate}},
            {"SCRIPTBLOCK", {model::EventType::ScriptBlock}},
        };
        if (auto it = kAliases.find(s); it != kAliases.end()) {
            for (auto t : it->second) m.set(static_cast<size_t>(t));
            return;
        }
        auto t = model::EventTypeFromString(s);
        if (!t || *t == model::EventType::Unknown) FailSchema("未知的事件型別 '" + raw + "'", at);
        m.set(static_cast<size_t>(*t));
    };
    if (n.IsScalar()) add(n.as<std::string>(), n);
    else if (n.IsSequence())
        for (const auto& x : n) add(Scalar(x, "event"), x);
    else FailSchema("'event' 必須是字串或字串陣列", n);
    if (m.none()) FailSchema("'event' 不可為空", n);
    return m;
}

std::vector<std::string> StringList(const YAML::Node& v, const char* key)
{
    std::vector<std::string> out;
    if (v.IsScalar()) {
        out.push_back(v.as<std::string>());
    } else if (v.IsSequence()) {
        for (const auto& x : v) out.push_back(Scalar(x, key));
    } else {
        FailSchema(std::string("'") + key + "' 必須是字串或字串陣列", v);
    }
    return out;
}

// 正則的廉價前置過濾：pattern 無交替（不含 '|'）時，抽出最長的「必要」純字面量（>= 3 字元）。
// 必要 = 任何命中都一定含有它。因此只收群組外（depth 0）、字元類別外的字面量：
//   [a-z0-9] 裡的字元不是字面量；(abc)? 整個群組可省略，群組內一律不收。
std::vector<std::string> AutoPrefilter(const std::string& pattern)
{
    if (pattern.find('|') != std::string::npos) return {};
    std::string best, cur;
    int depth = 0;
    auto flush = [&] {
        if (cur.size() > best.size()) best = cur;
        cur.clear();
    };
    for (size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '\\') {   // 跳脫序列整段視為斷點
            flush();
            ++i;
            continue;
        }
        if (c == '[') {    // 跳過整個字元類別（含 []] 與 [^]] 及類別內跳脫）
            flush();
            size_t j = i + 1;
            if (j < pattern.size() && pattern[j] == '^') ++j;
            if (j < pattern.size() && pattern[j] == ']') ++j;
            while (j < pattern.size() && pattern[j] != ']') j += (pattern[j] == '\\') ? 2 : 1;
            i = j;
            continue;
        }
        if (c == '(') { flush(); ++depth; continue; }
        if (c == ')') { flush(); if (depth > 0) --depth; continue; }
        if (depth > 0) continue;
        const bool lit = std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-';
        if (lit) {
            const char next = i + 1 < pattern.size() ? pattern[i + 1] : '\0';
            if (next == '?' || next == '*' || next == '{') {   // 可省略的字元不能當必要字面量
                flush();
                continue;
            }
            cur.push_back(c);
        } else {
            flush();
        }
    }
    flush();
    if (best.size() < 3) return {};
    return {model::ToLowerAscii(best)};
}

struct StepScope {
    std::unordered_map<std::string, uint8_t> stepIndexByName;
    uint8_t currentStep = 0;
    bool    allowRefs   = false;
    std::vector<std::pair<uint8_t, FieldId>> exportsNeeded;   // (來源步驟, 欄位)
};

ExprPtr ParseConditionList(const YAML::Node& n, StepScope& scope, bool isOr);

ExprPtr ParseCondition(const YAML::Node& c, StepScope& scope)
{
    if (!c.IsMap()) FailSchema("條件必須是物件", c);
    if (c["any_of"]) return ParseConditionList(c["any_of"], scope, true);
    if (c["all_of"]) return ParseConditionList(c["all_of"], scope, false);

    if (!c["field"] || !c["op"]) FailSchema("條件需有 field 與 op", c);
    const std::string fieldName = Scalar(c["field"], "field");
    const auto field = FieldFromName(fieldName);
    if (!field) {
        std::string avail;
        for (auto f : AllFieldNames()) {
            if (!avail.empty()) avail += ", ";
            avail.append(f);
        }
        Fail(ErrorCode::UnknownRuleField, "未知欄位 '" + fieldName + "'（可用：" + avail + "）", c["field"]);
    }
    const std::string op = model::ToLowerAscii(Scalar(c["op"], "op"));
    const YAML::Node  v  = c["value"];
    if (!v) FailSchema("條件缺少 value", c);
    const FieldKind kind = KindOf(*field);

    auto literalFor = [&](const YAML::Node& node) -> std::pair<FieldValue, std::string> {
        const std::string s = Scalar(node, "value");
        switch (kind) {
        case FieldKind::String: return {std::string_view{}, model::ToLowerAscii(s)};
        case FieldKind::Int: {
            auto i = ParseInt(s);
            if (!i) FailSchema("欄位 " + fieldName + " 需要整數值", node);
            return {*i, {}};
        }
        case FieldKind::Bool: {
            auto b = ParseBool(s);
            if (!b) FailSchema("欄位 " + fieldName + " 需要布林值", node);
            return {*b, {}};
        }
        case FieldKind::Guid: {
            auto g = model::GuidValue::Parse(s);
            if (!g) FailSchema("欄位 " + fieldName + " 需要 GUID", node);
            return {*g, {}};
        }
        }
        FailSchema("不支援的欄位型別", node);
    };

    auto inExpr = [&](InExpr::Mode mode, bool negate, bool listAllowed) -> ExprPtr {
        if (!listAllowed && !v.IsScalar()) FailSchema("運算子 " + op + " 需要單一值", v);
        if (kind != FieldKind::String && mode != InExpr::Mode::Exact)
            FailSchema("運算子 " + op + " 只能用於字串欄位", c["op"]);
        std::vector<std::string> vals = StringList(v, "value");
        if (vals.empty()) FailSchema("清單不可為空", v);
        if (kind == FieldKind::Int) {
            for (auto& s : vals) {
                auto i = ParseInt(s);
                if (!i) FailSchema("欄位 " + fieldName + " 需要整數值", v);
                s = std::to_string(*i);
            }
        }
        return std::make_unique<InExpr>(*field, mode, std::move(vals), negate);
    };

    if (op == "equals" || op == "not_equals") {
        if (v.IsSequence()) FailSchema(op + " 需要單一值（清單請用 in）", v);
        auto [lit, owned] = literalFor(v);
        return std::make_unique<CmpExpr>(*field, op == "equals" ? CmpExpr::Op::Eq : CmpExpr::Op::Ne, lit,
                                         std::move(owned));
    }
    if (op == "gt" || op == "lt") {
        if (kind != FieldKind::Int) FailSchema(op + " 只能用於整數欄位", c["op"]);
        auto [lit, owned] = literalFor(v);
        return std::make_unique<CmpExpr>(*field, op == "gt" ? CmpExpr::Op::Gt : CmpExpr::Op::Lt, lit, std::move(owned));
    }
    if (op == "in") return inExpr(InExpr::Mode::Exact, false, true);
    if (op == "not_in") return inExpr(InExpr::Mode::Exact, true, true);
    if (op == "contains") return inExpr(InExpr::Mode::Substring, false, false);
    if (op == "not_contains") return inExpr(InExpr::Mode::Substring, true, false);
    if (op == "starts_with") return inExpr(InExpr::Mode::Prefix, false, false);
    if (op == "not_starts_with") return inExpr(InExpr::Mode::Prefix, true, false);
    if (op == "ends_with") return inExpr(InExpr::Mode::Suffix, false, false);
    if (op == "not_ends_with") return inExpr(InExpr::Mode::Suffix, true, false);
    if (op == "contains_any") return inExpr(InExpr::Mode::Substring, false, true);
    if (op == "not_contains_any") return inExpr(InExpr::Mode::Substring, true, true);
    if (op == "starts_with_any") return inExpr(InExpr::Mode::Prefix, false, true);
    if (op == "not_starts_with_any") return inExpr(InExpr::Mode::Prefix, true, true);
    if (op == "ends_with_any") return inExpr(InExpr::Mode::Suffix, false, true);
    if (op == "not_ends_with_any") return inExpr(InExpr::Mode::Suffix, true, true);

    if (op == "matches" || op == "not_matches") {
        if (kind != FieldKind::String) FailSchema("matches 只能用於字串欄位", c["op"]);
        std::string pattern = Scalar(v, "value");
        std::string body    = pattern;
        if (body.rfind("(?i)", 0) == 0) body = body.substr(4);   // ECMAScript 不支援內嵌旗標；一律 icase
        std::regex re;
        try {
            re = std::regex(body, std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
        } catch (const std::regex_error& e) {
            FailSchema(std::string("正則編譯失敗：") + e.what(), v);
        }
        std::vector<std::string> pre;
        if (c["prefilter"]) pre = StringList(c["prefilter"], "prefilter");
        else pre = AutoPrefilter(body);
        return std::make_unique<MatchExpr>(*field, std::move(pattern), std::move(re), std::move(pre),
                                           op == "not_matches");
    }

    if (op == "has_any") {
        if (kind != FieldKind::Int) FailSchema("has_any 只能用於整數欄位", c["op"]);
        int64_t mask = 0;
        for (const auto& s : StringList(v, "value")) {
            auto i = ParseInt(s);
            if (!i) FailSchema("has_any 需要整數或 0x 十六進位遮罩", v);
            mask |= *i;
        }
        if (mask == 0) FailSchema("has_any 的遮罩不可為 0", v);
        return std::make_unique<MaskExpr>(*field, mask);
    }

    if (op == "equals_ref" || op == "not_equals_ref") {
        if (!scope.allowRefs) Fail(ErrorCode::RuleSemanticError, "步驟 0 與 booster 不可使用 equals_ref", c["op"]);
        const std::string ref = Scalar(v, "value");
        const auto dot = ref.find('.');
        if (dot == std::string::npos) FailSchema("equals_ref 的值需為 <step_id>.<field>", v);
        const std::string stepName = ref.substr(0, dot);
        const auto srcField = FieldFromName(ref.substr(dot + 1));
        if (!srcField) Fail(ErrorCode::UnknownRuleField, "equals_ref 引用未知欄位 '" + ref.substr(dot + 1) + "'", v);
        auto it = scope.stepIndexByName.find(stepName);
        if (it == scope.stepIndexByName.end() || it->second >= scope.currentStep)
            Fail(ErrorCode::RuleSemanticError, "equals_ref 引用的步驟 '" + stepName + "' 不存在於前序步驟", v);
        scope.exportsNeeded.emplace_back(it->second, *srcField);
        return std::make_unique<RefExpr>(*field, it->second, *srcField, stepName, op == "not_equals_ref");
    }

    FailSchema("未知運算子 '" + op + "'", c["op"]);
}

ExprPtr ParseConditionList(const YAML::Node& n, StepScope& scope, bool isOr)
{
    if (!n) return std::make_unique<TrueExpr>();
    std::vector<ExprPtr> kids;
    if (n.IsSequence()) {
        for (const auto& c : n) kids.push_back(ParseCondition(c, scope));
    } else if (n.IsMap()) {
        kids.push_back(ParseCondition(n, scope));
    } else {
        FailSchema("where 必須是條件陣列", n);
    }
    if (kids.empty()) return std::make_unique<TrueExpr>();
    if (kids.size() == 1) return std::move(kids.front());
    if (isOr) return std::make_unique<OrExpr>(std::move(kids));
    return std::make_unique<AndExpr>(std::move(kids));
}

int64_t DurationField(const YAML::Node& n, const char* key, int64_t minMs, int64_t maxMs)
{
    const std::string s = Scalar(n, key);
    auto ms = ParseDurationMs(s);
    if (!ms) FailSchema(std::string("'") + key + "' 格式需為 \\d+[sm]", n);
    if (*ms < minMs || *ms > maxMs)
        FailSchema(std::string("'") + key + "' 超出允許範圍（" + std::to_string(minMs / 1000) + "s–" +
                       std::to_string(maxMs / 1000) + "s）",
                   n);
    return *ms;
}

std::optional<ThresholdSpec> ParseThreshold(const YAML::Node& n)
{
    if (!n) return std::nullopt;
    if (!n.IsMap()) FailSchema("threshold 必須是物件", n);
    ThresholdSpec t;
    if (!n["count"]) FailSchema("threshold 需有 count", n);
    auto c = ParseInt(Scalar(n["count"], "count"));
    if (!c || *c < 1 || *c > 100000) FailSchema("threshold.count 需為 1–100000", n["count"]);
    t.count = static_cast<uint32_t>(*c);
    if (!n["within"]) FailSchema("threshold 需有 within", n);
    t.withinMs = DurationField(n["within"], "threshold.within", 1'000, 600'000);
    if (n["distinct_field"]) {
        auto f = FieldFromName(Scalar(n["distinct_field"], "distinct_field"));
        if (!f) Fail(ErrorCode::UnknownRuleField, "threshold.distinct_field 為未知欄位", n["distinct_field"]);
        t.distinctField = *f;
    }
    return t;
}

Step ParseStep(const YAML::Node& s, StepScope& scope, uint8_t index, bool requireId)
{
    if (!s.IsMap()) FailSchema("步驟必須是物件", s);
    Step st;
    if (s["id"]) st.id = Scalar(s["id"], "id");
    else if (requireId) FailSchema("序列步驟需有 id", s);
    else st.id = "match";
    if (!s["event"]) FailSchema("步驟需有 event", s);
    st.types = ParseEventTypes(s["event"]);
    scope.currentStep = index;
    scope.allowRefs   = index > 0;
    st.where          = ParseConditionList(s["where"], scope, false);
    st.threshold      = ParseThreshold(s["threshold"]);
    return st;
}

Rule CompileOne(const YAML::Node& doc, std::string_view sourceFile)
{
    if (!doc.IsMap()) FailSchema("規則文件必須是物件", doc);
    Rule r;
    r.sourceFile = std::string(sourceFile);

    // ---- 必填 ----
    if (!doc["id"]) FailSchema("缺少 id", doc);
    r.id = Scalar(doc["id"], "id");
    if (!IsValidRuleId(r.id)) FailSchema("id 格式需為 R-T<ATT&CK>-<三位序號>", doc["id"]);
    if (!doc["title"]) FailSchema("缺少 title", doc);
    r.title = Scalar(doc["title"], "title");
    if (r.title.empty() || r.title.size() > 360) FailSchema("title 需為 1–120 字", doc["title"]);   // UTF-8 中文每字 3 bytes
    if (doc["description"]) r.description = Scalar(doc["description"], "description");

    if (!doc["severity"]) FailSchema("缺少 severity", doc);
    auto sev = model::SeverityFromString(model::ToLowerAscii(Scalar(doc["severity"], "severity")));
    if (!sev) FailSchema("severity 需為 low|medium|high|critical", doc["severity"]);
    r.severity = *sev;

    r.status = model::RuleStatus::DryRun;   // 新規則一律先觀察
    if (doc["status"]) {
        auto st = model::RuleStatusFromString(model::ToLowerAscii(Scalar(doc["status"], "status")));
        if (!st) FailSchema("status 需為 enabled|dryrun|disabled", doc["status"]);
        r.status = *st;
    }

    if (!doc["score"]) FailSchema("缺少 score", doc);
    auto score = ParseInt(Scalar(doc["score"], "score"));
    if (!score || *score < 1 || *score > 100) FailSchema("score 需為整數 1–100", doc["score"]);
    r.scoreMilli = *score * model::kScoreScale;

    if (!doc["decay"]) FailSchema("缺少 decay", doc);
    r.halfLifeMs = static_cast<uint32_t>(DurationField(doc["decay"], "decay", 30'000, 3'600'000));

    if (doc["deterministic"]) {
        auto b = ParseBool(Scalar(doc["deterministic"], "deterministic"));
        if (!b) FailSchema("deterministic 需為布林", doc["deterministic"]);
        r.deterministic = *b;
    }

    if (!doc["requires_events"] || !doc["requires_events"].IsSequence())
        FailSchema("requires_events 必填且需為 EID 陣列", doc);
    for (const auto& e : doc["requires_events"]) {
        auto eid = ParseInt(Scalar(e, "requires_events"));
        if (!eid || *eid <= 0 || *eid > 65535) FailSchema("requires_events 需為正整數 EID", e);
        r.requiresEids.push_back(static_cast<uint16_t>(*eid));
    }

    if (doc["attack"]) {
        for (auto& a : StringList(doc["attack"], "attack")) r.attackIds.push_back(a);
    }

    // ---- 步驟：sequence 或單事件（Tier-1）簡寫 ----
    StepScope scope;
    if (const YAML::Node seq = doc["sequence"]; seq) {
        if (!seq.IsMap()) FailSchema("sequence 必須是物件", seq);
        if (!seq["within"]) FailSchema("sequence.within 必填", seq);
        r.withinMs = DurationField(seq["within"], "sequence.within", 30'000, 600'000);
        if (!seq["correlate_by"]) FailSchema("sequence.correlate_by 必填", seq);
        const std::string cb = model::ToLowerAscii(Scalar(seq["correlate_by"], "correlate_by"));
        if (cb == "process_tree_root") r.correlateBy = CorrelateBy::ProcessTreeRoot;
        else if (cb == "process_guid") r.correlateBy = CorrelateBy::ProcessGuid;
        else FailSchema("correlate_by 需為 process_tree_root|process_guid", seq["correlate_by"]);
        const YAML::Node steps = seq["steps"];
        if (!steps || !steps.IsSequence() || steps.size() == 0 || steps.size() > kMaxSteps)
            FailSchema("sequence.steps 需為 1–4 步", seq);
        uint8_t idx = 0;
        for (const auto& s : steps) {
            Step st = ParseStep(s, scope, idx, true);
            if (scope.stepIndexByName.count(st.id)) Fail(ErrorCode::RuleSemanticError, "步驟 id 重複：" + st.id, s);
            scope.stepIndexByName.emplace(st.id, idx);
            r.steps.push_back(std::move(st));
            ++idx;
        }
    } else {
        if (!doc["event"]) FailSchema("規則需有 sequence 或 event + where（單事件規則）", doc);
        Step st = ParseStep(doc, scope, 0, false);
        r.steps.push_back(std::move(st));
        r.withinMs = doc["within"] ? DurationField(doc["within"], "within", 30'000, 600'000) : 300'000;
        r.correlateBy = CorrelateBy::ProcessTreeRoot;
        if (doc["correlate_by"]) {
            const std::string cb = model::ToLowerAscii(Scalar(doc["correlate_by"], "correlate_by"));
            if (cb == "process_guid") r.correlateBy = CorrelateBy::ProcessGuid;
            else if (cb != "process_tree_root") FailSchema("correlate_by 需為 process_tree_root|process_guid", doc);
        }
    }

    // ---- 語意檢查 ----
    for (const auto& st : r.steps) {
        if (st.threshold && st.threshold->withinMs > r.withinMs)
            Fail(ErrorCode::RuleSemanticError, "threshold.within 不得大於 sequence.within（步驟 " + st.id + "）", doc);
    }
    for (const auto& [stepIdx, field] : scope.exportsNeeded) {
        auto& ex = r.steps[stepIdx].exports;
        if (std::find(ex.begin(), ex.end(), field) == ex.end()) ex.push_back(field);
    }
    size_t totalExports = 0;
    for (const auto& st : r.steps) totalExports += st.exports.size();
    if (totalExports > 6) Fail(ErrorCode::RuleSemanticError, "每條規則的匯出綁定至多 6 個", doc);

    // ---- boosters ----
    if (const YAML::Node bs = doc["boosters"]; bs) {
        if (!bs.IsSequence()) FailSchema("boosters 需為陣列", bs);
        for (const auto& b : bs) {
            if (!b.IsMap() || !b["id"] || !b["event"] || !b["score"]) FailSchema("booster 需有 id / event / score", b);
            Booster bo;
            bo.id    = Scalar(b["id"], "id");
            bo.types = ParseEventTypes(b["event"]);
            auto sc  = ParseInt(Scalar(b["score"], "score"));
            if (!sc || *sc < 1 || *sc > 100) FailSchema("booster.score 需為 1–100", b["score"]);
            bo.scoreMilli = *sc * model::kScoreScale;
            StepScope bscope;   // booster 不允許 equals_ref
            bo.where = ParseConditionList(b["where"], bscope, false);
            r.boosters.push_back(std::move(bo));
        }
    }

    // ---- response ----
    r.response.actions.clear();
    if (const YAML::Node resp = doc["response"]; resp) {
        if (!resp.IsMap()) FailSchema("response 需為物件", resp);
        if (resp["on_score_ge"]) {
            auto v = ParseInt(Scalar(resp["on_score_ge"], "on_score_ge"));
            if (!v || (*v != 40 && *v != 80 && *v != 95)) FailSchema("response.on_score_ge 需為 40|80|95", resp["on_score_ge"]);
            r.response.onScoreGe = static_cast<int>(*v);
        }
        if (resp["actions"]) {
            for (const auto& a : StringList(resp["actions"], "actions")) {
                const std::string l = model::ToLowerAscii(a);
                if (l == "alert") continue;
                auto k = model::ActionKindFromString(l);
                if (!k) FailSchema("response.actions 僅限 C-9 四個正規名與 alert：" + a, resp["actions"]);
                r.response.actions.push_back(*k);
            }
        }
        if (resp["require_confirmation"]) {
            auto b = ParseBool(Scalar(resp["require_confirmation"], "require_confirmation"));
            if (!b) FailSchema("require_confirmation 需為布林", resp["require_confirmation"]);
            r.response.requireConfirmation = *b;
        }
    }

    // ---- exceptions（規則範圍的排除）----
    if (const YAML::Node ex = doc["exceptions"]; ex) {
        if (!ex.IsSequence()) FailSchema("exceptions 需為陣列", ex);
        for (const auto& e : ex) {
            if (!e.IsMap() || !e["kind"] || !e["value"]) FailSchema("exception 需有 kind 與 value", e);
            auto k = model::ExclusionKindFromString(model::ToLowerAscii(Scalar(e["kind"], "kind")));
            if (!k) FailSchema("exception.kind 需對齊 exclusions.kind 六種", e["kind"]);
            r.exceptions.push_back(RuleException{*k, model::ToLowerAscii(Scalar(e["value"], "value"))});
        }
    }

    // ---- 觸發遮罩與內容雜湊 ----
    for (const auto& st : r.steps) r.triggerMask |= st.types;
    for (const auto& b : r.boosters) r.triggerMask |= b.types;

    YAML::Emitter em;
    em << doc;
    r.contentHash = Fnv1a64(std::string_view{em.c_str(), em.size()});
    char hex[24];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(r.contentHash));
    r.hashHex = hex;
    return r;
}

} // namespace

std::optional<int64_t> ParseDurationMs(std::string_view s) noexcept
{
    if (s.size() < 2) return std::nullopt;
    const char unit = s.back();
    int64_t mul;
    if (unit == 's') mul = 1000;
    else if (unit == 'm') mul = 60'000;
    else return std::nullopt;
    int64_t v = 0;
    for (size_t i = 0; i + 1 < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return std::nullopt;
        v = v * 10 + (s[i] - '0');
        if (v > 1'000'000) return std::nullopt;
    }
    return v * mul;
}

bool IsValidRuleId(std::string_view id) noexcept
{
    // ^R-T[0-9.]+-\d{3}$
    if (id.size() < 8 || id.substr(0, 3) != "R-T") return false;
    const auto lastDash = id.rfind('-');
    if (lastDash == std::string_view::npos || lastDash <= 3 || id.size() - lastDash - 1 != 3) return false;
    for (size_t i = lastDash + 1; i < id.size(); ++i)
        if (id[i] < '0' || id[i] > '9') return false;
    for (size_t i = 3; i < lastDash; ++i)
        if (!((id[i] >= '0' && id[i] <= '9') || id[i] == '.')) return false;
    return true;
}

uint64_t Fnv1a64(std::string_view s) noexcept
{
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

Result<std::vector<RuleCompileOutcome>> CompileRuleYaml(std::string_view text, std::string_view sourceFile)
{
    std::vector<YAML::Node> docs;
    try {
        docs = YAML::LoadAll(std::string(text));
    } catch (const YAML::Exception& e) {
        return MakeError(ErrorCode::RuleParseError,
                         std::string(sourceFile) + ":" + std::to_string(e.mark.line + 1) + " " + e.msg);
    } catch (const std::exception& e) {
        return MakeError(ErrorCode::RuleParseError, std::string(sourceFile) + " " + e.what());
    }

    std::vector<RuleCompileOutcome> out;
    for (const auto& doc : docs) {
        if (!doc || doc.IsNull()) continue;
        RuleCompileOutcome o;
        try {
            if (doc.IsMap() && doc["id"] && doc["id"].IsScalar()) o.ruleId = doc["id"].as<std::string>();
            o.rule = CompileOne(doc, sourceFile);
        } catch (const CompileError& e) {
            o.code  = e.code;
            o.line  = e.line;
            o.error = std::string(sourceFile) + ":" + std::to_string(e.line) + " " + e.message;
        } catch (const YAML::Exception& e) {
            o.code  = ErrorCode::RuleSchemaViolation;
            o.line  = e.mark.line + 1;
            o.error = std::string(sourceFile) + ":" + std::to_string(o.line) + " " + e.msg;
        } catch (const std::exception& e) {
            o.code  = ErrorCode::RuleSchemaViolation;
            o.error = std::string(sourceFile) + " " + e.what();
        }
        out.push_back(std::move(o));
    }
    return out;
}

} // namespace cairn::rules
