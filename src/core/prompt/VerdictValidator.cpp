#include "prompt/VerdictValidator.h"

#include <array>
#include <exception>

#include <nlohmann/json.hpp>

#include "prompt/InputSanitizer.h"

namespace cairn::llm {

namespace {

using nlohmann::json;

constexpr size_t kNarrativeMin = 40, kNarrativeMax = 800;
constexpr size_t kRecommendMin = 20, kRecommendMax = 400;
constexpr size_t kAttackIdsMax = 8;
constexpr size_t kIndicatorsMax = 5, kIndicatorMaxLen = 120;

// 不使用 std::regex：MSVC 的 std::regex 在 icase 模式下遇到 >0x7F 的位元組（中文 UTF-8）
// 會以負值呼叫 ctype，Debug 建置直接觸發 assertion。改為手寫掃描。
constexpr std::array<std::string_view, 22> kTlds{
    "com", "net", "org", "io", "ru", "cn", "top", "xyz", "info", "biz", "co",
    "me",  "tk",  "cc",  "su", "onion", "site", "online", "club", "pw", "ws", "link"};

char Lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool IsHostChar(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.';
}

bool IsB64Char(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '/' ||
           c == '=';
}

Error Fail(ValidationReport* r, ValidationFailure f, std::string reason)
{
    if (r) {
        r->failure = f;
        r->reason  = reason;
    }
    return MakeError(ErrorCode::LlmSchemaViolation,
                     std::string(ValidationFailureName(f)) + ": " + reason);
}

bool HasForbidden(std::string_view s)
{
    return VerdictValidator::ContainsUrl(s) || VerdictValidator::ContainsBase64Blob(s) ||
           VerdictValidator::ContainsDelimiter(s);
}

} // namespace

std::string_view ValidationFailureName(ValidationFailure f) noexcept
{
    switch (f) {
    case ValidationFailure::None: return "none";
    case ValidationFailure::NotJson: return "not_json";
    case ValidationFailure::Truncated: return "truncated";
    case ValidationFailure::SchemaViolation: return "schema_violation";
    case ValidationFailure::AttackIdsRejected: return "attack_ids_rejected";
    case ValidationFailure::ForbiddenContent: return "forbidden_content";
    }
    return "unknown";
}

bool VerdictValidator::ContainsUrl(std::string_view s)
{
    if (s.find("://") != std::string_view::npos) return true;
    // 逐一取出 [A-Za-z0-9.-]+ 的片段判斷是否像主機名
    size_t i = 0;
    while (i < s.size()) {
        if (!IsHostChar(s[i])) {
            ++i;
            continue;
        }
        size_t j = i;
        while (j < s.size() && IsHostChar(s[j])) ++j;
        std::string tok;
        tok.reserve(j - i);
        for (size_t k = i; k < j; ++k) tok.push_back(Lower(s[k]));
        while (!tok.empty() && (tok.back() == '.' || tok.back() == '-')) tok.pop_back();   // 句尾句點
        if (tok.rfind("www.", 0) == 0 && tok.size() > 4) return true;
        const size_t dot = tok.rfind('.');
        if (dot != std::string::npos && dot > 0) {
            const std::string_view tld = std::string_view(tok).substr(dot + 1);
            for (auto t : kTlds)
                if (tld == t) return true;
        }
        i = j;
    }
    return false;
}

bool VerdictValidator::ContainsBase64Blob(std::string_view s, size_t minRun) noexcept
{
    size_t run = 0;
    for (char c : s) {
        if (IsB64Char(c)) {
            if (++run >= minRun) return true;
        } else {
            run = 0;
        }
    }
    return false;
}

bool VerdictValidator::ContainsDelimiter(std::string_view s) noexcept
{
    if (s.find("<<<") != std::string_view::npos || s.find(">>>") != std::string_view::npos ||
        s.find("###") != std::string_view::npos || s.find("<|") != std::string_view::npos ||
        s.find("|>") != std::string_view::npos)
        return true;
    // "system:"（不分大小寫）
    static constexpr std::string_view kSys = "system:";
    if (s.size() < kSys.size()) return false;
    for (size_t i = 0; i + kSys.size() <= s.size(); ++i) {
        bool eq = true;
        for (size_t k = 0; k < kSys.size() && eq; ++k) eq = Lower(s[i + k]) == kSys[k];
        if (eq) return true;
    }
    return false;
}

Result<std::string> VerdictValidator::ExtractCompletionContent(std::string_view body, ValidationReport* report) const
{
    json doc;
    try {
        doc = json::parse(body.begin(), body.end());
    } catch (const std::exception& e) {
        return Fail(report, ValidationFailure::NotJson, std::string("回應體非 JSON: ") + e.what());
    }
    if (!doc.is_object() || !doc.contains("content") || !doc["content"].is_string())
        return Fail(report, ValidationFailure::NotJson, "回應缺少 content 字串");
    // GBNF 只保證合法前綴；n_predict 用盡時 JSON 會被截斷（SDD-03 §7.5.3）
    if (doc.contains("stopped_limit") && doc["stopped_limit"].is_boolean() && doc["stopped_limit"].get<bool>())
        return Fail(report, ValidationFailure::Truncated, "stopped_limit=true（n_predict 用盡）");
    if (doc.contains("stop_type") && doc["stop_type"].is_string() && doc["stop_type"].get<std::string>() == "limit")
        return Fail(report, ValidationFailure::Truncated, "stop_type=limit（n_predict 用盡）");
    // truncated=true 表示「prompt」超出 context 被截掉——system prompt 的安全規則可能已不在視窗內，輸出不可信
    if (doc.contains("truncated") && doc["truncated"].is_boolean() && doc["truncated"].get<bool>())
        return Fail(report, ValidationFailure::Truncated, "prompt 被 context 截斷（truncated=true）");
    return doc["content"].get<std::string>();
}

Result<model::NarrativeResult> VerdictValidator::Validate(std::string_view modelJson, ValidationReport* report) const
{
    json doc;
    try {
        doc = json::parse(modelJson.begin(), modelJson.end());
    } catch (const std::exception& e) {
        // 未閉合的 JSON 是最常見的截斷形態
        return Fail(report, ValidationFailure::Truncated, std::string("輸出 JSON 無法解析（可能被截斷）: ") + e.what());
    }
    if (!doc.is_object()) return Fail(report, ValidationFailure::SchemaViolation, "輸出不是 JSON 物件");

    // additionalProperties: false
    for (auto it = doc.begin(); it != doc.end(); ++it) {
        const auto& k = it.key();
        if (k != "attack_ids" && k != "narrative" && k != "recommendation" && k != "confidence" &&
            k != "evasion_attempt_detected" && k != "key_indicators")
            return Fail(report, ValidationFailure::SchemaViolation, "多餘欄位: " + k.substr(0, 40));
    }
    for (const char* req : {"attack_ids", "narrative", "recommendation", "confidence", "evasion_attempt_detected"})
        if (!doc.contains(req)) return Fail(report, ValidationFailure::SchemaViolation, std::string("缺少必填欄位: ") + req);

    model::NarrativeResult r;

    // ---- attack_ids ----
    const auto& ids = doc["attack_ids"];
    if (!ids.is_array()) return Fail(report, ValidationFailure::SchemaViolation, "attack_ids 不是陣列");
    if (ids.empty() || ids.size() > kAttackIdsMax)
        return Fail(report, ValidationFailure::SchemaViolation, "attack_ids 數量需為 1–8");
    std::vector<std::string> raw;
    for (const auto& v : ids) {
        if (!v.is_string()) return Fail(report, ValidationFailure::SchemaViolation, "attack_ids 含非字串項");
        raw.push_back(v.get<std::string>());
    }
    r.attackIds = m_catalog->Filter(raw);   // 白名單 (1)：剔除個別項
    if (report) report->attackIdsRejected = raw.size() - r.attackIds.size();
    if (r.attackIds.empty())
        return Fail(report, ValidationFailure::AttackIdsRejected, "attack_ids 全數未通過 ATT&CK 白名單");

    // ---- narrative / recommendation ----
    if (!doc["narrative"].is_string() || !doc["recommendation"].is_string())
        return Fail(report, ValidationFailure::SchemaViolation, "narrative / recommendation 需為字串");
    r.narrative      = doc["narrative"].get<std::string>();
    r.recommendation = doc["recommendation"].get<std::string>();
    const size_t nLen = InputSanitizer::CodePointCount(r.narrative);
    const size_t rLen = InputSanitizer::CodePointCount(r.recommendation);
    if (nLen < kNarrativeMin || nLen > kNarrativeMax)
        return Fail(report, ValidationFailure::SchemaViolation, "narrative 長度需為 40–800 字元");
    if (rLen < kRecommendMin || rLen > kRecommendMax)
        return Fail(report, ValidationFailure::SchemaViolation, "recommendation 長度需為 20–400 字元");
    // 白名單 (2)(3)：整則作廢
    if (ContainsUrl(r.narrative) || ContainsUrl(r.recommendation))
        return Fail(report, ValidationFailure::ForbiddenContent, "narrative/recommendation 含 URL 或主機名");
    if (ContainsBase64Blob(r.narrative) || ContainsBase64Blob(r.recommendation))
        return Fail(report, ValidationFailure::ForbiddenContent, "narrative/recommendation 含 Base64 長串");
    if (ContainsDelimiter(r.narrative) || ContainsDelimiter(r.recommendation))
        return Fail(report, ValidationFailure::ForbiddenContent, "narrative/recommendation 含提示分隔序列");

    // ---- confidence / evasion ----
    if (!doc["confidence"].is_number()) return Fail(report, ValidationFailure::SchemaViolation, "confidence 需為數值");
    r.confidence = doc["confidence"].get<double>();
    if (!(r.confidence >= 0.0 && r.confidence <= 1.0))
        return Fail(report, ValidationFailure::SchemaViolation, "confidence 需介於 0–1");
    if (!doc["evasion_attempt_detected"].is_boolean())
        return Fail(report, ValidationFailure::SchemaViolation, "evasion_attempt_detected 需為布林");
    r.evasionAttemptDetected = doc["evasion_attempt_detected"].get<bool>();

    // ---- key_indicators（選填）----
    if (doc.contains("key_indicators")) {
        const auto& ki = doc["key_indicators"];
        if (!ki.is_array() || ki.size() > kIndicatorsMax)
            return Fail(report, ValidationFailure::SchemaViolation, "key_indicators 需為至多 5 項的陣列");
        for (const auto& v : ki) {
            if (!v.is_string()) return Fail(report, ValidationFailure::SchemaViolation, "key_indicators 含非字串項");
            std::string s = v.get<std::string>();
            if (InputSanitizer::CodePointCount(s) > kIndicatorMaxLen)
                return Fail(report, ValidationFailure::SchemaViolation, "key_indicators 單項超過 120 字元");
            if (HasForbidden(s)) {
                if (report) ++report->keyIndicatorsDropped;
                continue;
            }
            r.keyIndicators.push_back(std::move(s));
        }
    }

    if (report) {
        report->failure = ValidationFailure::None;
        report->reason.clear();
    }
    return r;
}

Result<model::NarrativeResult> VerdictValidator::ValidateCompletion(std::string_view body, ValidationReport* report) const
{
    auto content = ExtractCompletionContent(body, report);
    if (!content) return content.GetError();
    return Validate(content.Value(), report);
}

} // namespace cairn::llm
