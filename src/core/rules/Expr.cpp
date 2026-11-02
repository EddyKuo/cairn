#include "rules/Expr.h"

#include <algorithm>
#include <cstdio>

#include "rules/TextMatch.h"

namespace cairn::rules {

namespace {
constexpr size_t kRegexInputLimit = 4096;   // std::regex 在 MSVC 上遞迴實作，長輸入可能爆棧

void AppendValue(std::string& out, const FieldValue& v)
{
    if (const auto* s = std::get_if<std::string_view>(&v)) {
        out += '"';
        out.append(*s);
        out += '"';
    } else if (const auto* i = std::get_if<int64_t>(&v)) {
        out += std::to_string(*i);
    } else if (const auto* b = std::get_if<bool>(&v)) {
        out += *b ? "true" : "false";
    } else if (const auto* g = std::get_if<model::GuidValue>(&v)) {
        out += g->ToString();
    } else {
        out += "null";
    }
}

FieldMask One(FieldId f)
{
    FieldMask m;
    m.set(static_cast<size_t>(f));
    return m;
}
} // namespace

bool ValuesEqualCi(const FieldValue& a, const FieldValue& b) noexcept
{
    if (std::holds_alternative<std::monostate>(a) || std::holds_alternative<std::monostate>(b)) return false;
    if (a.index() != b.index()) return false;
    if (const auto* sa = std::get_if<std::string_view>(&a)) {
        const auto& sb = std::get<std::string_view>(b);
        if (sa->size() != sb.size()) return false;
        for (size_t i = 0; i < sa->size(); ++i)
            if (LowerAscii((*sa)[i]) != LowerAscii(sb[i])) return false;
        return true;
    }
    return a == b;
}

// ---------------- AndExpr / OrExpr ----------------
AndExpr::AndExpr(std::vector<ExprPtr> kids) : m_kids(std::move(kids))
{
    std::stable_sort(m_kids.begin(), m_kids.end(),
                     [](const ExprPtr& a, const ExprPtr& b) { return a->Cost() < b->Cost(); });
}

bool AndExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    for (const auto& k : m_kids)
        if (!k->Evaluate(ctx)) return false;
    return true;
}

void AndExpr::Describe(std::string& out) const
{
    out += "(";
    for (size_t i = 0; i < m_kids.size(); ++i) {
        if (i) out += " AND ";
        m_kids[i]->Describe(out);
    }
    out += ")";
}

FieldMask AndExpr::RequiredFields() const
{
    FieldMask m;
    for (const auto& k : m_kids) m |= k->RequiredFields();
    return m;
}

int AndExpr::Cost() const noexcept
{
    int c = 0;
    for (const auto& k : m_kids) c = std::max(c, k->Cost());
    return c;
}

OrExpr::OrExpr(std::vector<ExprPtr> kids) : m_kids(std::move(kids))
{
    std::stable_sort(m_kids.begin(), m_kids.end(),
                     [](const ExprPtr& a, const ExprPtr& b) { return a->Cost() < b->Cost(); });
}

bool OrExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    for (const auto& k : m_kids)
        if (k->Evaluate(ctx)) return true;
    return false;
}

void OrExpr::Describe(std::string& out) const
{
    out += "(";
    for (size_t i = 0; i < m_kids.size(); ++i) {
        if (i) out += " OR ";
        m_kids[i]->Describe(out);
    }
    out += ")";
}

FieldMask OrExpr::RequiredFields() const
{
    // OR 的子樹缺欄位不代表整體必然 false，因此不回報任何「必要」欄位
    return {};
}

int OrExpr::Cost() const noexcept
{
    int c = 0;
    for (const auto& k : m_kids) c = std::max(c, k->Cost());
    return c;
}

// ---------------- CmpExpr ----------------
CmpExpr::CmpExpr(FieldId f, Op op, FieldValue literal, std::string ownedString)
    : m_field(f), m_op(op), m_str(std::move(ownedString)), m_literal(std::move(literal))
{
    if (std::holds_alternative<std::string_view>(m_literal)) m_literal = std::string_view{m_str};
}

bool CmpExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    const FieldValue v = ctx.Get(m_field);
    if (std::holds_alternative<std::monostate>(v)) return false;
    switch (m_op) {
    case Op::Eq:
        return ValuesEqualCi(v, m_literal);
    case Op::Ne:
        if (v.index() != m_literal.index()) return false;
        return !ValuesEqualCi(v, m_literal);
    case Op::Gt:
    case Op::Lt: {
        const auto* a = std::get_if<int64_t>(&v);
        const auto* b = std::get_if<int64_t>(&m_literal);
        if (!a || !b) return false;
        return m_op == Op::Gt ? *a > *b : *a < *b;
    }
    }
    return false;
}

void CmpExpr::Describe(std::string& out) const
{
    static constexpr const char* kOps[] = {" equals ", " not_equals ", " gt ", " lt "};
    out.append(FieldName(m_field));
    out += kOps[static_cast<int>(m_op)];
    AppendValue(out, m_literal);
}

FieldMask CmpExpr::RequiredFields() const { return One(m_field); }

// ---------------- InExpr ----------------
InExpr::InExpr(FieldId f, Mode m, std::vector<std::string> values, bool negate)
    : m_field(f), m_mode(m), m_values(std::move(values)), m_negate(negate)
{
    for (auto& s : m_values) s = model::ToLowerAscii(s);
    std::sort(m_values.begin(), m_values.end());
    m_values.erase(std::unique(m_values.begin(), m_values.end()), m_values.end());
}

bool InExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    const FieldValue v = ctx.Get(m_field);
    bool hit = false;
    if (const auto* s = std::get_if<std::string_view>(&v)) {
        for (const auto& val : m_values) {
            switch (m_mode) {
            case Mode::Exact: hit = EqualsCi(*s, val); break;
            case Mode::Suffix: hit = EndsWithCi(*s, val); break;
            case Mode::Prefix: hit = StartsWithCi(*s, val); break;
            case Mode::Substring: hit = ContainsCi(*s, val); break;
            }
            if (hit) break;
        }
    } else if (const auto* i = std::get_if<int64_t>(&v)) {
        if (m_mode != Mode::Exact) return false;
        const std::string n = std::to_string(*i);
        hit = std::binary_search(m_values.begin(), m_values.end(), n);
    } else {
        return false;   // 缺值：不翻轉
    }
    return m_negate ? !hit : hit;
}

void InExpr::Describe(std::string& out) const
{
    static constexpr const char* kModes[] = {"in", "ends_with_any", "starts_with_any", "contains_any"};
    out.append(FieldName(m_field));
    out += m_negate ? " not_" : " ";
    out += kModes[static_cast<int>(m_mode)];
    out += " [";
    for (size_t i = 0; i < m_values.size(); ++i) {
        if (i) out += ", ";
        out += m_values[i];
    }
    out += "]";
}

FieldMask InExpr::RequiredFields() const { return One(m_field); }

int InExpr::Cost() const noexcept
{
    switch (m_mode) {
    case Mode::Exact: return 2;
    case Mode::Suffix:
    case Mode::Prefix: return 3;
    case Mode::Substring: return 5;
    }
    return 5;
}

// ---------------- MatchExpr ----------------
MatchExpr::MatchExpr(FieldId f, std::string pattern, std::regex re, std::vector<std::string> prefilter, bool negate)
    : m_field(f), m_pattern(std::move(pattern)), m_re(std::move(re)), m_prefilter(std::move(prefilter)),
      m_negate(negate)
{
    for (auto& p : m_prefilter) p = model::ToLowerAscii(p);
}

bool MatchExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    const FieldValue v = ctx.Get(m_field);
    const auto* s = std::get_if<std::string_view>(&v);
    if (!s) return false;

    bool hit = false;
    bool pre = m_prefilter.empty();
    for (const auto& p : m_prefilter) {
        if (ContainsCi(*s, p)) {
            pre = true;
            break;
        }
    }
    if (pre) {
        const std::string_view in = s->substr(0, kRegexInputLimit);
        try {
            hit = std::regex_search(in.begin(), in.end(), m_re);
        } catch (...) {
            hit = false;   // error_complexity / error_stack：視為未命中（計入健康度由呼叫端負責）
        }
    }
    return m_negate ? !hit : hit;
}

void MatchExpr::Describe(std::string& out) const
{
    out.append(FieldName(m_field));
    out += m_negate ? " not_matches /" : " matches /";
    out += m_pattern;
    out += "/";
}

FieldMask MatchExpr::RequiredFields() const { return One(m_field); }

// ---------------- MaskExpr ----------------
MaskExpr::MaskExpr(FieldId f, int64_t mask) : m_field(f), m_mask(mask) {}

bool MaskExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    const FieldValue v = ctx.Get(m_field);
    const auto* i = std::get_if<int64_t>(&v);
    return i && ((*i & m_mask) != 0);
}

void MaskExpr::Describe(std::string& out) const
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(m_mask));
    out.append(FieldName(m_field));
    out += " has_any ";
    out += buf;
}

FieldMask MaskExpr::RequiredFields() const { return One(m_field); }

// ---------------- RefExpr ----------------
RefExpr::RefExpr(FieldId f, uint8_t srcStep, FieldId srcField, std::string srcStepName, bool negate)
    : m_field(f), m_srcStep(srcStep), m_srcField(srcField), m_srcStepName(std::move(srcStepName)), m_negate(negate)
{
}

bool RefExpr::Evaluate(const EvalContext& ctx) const noexcept
{
    if (!ctx.bindings) return false;   // 步驟 0：語意檢查已禁止，此處為防禦
    const FieldValue bound = ctx.bindings->Get(m_srcStep, m_srcField);
    const FieldValue cur   = ctx.Get(m_field);
    if (std::holds_alternative<std::monostate>(bound) || std::holds_alternative<std::monostate>(cur)) return false;
    const bool eq = ValuesEqualCi(cur, bound);
    return m_negate ? !eq : eq;
}

void RefExpr::Describe(std::string& out) const
{
    out.append(FieldName(m_field));
    out += m_negate ? " not_equals_ref " : " equals_ref ";
    out += m_srcStepName;
    out += ".";
    out.append(FieldName(m_srcField));
}

FieldMask RefExpr::RequiredFields() const { return One(m_field); }

} // namespace cairn::rules
