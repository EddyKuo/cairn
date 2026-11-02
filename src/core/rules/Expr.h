// src/core/rules/Expr.h                       namespace cairn::rules
// 條件 AST（SDD-02 §5.3）。編譯後不可變，可被任意執行緒讀取；求值在 AnalysisThread。
// 運算子：equals not_equals contains not_contains starts_with ends_with in not_in matches gt lt has_any
//        + equals_ref / not_equals_ref / *_any 家族（SDD-02 §5.4.6 要求回填）。
// 三值約定：欄位缺值時任何述詞（含否定）一律 false。
#pragma once
#include <memory>
#include <regex>
#include <string>
#include <vector>

#include "rules/Bindings.h"
#include "rules/Fields.h"

namespace cairn::rules {

class IExpr {
public:
    virtual ~IExpr() = default;
    [[nodiscard]] virtual bool Evaluate(const EvalContext& ctx) const noexcept = 0;
    virtual void Describe(std::string& out) const = 0;
    [[nodiscard]] virtual FieldMask RequiredFields() const = 0;
    [[nodiscard]] virtual int Cost() const noexcept = 0;   // §5.3.1 成本級，AndExpr 依此排序
};
using ExprPtr = std::unique_ptr<IExpr>;

class AndExpr final : public IExpr {
public:
    explicit AndExpr(std::vector<ExprPtr> kids);   // 建構時依成本排序（短路）
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override;

private:
    std::vector<ExprPtr> m_kids;
};

class OrExpr final : public IExpr {
public:
    explicit OrExpr(std::vector<ExprPtr> kids);
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override;

private:
    std::vector<ExprPtr> m_kids;
};

// equals / not_equals / gt / lt（字串、整數、布林、GUID）
class CmpExpr final : public IExpr {
public:
    enum class Op : uint8_t { Eq, Ne, Gt, Lt };
    CmpExpr(FieldId f, Op op, FieldValue literal, std::string ownedString = {});
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override { return 1; }

private:
    FieldId     m_field;
    Op          m_op;
    std::string m_str;         // 字串常數（已小寫）擁有者
    FieldValue  m_literal;     // string_view 指向 m_str
};

// in / not_in / ends_with(_any) / starts_with(_any) / contains(_any) 及其否定
class InExpr final : public IExpr {
public:
    enum class Mode : uint8_t { Exact, Suffix, Prefix, Substring };
    InExpr(FieldId f, Mode m, std::vector<std::string> values, bool negate);
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override;

private:
    FieldId                  m_field;
    Mode                     m_mode;
    std::vector<std::string> m_values;   // 已小寫、排序、去重
    bool                     m_negate;
};

// matches / not_matches（std::regex，icase）。prefilter：任一字面量（小寫）出現才跑 regex。
class MatchExpr final : public IExpr {
public:
    MatchExpr(FieldId f, std::string pattern, std::regex re, std::vector<std::string> prefilter, bool negate);
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override { return 6; }

private:
    FieldId                  m_field;
    std::string              m_pattern;
    std::regex               m_re;
    std::vector<std::string> m_prefilter;
    bool                     m_negate;
};

// has_any：(value & mask) != 0（EID 10 的 GrantedAccess 高危遮罩）
class MaskExpr final : public IExpr {
public:
    MaskExpr(FieldId f, int64_t mask);
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override { return 1; }

private:
    FieldId m_field;
    int64_t m_mask;
};

// equals_ref / not_equals_ref：與前序步驟匯出的值比對
class RefExpr final : public IExpr {
public:
    RefExpr(FieldId f, uint8_t srcStep, FieldId srcField, std::string srcStepName, bool negate);
    bool Evaluate(const EvalContext& ctx) const noexcept override;
    void Describe(std::string& out) const override;
    FieldMask RequiredFields() const override;
    int Cost() const noexcept override { return 4; }
    [[nodiscard]] uint8_t SourceStep() const noexcept { return m_srcStep; }
    [[nodiscard]] FieldId SourceField() const noexcept { return m_srcField; }

private:
    FieldId     m_field;
    uint8_t     m_srcStep;
    FieldId     m_srcField;
    std::string m_srcStepName;
    bool        m_negate;
};

// 恆真（where 為空時）
class TrueExpr final : public IExpr {
public:
    bool Evaluate(const EvalContext&) const noexcept override { return true; }
    void Describe(std::string& out) const override { out += "true"; }
    FieldMask RequiredFields() const override { return {}; }
    int Cost() const noexcept override { return 0; }
};

// 兩個 FieldValue 是否相等（字串大小寫不敏感）。缺值一律 false。
[[nodiscard]] bool ValuesEqualCi(const FieldValue& a, const FieldValue& b) noexcept;

} // namespace cairn::rules
