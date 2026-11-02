// src/core/base/Result.h                      namespace cairn
// 語意與 std::expected 一致（SDD-01 §2.7.3）。自行實作以避免相依 _HAS_CXX23。
// 與 SDD 原稿的差異：值以 std::optional 持有，T 不必可預設建構。
#pragma once
#include <optional>
#include <type_traits>
#include <utility>

#include "base/Assert.h"
#include "base/Errors.h"

namespace cairn {

template <class T>
class [[nodiscard]] Result {
public:
    Result(T value) noexcept(std::is_nothrow_move_constructible_v<T>)
        : m_value(std::move(value)) {}

    Result(Error err) noexcept : m_error(std::move(err)) {}

    [[nodiscard]] bool HasValue() const noexcept { return m_value.has_value(); }
    explicit operator bool() const noexcept { return m_value.has_value(); }

    [[nodiscard]] T&       Value() &      { CAIRN_ASSERT(m_value.has_value()); return *m_value; }
    [[nodiscard]] const T& Value() const& { CAIRN_ASSERT(m_value.has_value()); return *m_value; }
    [[nodiscard]] T&&      Value() &&     { CAIRN_ASSERT(m_value.has_value()); return std::move(*m_value); }

    [[nodiscard]] const Error& GetError() const noexcept { CAIRN_ASSERT(!m_value.has_value()); return m_error; }
    [[nodiscard]] ErrorCode Code() const noexcept { return m_value ? ErrorCode::Ok : m_error.code; }

    [[nodiscard]] T ValueOr(T fallback) const& { return m_value ? *m_value : std::move(fallback); }

private:
    std::optional<T> m_value;
    Error            m_error{};
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() noexcept : m_hasValue(true) {}
    Result(Error err) noexcept : m_error(std::move(err)), m_hasValue(false) {}

    [[nodiscard]] bool HasValue() const noexcept { return m_hasValue; }
    explicit operator bool() const noexcept { return m_hasValue; }
    [[nodiscard]] const Error& GetError() const noexcept { CAIRN_ASSERT(!m_hasValue); return m_error; }
    [[nodiscard]] ErrorCode Code() const noexcept { return m_hasValue ? ErrorCode::Ok : m_error.code; }

private:
    Error m_error{};
    bool  m_hasValue = false;
};

using Status = Result<void>;

[[nodiscard]] inline Status Ok() noexcept { return Status{}; }

#define CAIRN_CONCAT_(a, b) a##b
#define CAIRN_CONCAT(a, b)  CAIRN_CONCAT_(a, b)

// 用法： CAIRN_TRY(auto db, SqliteDb::Open(path));
#define CAIRN_TRY(decl, expr)                          \
    auto CAIRN_CONCAT(_r_, __LINE__) = (expr);         \
    if (!CAIRN_CONCAT(_r_, __LINE__))                  \
        return CAIRN_CONCAT(_r_, __LINE__).GetError(); \
    decl = std::move(CAIRN_CONCAT(_r_, __LINE__)).Value()

#define CAIRN_CHECK(expr)                                  \
    do {                                                   \
        auto CAIRN_CONCAT(_s_, __LINE__) = (expr);         \
        if (!CAIRN_CONCAT(_s_, __LINE__))                  \
            return CAIRN_CONCAT(_s_, __LINE__).GetError(); \
    } while (0)

} // namespace cairn
