#include "response/ConfirmationTokenStore.h"

#include "response/ResponseJson.h"

namespace cairn::response {

namespace {
std::string_view Trim(std::string_view s) noexcept
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}
} // namespace

bool TypedConfirmationMatches(std::string_view expected, std::string_view actual) noexcept
{
    const auto e = ToLower(Trim(expected));
    const auto a = ToLower(Trim(actual));
    return ConstantTimeEquals(e, a);
}

ConfirmationTokenStore::ConfirmationTokenStore(const IClock& clock, RandomFn random, size_t maxTokens,
                                               std::chrono::seconds ttl)
    : m_clock(clock), m_random(std::move(random)), m_maxTokens(maxTokens), m_ttl(ttl)
{
}

std::string ConfirmationTokenStore::NewTokenString()
{
    static constexpr char kHex[] = "0123456789abcdef";
    const auto bytes = m_random();
    std::string s = "ct_";
    s.reserve(3 + 32);
    for (auto b : bytes) {
        s.push_back(kHex[b >> 4]);
        s.push_back(kHex[b & 0x0F]);
    }
    return s;
}

Result<IssuedToken> ConfirmationTokenStore::Issue(TokenBinding binding)
{
    return Issue(std::move(binding), m_ttl);
}

Result<IssuedToken> ConfirmationTokenStore::Issue(TokenBinding binding, std::chrono::seconds ttl)
{
    std::lock_guard lk{m_mutex};
    const UnixMs now = m_clock.NowMs();
    if (m_tokens.size() >= m_maxTokens) {
        for (auto it = m_tokens.begin(); it != m_tokens.end();) {
            if (it->second.expiresAt <= now) it = m_tokens.erase(it);
            else ++it;
        }
    }
    if (m_tokens.size() >= m_maxTokens) {
        return MakeReject(ErrorCode::ConfirmationRequired, "TOKEN_LIMIT", "too many pending confirmations");
    }

    std::string token;
    for (int attempt = 0; attempt < 4; ++attempt) {   // 128-bit 碰撞實務上不會發生，仍不覆寫既有
        token = NewTokenString();
        if (!m_tokens.contains(token)) break;
        token.clear();
    }
    if (token.empty()) return MakeError(ErrorCode::InvalidArgument, "token generation failed (random source)");

    const UnixMs expiresAt = now + std::chrono::duration_cast<std::chrono::milliseconds>(ttl).count();
    m_tokens.emplace(token, TokenEntry{std::move(binding), expiresAt});
    return IssuedToken{token, expiresAt};
}

Status ConfirmationTokenStore::Consume(std::string_view token, const TokenBinding& expected,
                                       std::string_view typedActual)
{
    std::lock_guard lk{m_mutex};
    auto it = m_tokens.find(std::string(token));
    if (it == m_tokens.end()) {
        return MakeReject(ErrorCode::ConfirmationExpired, "TOKEN_INVALID", "unknown or already used token");
    }
    if (it->second.expiresAt <= m_clock.NowMs()) {
        m_tokens.erase(it);
        return MakeReject(ErrorCode::ConfirmationExpired, "TOKEN_EXPIRED", "confirmation token expired");
    }
    const TokenBinding& bound = it->second.binding;
    if (!bound.SameSubject(expected)) {
        m_tokens.erase(it);
        return MakeReject(ErrorCode::ConfirmationRequired, "TOKEN_BINDING_MISMATCH",
                          "token was issued for a different alert/action/target/caller");
    }
    if (bound.impactHash != expected.impactHash) {
        m_tokens.erase(it);
        return MakeReject(ErrorCode::ConfirmationRequired, "IMPACT_CHANGED",
                          "process tree or target changed since prepare; re-prepare required");
    }
    if (!bound.typedExpected.empty() && !TypedConfirmationMatches(bound.typedExpected, typedActual)) {
        // 保留 token：允許使用者在 TTL 內更正輸入
        return MakeReject(ErrorCode::InvalidArgument, "TYPED_CONFIRMATION_MISMATCH",
                          "typed confirmation does not match");
    }
    m_tokens.erase(it);
    return Ok();
}

Result<TokenBinding> ConfirmationTokenStore::Peek(std::string_view token) const
{
    std::lock_guard lk{m_mutex};
    auto it = m_tokens.find(std::string(token));
    if (it == m_tokens.end()) {
        return MakeReject(ErrorCode::ConfirmationExpired, "TOKEN_INVALID", "unknown or already used token");
    }
    if (it->second.expiresAt <= m_clock.NowMs()) {
        return MakeReject(ErrorCode::ConfirmationExpired, "TOKEN_EXPIRED", "confirmation token expired");
    }
    return it->second.binding;
}

void ConfirmationTokenStore::SweepExpired()
{
    std::lock_guard lk{m_mutex};
    const UnixMs now = m_clock.NowMs();
    for (auto it = m_tokens.begin(); it != m_tokens.end();) {
        if (it->second.expiresAt <= now) it = m_tokens.erase(it);
        else ++it;
    }
}

size_t ConfirmationTokenStore::Size() const
{
    std::lock_guard lk{m_mutex};
    return m_tokens.size();
}

} // namespace cairn::response
