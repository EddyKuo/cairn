// src/svc/response/ConfirmationTokenStore.h   namespace cairn::response
// prepare → execute 兩階段協定的 token 存放（SDD-03 §8.3.2）。可攜程式碼。
//
//   - token = "ct_" + 32 hex（128 bits）。亂數來源由建構者注入：
//     正式環境為 BCryptGenRandom（ResponseExecutor 注入），測試注入決定性來源。
//     ⚠ 不得用 rand()/mt19937：token 可預測 = 繞過二次確認。
//   - TTL 預設 60 秒（part3 §3.8.4 的 410 TOKEN_EXPIRED）
//   - 一次性消費：成功即刪除，重放必失敗
//   - 綁定五欄全等（alertId / actionName / targetKey / impactHash / peerSid）
//   - 打字確認以常數時間比對（ASCII 大小寫不敏感）
//   - 同時最多 64 個未消費 token
//
// 執行緒：任意（mutex 保護）。
//
// ⚠ 誠實揭露（SDD-03 §8.3.2）：同一 RPC 通道內的二次確認可被本機使用者自助完成；
//   它防的是誤點與樂觀併發，不防已取得本機使用者權限的攻擊者。
#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "base/IClock.h"
#include "base/Result.h"

namespace cairn::response {

struct TokenBinding {
    int64_t     alertId = 0;
    std::string actionName;     // C-9 正規名
    std::string targetKey;      // ResponseTarget::key
    std::string impactHash;     // ComputeImpactHash 的結果
    std::string typedExpected;  // L3 要求使用者打的字串；空 = 不需打字
    std::string peerSid;        // 呼叫端 SID；空字串亦參與比對

    // 不含 impactHash 與 typedExpected 的身分比對（impact 另行判斷以回 IMPACT_CHANGED）
    [[nodiscard]] bool SameSubject(const TokenBinding& o) const noexcept
    {
        return alertId == o.alertId && actionName == o.actionName && targetKey == o.targetKey &&
               peerSid == o.peerSid;
    }
    [[nodiscard]] bool Equals(const TokenBinding& o) const noexcept
    {
        return SameSubject(o) && impactHash == o.impactHash;
    }
};

struct IssuedToken {
    std::string token;
    UnixMs      expiresAt = 0;
};

class ConfirmationTokenStore {
public:
    using RandomFn = std::function<std::array<uint8_t, 16>()>;

    ConfirmationTokenStore(const IClock& clock, RandomFn random, size_t maxTokens = 64,
                           std::chrono::seconds ttl = std::chrono::seconds{60});

    // 超過上限時先清除過期者；仍滿則回 TOKEN_LIMIT。
    [[nodiscard]] Result<IssuedToken> Issue(TokenBinding binding);
    [[nodiscard]] Result<IssuedToken> Issue(TokenBinding binding, std::chrono::seconds ttl);

    // 驗證順序：存在 → 未過期 → 主體綁定 → impactHash → 打字確認 → 消費。
    //   不存在 / 已消費      → ConfirmationExpired "TOKEN_INVALID"
    //   已過期（並移除）      → ConfirmationExpired "TOKEN_EXPIRED"
    //   主體不符（並移除）    → ConfirmationRequired "TOKEN_BINDING_MISMATCH"
    //   impactHash 不符（並移除）→ ConfirmationRequired "IMPACT_CHANGED"（UI 自動重新 prepare）
    //   打字不符（**保留** token，使用者可在 TTL 內重打）→ InvalidArgument "TYPED_CONFIRMATION_MISMATCH"
    [[nodiscard]] Status Consume(std::string_view token, const TokenBinding& expected, std::string_view typedActual);

    // 不消費地讀取綁定（Execute 先以此取回 Prepare 時的綁定，再重算 impact）。
    [[nodiscard]] Result<TokenBinding> Peek(std::string_view token) const;

    void SweepExpired();
    [[nodiscard]] size_t Size() const;

private:
    struct TokenEntry {
        TokenBinding binding;
        UnixMs       expiresAt = 0;
    };

    [[nodiscard]] std::string NewTokenString();

    const IClock&                               m_clock;
    RandomFn                                    m_random;
    size_t                                      m_maxTokens;
    std::chrono::seconds                        m_ttl;
    mutable std::mutex                          m_mutex;
    std::unordered_map<std::string, TokenEntry> m_tokens;
};

// 打字確認的比對：去除前後空白、ASCII 小寫化後以常數時間比對。
[[nodiscard]] bool TypedConfirmationMatches(std::string_view expected, std::string_view actual) noexcept;

} // namespace cairn::response
