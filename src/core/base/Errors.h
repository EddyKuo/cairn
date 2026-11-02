// src/core/base/Errors.h                      namespace cairn
// 錯誤碼分層（SDD-01 §2.7.2）。高位元組 = 子系統編號。
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace cairn {

enum class ErrorDomain : uint8_t {
    General   = 0x00,
    Telemetry = 0x01,
    Rules     = 0x02,
    Store     = 0x03,
    Llm       = 0x04,
    Response  = 0x05,
    Rpc       = 0x06,
    Win32     = 0xFF,
};

enum class ErrorCode : uint32_t {
    Ok                      = 0x00000000,

    // General
    InvalidArgument         = 0x00000001,
    NotInitialized          = 0x00000002,
    Cancelled               = 0x00000003,
    Timeout                 = 0x00000004,
    NotFound                = 0x00000005,
    AlreadyExists           = 0x00000006,
    OutOfMemory             = 0x00000007,
    IoError                 = 0x00000008,
    Unsupported             = 0x00000009,

    // Telemetry
    ChannelNotFound         = 0x01000001,
    SubscribeFailed         = 0x01000002,
    RenderFailed            = 0x01000003,
    MalformedEventXml       = 0x01000004,
    QueueFull               = 0x01000005,
    SysmonNotInstalled      = 0x01000006,

    // Rules
    RuleParseError          = 0x02000001,
    RuleSchemaViolation     = 0x02000002,
    UnknownRuleField        = 0x02000003,
    NoRulesLoaded           = 0x02000004,
    RuleSemanticError       = 0x02000005,

    // Store
    DbOpenFailed            = 0x03000001,
    DbCorrupt               = 0x03000002,
    MigrationFailed         = 0x03000003,
    DbBusy                  = 0x03000004,
    DbDiskFull              = 0x03000005,
    DbQueryFailed           = 0x03000006,

    // Llm
    LlmUnavailable          = 0x04000001,
    LlmTimeout              = 0x04000002,
    LlmSchemaViolation      = 0x04000003,
    LlmContextOverflow      = 0x04000004,
    LlmHttpError            = 0x04000005,

    // Response
    ProcessGone             = 0x05000001,   // 目標程序已結束 —— 非錯誤，屬正常競態
    AccessDenied            = 0x05000002,
    FirewallComFailed       = 0x05000003,
    QuarantineIoFailed      = 0x05000004,
    RestoreHashMismatch     = 0x05000005,
    IdentityMismatch        = 0x05000006,   // PID 已被重用，身分驗證失敗
    ActionNotAllowed        = 0x05000007,

    // Rpc
    PipeBusy                = 0x06000001,
    BadRpcRequest           = 0x06000002,
    ConfirmationRequired    = 0x06000003,
    ConfirmationExpired     = 0x06000004,
    MethodNotFound          = 0x06000005,
    PayloadTooLarge         = 0x06000006,
    ServiceUnavailable      = 0x06000007,
};

[[nodiscard]] constexpr ErrorDomain DomainOf(ErrorCode c) noexcept
{
    return static_cast<ErrorDomain>((static_cast<uint32_t>(c) >> 24) & 0xFF);
}

[[nodiscard]] std::string_view ErrorCodeName(ErrorCode c) noexcept;

// 錯誤實體：碼 + 上下文字串 + 可選的原始 Win32 碼（P-5：保留原值）。
struct Error {
    ErrorCode   code  = ErrorCode::Ok;
    uint32_t    win32 = 0;
    std::string context;

    [[nodiscard]] bool IsOk() const noexcept { return code == ErrorCode::Ok; }
    [[nodiscard]] std::string ToString() const;
};

[[nodiscard]] Error MakeError(ErrorCode c, std::string_view ctx);
[[nodiscard]] Error MakeWin32Error(ErrorCode c, uint32_t lastError, std::string_view ctx);

} // namespace cairn
