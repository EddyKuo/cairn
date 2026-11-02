#include "base/Errors.h"

#include <cstdio>

namespace cairn {

std::string_view ErrorCodeName(ErrorCode c) noexcept
{
    switch (c) {
    case ErrorCode::Ok: return "Ok";
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::NotInitialized: return "NotInitialized";
    case ErrorCode::Cancelled: return "Cancelled";
    case ErrorCode::Timeout: return "Timeout";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::AlreadyExists: return "AlreadyExists";
    case ErrorCode::OutOfMemory: return "OutOfMemory";
    case ErrorCode::IoError: return "IoError";
    case ErrorCode::Unsupported: return "Unsupported";
    case ErrorCode::ChannelNotFound: return "ChannelNotFound";
    case ErrorCode::SubscribeFailed: return "SubscribeFailed";
    case ErrorCode::RenderFailed: return "RenderFailed";
    case ErrorCode::MalformedEventXml: return "MalformedEventXml";
    case ErrorCode::QueueFull: return "QueueFull";
    case ErrorCode::SysmonNotInstalled: return "SysmonNotInstalled";
    case ErrorCode::RuleParseError: return "RuleParseError";
    case ErrorCode::RuleSchemaViolation: return "RuleSchemaViolation";
    case ErrorCode::UnknownRuleField: return "UnknownRuleField";
    case ErrorCode::NoRulesLoaded: return "NoRulesLoaded";
    case ErrorCode::RuleSemanticError: return "RuleSemanticError";
    case ErrorCode::DbOpenFailed: return "DbOpenFailed";
    case ErrorCode::DbCorrupt: return "DbCorrupt";
    case ErrorCode::MigrationFailed: return "MigrationFailed";
    case ErrorCode::DbBusy: return "DbBusy";
    case ErrorCode::DbDiskFull: return "DbDiskFull";
    case ErrorCode::DbQueryFailed: return "DbQueryFailed";
    case ErrorCode::LlmUnavailable: return "LlmUnavailable";
    case ErrorCode::LlmTimeout: return "LlmTimeout";
    case ErrorCode::LlmSchemaViolation: return "LlmSchemaViolation";
    case ErrorCode::LlmContextOverflow: return "LlmContextOverflow";
    case ErrorCode::LlmHttpError: return "LlmHttpError";
    case ErrorCode::ProcessGone: return "ProcessGone";
    case ErrorCode::AccessDenied: return "AccessDenied";
    case ErrorCode::FirewallComFailed: return "FirewallComFailed";
    case ErrorCode::QuarantineIoFailed: return "QuarantineIoFailed";
    case ErrorCode::RestoreHashMismatch: return "RestoreHashMismatch";
    case ErrorCode::IdentityMismatch: return "IdentityMismatch";
    case ErrorCode::ActionNotAllowed: return "ActionNotAllowed";
    case ErrorCode::PipeBusy: return "PipeBusy";
    case ErrorCode::BadRpcRequest: return "BadRpcRequest";
    case ErrorCode::ConfirmationRequired: return "ConfirmationRequired";
    case ErrorCode::ConfirmationExpired: return "ConfirmationExpired";
    case ErrorCode::MethodNotFound: return "MethodNotFound";
    case ErrorCode::PayloadTooLarge: return "PayloadTooLarge";
    case ErrorCode::ServiceUnavailable: return "ServiceUnavailable";
    }
    return "Unknown";
}

std::string Error::ToString() const
{
    char buf[48];
    std::snprintf(buf, sizeof(buf), "0x%08X", static_cast<unsigned>(code));
    std::string s;
    s.reserve(64 + context.size());
    s.append(ErrorCodeName(code)).append(" (").append(buf).append(")");
    if (win32 != 0) {
        std::snprintf(buf, sizeof(buf), " win32=0x%08X", static_cast<unsigned>(win32));
        s.append(buf);
    }
    if (!context.empty()) s.append(": ").append(context);
    return s;
}

Error MakeError(ErrorCode c, std::string_view ctx)
{
    return Error{c, 0, std::string(ctx)};
}

Error MakeWin32Error(ErrorCode c, uint32_t lastError, std::string_view ctx)
{
    return Error{c, lastError, std::string(ctx)};
}

} // namespace cairn
