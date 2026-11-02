// src/svc/response/ResponseTypes.h            namespace cairn::response
// 回應執行器的值型別（SDD-03 §8.1 / §8.4）。可攜程式碼：不含任何 Win32 標頭。
//
// 與 SDD 的對應：
//   ActionStatus / TargetOutcome      —— §8.4（逐目標回報、207 部分成功）
//   ActionImpact / ImpactItem         —— §8.3（Prepare 的影響清單，impactHash 的輸入）
//   PrepareResponse / ExecuteResponse —— part3 §3.8.4 的 RPC 回應形狀
//   ActionRecord                      —— 還原所需的持久化紀錄（%ProgramData%\Cairn\actions\）
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "model/Domain.h"
#include "model/ResponseCommand.h"

namespace cairn::response {

using UnixMs = int64_t;

enum class ActionStatus : uint8_t {
    Succeeded = 0,       // 全部目標成功 → HTTP 200
    PartiallySucceeded,  // 至少一成一敗 → HTTP 207
    Failed,              // 全部失敗     → HTTP 502
    Rejected,            // 前置驗證未過 → HTTP 4xx（實務上以 Result 的 Error 回傳，見 RejectInfoOf）
};

struct TargetOutcome {
    std::string key;            // ProcessGuid / 路徑 / IP
    std::string label;          // "winword.exe (4820)" —— 給人看的
    bool        ok = false;
    uint32_t    win32Error = 0; // 0 = 無 Win32 錯誤
    std::string reason;         // "already exited" / "protected process" / ...
};

// 影響清單的單一項目
struct ImpactItem {
    std::string key;
    std::string label;
    std::optional<model::ProcessRef> process;   // 程序類動作
    std::optional<std::string> filePath;        // quarantine_file
    std::optional<uint64_t>    fileSize;
    std::optional<std::string> fileSha256;
    std::optional<std::string> ip;              // firewall_block
    bool        reachable = true;               // 目前是否仍存在且身分相符
    bool        protectedTarget = false;        // 受 Windows 保護（ACCESS_DENIED）或屬系統關鍵程序
    std::string warning;                        // 空 = 無警告
    std::string warningLevel;                   // "" | "medium" | "high"
};

struct ActionImpact {
    std::vector<ImpactItem>  items;
    int                      totalCount = 0;
    int                      protectedCount = 0;
    std::vector<std::string> warnings;          // 動作層級的警告（例如「IP 封鎖對換 IP 的攻擊者無效」）
    std::string              typedExpected;     // L3：要求使用者打的字串（根程序名），其餘為空
};

struct PrepareResponse {
    std::string       confirmationToken;        // L1 不強制使用；L2/L3 必須帶回
    UnixMs            expiresAt = 0;
    model::ActionKind action = model::ActionKind::SuspendProcess;
    int               riskLevel = 1;            // 1/2/3 → "L1"/"L2"/"L3"
    bool              reversible = true;
    bool              requireToken = false;     // L2/L3 = true
    bool              requireTypedConfirmation = false;
    std::string       typedConfirmationExpected;
    std::string       impactHash;
    ActionImpact      impact;
};

struct ExecuteRequest {
    int64_t           alertId = 0;
    model::ActionKind action = model::ActionKind::SuspendProcess;
    std::string       confirmationToken;        // L1 可為空（此時必須提供 target）
    std::string       typedConfirmation;
    std::string       reason;
    std::string       actor = "analyst";        // 寫入稽核；RPC 層填入 "user:<DOMAIN\\name>"
    std::string       peerSid;                  // 呼叫端 SID（token 綁定，SDD-03 §8.3.2）
    std::optional<model::ResponseTarget> target;// 僅 L1 無 token 時使用
};

struct ExecuteResponse {
    std::string       actionId;                 // "ACT-4821-03"，亦為 revert 的鍵
    model::ActionKind action = model::ActionKind::SuspendProcess;
    ActionStatus      status = ActionStatus::Failed;
    UnixMs            executedAt = 0;
    std::string       actor;
    std::string       reason;
    std::vector<TargetOutcome> results;
    std::optional<int64_t> auditId;             // audit_log.id；寫入佇列非同步配發，逾時則為空
    bool              reversible = true;
    std::string       errorSummary;
};

struct RevertRequest {
    std::string actionIdOrAuditId;              // "ACT-4821-03" 或 audit_log.id 的十進位字串
    std::string typedConfirmation;              // 還原隔離檔需打字確認（原檔名），SDD-03 §8.5.2
    std::string reason;
    std::string actor = "analyst";
};

struct RevertResponse {
    std::string actionId;
    ActionStatus status = ActionStatus::Failed;
    std::vector<TargetOutcome> results;
    std::optional<int64_t> auditId;
};

// 持久化的動作紀錄：Revert 需要找回原動作的參數。
struct ActionRecord {
    int32_t           schemaVersion = 1;
    std::string       actionId;
    int64_t           alertId = 0;
    model::ActionKind action = model::ActionKind::SuspendProcess;
    ActionStatus      status = ActionStatus::Failed;
    UnixMs            executedAt = 0;
    std::string       actor;
    std::string       reason;
    bool              automatic = false;
    std::string       impactHash;
    std::vector<TargetOutcome> results;

    // ---- 還原參數 ----
    std::vector<model::ProcessRef> suspended;   // suspend_process：成功暫停的程序（含身分）
    std::vector<std::string>       quarantineIds;// quarantine_file：隔離區 id
    std::string                    firewallRuleName; // firewall_block
    std::string                    ip;

    std::optional<int64_t> auditId;             // action_completed 那一列的 audit_log.id
    bool                   reverted = false;
    std::optional<UnixMs>  revertedAt;
    std::optional<int64_t> revertAuditId;
};

// 隔離區 metadata（SDD-03 §8.2.3）
struct QuarantineEntry {
    int32_t     schemaVersion = 1;
    std::string quarantineId;
    std::string originalPath;
    std::string originalSddl;
    std::string sha256;                         // 小寫十六進位
    uint64_t    sizeBytes = 0;
    UnixMs      quarantinedTs = 0;
    int64_t     alertId = 0;
    std::vector<std::string> ruleIds;
    std::string actor;
    std::string algo = "AES-256-GCM";
    std::string nonceB64;
    std::string tagB64;
    std::optional<std::string> actionId;
};

} // namespace cairn::response
