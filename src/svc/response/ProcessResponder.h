// src/svc/response/ProcessResponder.h         namespace cairn::response
// suspend_process / terminate_process_tree（SDD-03 §8.2.1 / §8.2.2、part2 §2.7）。
// 標頭可攜；實作（.cpp）為 Win32。
//
// ★ PID 身分驗證（W3-2，必做）：開啟 handle 後、動作前，以
//   GetProcessTimes 的建立時間 + QueryFullProcessImageNameW 的映像路徑
//   與 model::ProcessRef 比對；不符一律拒絕（IdentityMismatch），絕不殺錯。
//   從偵測到執行之間原程序可能已結束、PID 被指派給無辜程序。
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "model/ResponseCommand.h"
#include "response/IResponseAction.h"

namespace cairn::response {

// 終止時的退出碼，供事後鑑識辨識「此程序由 Cairn 終止」
inline constexpr uint32_t kCairnTerminateExitCode = 0x0ED00001;
// Sysmon UtcTime（ms 精度）與 GetProcessTimes 的容許誤差
inline constexpr int64_t kStartTimeToleranceMs = 100;

enum class IdentityCheck : uint8_t {
    Match = 0,      // 存在且身分相符，可動作
    Gone,           // 已結束（OpenProcess → ERROR_INVALID_PARAMETER 或已有退出碼）
    Mismatch,       // PID 已被重用 —— 拒絕
    AccessDenied,   // 身分相符但無權限（PPL / 系統保護）
    Critical,       // 系統關鍵程序或 Cairn 自身 —— 政策拒絕
    Error,          // 其他 Win32 錯誤
};

struct ProbeResult {
    IdentityCheck check = IdentityCheck::Error;
    uint32_t      win32Error = 0;
    int64_t       actualStartMs = 0;
    std::string   actualImage;
};

// 探測目標程序（不做任何動作）。desiredAccess 為 PROCESS_* 遮罩（例如 PROCESS_SUSPEND_RESUME）。
[[nodiscard]] ProbeResult ProbeProcess(const model::ProcessRef& ref, uint32_t desiredAccess);

// 系統關鍵程序或 Cairn 自身（以映像名判斷 + pid <= 4 + 自身 pid）
[[nodiscard]] bool IsCriticalProcess(const model::ProcessRef& ref) noexcept;

// 互動式應用程式的警告文字（winword.exe 等）；非互動回空字串
[[nodiscard]] std::string InteractiveWarning(const model::ProcessRef& ref);

// 目標鍵：有 ProcessGuid 用 GUID 字串，否則 "pid:{pid}@{startMs}"
[[nodiscard]] std::string ProcessKey(const model::ProcessRef& ref);
[[nodiscard]] std::string ProcessLabel(const model::ProcessRef& ref);   // "winword.exe (4820)"

class SuspendProcessAction final : public IResponseAction {
public:
    SuspendProcessAction() = default;
    [[nodiscard]] Status Init();   // 解析 ntdll 的 NtSuspendProcess / NtResumeProcess
    [[nodiscard]] model::ActionKind Kind() const noexcept override { return model::ActionKind::SuspendProcess; }
    [[nodiscard]] Result<ActionImpact> Prepare(const ActionContext& ctx) override;
    [[nodiscard]] std::vector<TargetOutcome> Execute(const ActionContext& ctx, ActionRecord& record) override;
    [[nodiscard]] Result<std::vector<TargetOutcome>> Revert(const ActionRecord& record) override;
};

class TerminateTreeAction final : public IResponseAction {
public:
    TerminateTreeAction() = default;
    [[nodiscard]] Status Init();
    [[nodiscard]] model::ActionKind Kind() const noexcept override { return model::ActionKind::TerminateProcessTree; }
    // 影響清單 = 快照中的程序 + 目前仍存活、但快照未列出的後代（Toolhelp 列舉）
    [[nodiscard]] Result<ActionImpact> Prepare(const ActionContext& ctx) override;
    // 兩階段：根→葉全樹暫停（含 ≤ 3 輪新派生程序補抓）→ 葉→根 TerminateProcess + 等待 2 秒確認
    [[nodiscard]] std::vector<TargetOutcome> Execute(const ActionContext& ctx, ActionRecord& record) override;
    // 不可逆：回傳 NOT_REVERSIBLE
    [[nodiscard]] Result<std::vector<TargetOutcome>> Revert(const ActionRecord& record) override;
};

} // namespace cairn::response
