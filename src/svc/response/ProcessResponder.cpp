// src/svc/response/ProcessResponder.cpp       Win32 實作
#include "response/ProcessResponder.h"

#include <windows.h>
#include <tlhelp32.h>

#include <wil/resource.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <unordered_set>

#include "common/WinUtil.h"
#include "response/ResponseJson.h"

namespace cairn::response {

namespace {

// NtSuspendProcess / NtResumeProcess 未在任何 .lib 匯出，執行期解析（SDD-03 §8.2.1）。
using PfnNtProcess = LONG(NTAPI*)(HANDLE);

struct NtFns {
    PfnNtProcess suspend = nullptr;
    PfnNtProcess resume  = nullptr;
};

const NtFns& Nt() noexcept
{
    static const NtFns fns = [] {
        NtFns f;
        if (const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll")) {
            f.suspend = reinterpret_cast<PfnNtProcess>(reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtSuspendProcess")));
            f.resume  = reinterpret_cast<PfnNtProcess>(reinterpret_cast<void*>(::GetProcAddress(ntdll, "NtResumeProcess")));
        }
        return f;
    }();
    return fns;
}

constexpr std::array<std::string_view, 8> kCriticalImages{
    "csrss.exe", "smss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "cairnagent.exe", "system"};

constexpr std::array<std::string_view, 12> kInteractiveImages{
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "notepad.exe",
    "code.exe", "chrome.exe", "msedge.exe", "firefox.exe", "teams.exe", "explorer.exe"};

std::string NtStatusText(LONG st)
{
    char buf[48];
    std::snprintf(buf, sizeof(buf), "NTSTATUS 0x%08lX", static_cast<unsigned long>(st));
    return buf;
}

// 開啟並驗證身分；成功時 out 持有 handle。
ProbeResult OpenVerified(const model::ProcessRef& ref, DWORD desiredAccess, wil::unique_handle& out)
{
    ProbeResult pr;
    out.reset();
    if (IsCriticalProcess(ref)) {
        pr.check = IdentityCheck::Critical;
        return pr;
    }

    const DWORD access = desiredAccess | PROCESS_QUERY_LIMITED_INFORMATION;
    wil::unique_handle h{::OpenProcess(access, FALSE, ref.pid)};
    if (!h) {
        const DWORD err = ::GetLastError();
        pr.win32Error = err;
        if (err == ERROR_INVALID_PARAMETER) {
            pr.check = IdentityCheck::Gone;
            return pr;
        }
        if (err != ERROR_ACCESS_DENIED) {
            pr.check = IdentityCheck::Error;
            return pr;
        }
        // 權限不足：以最低權限再開一次，確認是否確為同一程序（受保護）或已被重用
        h.reset(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ref.pid));
        if (!h) {
            pr.check = IdentityCheck::AccessDenied;   // 連查詢都不行：視為受保護
            return pr;
        }
        pr.check = IdentityCheck::AccessDenied;       // 暫定；下方身分比對可能改為 Mismatch
    }

    DWORD exitCode = 0;
    if (::GetExitCodeProcess(h.get(), &exitCode) && exitCode != STILL_ACTIVE) {
        pr.check = IdentityCheck::Gone;
        return pr;
    }

    FILETIME create{}, exitT{}, kernel{}, user{};
    if (!::GetProcessTimes(h.get(), &create, &exitT, &kernel, &user)) {
        pr.check = IdentityCheck::Error;
        pr.win32Error = ::GetLastError();
        return pr;
    }
    pr.actualStartMs = svc::FileTimeToUnixMs(create);

    wchar_t buf[32768];
    DWORD size = static_cast<DWORD>(std::size(buf));
    if (::QueryFullProcessImageNameW(h.get(), 0, buf, &size)) {
        pr.actualImage = svc::WideToUtf8(std::wstring_view(buf, size));
    }

    // ---- 身分比對 ----
    bool startOk = true;
    if (ref.startTsMs != 0) startOk = std::llabs(pr.actualStartMs - ref.startTsMs) <= kStartTimeToleranceMs;
    bool imageOk = true;
    if (!ref.image.empty() && !pr.actualImage.empty()) {
        const bool fullEq = ToLower(ref.image) == ToLower(pr.actualImage);
        const bool baseEq = BaseNameLower(ref.image) == BaseNameLower(pr.actualImage);
        // 建立時間已知時允許只比對檔名（路徑可能有 8.3 短名 / \\?\ 前綴差異）；
        // 建立時間未知時要求完整路徑相符，否則寧可拒絕。
        imageOk = ref.startTsMs != 0 ? baseEq : fullEq;
    } else if (ref.startTsMs == 0) {
        imageOk = false;   // 兩項身分資訊都沒有：無法驗證 → 拒絕
    }
    if (!startOk || !imageOk) {
        pr.check = IdentityCheck::Mismatch;
        return pr;
    }
    if (pr.check == IdentityCheck::AccessDenied) return pr;   // 同一程序但無權限

    // 以要求的權限重開（第一次已用 access 開成功時 h 即為所需 handle）
    pr.check = IdentityCheck::Match;
    out = std::move(h);
    return pr;
}

TargetOutcome OutcomeFor(const model::ProcessRef& ref, const ProbeResult& pr)
{
    TargetOutcome o{ProcessKey(ref), ProcessLabel(ref), false, pr.win32Error, {}};
    switch (pr.check) {
    case IdentityCheck::Match: o.ok = true; break;
    case IdentityCheck::Gone: o.ok = true; o.reason = "already exited"; break;   // 目標狀態已達成
    case IdentityCheck::Mismatch: o.reason = "PID reused — refusing to act（身分驗證失敗，拒絕動作）"; break;
    case IdentityCheck::AccessDenied:
        o.reason = "protected process（此程序受 Windows 保護，M0 無驅動故無法處置）";
        if (o.win32Error == 0) o.win32Error = ERROR_ACCESS_DENIED;
        break;
    case IdentityCheck::Critical: o.reason = "critical system process — refused by policy（系統關鍵程序，政策拒絕）"; break;
    case IdentityCheck::Error: o.reason = "open process failed: " + svc::LastErrorMessage(pr.win32Error); break;
    }
    return o;
}

ImpactItem ImpactFor(const model::ProcessRef& ref, const ProbeResult& pr)
{
    ImpactItem it;
    it.key     = ProcessKey(ref);
    it.label   = ProcessLabel(ref);
    it.process = ref;
    it.reachable = pr.check == IdentityCheck::Match || pr.check == IdentityCheck::AccessDenied;
    it.protectedTarget = pr.check == IdentityCheck::AccessDenied || pr.check == IdentityCheck::Critical;
    switch (pr.check) {
    case IdentityCheck::Gone: it.warning = "程序已結束"; it.warningLevel = "medium"; break;
    case IdentityCheck::Mismatch: it.warning = "PID 已被其他程序重用，此項將被拒絕"; it.warningLevel = "high"; break;
    case IdentityCheck::AccessDenied: it.warning = "此程序受 Windows 保護，預期無法處置"; it.warningLevel = "medium"; break;
    case IdentityCheck::Critical: it.warning = "系統關鍵程序，政策拒絕處置"; it.warningLevel = "high"; break;
    case IdentityCheck::Error: it.warning = "無法探測此程序"; it.warningLevel = "medium"; break;
    case IdentityCheck::Match: {
        auto w = InteractiveWarning(ref);
        if (!w.empty()) {
            it.warning = std::move(w);
            it.warningLevel = "high";
        }
        break;
    }
    }
    return it;
}

struct LiveProc {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string exe;
};

std::vector<LiveProc> SnapshotProcesses()
{
    std::vector<LiveProc> out;
    wil::unique_handle snap{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snap || snap.get() == INVALID_HANDLE_VALUE) {
        snap.release();
        return out;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap.get(), &pe)) {
        do {
            out.push_back(LiveProc{pe.th32ProcessID, pe.th32ParentProcessID, svc::WideToUtf8(pe.szExeFile)});
        } while (::Process32NextW(snap.get(), &pe));
    }
    return out;
}

// 找出「父 PID 在 known 集合中、且建立時間不早於父程序」的新程序（父 PID 可能已被重用，需以時間排除）。
std::vector<model::ProcessRef> FindNewDescendants(const std::vector<model::ProcessRef>& known)
{
    std::unordered_set<uint32_t> knownPids;
    for (const auto& k : known) knownPids.insert(k.pid);

    std::vector<model::ProcessRef> found;
    const auto procs = SnapshotProcesses();
    // 反覆擴張直到不再新增（處理孫程序）
    bool grew = true;
    while (grew) {
        grew = false;
        for (const auto& p : procs) {
            if (knownPids.contains(p.pid) || !knownPids.contains(p.ppid)) continue;
            wil::unique_handle h{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid)};
            if (!h) continue;
            FILETIME c{}, e{}, k{}, u{};
            if (!::GetProcessTimes(h.get(), &c, &e, &k, &u)) continue;
            const int64_t start = svc::FileTimeToUnixMs(c);

            // 父程序建立時間（若父在 known 中有記錄）
            int64_t parentStart = 0;
            for (const auto& kk : known)
                if (kk.pid == p.ppid) parentStart = kk.startTsMs;
            for (const auto& ff : found)
                if (ff.pid == p.ppid) parentStart = ff.startTsMs;
            if (parentStart != 0 && start + kStartTimeToleranceMs < parentStart) continue;   // 父 PID 已被重用

            wchar_t buf[32768];
            DWORD size = static_cast<DWORD>(std::size(buf));
            std::string image = ::QueryFullProcessImageNameW(h.get(), 0, buf, &size)
                                    ? svc::WideToUtf8(std::wstring_view(buf, size))
                                    : p.exe;
            model::ProcessRef ref;
            ref.pid = p.pid;
            ref.startTsMs = start;
            ref.image = std::move(image);
            ref.depth = 99;
            found.push_back(std::move(ref));
            knownPids.insert(p.pid);
            grew = true;
        }
    }
    return found;
}

} // namespace

// ------------------------------------------------------------
// 共用工具
// ------------------------------------------------------------
bool IsCriticalProcess(const model::ProcessRef& ref) noexcept
{
    if (ref.pid <= 4) return true;
    if (ref.pid == ::GetCurrentProcessId()) return true;
    const auto base = BaseNameLower(ref.image);
    for (auto c : kCriticalImages)
        if (base == c) return true;
    return false;
}

std::string InteractiveWarning(const model::ProcessRef& ref)
{
    const auto base = BaseNameLower(ref.image);
    for (auto c : kInteractiveImages) {
        if (base == c) {
            if (base == "explorer.exe") return "Windows 檔案總管 / 桌面殼層，處置將使桌面短暫消失";
            return "互動式應用程式，處置將導致使用者未存檔的工作遺失";
        }
    }
    return {};
}

ProbeResult ProbeProcess(const model::ProcessRef& ref, uint32_t desiredAccess)
{
    wil::unique_handle h;
    return OpenVerified(ref, desiredAccess, h);
}

// ------------------------------------------------------------
// SuspendProcessAction
// ------------------------------------------------------------
Status SuspendProcessAction::Init()
{
    if (!Nt().suspend || !Nt().resume)
        return MakeError(ErrorCode::Unsupported, "NtSuspendProcess/NtResumeProcess unavailable");
    return Ok();
}

Result<ActionImpact> SuspendProcessAction::Prepare(const ActionContext& ctx)
{
    if (!ctx.target || ctx.target->processes.empty())
        return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "suspend_process requires target processes");
    ActionImpact impact;
    for (const auto& ref : ctx.target->processes) {
        const auto pr = ProbeProcess(ref, PROCESS_SUSPEND_RESUME);
        auto item = ImpactFor(ref, pr);
        if (item.protectedTarget) ++impact.protectedCount;
        impact.items.push_back(std::move(item));
    }
    impact.totalCount = static_cast<int>(impact.items.size());
    return impact;
}

std::vector<TargetOutcome> SuspendProcessAction::Execute(const ActionContext& ctx, ActionRecord& record)
{
    std::vector<TargetOutcome> outcomes;
    if (!ctx.target) return outcomes;
    // 前序（根→葉）：先凍結父程序才防得住它在暫停過程中派生新程序
    for (const auto& ref : ctx.target->processes) {
        wil::unique_handle h;
        const auto pr = OpenVerified(ref, PROCESS_SUSPEND_RESUME, h);
        auto o = OutcomeFor(ref, pr);
        if (pr.check == IdentityCheck::Match) {
            if (!Nt().suspend) {
                o.ok = false;
                o.reason = "NtSuspendProcess unavailable";
            } else if (const LONG st = Nt().suspend(h.get()); st < 0) {
                o.ok = false;
                o.win32Error = static_cast<uint32_t>(st);
                o.reason = "suspend failed: " + NtStatusText(st);
            } else {
                o.reason = "suspended";
                record.suspended.push_back(ref);
            }
        }
        outcomes.push_back(std::move(o));
    }
    return outcomes;
}

Result<std::vector<TargetOutcome>> SuspendProcessAction::Revert(const ActionRecord& record)
{
    std::vector<TargetOutcome> outcomes;
    // 還原順序：葉→根（與暫停相反），讓子程序先恢復、父程序最後恢復
    for (auto it = record.suspended.rbegin(); it != record.suspended.rend(); ++it) {
        const auto& ref = *it;
        wil::unique_handle h;
        const auto pr = OpenVerified(ref, PROCESS_SUSPEND_RESUME, h);
        TargetOutcome o{ProcessKey(ref), ProcessLabel(ref), false, pr.win32Error, {}};
        if (pr.check == IdentityCheck::Gone) {
            o.reason = "target gone（程序已結束，無法解除暫停）";
        } else if (pr.check != IdentityCheck::Match) {
            o = OutcomeFor(ref, pr);
            o.ok = false;
        } else if (const LONG st = Nt().resume ? Nt().resume(h.get()) : -1; st < 0) {
            o.win32Error = static_cast<uint32_t>(st);
            o.reason = "resume failed: " + NtStatusText(st);
        } else {
            o.ok = true;
            o.reason = "resumed";
        }
        outcomes.push_back(std::move(o));
    }
    return outcomes;
}

// ------------------------------------------------------------
// TerminateTreeAction
// ------------------------------------------------------------
Status TerminateTreeAction::Init()
{
    if (!Nt().suspend) return MakeError(ErrorCode::Unsupported, "NtSuspendProcess unavailable");
    return Ok();
}

Result<ActionImpact> TerminateTreeAction::Prepare(const ActionContext& ctx)
{
    if (!ctx.target || ctx.target->processes.empty())
        return MakeReject(ErrorCode::InvalidArgument, "INVALID_TARGET", "terminate_process_tree requires target processes");
    ActionImpact impact;
    for (const auto& ref : ctx.target->processes) {
        const auto pr = ProbeProcess(ref, PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
        auto item = ImpactFor(ref, pr);
        if (item.protectedTarget) ++impact.protectedCount;
        impact.items.push_back(std::move(item));
    }
    for (auto& extra : FindNewDescendants(ctx.target->processes)) {
        const auto pr = ProbeProcess(extra, PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
        auto item = ImpactFor(extra, pr);
        if (item.warning.empty()) {
            item.warning = "快照後新派生的子程序";
            item.warningLevel = "medium";
        }
        if (item.protectedTarget) ++impact.protectedCount;
        impact.items.push_back(std::move(item));
    }
    impact.totalCount = static_cast<int>(impact.items.size());
    impact.typedExpected = BaseNameLower(ctx.target->processes.front().image);
    impact.warnings.push_back("終止程序樹不可逆，已終止的程序無法復原");
    return impact;
}

std::vector<TargetOutcome> TerminateTreeAction::Execute(const ActionContext& ctx, ActionRecord& /*record*/)
{
    struct Member {
        model::ProcessRef  ref;
        wil::unique_handle h;
        TargetOutcome      outcome;
    };
    std::vector<Member> members;
    if (!ctx.target) return {};

    constexpr DWORD kAccess = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | SYNCHRONIZE;

    auto suspendOne = [&](const model::ProcessRef& ref) {
        Member m;
        m.ref = ref;
        const auto pr = OpenVerified(ref, kAccess, m.h);
        m.outcome = OutcomeFor(ref, pr);
        if (pr.check == IdentityCheck::Match && Nt().suspend) {
            if (const LONG st = Nt().suspend(m.h.get()); st < 0) {
                // 暫停失敗仍嘗試終止（終止才是目的）
                m.outcome.reason = "suspend failed (" + NtStatusText(st) + "), will still terminate";
            }
        }
        members.push_back(std::move(m));
    };

    // 階段 1：根→葉全樹暫停
    for (const auto& ref : ctx.target->processes) suspendOne(ref);

    // 階段 2：補抓暫停期間新派生的程序（≤ 3 輪）
    bool stillGrowing = false;
    for (int round = 0; round < 3; ++round) {
        std::vector<model::ProcessRef> known;
        known.reserve(members.size());
        for (const auto& m : members) known.push_back(m.ref);
        auto extra = FindNewDescendants(known);
        if (extra.empty()) {
            stillGrowing = false;
            break;
        }
        stillGrowing = true;
        for (const auto& e : extra) suspendOne(e);
    }

    // 階段 3：葉→根終止（前序的反向即「後代先於祖先」）
    for (auto it = members.rbegin(); it != members.rend(); ++it) {
        auto& m = *it;
        if (!m.h) continue;   // 未通過身分驗證或已結束：outcome 已由 OutcomeFor 決定
        if (!::TerminateProcess(m.h.get(), kCairnTerminateExitCode)) {
            const DWORD err = ::GetLastError();
            m.outcome.ok = false;
            m.outcome.win32Error = err;
            m.outcome.reason = err == ERROR_ACCESS_DENIED
                                   ? "protected process（拒絕存取，程序可能受 Windows 保護）"
                                   : "TerminateProcess failed: " + svc::LastErrorMessage(err);
        }
    }

    // 階段 4：等待確認（TerminateProcess 為非同步）
    std::vector<TargetOutcome> outcomes;
    outcomes.reserve(members.size() + 1);
    for (auto& m : members) {
        if (m.h && m.outcome.ok) {
            const DWORD w = ::WaitForSingleObject(m.h.get(), 2000);
            if (w == WAIT_OBJECT_0) {
                m.outcome.reason = "terminated";
            } else {
                m.outcome.ok = false;
                m.outcome.reason = "terminate issued but process still alive after 2s";
            }
        }
        outcomes.push_back(std::move(m.outcome));
    }
    if (stillGrowing) {
        outcomes.push_back(TargetOutcome{"tree", "新派生程序", false, 0,
                                         "process tree still growing after 3 re-enumeration rounds"});
    }
    return outcomes;
}

Result<std::vector<TargetOutcome>> TerminateTreeAction::Revert(const ActionRecord& /*record*/)
{
    return MakeReject(ErrorCode::ActionNotAllowed, "NOT_REVERSIBLE", "terminate_process_tree is irreversible");
}

} // namespace cairn::response
