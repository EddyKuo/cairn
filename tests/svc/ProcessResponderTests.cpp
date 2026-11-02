// tests/svc/ProcessResponderTests.cpp
// suspend_process / terminate_process_tree 與 PID 身分驗證（W3-2）。
// 自行建立 cmd.exe 子程序作為目標，不需管理員。
//   ⚠ 目標用 `ping -n 30 127.0.0.1` 而非 `timeout /t`：timeout 在 stdin 被重導（無主控台）時立即失敗退出。
#include <gtest/gtest.h>

#include <windows.h>

#include <string>
#include <vector>

#include "common/WinUtil.h"
#include "response/ProcessResponder.h"

using namespace cairn;
using namespace cairn::response;

namespace {

class ChildProcess {
public:
    ChildProcess()
    {
        std::wstring cmd = L"cmd.exe /c ping -n 30 127.0.0.1 >nul";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        if (::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si,
                             &m_pi)) {
            ::CloseHandle(m_pi.hThread);
            m_pi.hThread = nullptr;
            ::Sleep(500);   // 讓 cmd 派生 ping 子程序（終止樹測試要抓到它）
        }
    }
    ~ChildProcess()
    {
        if (m_pi.hProcess) {
            ::TerminateProcess(m_pi.hProcess, 0);
            ::WaitForSingleObject(m_pi.hProcess, 2000);
            ::CloseHandle(m_pi.hProcess);
        }
    }
    [[nodiscard]] bool Ok() const { return m_pi.hProcess != nullptr; }
    [[nodiscard]] HANDLE Handle() const { return m_pi.hProcess; }

    [[nodiscard]] model::ProcessRef Ref() const
    {
        model::ProcessRef r;
        r.pid = m_pi.dwProcessId;
        FILETIME c{}, e{}, k{}, u{};
        ::GetProcessTimes(m_pi.hProcess, &c, &e, &k, &u);
        r.startTsMs = svc::FileTimeToUnixMs(c);
        wchar_t buf[MAX_PATH * 2];
        DWORD size = MAX_PATH * 2;
        if (::QueryFullProcessImageNameW(m_pi.hProcess, 0, buf, &size)) r.image = svc::WideToUtf8({buf, size});
        if (auto g = model::GuidValue::Parse("{11111111-2222-3333-4444-555555555555}")) r.processGuid = *g;
        return r;
    }

    [[nodiscard]] bool Alive() const { return ::WaitForSingleObject(m_pi.hProcess, 0) == WAIT_TIMEOUT; }

private:
    PROCESS_INFORMATION m_pi{};
};

model::ResponseTarget TargetOf(const model::ProcessRef& r)
{
    model::ResponseTarget t;
    t.processes = {r};
    return t;
}

} // namespace

TEST(ProcessResponder, ProbeMatchesOwnChild)
{
    ChildProcess child;
    ASSERT_TRUE(child.Ok());
    const auto pr = ProbeProcess(child.Ref(), PROCESS_SUSPEND_RESUME);
    EXPECT_EQ(pr.check, IdentityCheck::Match);
}

TEST(ProcessResponder, IdentityMismatchOnWrongStartTimeRefusesToAct)
{
    ChildProcess child;
    ASSERT_TRUE(child.Ok());
    auto ref = child.Ref();
    ref.startTsMs -= 10'000;   // 模擬 PID 被重用：建立時間不符
    EXPECT_EQ(ProbeProcess(ref, PROCESS_SUSPEND_RESUME).check, IdentityCheck::Mismatch);

    SuspendProcessAction action;
    ASSERT_TRUE(action.Init());
    const auto target = TargetOf(ref);
    ActionContext ctx{1, model::ActionKind::SuspendProcess, &target, "test", "test", false};
    ActionRecord rec;
    const auto out = action.Execute(ctx, rec);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_FALSE(out[0].ok);
    EXPECT_TRUE(rec.suspended.empty()) << "身分不符絕不可動作";
}

TEST(ProcessResponder, IdentityMismatchOnWrongImage)
{
    ChildProcess child;
    ASSERT_TRUE(child.Ok());
    auto ref = child.Ref();
    ref.image = "C:\\Windows\\System32\\notepad.exe";
    EXPECT_EQ(ProbeProcess(ref, PROCESS_SUSPEND_RESUME).check, IdentityCheck::Mismatch);
}

TEST(ProcessResponder, SuspendThenRevertResumes)
{
    ChildProcess child;
    ASSERT_TRUE(child.Ok());
    SuspendProcessAction action;
    ASSERT_TRUE(action.Init());
    const auto target = TargetOf(child.Ref());
    ActionContext ctx{1, model::ActionKind::SuspendProcess, &target, "test", "test", false};

    auto impact = action.Prepare(ctx);
    ASSERT_TRUE(impact);
    EXPECT_EQ(impact.Value().totalCount, 1);

    ActionRecord rec;
    const auto out = action.Execute(ctx, rec);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_TRUE(out[0].ok) << out[0].reason;
    ASSERT_EQ(rec.suspended.size(), 1u);
    EXPECT_TRUE(child.Alive());

    auto rev = action.Revert(rec);
    ASSERT_TRUE(rev);
    ASSERT_EQ(rev.Value().size(), 1u);
    EXPECT_TRUE(rev.Value()[0].ok) << rev.Value()[0].reason;
}

TEST(ProcessResponder, TerminateTreeKillsRootAndDescendants)
{
    ChildProcess child;
    ASSERT_TRUE(child.Ok());
    TerminateTreeAction action;
    ASSERT_TRUE(action.Init());
    const auto target = TargetOf(child.Ref());
    ActionContext ctx{1, model::ActionKind::TerminateProcessTree, &target, "test", "test", false};

    auto impact = action.Prepare(ctx);
    ASSERT_TRUE(impact);
    EXPECT_EQ(impact.Value().typedExpected, "cmd.exe");
    EXPECT_GE(impact.Value().totalCount, 2) << "Prepare 應列出快照未包含的 ping.exe 子程序";

    ActionRecord rec;
    const auto out = action.Execute(ctx, rec);
    ASSERT_GE(out.size(), 2u);
    for (const auto& o : out) EXPECT_TRUE(o.ok) << o.label << ": " << o.reason;

    EXPECT_EQ(::WaitForSingleObject(child.Handle(), 0), WAIT_OBJECT_0);
    DWORD code = 0;
    ::GetExitCodeProcess(child.Handle(), &code);
    EXPECT_EQ(code, kCairnTerminateExitCode);

    EXPECT_FALSE(action.Revert(rec)) << "terminate_process_tree 不可逆";
}

TEST(ProcessResponder, GoneTargetIsTreatedAsSuccess)
{
    model::ProcessRef ref;
    {
        ChildProcess child;
        ASSERT_TRUE(child.Ok());
        ref = child.Ref();
    }   // 解構時終止
    ::Sleep(200);
    SuspendProcessAction action;
    ASSERT_TRUE(action.Init());
    const auto target = TargetOf(ref);
    ActionContext ctx{1, model::ActionKind::SuspendProcess, &target, "test", "test", false};
    ActionRecord rec;
    const auto out = action.Execute(ctx, rec);
    ASSERT_EQ(out.size(), 1u);
    // PID 可能已被系統重用（身分不符 → 拒絕）或確實已不存在（ok=true "already exited"）——兩者都不得動到別的程序
    if (out[0].ok) EXPECT_EQ(out[0].reason, "already exited");
    EXPECT_TRUE(rec.suspended.empty());
}

TEST(ProcessResponder, CriticalProcessesAreRefused)
{
    model::ProcessRef sys;
    sys.pid = 4;
    sys.image = "System";
    EXPECT_TRUE(IsCriticalProcess(sys));
    model::ProcessRef self;
    self.pid = ::GetCurrentProcessId();
    EXPECT_TRUE(IsCriticalProcess(self));
    model::ProcessRef lsass;
    lsass.pid = 1234;
    lsass.image = "C:\\Windows\\System32\\lsass.exe";
    EXPECT_TRUE(IsCriticalProcess(lsass));
    EXPECT_EQ(ProbeProcess(lsass, PROCESS_TERMINATE).check, IdentityCheck::Critical);
}
