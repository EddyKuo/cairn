#include "telemetry/ProcessSnapshot.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <unordered_map>

#include <wil/resource.h>

#include "common/WinUtil.h"

namespace cairn::telemetry {

model::GuidValue SnapshotGuid(uint32_t pid, int64_t createMs) noexcept
{
    model::GuidValue g;
    g.bytes[0] = 0xCA;
    g.bytes[1] = 0x1E;
    g.bytes[2] = 0x5A;
    g.bytes[3] = 0x9E;
    for (int i = 0; i < 4; ++i) g.bytes[4 + i] = static_cast<uint8_t>((pid >> (8 * i)) & 0xFF);
    const auto t = static_cast<uint64_t>(createMs);
    for (int i = 0; i < 8; ++i) g.bytes[8 + i] = static_cast<uint8_t>((t >> (8 * i)) & 0xFF);
    return g;
}

Result<std::vector<SnapshotProcess>> TakeProcessSnapshot()
{
    wil::unique_handle snap{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snap || snap.get() == INVALID_HANDLE_VALUE) {
        (void)snap.release();   // INVALID_HANDLE_VALUE 不可 CloseHandle
        return svc::Win32Error(ErrorCode::IoError, "CreateToolhelp32Snapshot");
    }

    std::vector<SnapshotProcess> out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!::Process32FirstW(snap.get(), &pe)) return svc::Win32Error(ErrorCode::IoError, "Process32FirstW");
    do {
        SnapshotProcess p;
        p.pid       = pe.th32ProcessID;
        p.parentPid = pe.th32ParentProcessID;
        p.exeName   = svc::WideToUtf8(pe.szExeFile);
        DWORD sid = 0;
        if (::ProcessIdToSessionId(p.pid, &sid)) p.sessionId = sid;

        if (p.pid != 0) {
            wil::unique_handle h{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid)};
            if (h) {
                FILETIME c{}, e{}, k{}, u{};
                if (::GetProcessTimes(h.get(), &c, &e, &k, &u)) p.createMs = svc::FileTimeToUnixMs(c);
                wchar_t path[MAX_PATH * 2]{};
                DWORD   len = static_cast<DWORD>(std::size(path));
                if (::QueryFullProcessImageNameW(h.get(), 0, path, &len)) p.imagePath = svc::WideToUtf8({path, len});
            }
        }
        if (p.imagePath.empty()) p.imagePath = p.exeName;   // 受保護程序（PPL）只拿得到檔名
        p.syntheticGuid = SnapshotGuid(p.pid, p.createMs);
        out.push_back(std::move(p));
    } while (::Process32NextW(snap.get(), &pe));
    return out;
}

std::vector<model::NormalizedEvent> ToSyntheticEvents(const std::vector<SnapshotProcess>& procs,
                                                     model::StringInterner& interner)
{
    std::unordered_map<uint32_t, const SnapshotProcess*> byPid;
    for (const auto& p : procs) byPid[p.pid] = &p;

    // 父先子後：依建立時間排序（父程序必然較早建立；建立時間未知者排最前，當作根）
    std::vector<const SnapshotProcess*> order;
    order.reserve(procs.size());
    for (const auto& p : procs) order.push_back(&p);
    std::stable_sort(order.begin(), order.end(),
                     [](const SnapshotProcess* a, const SnapshotProcess* b) { return a->createMs < b->createMs; });

    const auto now = std::chrono::system_clock::now();
    std::vector<model::NormalizedEvent> events;
    events.reserve(order.size());
    for (const SnapshotProcess* p : order) {
        model::NormalizedEvent e;
        e.time          = p->createMs > 0 ? std::chrono::system_clock::time_point{std::chrono::milliseconds{p->createMs}}
                                          : now;
        e.recvTime      = std::chrono::steady_clock::now();
        e.source        = model::EventSourceKind::Sysmon;
        e.sourceEventId = 0;   // 0 = 啟動快照合成，非真實 Sysmon 事件
        e.type          = model::EventType::ProcessCreate;
        e.priority      = EventPriority::High;
        e.processGuid   = p->syntheticGuid;
        e.pid           = p->pid;
        e.parentPid     = p->parentPid;
        // 父程序必須存在且建立時間不晚於子程序，否則視為 PID 重用 → 不掛載（自成一根）
        if (auto it = byPid.find(p->parentPid); it != byPid.end() && it->second != p &&
                                                 (it->second->createMs <= p->createMs || p->createMs == 0)) {
            e.parentProcessGuid = it->second->syntheticGuid;
            e.parentImage = interner.InternLower(it->second->imagePath);
            if (e.parentImage == model::kInvalidInternId) e.parentImageFallback = model::ToLowerAscii(it->second->imagePath);
        }
        e.image = interner.InternLower(p->imagePath);
        if (e.image == model::kInvalidInternId) e.imageFallback = model::ToLowerAscii(p->imagePath);
        events.push_back(std::move(e));
    }
    return events;
}

} // namespace cairn::telemetry
