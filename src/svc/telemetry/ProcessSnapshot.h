// src/svc/telemetry/ProcessSnapshot.h         namespace cairn::telemetry
// 服務啟動時列舉既存程序，建立程序樹骨架（part2 §2.4.1「啟動時的樹重建」）。
//
// ⚠ 已知限制（誠實揭露）：Sysmon 的 ProcessGuid 無法由 user-mode 推算，因此既存程序一律使用
//   「合成 GUID」（標記位元組 CA 1E 5A 9E + PID + 建立時間），並以 sourceEventId = 0 表示「快照合成」。
//   後續由這些程序產生的 Sysmon 事件帶的是**真實** ProcessGuid，不會與合成節點對上；
//   合成節點的價值在於：① 提供 PID → 映像路徑的對照（4104 只有 PID）② 讓 UI 能顯示既存程序。
//   真正把事件掛上樹的仍是 SDD-02 §4.2.3 的孤兒暫存區機制。
#pragma once
#ifndef _WIN32
#error "ProcessSnapshot 僅支援 Windows"
#endif

#include <cstdint>
#include <string>
#include <vector>

#include "base/Result.h"
#include "model/NormalizedEvent.h"
#include "model/StringInterner.h"

namespace cairn::telemetry {

struct SnapshotProcess {
    uint32_t    pid       = 0;
    uint32_t    parentPid = 0;
    uint32_t    sessionId = 0;
    int64_t     createMs  = 0;      // GetProcessTimes；取不到（受保護程序）為 0
    std::string imagePath;          // QueryFullProcessImageNameW；取不到時退回 exe 檔名
    std::string exeName;            // PROCESSENTRY32W::szExeFile
    model::GuidValue syntheticGuid{};
};

// 合成 GUID 的佈局：[0..3]=CA 1E 5A 9E，[4..7]=pid（LE），[8..15]=createMs（LE）
[[nodiscard]] model::GuidValue SnapshotGuid(uint32_t pid, int64_t createMs) noexcept;

// CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) + 逐一 OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)。
// 父子以 (parentPid, 父程序建立時間 <= 子程序建立時間) 判定，防 PID 重用造成錯誤掛載。
[[nodiscard]] Result<std::vector<SnapshotProcess>> TakeProcessSnapshot();

// 轉為合成的 ProcessCreate 事件（sourceEventId = 0、priority High），依父先子後排序，
// 交給 AnalysisThread 依一般事件路徑建立骨架節點。image 以 InternLower 駐留。
[[nodiscard]] std::vector<model::NormalizedEvent> ToSyntheticEvents(const std::vector<SnapshotProcess>& procs,
                                                                     model::StringInterner& interner);

} // namespace cairn::telemetry
