// src/core/model/ResponseCommand.h            namespace cairn::model
// 回應指令（SDD-01 §2.4 L-2：ResponseCommand 置於 core.common，避免 core.rpc 橫向相依 core.response）。
// 來源：AnalysisThread 自動觸發（分數 >= 95 或 deterministic）／RPC response.execute 人工觸發。
// 執行：一律投遞到 T6 ResponseExecutor（INetFwPolicy2 / CNG 是數百 ms 級 I/O，絕不可放在 T3）。
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "model/Domain.h"
#include "model/GuidValue.h"

namespace cairn::model {

// 程序身分：PID 會被重用，執行動作前必須以 (pid, 建立時間, 映像路徑) 驗證身分（W3-2 PID 身分驗證）。
struct ProcessRef {
    GuidValue   processGuid{};
    uint32_t    pid = 0;
    int64_t     startTsMs = 0;      // 程序建立時間（Sysmon UtcTime），與 GetProcessTimes 比對
    std::string image;              // 完整路徑（原始大小寫）
    int32_t     depth = 0;
};

struct ResponseTarget {
    // suspend_process / terminate_process_tree：根 → 葉的前序走訪順序（暫停時先凍結父程序）
    std::vector<ProcessRef>    processes;
    std::optional<std::string> filePath;   // quarantine_file
    std::optional<std::string> ip;         // firewall_block
    std::optional<uint16_t>    port;

    // 供 ConfirmationTokenStore 綁定用的穩定鍵（例如 "pid:1234@1700000000000" / "file:C:\\x.exe" / "ip:1.2.3.4"）
    std::string key;
};

struct ResponseCommand {
    int64_t        alertId = 0;
    ActionKind     action  = ActionKind::SuspendProcess;
    ResponseTarget target;
    GuidValue      rootProcessGuid{};
    std::string    actor  = "rule_engine";  // rule_engine | analyst | system
    std::string    reason;
    bool           automatic = false;       // true = AnalysisThread 依規則自動觸發
};

// 自動回應的出口：AnalysisEngine 透過此介面把指令交給 svc（svc 再投遞到 T6）。
class IResponseSink {
public:
    virtual ~IResponseSink() = default;
    virtual void Submit(ResponseCommand&& cmd) = 0;   // 非阻塞
};

} // namespace cairn::model
