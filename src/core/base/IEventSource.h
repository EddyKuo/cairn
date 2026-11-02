// src/core/base/IEventSource.h                namespace cairn::telemetry
// 感測抽象（SDD-01 §3.2.1）。M1 換自有 ETW 消費器時下游不動。
#pragma once
#include <string_view>

#include "base/Result.h"
#include "model/NormalizedEvent.h"
#include "model/RawEvent.h"

namespace cairn::telemetry {

enum class SourceHealth {
    Stopped,
    Healthy,
    Silent,         // 訂閱中但超過 SilentThreshold 沒有任何事件（可疑）
    Reconnecting,
    Failed,
};

// 原始事件的接收端。多個 source 會併發呼叫，實作必須 lock-free 且不得阻塞。
class IRawEventSink {
public:
    virtual ~IRawEventSink() = default;
    // false = 佇列滿且已丟棄。呼叫端不得重試或阻塞。
    [[nodiscard]] virtual bool Push(model::RawEvent&& ev) noexcept = 0;
};

class IEventSource {
public:
    virtual ~IEventSource() = default;
    [[nodiscard]] virtual Status Start(IRawEventSink* sink) = 0;
    // 冪等；阻塞至所有 in-flight 回呼結束後才返回。
    virtual void Stop() noexcept = 0;
    [[nodiscard]] virtual SourceHealth GetHealth() const noexcept = 0;
    [[nodiscard]] virtual std::string_view Name() const noexcept = 0;
    // 最後一次收到事件的 steady 毫秒（Watchdog 的訂閱靜默偵測用）；0 = 從未收到。
    [[nodiscard]] virtual int64_t LastEventSteadyMs() const noexcept = 0;
    // 重新訂閱（Watchdog 偵測到靜默 120 秒時呼叫）。
    [[nodiscard]] virtual Status Resubscribe() = 0;
};

// XML → NormalizedEvent。純字串處理，置於 svc/telemetry 實作但介面在 core。
class IEventNormalizer {
public:
    virtual ~IEventNormalizer() = default;
    [[nodiscard]] virtual bool CanHandle(model::EventSourceKind kind) const noexcept = 0;
    [[nodiscard]] virtual Status Normalize(const model::RawEvent& raw, model::NormalizedEvent& out) = 0;
};

} // namespace cairn::telemetry
