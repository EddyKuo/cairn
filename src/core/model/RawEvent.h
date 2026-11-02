// src/core/model/RawEvent.h                   namespace cairn::model
// T1（OS 回呼）→ T2（Normalizer）之間傳遞的原始事件：只有 EvtRender 出來的 XML。
// T1 只做 memcpy，零解析（part2 §2.1.2）。
#pragma once
#include <chrono>
#include <cstdint>
#include <string>

#include "base/EventPriority.h"
#include "model/EventType.h"

namespace cairn::model {

struct RawEvent {
    EventSourceKind kind     = EventSourceKind::Sysmon;
    uint16_t        eventId  = 0;                     // 由來源端從 System/EventID 快速取得（或 0 = 待 Normalizer 判定）
    cairn::EventPriority priority = cairn::EventPriority::Normal;   // 來源端以 PriorityOfEid 指定
    std::chrono::steady_clock::time_point recvTime{};
    std::string     xml;                              // EvtRender(EvtRenderEventXml) 結果，已由 UTF-16 轉 UTF-8
};

} // namespace cairn::model
