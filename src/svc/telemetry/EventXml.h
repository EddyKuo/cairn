// src/svc/telemetry/EventXml.h                namespace cairn::telemetry
// EvtRender(EvtRenderEventXml) 輸出的單趟 pull 掃描器（SDD-01 §3.5「不建 DOM，單趟掃描」）。
//
// ★ 可攜程式碼：不 include <windows.h>，純字串處理 —— 可在非 Windows 開發機做語法檢查與單元測試。
//
// 為何不引入 XML 函式庫（SDD-01 附錄 B-1 的決定）：Windows 事件 XML 的結構是固定的
//   <Event><System>…</System><EventData><Data Name='X'>v</Data>…</EventData></Event>
// 只需要 System 下的少數欄位與 EventData 的 name/value 對。單趟掃描、零 DOM 配置，
// 值的 entity 解碼只在呼叫端真的取用該欄位時才做（大部分欄位不會被取用）。
//
// 容錯原則：輸入是 OS 渲染的 XML，但欄位值（命令列、檔名）是攻擊者可控字串。
// 掃描器對任何畸形輸入都必須「回傳失敗或空值」，絕不越界讀取、絕不無限迴圈。
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cairn::telemetry {

// XML 預定義 entity 與數字字元參照（&#NN; / &#xHH;）解碼。數字參照輸出為 UTF-8。
// 不認得的 entity 原樣保留（不丟字元：寧可顯示 &foo; 也不要讓證據消失）。
[[nodiscard]] std::string DecodeXmlEntities(std::string_view raw);

// 一次掃描後的事件視圖。所有 string_view 指向傳入的 xml 緩衝，呼叫端須保證其生命週期。
class EventXmlView {
public:
    struct DataField {
        std::string_view name;   // Data 的 Name 屬性（不含引號）
        std::string_view raw;    // 未解碼的值；<Data Name='X'/> 時為空
    };

    // 掃描失敗（找不到 <Event 或 </Event> 結構破損）回傳 nullopt。
    [[nodiscard]] static std::optional<EventXmlView> Parse(std::string_view xml);

    [[nodiscard]] uint16_t         EventId() const noexcept { return m_eventId; }
    [[nodiscard]] std::string_view ProviderName() const noexcept { return m_provider; }
    [[nodiscard]] std::string_view Channel() const noexcept { return m_channel; }
    [[nodiscard]] std::string_view Computer() const noexcept { return m_computer; }
    [[nodiscard]] std::string_view SystemTime() const noexcept { return m_systemTime; }   // ISO-8601
    [[nodiscard]] uint32_t         ExecutionProcessId() const noexcept { return m_execPid; }
    [[nodiscard]] uint64_t         EventRecordId() const noexcept { return m_recordId; }
    [[nodiscard]] std::string_view SecurityUserId() const noexcept { return m_userSid; }

    // 依 Name 取未解碼值。Name 比對大小寫不敏感（Sysmon EID 10 用 SourceProcessGUID，其他用 Guid）。
    [[nodiscard]] std::optional<std::string_view> RawField(std::string_view name) const noexcept;

    // 取解碼後的值；欄位不存在或值為空 / "-"（Sysmon 的空值慣例）回傳 nullopt。
    [[nodiscard]] std::optional<std::string> Field(std::string_view name) const;

    [[nodiscard]] const std::vector<DataField>& Fields() const noexcept { return m_fields; }

private:
    uint16_t         m_eventId  = 0;
    uint32_t         m_execPid  = 0;
    uint64_t         m_recordId = 0;
    std::string_view m_provider;
    std::string_view m_channel;
    std::string_view m_computer;
    std::string_view m_systemTime;
    std::string_view m_userSid;
    std::vector<DataField> m_fields;
};

// 快速取出 EventID，不做完整掃描（給 OS 回呼執行緒用：只為決定 Priority）。
// 找不到回 0。成本：一次 find。
[[nodiscard]] uint16_t PeekEventId(std::string_view xml) noexcept;
// UTF-16 版本，讓回呼執行緒在轉碼前就能決定 Priority（wchar_t 在 Windows 為 UTF-16）。
[[nodiscard]] uint16_t PeekEventIdW(std::wstring_view xml) noexcept;

// ---- 時間解析 ----
// Sysmon UtcTime："2026-08-19 06:22:01.220"；System/TimeCreated：ISO-8601 "2026-08-19T06:22:01.2201234Z"
// 回傳 Unix epoch 毫秒；格式不符回傳 nullopt。不依賴 timegm / _mkgmtime（可攜且無時區副作用）。
[[nodiscard]] std::optional<int64_t> ParseUtcTimeMs(std::string_view s) noexcept;

// ---- 數值解析 ----
// 十進位或 0x 前綴十六進位。失敗回 nullopt。
[[nodiscard]] std::optional<uint64_t> ParseUInt(std::string_view s) noexcept;

// Sysmon Hashes 欄位："SHA1=..,MD5=..,SHA256=..,IMPHASH=.." 或單一 "SHA256=..."，取出 SHA256（轉大寫）。
[[nodiscard]] std::string ExtractSha256(std::string_view hashes);

} // namespace cairn::telemetry
