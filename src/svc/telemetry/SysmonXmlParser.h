// src/svc/telemetry/SysmonXmlParser.h         namespace cairn::telemetry
// Sysmon / PowerShell 4104 / Security 4688 的 XML → NormalizedEvent（實作 IEventNormalizer）。
//
// ★ 可攜程式碼：不 include <windows.h>。可在非 Windows 開發機做語法檢查與單元測試。
//
// 執行緒親和性：只由 NormalizerThread（T2）呼叫 —— 它是 StringInterner 的唯一寫者，
// 且 4688 合成 GUID 的 pid → guid 對照表為本物件的可變狀態（無鎖）。
//
// 字串正規化（StringInterner.h 的約定）：image / parentImage / user / signer / targetImage
// 一律 InternLower（Windows 路徑比對不分大小寫）；interner 飽和時 id 為 kInvalidInternId，
// 改把**小寫化後**的字串放進對應的 *Fallback 欄位，規則求值以字串比對退路，只損失效能不損失偵測。
// 攻擊者可控的高熵欄位（commandLine / scriptBlock / targetFilename …）保留原始大小寫、絕不駐留。
#pragma once
#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "base/IEventSource.h"
#include "model/StringInterner.h"

namespace cairn::telemetry {

class EventXmlView;

class SysmonXmlParser final : public IEventNormalizer {
public:
    struct Options {
        bool   keepRawXml       = false;   // 除錯用：把原始 XML 存入 NormalizedEvent::rawXml
        size_t maxScriptBlock   = 256 * 1024;   // 4104 腳本內容上限（超過截斷，保護記憶體）
        size_t maxCommandLine   = 32 * 1024;    // Windows 命令列上限約 32K 字元
        size_t maxSyntheticPids = 65536;        // 4688 合成 GUID 對照表上限
    };

    explicit SysmonXmlParser(model::StringInterner& interner) : SysmonXmlParser(interner, Options{}) {}
    SysmonXmlParser(model::StringInterner& interner, Options opt);

    [[nodiscard]] bool CanHandle(model::EventSourceKind) const noexcept override { return true; }

    // 失敗碼：MalformedEventXml（結構無法掃描 / EID 不支援 / 必要欄位缺失）。
    // 失敗時 out 的內容未定義，呼叫端應丟棄。
    [[nodiscard]] Status Normalize(const model::RawEvent& raw, model::NormalizedEvent& out) override;

    // 統計（只由 T2 寫，供健康度讀取時容忍短暫不一致）
    [[nodiscard]] uint64_t ParseFailures() const noexcept { return m_parseFailures; }
    [[nodiscard]] uint64_t UnsupportedEids() const noexcept { return m_unsupported; }

    // 4688 降級路徑的合成 ProcessGuid：無 Sysmon 時以 (PID, 建立時間) 為合成鍵（SDD-01 §3.2.4）。
    // 位元組佈局：[0..3]=0xCA 0x1E 0x46 0x88 標記，[4..7]=pid（LE），[8..15]=建立時間 ms（LE）。
    // 標記讓 UI / 鑑識人員一眼看出這是合成值而非 Sysmon 的真實 GUID。
    [[nodiscard]] static model::GuidValue SyntheticGuid(uint32_t pid, int64_t createMs) noexcept;

private:
    Status MapSysmon(const EventXmlView& x, model::NormalizedEvent& e);
    Status MapPowerShell4104(const EventXmlView& x, model::NormalizedEvent& e);
    Status MapSecurity4688(const EventXmlView& x, model::NormalizedEvent& e);

    // InternLower + 飽和退路。回傳 id；飽和時把小寫字串寫入 fallback。
    model::InternId InternPath(std::string_view s, std::optional<std::string>& fallback);

    model::StringInterner& m_interner;
    Options                m_opt;
    uint64_t               m_parseFailures = 0;
    uint64_t               m_unsupported   = 0;
    // 4688：pid → 最近一次看到的合成 GUID（讓子程序能找到父程序的合成 GUID）
    std::unordered_map<uint32_t, model::GuidValue> m_syntheticByPid;
};

} // namespace cairn::telemetry
