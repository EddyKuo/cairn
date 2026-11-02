// src/svc/rpc/Framing.h                       namespace cairn::rpc
// 4-byte little-endian 長度前綴框架（CONVENTIONS C-2.3、SDD-03 §9.4.2）。
// 純位元組處理、不含 Win32，可在任何平台單元測試（JsonRpcFramingTests）。
//
// +--------+------------------------+
// | len(4) |  JSON-RPC payload      |
// | LE u32 |  UTF-8, len bytes      |
// +--------+------------------------+
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cairn::rpc {

inline constexpr uint32_t kMaxMessageBytes = 1u << 20;   // 1 MiB（超限：不讀 body、回錯誤、關連線）

// 編碼：回傳「長度前綴 + payload」。payload 超過上限時回 nullopt。
[[nodiscard]] std::optional<std::string> EncodeFrame(std::string_view payload);

// 增量解碼器：Byte 模式管線不保證一次讀完，也可能一次讀到多則（黏包）。
// 用法：每次讀到資料就 Feed()，然後反覆 Next() 直到回 nullopt。
class FrameDecoder {
public:
    enum class State { NeedMore, Ready, TooLarge };

    void Feed(std::span<const uint8_t> bytes);
    void Feed(std::string_view bytes);

    // 取出下一則完整訊息；資料不足時回 nullopt。
    // 一旦遇到超限長度，狀態永久變為 TooLarge（呼叫端必須回錯誤並關閉連線）。
    [[nodiscard]] std::optional<std::string> Next();

    [[nodiscard]] State GetState() const noexcept { return m_state; }
    [[nodiscard]] size_t Buffered() const noexcept { return m_buf.size() - m_pos; }

private:
    std::vector<uint8_t> m_buf;
    size_t               m_pos   = 0;
    State                m_state = State::NeedMore;
};

} // namespace cairn::rpc
