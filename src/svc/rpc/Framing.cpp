#include "rpc/Framing.h"

namespace cairn::rpc {

std::optional<std::string> EncodeFrame(std::string_view payload)
{
    if (payload.size() > kMaxMessageBytes) return std::nullopt;
    const auto n = static_cast<uint32_t>(payload.size());
    std::string out;
    out.reserve(4 + payload.size());
    out.push_back(static_cast<char>(n & 0xFF));
    out.push_back(static_cast<char>((n >> 8) & 0xFF));
    out.push_back(static_cast<char>((n >> 16) & 0xFF));
    out.push_back(static_cast<char>((n >> 24) & 0xFF));
    out.append(payload);
    return out;
}

void FrameDecoder::Feed(std::span<const uint8_t> bytes)
{
    if (m_state == State::TooLarge) return;
    // 壓縮已消費的前段，避免緩衝區無限成長
    if (m_pos > 0 && m_pos >= m_buf.size() / 2) {
        m_buf.erase(m_buf.begin(), m_buf.begin() + static_cast<std::ptrdiff_t>(m_pos));
        m_pos = 0;
    }
    m_buf.insert(m_buf.end(), bytes.begin(), bytes.end());
}

void FrameDecoder::Feed(std::string_view bytes)
{
    Feed(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()));
}

std::optional<std::string> FrameDecoder::Next()
{
    if (m_state == State::TooLarge) return std::nullopt;
    const size_t avail = m_buf.size() - m_pos;
    if (avail < 4) {
        m_state = State::NeedMore;
        return std::nullopt;
    }
    const uint32_t len = static_cast<uint32_t>(m_buf[m_pos]) | (static_cast<uint32_t>(m_buf[m_pos + 1]) << 8) |
                         (static_cast<uint32_t>(m_buf[m_pos + 2]) << 16) |
                         (static_cast<uint32_t>(m_buf[m_pos + 3]) << 24);
    if (len > kMaxMessageBytes) {
        // 不讀 body：繼續讀會讓攻擊者以 4 bytes 標頭誘使我們配置任意記憶體
        m_state = State::TooLarge;
        m_buf.clear();
        m_pos = 0;
        return std::nullopt;
    }
    if (avail - 4 < len) {
        m_state = State::NeedMore;
        return std::nullopt;
    }
    std::string msg(reinterpret_cast<const char*>(m_buf.data() + m_pos + 4), len);
    m_pos += 4 + len;
    m_state = (m_buf.size() - m_pos) >= 4 ? State::Ready : State::NeedMore;
    return msg;
}

} // namespace cairn::rpc
