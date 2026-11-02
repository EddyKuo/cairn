// src/svc/response/Sha256.h                   namespace cairn::response
// 可攜的 SHA-256（FIPS 180-4）。用於 impactHash、隔離檔雜湊與還原比對。
// 刻意不用 CNG：此檔需在非 Windows 開發機上通過語法檢查，且 impactHash 的
// 計算必須與 ConfirmationTokenStore 的單元測試完全一致（不依賴 OS）。
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace cairn::response {

class Sha256 {
public:
    Sha256() noexcept { Reset(); }
    void Reset() noexcept;
    void Update(const void* data, size_t len) noexcept;
    void Update(std::string_view s) noexcept { Update(s.data(), s.size()); }
    [[nodiscard]] std::array<uint8_t, 32> Final() noexcept;

    // 便利函式：一次性計算，回傳 64 字元小寫十六進位
    [[nodiscard]] static std::string HexOf(const void* data, size_t len);
    [[nodiscard]] static std::string HexOf(std::string_view s) { return HexOf(s.data(), s.size()); }
    [[nodiscard]] static std::string ToHex(const std::array<uint8_t, 32>& digest);

private:
    void Transform(const uint8_t* block) noexcept;

    std::array<uint32_t, 8> m_state{};
    std::array<uint8_t, 64> m_buffer{};
    uint64_t                m_bitLen = 0;
    size_t                  m_bufLen = 0;
};

} // namespace cairn::response
