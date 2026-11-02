// src/core/base/IClock.h                      namespace cairn
// 時間注入介面 —— 衰減測試不能靠真的等（part4 §4.2）。
// 全系統時間單位：Unix epoch 毫秒（int64），與 DB 欄位 ts 一致。
#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>

namespace cairn {

using UnixMs = int64_t;

[[nodiscard]] inline UnixMs ToUnixMs(std::chrono::system_clock::time_point tp) noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

[[nodiscard]] inline std::chrono::system_clock::time_point FromUnixMs(UnixMs ms) noexcept
{
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{ms}};
}

class IClock {
public:
    virtual ~IClock() = default;
    [[nodiscard]] virtual UnixMs NowMs() const noexcept = 0;              // 牆鐘
    [[nodiscard]] virtual int64_t SteadyMs() const noexcept = 0;          // 單調時鐘（量測延遲用）
};

class SystemClock final : public IClock {
public:
    [[nodiscard]] UnixMs NowMs() const noexcept override { return ToUnixMs(std::chrono::system_clock::now()); }
    [[nodiscard]] int64_t SteadyMs() const noexcept override
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
};

// 測試用：手動推進的時鐘。
class FakeClock final : public IClock {
public:
    explicit FakeClock(UnixMs start = 1'700'000'000'000) : m_now(start), m_steady(0) {}
    [[nodiscard]] UnixMs NowMs() const noexcept override { return m_now.load(); }
    [[nodiscard]] int64_t SteadyMs() const noexcept override { return m_steady.load(); }
    void Advance(int64_t ms) noexcept
    {
        m_now.fetch_add(ms);
        m_steady.fetch_add(ms);
    }
    void Set(UnixMs ms) noexcept { m_now.store(ms); }

private:
    std::atomic<UnixMs>  m_now;
    std::atomic<int64_t> m_steady;
};

} // namespace cairn
