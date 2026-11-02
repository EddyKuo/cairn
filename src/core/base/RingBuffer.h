// src/core/base/RingBuffer.h                  namespace cairn
// MPSC 有界環形佇列（SDD-01 §3.3）。兩個實作共用同一介面：
//   - LockFreeRingBuffer<T,N>：無鎖版本（Vyukov 有界佇列的 MPSC 化）
//   - BoundedQueue<T,N>      ：std::mutex + std::deque 的加鎖版本
// part4 W1-3 的降險路徑：RingBufferTests 以 TYPED_TEST_SUITE 同時對兩者跑；
// 若無鎖版本未在 ASan/TSan 下穩定通過，EventPipeline 以 CAIRN_USE_LOCKED_RING 切換為加鎖版本。
#pragma once
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

#include "base/EventPriority.h"

namespace cairn {

// 分級丟棄門檻：低優先級先被拒收，高優先級一路留到真正滿為止（SDD-01 §3.3.4）。
[[nodiscard]] constexpr uint8_t DropThresholdFor(EventPriority p) noexcept
{
    switch (p) {
    case EventPriority::Low:      return 70;
    case EventPriority::Normal:   return 85;
    case EventPriority::High:     return 95;
    case EventPriority::Critical: return 100;   // 只有真的滿了才丟
    }
    return 100;
}

template <class T, size_t N>
class LockFreeRingBuffer {
    static_assert(std::has_single_bit(N), "N 必須是 2 的冪");
    static constexpr uint64_t kMask = N - 1;

    struct alignas(64) Slot {
        std::atomic<uint64_t> sequence{0};
        T                     value{};
    };

public:
    static constexpr size_t kCapacity = N;

    LockFreeRingBuffer()
    {
        for (uint64_t i = 0; i < N; ++i) m_slots[i].sequence.store(i, std::memory_order_relaxed);
    }
    LockFreeRingBuffer(const LockFreeRingBuffer&) = delete;
    LockFreeRingBuffer& operator=(const LockFreeRingBuffer&) = delete;

    // 多生產者。回傳 false 表示已丟棄（並已計數）。絕不阻塞。
    [[nodiscard]] bool TryPush(T&& value, EventPriority prio) noexcept
    {
        if (DropThresholdFor(prio) < 100 && UsagePercent() >= DropThresholdFor(prio)) {
            m_dropped[static_cast<size_t>(prio)].fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        uint64_t pos = m_head.load(std::memory_order_relaxed);
        for (;;) {
            Slot& slot = m_slots[pos & kMask];
            const uint64_t seq  = slot.sequence.load(std::memory_order_acquire);
            const int64_t  diff = static_cast<int64_t>(seq) - static_cast<int64_t>(pos);

            if (diff == 0) {
                if (m_head.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed,
                                                 std::memory_order_relaxed)) {
                    slot.value = std::move(value);
                    slot.sequence.store(pos + 1, std::memory_order_release);
                    m_pushed.fetch_add(1, std::memory_order_relaxed);
                    return true;
                }
            } else if (diff < 0) {
                m_dropped[static_cast<size_t>(prio)].fetch_add(1, std::memory_order_relaxed);
                return false;
            } else {
                pos = m_head.load(std::memory_order_relaxed);
            }
        }
    }

    // 單消費者專用。
    [[nodiscard]] bool TryPop(T& out) noexcept
    {
        const uint64_t pos  = m_tail.load(std::memory_order_relaxed);
        Slot&          slot = m_slots[pos & kMask];
        const uint64_t seq  = slot.sequence.load(std::memory_order_acquire);
        const int64_t  diff = static_cast<int64_t>(seq) - static_cast<int64_t>(pos + 1);

        if (diff != 0) return false;
        out = std::move(slot.value);
        slot.value = T{};                              // 釋放大字串，避免槽位長期持有記憶體
        m_tail.store(pos + 1, std::memory_order_relaxed);
        slot.sequence.store(pos + N, std::memory_order_release);
        return true;
    }

    [[nodiscard]] size_t SizeApprox() const noexcept
    {
        // 必須先讀 tail 再讀 head，且必須 clamp（SDD-01 §3.3.2 的 ⚠）。
        const uint64_t t = m_tail.load(std::memory_order_acquire);
        const uint64_t h = m_head.load(std::memory_order_acquire);
        return static_cast<size_t>(h > t ? std::min<uint64_t>(h - t, N) : 0);
    }

    [[nodiscard]] uint8_t UsagePercent() const noexcept
    {
        return static_cast<uint8_t>(SizeApprox() * 100 / N);
    }

    [[nodiscard]] uint64_t DroppedCount(EventPriority p) const noexcept
    {
        return m_dropped[static_cast<size_t>(p)].load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t DroppedTotal() const noexcept
    {
        uint64_t s = 0;
        for (const auto& d : m_dropped) s += d.load(std::memory_order_relaxed);
        return s;
    }

    [[nodiscard]] uint64_t PushedTotal() const noexcept { return m_pushed.load(std::memory_order_relaxed); }

private:
    alignas(64) std::atomic<uint64_t> m_head{0};
    alignas(64) std::atomic<uint64_t> m_tail{0};
    alignas(64) std::array<std::atomic<uint64_t>, kPriorityCount> m_dropped{};
    std::atomic<uint64_t> m_pushed{0};
    std::array<Slot, N> m_slots;
};

// 加鎖版本：介面與語意完全相同。2,000 事件/秒對加鎖佇列不構成瓶頸（part4 W1-3）。
template <class T, size_t N>
class BoundedQueue {
public:
    static constexpr size_t kCapacity = N;

    BoundedQueue() = default;
    BoundedQueue(const BoundedQueue&) = delete;
    BoundedQueue& operator=(const BoundedQueue&) = delete;

    [[nodiscard]] bool TryPush(T&& value, EventPriority prio) noexcept
    {
        std::lock_guard lk{m_mutex};
        const size_t usage = m_items.size() * 100 / N;
        if ((DropThresholdFor(prio) < 100 && usage >= DropThresholdFor(prio)) || m_items.size() >= N) {
            ++m_dropped[static_cast<size_t>(prio)];
            return false;
        }
        m_items.push_back(std::move(value));
        ++m_pushed;
        return true;
    }

    [[nodiscard]] bool TryPop(T& out) noexcept
    {
        std::lock_guard lk{m_mutex};
        if (m_items.empty()) return false;
        out = std::move(m_items.front());
        m_items.pop_front();
        return true;
    }

    [[nodiscard]] size_t SizeApprox() const noexcept
    {
        std::lock_guard lk{m_mutex};
        return m_items.size();
    }

    [[nodiscard]] uint8_t UsagePercent() const noexcept
    {
        return static_cast<uint8_t>(SizeApprox() * 100 / N);
    }

    [[nodiscard]] uint64_t DroppedCount(EventPriority p) const noexcept
    {
        std::lock_guard lk{m_mutex};
        return m_dropped[static_cast<size_t>(p)];
    }

    [[nodiscard]] uint64_t DroppedTotal() const noexcept
    {
        std::lock_guard lk{m_mutex};
        uint64_t s = 0;
        for (auto d : m_dropped) s += d;
        return s;
    }

    [[nodiscard]] uint64_t PushedTotal() const noexcept
    {
        std::lock_guard lk{m_mutex};
        return m_pushed;
    }

private:
    mutable std::mutex m_mutex;
    std::deque<T>      m_items;
    std::array<uint64_t, kPriorityCount> m_dropped{};
    uint64_t           m_pushed = 0;
};

} // namespace cairn
