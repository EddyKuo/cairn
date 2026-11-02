// src/core/base/BlockingQueue.h               namespace cairn
// 通用的有界多生產者佇列（mutex + condition_variable），用於執行緒間傳值：
//   T2→T3（NormalizedEvent）、T3/T5/T6/T7→T4（WriteOp）、T3→T5（NarrativeRequest）、
//   T3/T7→T6（ResponseCommand）、T7→T3（AnalysisCommand）。
// 熱路徑的 T1→T2 才用 RingBuffer.h 的無鎖佇列；其餘路徑事件率低，加鎖足矣。
//
// 生產端永不阻塞：Post 滿了就回 false，由呼叫端決定丟棄或降級（「AnalysisThread 絕不阻塞等待寫入」）。
// Urgent lane：PostUrgent 的項目一律先於一般項目被取出（WriteOp 的 alerts/audit，SDD-02 §6.3.3）。
#pragma once
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <stop_token>

namespace cairn {

template <class T>
class BlockingQueue {
public:
    explicit BlockingQueue(size_t capacity) : m_capacity(capacity) {}
    BlockingQueue(const BlockingQueue&) = delete;
    BlockingQueue& operator=(const BlockingQueue&) = delete;

    // 非阻塞。回傳 false = 佇列滿，已計入 Dropped()。
    [[nodiscard]] bool Post(T&& item)
    {
        {
            std::lock_guard lk{m_mutex};
            if (m_closed || m_normal.size() + m_urgent.size() >= m_capacity) {
                ++m_dropped;
                return false;
            }
            m_normal.push_back(std::move(item));
        }
        m_cv.notify_one();
        return true;
    }

    // Urgent 項目不受容量限制（告警與稽核不可丟），但仍受 Close() 限制。
    [[nodiscard]] bool PostUrgent(T&& item)
    {
        {
            std::lock_guard lk{m_mutex};
            if (m_closed) return false;
            m_urgent.push_back(std::move(item));
        }
        m_cv.notify_one();
        return true;
    }

    // 等待至多 timeout；stop 被請求或 Close 後且佇列已空時回傳 nullopt。
    [[nodiscard]] std::optional<T> PopFor(std::chrono::milliseconds timeout, std::stop_token stop = {})
    {
        std::unique_lock lk{m_mutex};
        if (m_urgent.empty() && m_normal.empty()) {
            if (stop.stop_possible()) {
                m_cv.wait_for(lk, stop, timeout, [&] { return !m_urgent.empty() || !m_normal.empty() || m_closed; });
            } else {
                m_cv.wait_for(lk, timeout, [&] { return !m_urgent.empty() || !m_normal.empty() || m_closed; });
            }
        }
        return PopLocked();
    }

    [[nodiscard]] std::optional<T> TryPop()
    {
        std::lock_guard lk{m_mutex};
        return PopLocked();
    }

    // 丟棄最舊的一般項目（LlmWorker 的「滿則丟最舊」）。回傳被丟的項目供呼叫端記錄 skipped。
    [[nodiscard]] std::optional<T> EvictOldest()
    {
        std::lock_guard lk{m_mutex};
        if (m_normal.empty()) return std::nullopt;
        T v = std::move(m_normal.front());
        m_normal.pop_front();
        return v;
    }

    // 停止接收新項目並喚醒所有等待者；已在佇列中的項目仍可被取出（優雅關機時排空用）。
    void Close()
    {
        {
            std::lock_guard lk{m_mutex};
            m_closed = true;
        }
        m_cv.notify_all();
    }

    [[nodiscard]] size_t Size() const
    {
        std::lock_guard lk{m_mutex};
        return m_normal.size() + m_urgent.size();
    }
    [[nodiscard]] size_t Capacity() const noexcept { return m_capacity; }
    [[nodiscard]] uint64_t Dropped() const
    {
        std::lock_guard lk{m_mutex};
        return m_dropped;
    }
    [[nodiscard]] uint8_t UsagePercent() const
    {
        std::lock_guard lk{m_mutex};
        return static_cast<uint8_t>(std::min<size_t>(100, (m_normal.size() * 100) / (m_capacity ? m_capacity : 1)));
    }

private:
    std::optional<T> PopLocked()
    {
        if (!m_urgent.empty()) {
            T v = std::move(m_urgent.front());
            m_urgent.pop_front();
            return v;
        }
        if (!m_normal.empty()) {
            T v = std::move(m_normal.front());
            m_normal.pop_front();
            return v;
        }
        return std::nullopt;
    }

    mutable std::mutex          m_mutex;
    std::condition_variable_any m_cv;
    std::deque<T>               m_urgent;
    std::deque<T>               m_normal;
    size_t                      m_capacity;
    uint64_t                    m_dropped = 0;
    bool                        m_closed  = false;
};

} // namespace cairn
