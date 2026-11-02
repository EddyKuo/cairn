// RingBufferTests —— 無鎖版與加鎖版以 TYPED_TEST_SUITE 跑同一組介面測試（part4 W1-3 的降險路徑）
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <set>
#include <thread>
#include <vector>

#include "base/RingBuffer.h"

using cairn::BoundedQueue;
using cairn::EventPriority;
using cairn::LockFreeRingBuffer;

template <class Q>
class RingBufferTest : public ::testing::Test {};

using Impls = ::testing::Types<LockFreeRingBuffer<int, 1024>, BoundedQueue<int, 1024>>;
TYPED_TEST_SUITE(RingBufferTest, Impls);

TYPED_TEST(RingBufferTest, PushPopFifo)
{
    auto q = std::make_unique<TypeParam>();
    for (int i = 0; i < 100; ++i) EXPECT_TRUE(q->TryPush(int{i}, EventPriority::Critical));
    EXPECT_EQ(q->SizeApprox(), 100u);
    int v = -1;
    for (int i = 0; i < 100; ++i) {
        ASSERT_TRUE(q->TryPop(v));
        EXPECT_EQ(v, i);
    }
    EXPECT_FALSE(q->TryPop(v));
    EXPECT_EQ(q->SizeApprox(), 0u);
}

TYPED_TEST(RingBufferTest, LowPriorityDroppedAt70Percent)
{
    auto q = std::make_unique<TypeParam>();
    // 填到 70%（716 / 1024 ≈ 69.9% → 716 筆後 UsagePercent == 69；717 筆後 70）
    int pushed = 0;
    while (q->UsagePercent() < 70) {
        ASSERT_TRUE(q->TryPush(int{pushed}, EventPriority::Critical));
        ++pushed;
    }
    EXPECT_FALSE(q->TryPush(int{-1}, EventPriority::Low));
    EXPECT_EQ(q->DroppedCount(EventPriority::Low), 1u);
    EXPECT_TRUE(q->TryPush(int{-2}, EventPriority::Normal));   // Normal 門檻 85%
    EXPECT_TRUE(q->TryPush(int{-3}, EventPriority::High));     // High 門檻 95%
}

TYPED_TEST(RingBufferTest, CriticalOnlyDroppedWhenTrulyFull)
{
    auto q = std::make_unique<TypeParam>();
    for (int i = 0; i < 1024; ++i) ASSERT_TRUE(q->TryPush(int{i}, EventPriority::Critical));
    EXPECT_FALSE(q->TryPush(int{1024}, EventPriority::Critical));
    EXPECT_EQ(q->DroppedCount(EventPriority::Critical), 1u);
    EXPECT_FALSE(q->TryPush(int{1025}, EventPriority::High));
    EXPECT_EQ(q->DroppedTotal(), 2u);
    int v;
    ASSERT_TRUE(q->TryPop(v));
    EXPECT_TRUE(q->TryPush(int{2000}, EventPriority::Critical));   // 讓出一格後可再進
}

TYPED_TEST(RingBufferTest, WrapAroundManyCycles)
{
    auto q = std::make_unique<TypeParam>();
    int next = 0, expect = 0, v = 0;
    for (int round = 0; round < 50; ++round) {
        for (int i = 0; i < 700; ++i) ASSERT_TRUE(q->TryPush(int{next++}, EventPriority::High));
        for (int i = 0; i < 700; ++i) {
            ASSERT_TRUE(q->TryPop(v));
            ASSERT_EQ(v, expect++);
        }
    }
    EXPECT_EQ(q->PushedTotal(), static_cast<uint64_t>(next));
}

TYPED_TEST(RingBufferTest, MpscConcurrentNoLossNoDuplicate)
{
    auto q = std::make_unique<TypeParam>();
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 50'000;
    std::atomic<bool> done{false};
    std::atomic<int>  finished{0};
    std::vector<int>  received;
    received.reserve(kProducers * kPerProducer);

    std::thread consumer([&] {
        int v;
        while (!done.load(std::memory_order_acquire) || q->SizeApprox() > 0) {
            if (q->TryPop(v)) received.push_back(v);
            else std::this_thread::yield();
        }
        while (q->TryPop(v)) received.push_back(v);
    });

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&, p] {
            for (int i = 0; i < kPerProducer; ++i) {
                // Critical：只有真滿才丟，丟了就計數（呼叫端不得重試——但測試要驗證「推入成功者必被取出」）
                (void)q->TryPush(int{p * kPerProducer + i}, EventPriority::Critical);
            }
            finished.fetch_add(1);
        });
    }
    for (auto& t : producers) t.join();
    done.store(true, std::memory_order_release);
    consumer.join();

    const uint64_t dropped = q->DroppedTotal();
    EXPECT_EQ(received.size() + dropped, static_cast<size_t>(kProducers * kPerProducer));
    std::set<int> uniq(received.begin(), received.end());
    EXPECT_EQ(uniq.size(), received.size()) << "不得重複取出";

    // 每個生產者自己的序列必須保持相對順序（MPSC 的 FIFO 保證）
    std::vector<int> last(kProducers, -1);
    for (int v : received) {
        const int p = v / kPerProducer;
        EXPECT_GT(v, last[p]);
        last[p] = v;
    }
}

TYPED_TEST(RingBufferTest, UsagePercentNeverExceeds100)
{
    auto q = std::make_unique<TypeParam>();
    for (int i = 0; i < 2000; ++i) (void)q->TryPush(int{i}, EventPriority::Critical);
    EXPECT_LE(q->UsagePercent(), 100);
    EXPECT_LE(q->SizeApprox(), 1024u);
}
