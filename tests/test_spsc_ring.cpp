#include <packet-engine/spsc_ring.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <thread>
#include <vector>

using packet_engine::SpscRing;

TEST(SpscRingTest, BasicPushPop) {
    SpscRing<int, 16> ring;
    EXPECT_TRUE(ring.was_empty());
    EXPECT_EQ(ring.size_approx(), 0u);

    EXPECT_TRUE(ring.push(42));
    EXPECT_FALSE(ring.was_empty());
    EXPECT_EQ(ring.size_approx(), 1u);

    int value = 0;
    EXPECT_TRUE(ring.pop(value));
    EXPECT_EQ(value, 42);
    EXPECT_TRUE(ring.was_empty());
    EXPECT_EQ(ring.size_approx(), 0u);
}

TEST(SpscRingTest, FifoAcrossOneMillion) {
    constexpr std::size_t kCapacity = 4096;
    constexpr std::uint64_t kTotal = 1'000'000;
    SpscRing<std::uint64_t, kCapacity> ring;

    auto producer = std::async(std::launch::async, [&ring] {
        for (std::uint64_t i = 0; i < kTotal; ++i) {
            while (!ring.push(i)) {
                std::this_thread::yield();
            }
        }
    });

    std::uint64_t expected = 0;
    while (expected < kTotal) {
        std::uint64_t value = 0;
        if (ring.pop(value)) {
            EXPECT_EQ(value, expected);
            ++expected;
        } else {
            std::this_thread::yield();
        }
    }

    producer.wait();
    EXPECT_EQ(ring.size_approx(), 0u);
    EXPECT_TRUE(ring.was_empty());
}

TEST(SpscRingTest, PowerOfTwoCapacityRequired) {
    // 16 is power of two; compiles.
    [[maybe_unused]] SpscRing<int, 16> ok;
    // 4096 is power of two; compiles.
    [[maybe_unused]] SpscRing<int, 4096> ok_default;
}
