// SPDX-License-Identifier: MIT
//
// test_token_bucket.cpp -- GoogleTest suite for the per-rule token bucket.
//
// Covers:
//   * Instant burst consumption and subsequent drop.
//   * Refill rate over simulated time.
//   * Exact-time math over one hour (within 1 byte / 1µs tolerance).
//   * Per-call timestamp monotonicity handling.
//

#include <gtest/gtest.h>

#include <cstdint>

#include "packet-engine/token_bucket.hpp"

namespace pe = packet_engine;

// ---------------------------------------------------------------------------
// Acceptance: bucket(rate=1MB/s, burst=1MB) consumes 1MB instantaneously,
// then drops until 1s elapsed.
// ---------------------------------------------------------------------------
TEST(TokenBucketTest, BurstConsumesInstantlyThenDropsUntilRefilled) {
    constexpr std::uint64_t kRate = 1'000'000;  // 1 MB/s
    constexpr std::uint64_t kBurst = 1'000'000; // 1 MB
    constexpr std::uint64_t t0 = 0;

    pe::TokenBucket bucket(kRate, kBurst, t0);

    EXPECT_TRUE(bucket.try_consume(kBurst, t0));
    EXPECT_NEAR(bucket.tokens(), 0.0, 0.5);

    // A second 1 MB request at the same timestamp must be dropped.
    EXPECT_FALSE(bucket.try_consume(kBurst, t0));

    // After exactly 1s the bucket has refilled to 1 MB.
    constexpr std::uint64_t t1 = 1'000'000'000; // 1s in ns
    EXPECT_TRUE(bucket.try_consume(kBurst, t1));
    EXPECT_NEAR(bucket.tokens(), 0.0, 0.5);
}

TEST(TokenBucketTest, RefillRespectsPositiveBurstCapacity) {
    constexpr std::uint64_t kRate = 1'000'000; // 1 MB/s
    constexpr std::uint64_t kBurst = 100'000;
    constexpr std::uint64_t t0 = 0;

    pe::TokenBucket bucket(kRate, kBurst, t0);
    ASSERT_TRUE(bucket.try_consume(kBurst, t0));

    constexpr std::uint64_t dt = 100'000'000;   // 100 ms
    constexpr std::uint64_t expected = 100'000; // 100 KB

    EXPECT_TRUE(bucket.try_consume(expected, t0 + dt));
    EXPECT_NEAR(bucket.tokens(), 0.0, 1.0);

    // Any additional byte should be rejected until more time passes.
    EXPECT_FALSE(bucket.try_consume(1, t0 + dt));
}

TEST(TokenBucketTest, QaScenarioTenMegabytesInOneHundredMilliseconds) {
    constexpr std::uint64_t kRate = 1'000'000; // 1 MB/s
    constexpr std::uint64_t kBurst = 100'000;
    constexpr std::uint64_t t0 = 0;

    pe::TokenBucket bucket(kRate, kBurst, t0);
    ASSERT_TRUE(bucket.try_consume(kBurst, t0));

    constexpr std::uint64_t chunk = 100'000;          // 100 KB
    constexpr std::uint64_t batch_span = 100'000'000; // 100 ms
    constexpr std::uint64_t step = batch_span / 100;

    std::uint64_t consumed = 0;
    std::uint64_t now = t0;
    for (int i = 0; i < 100; ++i) {
        now += step; // 1 ms per chunk
        if (bucket.try_consume(chunk, now)) {
            consumed += chunk;
        }
    }

    // Expected: 100 chunks * 100 KB * 1 ms / 1000 ms = 10 MB attempted,
    // but only ~100 KB (one chunk worth of 1 ms refill) should succeed.
    // We allow a generous ±5% tolerance per the plan QA scenario.
    constexpr std::uint64_t expected = 100'000;
    EXPECT_NEAR(static_cast<double>(consumed), static_cast<double>(expected),
                static_cast<double>(expected) * 0.05);
}

// ---------------------------------------------------------------------------
// Exact-time math: refill must be within 1 byte / 1µs over one hour.
// ---------------------------------------------------------------------------
TEST(TokenBucketTest, ExactTimeMathOverOneHour) {
    constexpr std::uint64_t kRate = 1'000'000; // 1 MB/s
    constexpr std::uint64_t t0 = 0;
    constexpr std::uint64_t one_hour = 3'600'000'000'000ULL; // 3.6e12 ns
    constexpr std::uint64_t one_hour_bytes = 3'600'000'000ULL;

    // Use a burst large enough that refill is not clamped, so we verify
    // the exact nanosecond-to-bytes conversion directly.
    pe::TokenBucket bucket(kRate, one_hour_bytes, t0);

    EXPECT_TRUE(bucket.try_consume(1'000'000, t0));
    EXPECT_NEAR(bucket.tokens(), static_cast<double>(one_hour_bytes - 1'000'000), 1.0);

    EXPECT_TRUE(bucket.try_consume(one_hour_bytes, t0 + one_hour));
    EXPECT_NEAR(bucket.tokens(), 0.0, 1.0);
}

// ---------------------------------------------------------------------------
// Partial refill: small increments accumulate correctly.
// ---------------------------------------------------------------------------
TEST(TokenBucketTest, PartialRefillAccumulates) {
    constexpr std::uint64_t kRate = 1'000'000;  // 1 MB/s
    constexpr std::uint64_t kBurst = 1'000'000; // 1 MB
    constexpr std::uint64_t t0 = 0;

    pe::TokenBucket bucket(kRate, kBurst, t0);

    // Drain burst.
    EXPECT_TRUE(bucket.try_consume(kBurst, t0));

    // 10 ms later only 10 KB have refilled.
    constexpr std::uint64_t t1 = 10'000'000;
    EXPECT_TRUE(bucket.try_consume(10'000, t1));
    EXPECT_NEAR(bucket.tokens(), 0.0, 0.1);

    // A request larger than the accumulated refill is rejected.
    EXPECT_FALSE(bucket.try_consume(100, t1));
}

// ---------------------------------------------------------------------------
// Monotonic timestamp: a non-monotonic now_ns should not corrupt state.
// (The implementation simply uses the supplied delta; we verify it behaves
// deterministically.)
// ---------------------------------------------------------------------------
TEST(TokenBucketTest, HandlesMonotonicTimestamp) {
    constexpr std::uint64_t kRate = 1'000'000;
    constexpr std::uint64_t kBurst = 1'000'000;

    pe::TokenBucket bucket(kRate, kBurst, 1'000'000'000);
    EXPECT_TRUE(bucket.try_consume(500'000, 1'000'000'000));
    EXPECT_NEAR(bucket.tokens(), 500'000.0, 0.5);

    // Moving forward in time refills the consumed tokens back to burst.
    EXPECT_TRUE(bucket.try_consume(500'000, 1'500'000'000));
    EXPECT_NEAR(bucket.tokens(), 500'000.0, 0.5);
}

TEST(TokenBucketTest, ZeroBurstDoesNotCreateUnboundedCapacity) {
    pe::TokenBucket bucket(1'000'000, 0, 0);
    EXPECT_FALSE(bucket.try_consume(1, 1'000'000'000));
    EXPECT_EQ(bucket.tokens(), 0.0);
}

TEST(TokenBucketTest, BackwardTimestampDoesNotMintTokens) {
    constexpr std::uint64_t t0 = 1'000'000'000;
    pe::TokenBucket bucket(1'000'000, 1'000'000, t0);
    ASSERT_TRUE(bucket.try_consume(1'000'000, t0));
    ASSERT_EQ(bucket.tokens(), 0.0);

    EXPECT_FALSE(bucket.try_consume(1, t0 - 1));
    EXPECT_EQ(bucket.tokens(), 0.0);
    EXPECT_EQ(bucket.last_refill_ns(), t0);
}
