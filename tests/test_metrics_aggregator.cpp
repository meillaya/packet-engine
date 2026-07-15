#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "packet-engine/metrics_aggregator.hpp"

using namespace pe;

class MetricsAggregatorTest : public ::testing::Test {
  protected:
    MetricsRegistry registry_;
};

TEST_F(MetricsAggregatorTest, AggregateRxCounters) {
    MetricsAggregator agg(2, &registry_);

    for (int i = 0; i < 1000; ++i) {
        agg.record_rx(0);
    }
    for (int i = 0; i < 1000; ++i) {
        agg.record_rx(1);
    }

    GlobalMetrics m = agg.snapshot();
    EXPECT_EQ(m.rx_packets, 2000u);
    EXPECT_EQ(m.drops, 0u);
    EXPECT_EQ(m.tx_packets, 0u);
}

TEST_F(MetricsAggregatorTest, AggregateMixedCounters) {
    MetricsAggregator agg(4, &registry_);

    agg.record_rx(0, 10);
    agg.record_rx(1, 20);
    agg.record_drop(2, 5);
    agg.record_tx(3, 7);

    GlobalMetrics m = agg.snapshot();
    EXPECT_EQ(m.rx_packets, 30u);
    EXPECT_EQ(m.drops, 5u);
    EXPECT_EQ(m.tx_packets, 7u);
}

TEST_F(MetricsAggregatorTest, LatencyPercentiles) {
    MetricsAggregator agg(1, &registry_);

    // 100 observations uniformly spread across 1..100 us.
    for (uint64_t us = 1; us <= 100; ++us) {
        agg.record_latency_us(0, us);
    }

    // All observations fall into bucket 1 (upper bound 50 us).
    // p50 (50th of 100) lands in bucket 1 -> 50 us.
    // p99 (99th of 100) lands in bucket 2 (upper bound 100 us) -> 100 us.
    EXPECT_EQ(agg.latency_p50_us(), 50u);
    EXPECT_EQ(agg.latency_p99_us(), 100u);
}

TEST_F(MetricsAggregatorTest, LatencyPercentilesLargeValue) {
    MetricsAggregator agg(1, &registry_);

    agg.record_latency_us(0, 500);
    agg.record_latency_us(0, 5000);
    agg.record_latency_us(0, 50000);

    EXPECT_EQ(agg.latency_p50_us(), 5000u);
    EXPECT_EQ(agg.latency_p99_us(), std::numeric_limits<uint64_t>::max());
}

TEST_F(MetricsAggregatorTest, ConcurrentWorkersNoContention) {
    constexpr size_t kWorkers = 4;
    constexpr uint64_t kIncrements = 1000;
    MetricsAggregator agg(kWorkers, &registry_);

    std::vector<std::jthread> threads;
    threads.reserve(kWorkers);
    for (size_t w = 0; w < kWorkers; ++w) {
        threads.emplace_back([w, &agg] {
            for (uint64_t i = 0; i < kIncrements; ++i) {
                agg.record_rx(w);
                agg.record_tx(w);
                if (i % 64 == 0) {
                    agg.record_latency_us(w, static_cast<uint64_t>(i % 100) + 1);
                }
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    GlobalMetrics m = agg.snapshot();
    EXPECT_EQ(m.rx_packets, kWorkers * kIncrements);
    EXPECT_EQ(m.tx_packets, kWorkers * kIncrements);
    EXPECT_GE(m.latency_observations, kWorkers * (kIncrements / 64));
}

TEST_F(MetricsAggregatorTest, PublishToRegistry) {
    MetricsAggregator agg(2, &registry_);

    agg.record_rx(0, 123);
    agg.record_drop(1, 7);
    agg.record_latency_us(0, 25);
    agg.publish();

    std::string exposed = registry_.expose_text();
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_rx_packets_total 123"));
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_drops_total 7"));
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_latency_seconds_bucket{le=\"5e-05\"} 1"));
    EXPECT_THAT(exposed, ::testing::Not(::testing::HasSubstr("engine_latency_p50_us")));
    EXPECT_THAT(exposed, ::testing::Not(::testing::HasSubstr("engine_latency_p99_us")));
}

TEST_F(MetricsAggregatorTest, PublishedHistogramKeepsExactObservationSum) {
    MetricsAggregator agg(1, &registry_);
    agg.record_latency_us(0, 25);
    agg.record_latency_us(0, 25'000);
    agg.publish();

    auto& histogram = registry_.histogram(
        "engine_latency_seconds", "Packet batch processing latency in seconds",
        {0.00001, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01});
    EXPECT_EQ(histogram.count(), 2u);
    EXPECT_NEAR(histogram.sum(), 0.025025, 1e-12);
}

TEST_F(MetricsAggregatorTest, PublishingCumulativeSnapshotTwiceDoesNotDoubleCount) {
    // Given: a worker has published an absolute cumulative total once.
    MetricsAggregator agg(1, &registry_);
    agg.record_rx(0, 10);
    agg.publish();

    // When: the same worker advances to 15 and publishes the cumulative snapshot again.
    agg.record_rx(0, 5);
    agg.publish();

    // Then: the exported counter is the worker's absolute total, not 10 + 15.
    EXPECT_EQ(registry_.counter("engine_rx_packets_total", "Total received packets").value(), 15u);
}

TEST_F(MetricsAggregatorTest, PeriodicPublisherRegistersZeroMetricsBeforeReturningFromStart) {
    MetricsAggregator agg(1, &registry_);
    PeriodicMetricsPublisher publisher(agg, std::chrono::milliseconds{10});

    publisher.start();

    const std::string exposed = registry_.expose_text();
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_rx_packets_total 0"));
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_drops_total 0"));
    EXPECT_THAT(exposed, ::testing::HasSubstr("engine_tx_packets_total 0"));
}

TEST_F(MetricsAggregatorTest, PeriodicPublisherMovesRecordedBatchToRegistryOffCallerThread) {
    MetricsAggregator agg(1, &registry_);
    PeriodicMetricsPublisher publisher(agg, std::chrono::milliseconds{1});
    publisher.start();
    agg.record_rx(0, 7);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (registry_.counter("engine_rx_packets_total", "Total received packets").value() != 7 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }

    EXPECT_EQ(registry_.counter("engine_rx_packets_total", "Total received packets").value(), 7U);
}

TEST_F(MetricsAggregatorTest, SnapshotLatencyBudget) {
    MetricsAggregator agg(2, &registry_);

    auto start = std::chrono::steady_clock::now();
    GlobalMetrics m = agg.snapshot();
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::microseconds(1));
    EXPECT_EQ(m.rx_packets, 0u);
}
