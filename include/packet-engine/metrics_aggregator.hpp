#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "packet-engine/prometheus_client.hpp"

namespace pe {

//
// Per-worker counters aggregated into a shared atomic snapshot.
//
// PERFORMANCE CONSTRAINT — DO NOT VIOLATE:
//   Workers MUST NOT call the record_* functions on a per-packet basis.
//   Each worker should accumulate counters locally and call record_* once
//   per batch (e.g. once every 64 packets, or once every 100 us).  Per-packet
//   atomic increments are the forbidden anti-pattern because they serialize
//   across cores and destroy cache efficiency.
//
//   WorkerCounters is cache-line-aligned to prevent false sharing between
//   adjacent workers.  Each worker owns one struct exclusively.
//

struct alignas(64) WorkerCounters {
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> drops{0};
    std::atomic<uint64_t> tx_packets{0};

    // Simple fixed-bucket latency histogram, no external HDR library.
    // Buckets (microseconds):
    //   [0, 10), [10, 50), [50, 100), [100, 250), [250, 500),
    //   [500, 1000), [1000, 2500), [2500, 5000), [5000, 10000), [10000, +inf)
    static constexpr size_t kLatencyBuckets = 10;
    std::array<std::atomic<uint64_t>, kLatencyBuckets> latency_buckets{};
    std::atomic<uint64_t> latency_observations{0};
    std::atomic<uint64_t> latency_sum_us{0}; // sum of observations in us

    // Pad to a full cache line (or two) so two WorkerCounters never share a line.
    // With 13 atomic uint64_t = 104 bytes, alignas(64) plus padding guarantees
    // at least one cache line of separation.
    std::byte padding[64 - (13 * sizeof(uint64_t)) % 64]{};
};

static_assert(alignof(WorkerCounters) >= 64, "WorkerCounters must be cache-line aligned");
static_assert(sizeof(WorkerCounters) % 64 == 0,
              "WorkerCounters size must be a multiple of cache line");

struct GlobalMetrics {
    uint64_t rx_packets = 0;
    uint64_t drops = 0;
    uint64_t tx_packets = 0;
    std::array<uint64_t, WorkerCounters::kLatencyBuckets> latency_buckets{};
    uint64_t latency_observations = 0;
    uint64_t latency_sum_us = 0;
};

class MetricsAggregator {
  public:
    explicit MetricsAggregator(size_t worker_count, MetricsRegistry* registry = nullptr);

    // Returns the number of configured workers.
    size_t worker_count() const noexcept { return workers_.size(); }

    // Record per-worker counter deltas.  Call once per batch, NOT per packet.
    void record_rx(size_t worker_id, uint64_t delta = 1) noexcept;
    void record_drop(size_t worker_id, uint64_t delta = 1) noexcept;
    void record_tx(size_t worker_id, uint64_t delta = 1) noexcept;

    // Record latency observation in microseconds.  Call once per batch.
    void record_latency_us(size_t worker_id, uint64_t latency_us) noexcept;

    // Atomically read all worker counters and produce an aggregate snapshot.
    GlobalMetrics snapshot() const noexcept;

    // Publish the current snapshot into the attached MetricsRegistry.
    // Safe to call from a slow / management thread; never from the hot path.
    void publish() noexcept;

    // Local diagnostic helpers; Prometheus percentiles are derived from the
    // exported seconds histogram with histogram_quantile().
    uint64_t latency_p50_us() const;
    uint64_t latency_p99_us() const;

  private:
    std::vector<WorkerCounters> workers_;
    MetricsRegistry* registry_;
    mutable GlobalMetrics last_snapshot_;
    GlobalMetrics published_snapshot_;
    mutable std::atomic<bool> has_snapshot_{false};

    uint64_t latency_percentile_us(double p) const;
};

class PeriodicMetricsPublisher {
  public:
    explicit PeriodicMetricsPublisher(MetricsAggregator& aggregator,
                                      std::chrono::milliseconds interval) noexcept;
    ~PeriodicMetricsPublisher();

    PeriodicMetricsPublisher(const PeriodicMetricsPublisher&) = delete;
    PeriodicMetricsPublisher& operator=(const PeriodicMetricsPublisher&) = delete;

    void start();
    void stop() noexcept;

  private:
    MetricsAggregator& aggregator_;
    std::chrono::milliseconds interval_;
    std::mutex mutex_;
    std::condition_variable_any wakeup_;
    std::jthread thread_;
};

} // namespace pe
