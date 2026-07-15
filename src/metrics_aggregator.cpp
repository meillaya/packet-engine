#include "packet-engine/metrics_aggregator.hpp"

#include <cassert>
#include <chrono>
#include <cmath>
#include <mutex>
#include <stop_token>

namespace pe {

namespace {

constexpr std::array<uint64_t, WorkerCounters::kLatencyBuckets> kBucketUpperBoundsUs = {
    10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, std::numeric_limits<uint64_t>::max()};

size_t latency_bucket_index(uint64_t latency_us) noexcept {
    for (size_t i = 0; i < kBucketUpperBoundsUs.size(); ++i) {
        if (latency_us <= kBucketUpperBoundsUs[i]) {
            return i;
        }
    }
    return kBucketUpperBoundsUs.size() - 1;
}

uint64_t cumulative_delta(uint64_t current, uint64_t published) noexcept {
    return current >= published ? current - published : current;
}

} // namespace

MetricsAggregator::MetricsAggregator(size_t worker_count, MetricsRegistry* registry)
    : workers_(worker_count), registry_(registry) {
    // Vector default-constructs WorkerCounters; atomics are zero-initialized.
}

void MetricsAggregator::record_rx(size_t worker_id, uint64_t delta) noexcept {
    assert(worker_id < workers_.size());
    workers_[worker_id].rx_packets.fetch_add(delta, std::memory_order_relaxed);
}

void MetricsAggregator::record_drop(size_t worker_id, uint64_t delta) noexcept {
    assert(worker_id < workers_.size());
    workers_[worker_id].drops.fetch_add(delta, std::memory_order_relaxed);
}

void MetricsAggregator::record_tx(size_t worker_id, uint64_t delta) noexcept {
    assert(worker_id < workers_.size());
    workers_[worker_id].tx_packets.fetch_add(delta, std::memory_order_relaxed);
}

void MetricsAggregator::record_latency_us(size_t worker_id, uint64_t latency_us) noexcept {
    assert(worker_id < workers_.size());
    WorkerCounters& wc = workers_[worker_id];
    wc.latency_buckets[latency_bucket_index(latency_us)].fetch_add(1, std::memory_order_relaxed);
    wc.latency_observations.fetch_add(1, std::memory_order_relaxed);
    wc.latency_sum_us.fetch_add(latency_us, std::memory_order_relaxed);
}

GlobalMetrics MetricsAggregator::snapshot() const noexcept {
    GlobalMetrics out{};
    for (const auto& wc : workers_) {
        out.rx_packets += wc.rx_packets.load(std::memory_order_relaxed);
        out.drops += wc.drops.load(std::memory_order_relaxed);
        out.tx_packets += wc.tx_packets.load(std::memory_order_relaxed);
        out.latency_observations += wc.latency_observations.load(std::memory_order_relaxed);
        out.latency_sum_us += wc.latency_sum_us.load(std::memory_order_relaxed);
        for (size_t i = 0; i < WorkerCounters::kLatencyBuckets; ++i) {
            out.latency_buckets[i] += wc.latency_buckets[i].load(std::memory_order_relaxed);
        }
    }
    last_snapshot_ = out;
    has_snapshot_.store(true, std::memory_order_release);
    return out;
}

void MetricsAggregator::publish() noexcept {
    if (registry_ == nullptr)
        return;

    GlobalMetrics m = snapshot();

    registry_->counter("engine_rx_packets_total", "Total received packets")
        .inc(cumulative_delta(m.rx_packets, published_snapshot_.rx_packets));
    registry_->counter("engine_drops_total", "Total dropped packets")
        .inc(cumulative_delta(m.drops, published_snapshot_.drops));
    registry_->counter("engine_tx_packets_total", "Total transmitted packets")
        .inc(cumulative_delta(m.tx_packets, published_snapshot_.tx_packets));

    // Expose fixed-bucket histogram counts under a single histogram metric.
    // The registry's histogram uses the same upper bounds.
    Histogram& hist = registry_->histogram(
        "engine_latency_seconds", "Packet batch processing latency in seconds",
        {0.00001, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01});
    std::array<uint64_t, WorkerCounters::kLatencyBuckets - 1u> cumulative_counts{};
    uint64_t cumulative = 0;
    for (size_t i = 0; i < cumulative_counts.size(); ++i) {
        cumulative +=
            cumulative_delta(m.latency_buckets[i], published_snapshot_.latency_buckets[i]);
        cumulative_counts[i] = cumulative;
    }
    const auto observation_delta =
        cumulative_delta(m.latency_observations, published_snapshot_.latency_observations);
    const auto sum_delta_us =
        cumulative_delta(m.latency_sum_us, published_snapshot_.latency_sum_us);
    hist.merge(cumulative_counts, observation_delta,
               static_cast<double>(sum_delta_us) / 1'000'000.0);
    published_snapshot_ = m;
}

uint64_t MetricsAggregator::latency_p50_us() const {
    if (!has_snapshot_.load(std::memory_order_acquire)) {
        snapshot();
    }
    return latency_percentile_us(0.50);
}

uint64_t MetricsAggregator::latency_p99_us() const {
    if (!has_snapshot_.load(std::memory_order_acquire)) {
        snapshot();
    }
    return latency_percentile_us(0.99);
}

uint64_t MetricsAggregator::latency_percentile_us(double p) const {
    assert(p >= 0.0 && p <= 1.0);
    const GlobalMetrics& m = last_snapshot_;
    if (m.latency_observations == 0)
        return 0;

    const uint64_t target =
        static_cast<uint64_t>(std::ceil(p * static_cast<double>(m.latency_observations)));

    uint64_t cumulative = 0;
    for (size_t i = 0; i < WorkerCounters::kLatencyBuckets; ++i) {
        cumulative += m.latency_buckets[i];
        if (cumulative >= target) {
            return kBucketUpperBoundsUs[i];
        }
    }
    return kBucketUpperBoundsUs.back();
}

PeriodicMetricsPublisher::PeriodicMetricsPublisher(MetricsAggregator& aggregator,
                                                   std::chrono::milliseconds interval) noexcept
    : aggregator_{aggregator}, interval_{interval} {}

PeriodicMetricsPublisher::~PeriodicMetricsPublisher() { stop(); }

void PeriodicMetricsPublisher::start() {
    if (thread_.joinable()) {
        return;
    }
    aggregator_.publish();
    thread_ = std::jthread([this](std::stop_token stop) {
        std::unique_lock lock{mutex_};
        while (!stop.stop_requested()) {
            wakeup_.wait_for(lock, stop, interval_, [] { return false; });
            if (stop.stop_requested()) {
                break;
            }
            lock.unlock();
            aggregator_.publish();
            lock.lock();
        }
    });
}

void PeriodicMetricsPublisher::stop() noexcept {
    if (!thread_.joinable()) {
        return;
    }
    thread_.request_stop();
    wakeup_.notify_all();
    thread_.join();
    aggregator_.publish();
}

} // namespace pe
