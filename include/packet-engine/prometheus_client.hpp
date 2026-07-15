#pragma once

#include <algorithm>
#include <atomic>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pe {

//
// Prometheus text-format emitter (v0.0.4) for the packet engine.
//
// PERFORMANCE CONSTRAINT — DO NOT VIOLATE:
//   Hot-path code MUST NOT call Counter::inc() / Gauge::set() / Histogram::observe()
//   on a per-packet basis. Instead, each worker thread should accumulate into a
//   thread-local counter (e.g. alignas(64) uint64_t) and the registry's snapshot()
//   path should read those thread-local values atomically, e.g. every 100 ms.
//   The classes below are intended for low-frequency metric aggregation, not
//   per-packet increments.
//

namespace detail {

inline std::string escape_label_value(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

inline void write_labels(std::ostringstream& oss,
                         const std::map<std::string, std::string>& labels) {
    if (labels.empty())
        return;
    oss << '{';
    bool first = true;
    for (const auto& [k, v] : labels) {
        if (!first)
            oss << ',';
        first = false;
        oss << k << "=\"" << escape_label_value(v) << '"';
    }
    oss << '}';
}

} // namespace detail

class Counter {
  public:
    Counter(std::string name, std::string help)
        : name_(std::move(name)), help_(std::move(help)), value_(0) {}

    // See PERFORMANCE CONSTRAINT at the top of this file.
    void inc(uint64_t delta = 1) noexcept { value_.fetch_add(delta, std::memory_order_relaxed); }

    uint64_t value() const noexcept { return value_.load(std::memory_order_relaxed); }
    const std::string& name() const noexcept { return name_; }
    const std::string& help() const noexcept { return help_; }

  private:
    std::string name_;
    std::string help_;
    std::atomic<uint64_t> value_;
};

class Gauge {
  public:
    Gauge(std::string name, std::string help)
        : name_(std::move(name)), help_(std::move(help)), value_(0) {}

    // See PERFORMANCE CONSTRAINT at the top of this file.
    void set(int64_t v) noexcept { value_.store(v, std::memory_order_relaxed); }
    void add(int64_t delta) noexcept { value_.fetch_add(delta, std::memory_order_relaxed); }

    int64_t value() const noexcept { return value_.load(std::memory_order_relaxed); }
    const std::string& name() const noexcept { return name_; }
    const std::string& help() const noexcept { return help_; }

  private:
    std::string name_;
    std::string help_;
    std::atomic<int64_t> value_;
};

class Histogram {
  public:
    Histogram(std::string name, std::string help, std::vector<double> buckets)
        : name_(std::move(name)), help_(std::move(help)), buckets_(std::move(buckets)),
          counts_(buckets_.size() + 1), sum_(0.0) {
        // Ensure buckets are sorted and finite.
        for (double b : buckets_) {
            assert(std::isfinite(b));
            (void)b;
        }
        std::sort(buckets_.begin(), buckets_.end());
        for (auto& c : counts_)
            c.store(0, std::memory_order_relaxed);
    }

    // See PERFORMANCE CONSTRAINT at the top of this file.
    void observe(double value) noexcept {
        assert(std::isfinite(value));
        for (size_t i = 0; i < buckets_.size(); ++i) {
            if (value <= buckets_[i]) {
                counts_[i].fetch_add(1, std::memory_order_relaxed);
            }
        }
        counts_[buckets_.size()].fetch_add(1, std::memory_order_relaxed);
        sum_.fetch_add(value, std::memory_order_relaxed);
    }

    void merge(std::span<const uint64_t> cumulative_counts, uint64_t count, double sum) noexcept {
        assert(cumulative_counts.size() == buckets_.size());
        assert(std::isfinite(sum));
        for (size_t i = 0; i < cumulative_counts.size(); ++i) {
            counts_[i].fetch_add(cumulative_counts[i], std::memory_order_relaxed);
        }
        counts_[buckets_.size()].fetch_add(count, std::memory_order_relaxed);
        sum_.fetch_add(sum, std::memory_order_relaxed);
    }

    const std::string& name() const noexcept { return name_; }
    const std::string& help() const noexcept { return help_; }
    const std::vector<double>& buckets() const noexcept { return buckets_; }
    uint64_t bucket_count(size_t idx) const noexcept {
        return counts_[idx].load(std::memory_order_relaxed);
    }
    uint64_t count() const noexcept {
        return counts_[buckets_.size()].load(std::memory_order_relaxed);
    }
    double sum() const noexcept { return sum_.load(std::memory_order_relaxed); }

  private:
    std::string name_;
    std::string help_;
    std::vector<double> buckets_;
    std::vector<std::atomic<uint64_t>> counts_;
    std::atomic<double> sum_;
};

class MetricsRegistry {
  public:
    Counter& counter(const std::string& name, const std::string& help) {
        std::lock_guard lock(mutex_);
        auto it = counters_.find(name);
        if (it == counters_.end()) {
            it = counters_.emplace(name, std::make_unique<Counter>(name, help)).first;
        }
        return *it->second;
    }

    Gauge& gauge(const std::string& name, const std::string& help) {
        std::lock_guard lock(mutex_);
        auto it = gauges_.find(name);
        if (it == gauges_.end()) {
            it = gauges_.emplace(name, std::make_unique<Gauge>(name, help)).first;
        }
        return *it->second;
    }

    Histogram& histogram(const std::string& name, const std::string& help,
                         const std::vector<double>& buckets) {
        std::lock_guard lock(mutex_);
        auto it = histograms_.find(name);
        if (it == histograms_.end()) {
            it = histograms_.emplace(name, std::make_unique<Histogram>(name, help, buckets)).first;
        }
        return *it->second;
    }

    // snapshot() is the intended path for hot-path metric collection: workers
    // update thread-local counters, and this method is called periodically (e.g.
    // every 100 ms) to fold those values into the registry.
    void snapshot() {
        // Placeholder for future thread-local aggregation fold-in.
    }

    std::string expose_text() const {
        std::ostringstream oss;
        std::lock_guard lock(mutex_);

        for (const auto& [name, counter] : counters_) {
            oss << "# HELP " << name << ' ' << counter->help() << '\n';
            oss << "# TYPE " << name << " counter\n";
            oss << name << ' ' << counter->value() << '\n';
        }

        for (const auto& [name, gauge] : gauges_) {
            oss << "# HELP " << name << ' ' << gauge->help() << '\n';
            oss << "# TYPE " << name << " gauge\n";
            oss << name << ' ' << gauge->value() << '\n';
        }

        for (const auto& [name, hist] : histograms_) {
            oss << "# HELP " << name << ' ' << hist->help() << '\n';
            oss << "# TYPE " << name << " histogram\n";
            size_t idx = 0;
            for (double b : hist->buckets()) {
                oss << name << "_bucket{le=\"" << b << "\"} " << hist->bucket_count(idx++) << '\n';
            }
            oss << name << "_bucket{le=\"+Inf\"} " << hist->count() << '\n';
            oss << name << "_sum " << hist->sum() << '\n';
            oss << name << "_count " << hist->count() << '\n';
        }

        return oss.str();
    }

  private:
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Counter>> counters_;
    std::map<std::string, std::unique_ptr<Gauge>> gauges_;
    std::map<std::string, std::unique_ptr<Histogram>> histograms_;
};

} // namespace pe
