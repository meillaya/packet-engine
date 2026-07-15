// SPDX-License-Identifier: MIT
//
// health_prober.hpp -- active TCP health probing for BackendRegistry.
//
// Design notes
// ============
//
// * This is the **active** half of the load balancer's health story: a
//   dedicated thread periodically opens a non-blocking TCP socket against
//   each HEALTHY / DEGRADED backend's `health_port` and reports the outcome
//   to the registry.  The registry's `report_failure` / `report_success`
//   methods apply the passive-health threshold (Task 19).
//
// * We deliberately decouple from the concrete `BackendRegistry` type via
//   the `IBackendRegistry` interface defined here.  `BackendRegistry`
//   implements this interface naturally; tests can inject a mock that
//   records `report_*` calls and toggle the reported state without
//   touching the registry's `std::shared_mutex`.
//
// * The probe loop runs on a `std::jthread` (C++20+) so the destructor
//   cooperatively requests shutdown via `std::stop_token`.  No detached
//   threads, no `pthread_cancel`.
//
// * The probe itself is bounded by `probe_timeout`.  We use
//   `connect(2)` with `O_NONBLOCK` + `poll(POLLOUT)` +
//   `getsockopt(SO_ERROR)` so a back-end that SYN-drops packets cannot
//   hang the prober indefinitely.  See `connect(2)` and `poll(2)` for
//   the rationale.
//
// * State-change side effects:
//     - HEALTHY  -> DEGRADED   : LOG_WARN + metrics counter bump
//     - DEGRADED -> HEALTHY    : LOG_INFO  + metrics counter bump
//   Anything else (e.g. report_failure while already DEGRADED) is silent.
//
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "backend_registry.hpp"

namespace packet_engine {

/// Minimal interface that `HealthProber` requires from the backend
/// directory.  Defined in `backend_registry.hpp` (so `BackendRegistry`'s
/// inheritance + the prober's dependency share one declaration).
/// `BackendRegistry` implements it directly; tests can supply a mock.

/// Counts the number of HEALTHY -> DEGRADED and DEGRADED -> HEALTHY
/// transitions the prober has observed.  Kept deliberately minimal --
/// the Prometheus export work lives in Task 12 / Task 23.
///
/// The struct intentionally provides explicit copy / move constructors
/// that load from / store to each atomic, because `std::atomic<T>` is
/// neither copyable nor movable by default.  This lets callers snapshot
/// the metrics with `auto m = prober.metrics();` cheaply.
struct HealthProberMetrics {
    HealthProberMetrics() = default;

    HealthProberMetrics(const HealthProberMetrics& other) noexcept { copy_from(other); }

    HealthProberMetrics& operator=(const HealthProberMetrics& other) noexcept {
        if (this != &other) {
            copy_from(other);
        }
        return *this;
    }

    HealthProberMetrics(HealthProberMetrics&& other) noexcept { copy_from(other); }

    HealthProberMetrics& operator=(HealthProberMetrics&& other) noexcept {
        if (this != &other) {
            copy_from(other);
        }
        return *this;
    }

    std::atomic<std::uint64_t> success_to_degraded{0};
    std::atomic<std::uint64_t> degraded_to_healthy{0};
    std::atomic<std::uint64_t> probes_attempted{0};
    std::atomic<std::uint64_t> probes_succeeded{0};
    std::atomic<std::uint64_t> probes_failed{0};

  private:
    void copy_from(const HealthProberMetrics& other) noexcept {
        success_to_degraded.store(other.success_to_degraded.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
        degraded_to_healthy.store(other.degraded_to_healthy.load(std::memory_order_relaxed),
                                  std::memory_order_relaxed);
        probes_attempted.store(other.probes_attempted.load(std::memory_order_relaxed),
                               std::memory_order_relaxed);
        probes_succeeded.store(other.probes_succeeded.load(std::memory_order_relaxed),
                               std::memory_order_relaxed);
        probes_failed.store(other.probes_failed.load(std::memory_order_relaxed),
                            std::memory_order_relaxed);
    }
};

/// Active TCP health prober.  Periodically opens a non-blocking TCP
/// connection to each registered backend's `health_port` and reports the
/// outcome to an `IBackendRegistry`.
///
/// Threading model:
///   - `start()` spawns exactly one `std::jthread` running `probe_loop`.
///   - The destructor (or `stop()`) requests shutdown; the loop joins.
///   - All public methods are safe to call from any thread once `start()`
///     has been invoked.
class HealthProber {
  public:
    /// Defaults specified by Task 22.
    static constexpr std::chrono::seconds kDefaultProbeInterval{5};
    static constexpr std::chrono::seconds kDefaultProbeTimeout{1};
    static constexpr std::uint16_t kDefaultHealthPort{8080};

    /// Construct a prober bound to `registry`.  `probe_interval` and
    /// `probe_timeout` are forwarded to the worker; `default_health_port`
    /// is used when `Backend::health_port == 0`.
    ///
    /// `registry` must outlive the prober.
    explicit HealthProber(IBackendRegistry& registry,
                          std::chrono::seconds probe_interval = kDefaultProbeInterval,
                          std::chrono::seconds probe_timeout = kDefaultProbeTimeout,
                          std::uint16_t default_health_port = kDefaultHealthPort);

    HealthProber(const HealthProber&) = delete;
    HealthProber& operator=(const HealthProber&) = delete;
    HealthProber(HealthProber&&) = delete;
    HealthProber& operator=(HealthProber&&) = delete;

    /// RAII cleanup: requests shutdown and joins the worker thread.
    ~HealthProber();

    /// Spawn the prober thread.  No-op if already running.
    void start();

    /// Request cooperative shutdown.  Safe to call multiple times.
    void stop();

    /// True iff the worker thread is alive (i.e. `start()` was called
    /// and `stop()` has not yet been honoured).
    [[nodiscard]] bool running() const noexcept;

    /// Snapshot the metric counters.  Cheap; safe from any thread.
    [[nodiscard]] HealthProberMetrics metrics() const;

    [[nodiscard]] std::chrono::seconds probe_interval() const noexcept { return probe_interval_; }
    [[nodiscard]] std::chrono::seconds probe_timeout() const noexcept { return probe_timeout_; }

  protected:
    /// Virtual hook: open a non-blocking TCP socket against
    /// `backend.authority` and return true iff the connection completes
    /// within `timeout`.  Tests may override this to short-circuit the
    /// network and exercise the rest of the pipeline.
    virtual bool probe_one(const Backend& backend, std::chrono::milliseconds timeout,
                           std::string* error_out);

    /// Helper exposed for tests: do one synchronous probe round against
    /// the backends in `ids`.  For each id we look it up in the
    /// registry; if found we invoke `predicate(id)` to decide whether the
    /// probe would succeed and report the outcome.  Returns the number of
    /// successful probes.  Tests subclass `HealthProber` to override
    /// `probe_one` and read this method deterministically without the
    /// worker thread.
    using ProbePredicate = std::function<bool(BackendId)>;

    std::size_t probe_round_for_test(const std::vector<BackendId>& ids,
                                     const ProbePredicate& predicate);

  private:
    void probe_loop(std::stop_token st);

    /// Snapshot the registry, dispatch each backend to `probe_one`, then
    /// report outcomes via `registry_`.
    void run_probe_round(std::stop_token st);

    /// Parse "host[:port]" into (host, port).  Missing port defaults to
    /// `default_health_port_`.  Returns false on malformed input.
    bool parse_authority(const std::string& authority, std::string* host,
                         std::uint16_t* port) const;

    /// Update metrics and emit a log line on observable state changes.
    /// `before` is the snapshot of state before the report call;
    /// `after` is the state after the call.
    void observe_transition(BackendId id, bool ok, BackendState before, BackendState after);

    IBackendRegistry& registry_;
    const std::chrono::seconds probe_interval_;
    const std::chrono::seconds probe_timeout_;
    const std::uint16_t default_health_port_;

    std::unique_ptr<std::jthread> thread_;
    std::atomic<bool> running_{false};

    HealthProberMetrics metrics_;
};

} // namespace packet_engine
