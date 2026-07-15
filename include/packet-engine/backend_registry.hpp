// SPDX-License-Identifier: MIT
//
// backend_registry.hpp -- control-plane backend directory + passive health.
//
// Design notes
// ============
//
// * This registry is intentionally on the COLD path (control plane).  It is
//   implemented with `std::unordered_map` and a single `std::shared_mutex`,
//   which is perfectly acceptable here: per-packet LB decisions that need
//   sub-microsecond latency go through the Ketama ring (Task 18), not this
//   registry.
//
// * The registry owns the authoritative backend map and failure tracking.
//   It delegates ring rebuilds to an injected `IKetamaRebuildCallback` so
//   that Task 18 (KetamaRing) and Task 19 can be developed in parallel.
//
// * Passive health demotion is intentionally simple: N consecutive failures
//   inside a fixed wall-clock window demote a backend to DEGRADED.  Success
//   reports clear the failure window and restore HEALTHY.  Task 22's active
//   probes will call `report_failure` / `report_success` from a dedicated
//   health-check thread.
//
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "packet-engine/types.hpp"

namespace packet_engine {

/// Opaque backend identifier.
using BackendId = std::uint64_t;

/// Backend health state.
enum class BackendState : std::uint8_t {
    HEALTHY,
    DEGRADED,
    DOWN,
};

/// Backend record stored in the registry.
struct Backend {
    BackendId id{0};
    std::string authority;
    std::uint64_t health_port{0};
    BackendState state{BackendState::HEALTHY};
    MacAddr next_hop_mac{};

    bool operator==(const Backend& other) const noexcept {
        return id == other.id && authority == other.authority && health_port == other.health_port &&
               state == other.state && next_hop_mac.bytes == other.next_hop_mac.bytes;
    }
};

/// Callback interface used to rebuild the consistent-hashing ring whenever
/// the backend set changes.  Implementations are supplied by the caller and
/// must be thread-safe on their own (the registry invokes them under a unique
/// lock, but the implementation may publish the new ring with whatever
/// lock-free scheme it prefers).
class IKetamaRebuildCallback {
  public:
    virtual ~IKetamaRebuildCallback() = default;

    /// Called with the current list of HEALTHY backends. DEGRADED and DOWN
    /// backends are excluded from new load-balanced flows.
    virtual void rebuild(const std::vector<Backend>& backends) = 0;
};

/// Minimal interface that the active health prober (Task 22) requires
/// from the backend directory.  `BackendRegistry` implements this
/// naturally; tests can supply a mock that records transition events
/// without depending on the registry's mutex / threshold bookkeeping.
class IBackendRegistry {
  public:
    virtual ~IBackendRegistry() = default;

    /// Look up a single backend by id (returns nullptr when missing).
    virtual std::optional<Backend> find(BackendId id) const = 0;

    /// Snapshot of backends eligible for active probing (HEALTHY + DEGRADED).
    virtual std::vector<Backend> healthy_snapshot() const = 0;

    /// Report an active-probe failure for backend `id`.  Implementations
    /// decide whether to demote the backend to DEGRADED.
    virtual void report_failure(BackendId id) = 0;

    /// Report an active-probe success for backend `id`.  Implementations
    /// decide whether to restore the backend to HEALTHY.
    virtual void report_success(BackendId id) = 0;
};

/// Thread-safe directory of backends with passive health demotion.
///
/// Implements the `IBackendRegistry` interface so the active health
/// prober (Task 22) can drive `report_*` without depending on the
/// concrete mutex / threshold bookkeeping below.
class BackendRegistry : public IBackendRegistry {
  public:
    /// Default passive-health thresholds.
    static constexpr std::size_t kDefaultFailureThreshold = 3;
    static constexpr std::chrono::seconds kDefaultFailureWindow{10};

    /// Construct with an optional Ketama rebuild callback.  The callback
    /// must outlive the registry or be null.
    explicit BackendRegistry(IKetamaRebuildCallback* ketama_callback = nullptr,
                             std::size_t failure_threshold = kDefaultFailureThreshold,
                             std::chrono::seconds failure_window = kDefaultFailureWindow);

    BackendRegistry(const BackendRegistry&) = delete;
    BackendRegistry& operator=(const BackendRegistry&) = delete;
    BackendRegistry(BackendRegistry&&) = delete;
    BackendRegistry& operator=(BackendRegistry&&) = delete;

    /// Register a backend.  If the id already exists it is overwritten.
    /// State is forced to HEALTHY on registration.
    void register_backend(Backend backend);

    /// Remove a backend.  No-op if the id does not exist.
    void unregister_backend(BackendId id);

    [[nodiscard]] bool replace_all(std::vector<Backend> backends);

    /// Report a passive failure.  When the number of failures reported for
    /// `id` within the configured window exceeds the threshold, the backend
    /// is marked DEGRADED and the Ketama ring is rebuilt.
    void report_failure(BackendId id) override;

    /// Report a success.  Clears the failure window and marks HEALTHY.
    void report_success(BackendId id) override;

    /// Lookup a backend by id.  Returns nullptr if not found.
    std::optional<Backend> find(BackendId id) const override;

    /// Return a snapshot of all currently registered backends.
    std::vector<Backend> snapshot() const;

    /// Return HEALTHY and DEGRADED backends for active recovery probing.
    std::vector<Backend> healthy_snapshot() const override;

    /// Number of registered backends.
    std::size_t size() const;

  private:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    struct FailureRecord {
        std::vector<TimePoint> times;
    };

    mutable std::shared_mutex mutex_;
    IKetamaRebuildCallback* ketama_callback_;
    std::size_t failure_threshold_;
    std::chrono::seconds failure_window_;

    std::unordered_map<BackendId, Backend> backends_;
    std::unordered_map<BackendId, FailureRecord> failures_;

    void rebuild_ketama_locked();
    void prune_failures_locked(BackendId id, TimePoint now);
    void set_state_locked(BackendId id, BackendState new_state);
};

} // namespace packet_engine
