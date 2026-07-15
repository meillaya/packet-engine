// SPDX-License-Identifier: MIT
//
// ketama.hpp -- Ketama consistent-hash ring (160 virtual nodes per backend,
// MD5-based) used by the load balancer.
//
// Algorithm
// =========
//
// Ketama is the de-facto consistent-hash ring originally written for
// memcached's libketama and now standardised in Couchbase's SDK-RFC 0026.
// Each backend (a.k.a. server) is replicated as **160 virtual nodes**
// distributed on a 32-bit continuum.  Lookups hash a flow key to a 32-bit
// position and walk clockwise to find the first continuum point, which
// belongs to a particular backend.  Removing a backend only invalidates
// the keys that hashed into its slice -- that's the rebalance property:
// keys per backend are stable across cluster changes up to a 1/N fraction
// (N = number of backends).
//
// Point generation
// ----------------
//
// For every backend address `addr` and every replica index `i` in [0, 40)
// we MD5-hash the string `addr-i`, take the 128-bit digest, and extract
// four 32-bit continuum points by reading the digest as four
// little-endian u32s.  This is exactly the layout libketama.c uses
// (`(digest[3] << 24) | (digest[2] << 16) | (digest[1] << 8) | digest[0]`)
// with the index running 0..160 -- four points per replica, 40 replicas,
// 160 points per backend.
//
// We then sort the resulting `ContinuumPoint`s once by their `point_hash`
// so the lookup is a single binary search (lower_bound + wrap-around) and
// O(log N) in the number of continuum points, exactly as Ketama mandates.
//
// Hot-path lookup
// ---------------
//
// `pick(key)` is the only per-packet call site.  It does:
//   1. A small, allocation-free MD5 of the canonical 5-tuple serialisation.
//   2. A 32-bit binary search (`std::lower_bound`) over `ring_`.
//   3. A wrap-around index selection on miss -- one branch.
//
// The MV lookup function keeps three guarantees:
//   * `noexcept` -- the hot path must not throw.
//   * O(log R) operations where R = number of continuum points (R = 160*N).
//   * Zero allocations on the hot path.
//
// The atomic swap / rebuild discipline:
// -------------------------------------
//
// `add_backend` and `remove_backend` operate on the cold path.  They
// create a fresh `ContinuumSnapshot` (a `std::shared_ptr<const
// ContinuumSnapshot>`) and store it via `std::atomic::store(release)`.  A
// concurrent reader picks up the new snapshot via `active_.load(acquire)`
// and proceeds; the old snapshot stays alive exactly until the last reader
// drops it -- the canonical C++20 atomic-shared-ptr pattern (mirrors the
// `RuleTableRegistry` design in `rule_table.hpp`).
//
// `std::atomic<std::shared_ptr<T>>` is **required** by the C++20 standard
// to be torn-read-free.  On glibc/libstdc++ the implementation may fall
// back to an internal mutex if the platform cannot do a double-word CAS,
// but the hot path is still correct -- we just pay a small cost on
// platforms where the underlying type is not actually lock-free.
//
// Cold-path `id_map_`
// -------------------
//
// `id_map_` is built once per `add_*` / `remove_*` call.  It is the only
// `std::unordered_map` on the class, and per the plan it stays a cold-path
// structure: readers never traverse it on the per-packet path.  The hot
// path uses `ring_` and the snapshot pointer exclusively.
//
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "packet-engine/types.hpp"

namespace packet_engine {

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Numeric identifier for a backend on the Ketama ring (the wire-format
/// id assigned by the control plane).  Stable across rebuilds -- adding
/// or removing backends does not reassign existing ids.  Unknown /
/// removed ids surface as `INVALID_KETAMA_BACKEND_ID` from `pick()`.
///
/// `KetamaBackendId` is deliberately distinct from the `BackendId`
/// defined by `backend_registry.hpp` (which is `uint64_t`).  They live
/// in the same namespace, so two `using` declarations of the same name
/// would collide -- hence the `Ketama` prefix here.  In practice, the
/// Ketama id is a 32-bit continuum index that maps 1:1 onto a
/// `backend_registry::BackendId` via the `address` string at ring build
/// time.  See Task 21 (`nat.cpp`) for the integration glue.
using KetamaBackendId = std::uint32_t;
inline constexpr KetamaBackendId INVALID_KETAMA_BACKEND_ID = 0xFFFF'FFFFu;

/// A backend submitted to the `KetamaRing`.  `address` is the canonical
/// string used to seed the continuum points ("10.0.0.1:11211" is the
/// libketama convention; any ASCII string that uniquely identifies the
/// backend is fine).
///
/// Named `KetamaBackend` to coexist with `backend_registry::Backend`
/// (which carries state + health_port).  At ring-build time the
/// registry-provided `id` is used here as `id` and the canonical
/// "ip:port" string as `address`.
struct KetamaBackend {
    KetamaBackendId id{};
    std::string address;
};

/// A single continuum point: the 32-bit hash of the point and the
/// backend it routes to.  Sorted by `point_hash` in the ring.
struct alignas(8) ContinuumPoint {
    std::uint32_t point_hash{};
    KetamaBackendId backend_id{INVALID_KETAMA_BACKEND_ID};
};

/// Immutable snapshot of the ring + id map.  Used by the atomic swap
/// pattern; tests reach into this for introspection.
class ContinuumSnapshot {
  public:
    /// Sorted list of all continuum points (160 × |backends| entries).
    [[nodiscard]] const std::vector<ContinuumPoint>& ring() const noexcept { return ring_; }

    /// Cold-path map from address string -> KetamaBackendId.  Built once per
    /// snapshot.  Reads are O(1) but never taken on the per-packet path.
    [[nodiscard]] const std::unordered_map<std::string, KetamaBackendId>& id_map() const noexcept {
        return id_map_;
    }

    [[nodiscard]] std::size_t size() const noexcept { return ring_.size(); }
    [[nodiscard]] std::size_t backend_count() const noexcept { return id_map_.size(); }

    [[nodiscard]] bool empty() const noexcept { return ring_.empty(); }

  private:
    friend class KetamaRing;
    std::vector<ContinuumPoint> ring_{};
    std::unordered_map<std::string, KetamaBackendId> id_map_{};
};

using ContinuumSnapshotPtr = std::shared_ptr<const ContinuumSnapshot>;

// ---------------------------------------------------------------------------
// `KetamaRing`
// ---------------------------------------------------------------------------
//
// The Ketama ring itself.  Constructed with the initial backend set; mutated
// at runtime via `add_backend` / `remove_backend`.  Each mutation rebuilds
// the snapshot under a `std::mutex` and atomically swaps the snapshot
// pointer; readers see either the old snapshot or the new snapshot, never a
// torn intermediate state.
//
class KetamaRing {
  public:
    /// Number of continuum points per backend (libketama spec).
    static constexpr std::uint32_t kPointsPerBackend = 160;
    /// Number of MD5 replicas per backend.  Each replica contributes 4
    /// continuum points extracted from the digest.  40 × 4 = 160.
    static constexpr std::uint32_t kReplicasPerBackend = 40;
    /// Number of 32-bit points per replica (= MD5 size in u32s).
    static constexpr std::uint32_t kPointsPerReplica = 4;

    KetamaRing() = default;

    /// Build a ring with an initial backend set.  Empty input is allowed;
    /// `pick()` returns `INVALID_KETAMA_BACKEND_ID` until at least one backend
    /// has been added.
    explicit KetamaRing(std::vector<KetamaBackend> backends);

    KetamaRing(const KetamaRing&) = delete;
    KetamaRing& operator=(const KetamaRing&) = delete;

    /// Pick a backend for `key`.  Returns `INVALID_KETAMA_BACKEND_ID` when the
    /// ring is empty.  This is the **hot path** -- noexcept, zero
    /// allocations, O(log R) where R = ring size.
    [[nodiscard]] KetamaBackendId pick(const FiveTuple& key) const noexcept;

    /// Pick a backend for an arbitrary 32-bit hash.  Useful for testing
    /// and for callers that have already hashed the key themselves.
    [[nodiscard]] KetamaBackendId pick_hash(std::uint32_t key_hash) const noexcept;

    /// Add a backend atomically.  Rebuilds the ring and publishes the new
    /// snapshot.  Returns false if the address already exists -- we never
    /// silently overwrite entries.
    [[nodiscard]] bool add_backend(const KetamaBackend& b);

    /// Remove a backend by id.  Rebuilds the ring and publishes the new
    /// snapshot.  Returns false if `id` was not present.
    [[nodiscard]] bool remove_backend(KetamaBackendId id);

    [[nodiscard]] bool replace_backends(std::vector<KetamaBackend> backends);

    /// Introspection -- cold path.
    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] std::size_t backend_count() const noexcept;

    /// Acquire the current snapshot for diagnostic purposes.  NOT on the
    /// hot path; `pick()` already takes the snapshot internally.
    [[nodiscard]] ContinuumSnapshotPtr snapshot() const noexcept;

  private:
    /// Build a new snapshot from the current backend map.
    [[nodiscard]] ContinuumSnapshotPtr rebuild_() const;

    /// Build a snapshot from an explicit list of backends.
    [[nodiscard]] ContinuumSnapshotPtr build_(std::vector<KetamaBackend> backends) const;

    /// The active snapshot -- atomic shared pointer.
    std::atomic<ContinuumSnapshotPtr> active_{};

    /// Backends keyed by id, used by the cold-path rebuild.
    std::unordered_map<KetamaBackendId, std::string> backends_by_id_;
    /// Backends keyed by address string, used by the cold-path rebuild.
    std::unordered_map<std::string, KetamaBackendId> backends_by_addr_;

    /// Mutex protecting the cold-path state during add / remove rebuilds.
    mutable std::mutex mutate_mu_;
};

// ---------------------------------------------------------------------------
// Detail helpers (exposed for tests; not for hot-path callers).
// ---------------------------------------------------------------------------

namespace detail {

/// Generate 160 continuum points for a single backend address.  Returns a
/// stable, sorted vector.  Exposed for unit tests that want to verify the
/// Ketama point-generation contract directly.
[[nodiscard]] std::vector<ContinuumPoint>
ketama_points_for_backend(KetamaBackendId id, std::string_view address) noexcept;

} // namespace detail

} // namespace packet_engine
