// SPDX-License-Identifier: MIT
//
// rule_table.hpp -- aggregator and atomic-shared-ptr hot reload for the rule
// engine.
//
// Design summary
// ==============
//
// `RuleTable`
// -----------
// A `RuleTable` is an immutable snapshot of the rule store.  Each instance owns
// three hot-path lookup structures and one cold-path state map:
//
//   * `exact_`      -- `OpenAddrHashTable<FiveTuple, RuleEntry, 65536>` for
//                      exact 5-tuple matches.  This is the per-packet fast
//                      path: a single bounded linear probe with prefetched
//                      reads, see `rule_hash.hpp`.
//
//   * `ipv4_trie_`  -- `CidrTrie<IPv4Addr, RuleEntry>` for longest-prefix
//                      match on the packet's destination IPv4.
//
//   * `ipv6_trie_`  -- `CidrTrie<IPv6Addr, RuleEntry>` for longest-prefix
//                      match on the packet's destination IPv6.
//
//   * `rate_limit_state_` -- `std::unordered_map<RuleId, TokenBucket>` that
//                            holds the runtime byte-bucket counters for
//                            rules whose `Action` is `RATE_LIMIT`.  This map
//                            is documented as **COLD PATH ONLY**: it is
//                            written by the control plane when a
//                            `RuleTable` is being built, and read-only at
//                            lookup time.  Per-packet workers only access
//                            it when a rule actually matches AND the rule
//                            is `RATE_LIMIT`.  Hot-path traffic for ALLOW /
//                            DROP / FORWARD_TO_BACKEND never touches this
//                            map.
//
// The `CidrTrie<...>` instantiations carry the full `RuleEntry` as their
// value (not just a `RuleId`) so that the hot-path CIDR hit does not require
// a second lookup of any kind.  This keeps the entire `lookup()` call on the
// fast hash / trie path; the only data structure with non-deterministic
// access on a match is the rate-limit `unordered_map`, and that only fires
// when the rule is actually rate-limited.
//
// `RuleTable` is published via `std::shared_ptr<const RuleTable>`.  All
// mutators (`add_*`) are control-plane-only and refuse to run after the
// table has been frozen by the registry.  In practice the control plane
// builds a fresh `RuleTable`, wraps it in a `shared_ptr<const RuleTable>`,
// and hands it off to the registry.
//
// `RuleTableRegistry`
// -------------------
// The hot-path handle to the rule store.  Holds a
// `std::atomic<std::shared_ptr<const RuleTable>>` (C++20 introduced the
// primary template that makes this type well-defined), and replaces it
// atomically when a new rule set is published.  Readers take a single
// `acquire` load and use the resulting shared pointer for the duration of
// the packet; the old table reference count stays non-zero while any reader
// is still inside `lookup()`, so the table is freed exactly when the last
// reader releases it -- no torn reads, no leaks.
//
// Hot-path lookup:
//   auto t = active_.load(std::memory_order_acquire);
//   return t->lookup(pkt);
//
// `swap(new_table)`:
//   active_.store(new_table, std::memory_order_release);
//
// ALLOW, DROP, and FORWARD matches do not take an application mutex. A
// RATE_LIMIT match updates its byte-rate schedule with a 64-bit atomic CAS.
// The registry does not copy the `RuleTable` on swap.
//
// Thread-safety contract
// ======================
//
//   * `lookup()` may be called concurrently from any number of worker
//     threads, as long as all callers observe the table through a
//     `shared_ptr<const RuleTable>` taken from the same `RuleTableRegistry`.
//
//   * `add_*()` mutators are NOT thread-safe.  They are control-plane only
//     and run while no worker is observing the table.  Publishing a new
//     rule set after the build is the registry's job.
//
// References
// ==========
//
//   * std::atomic<std::shared_ptr<T>>: cppreference.com/w/cpp/memory/shared_ptr/atomic
//   * Linux RCU pattern: lwn.net/Articles/262464/
//   * folly AtomicSharedPtr:
//       github.com/facebook/folly/blob/main/folly/concurrency/AtomicSharedPtr.h
//
#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>

#include "packet-engine/cidr_trie.hpp"
#include "packet-engine/rule_entry.hpp"
#include "packet-engine/rule_hash.hpp"
#include "packet-engine/token_bucket.hpp"
#include "packet-engine/types.hpp"

namespace packet_engine {

class RuleTable;
using RuleTablePtr = std::shared_ptr<const RuleTable>;

// ---------------------------------------------------------------------------
// `RuleTable` -- immutable snapshot of the rule store.
// ---------------------------------------------------------------------------
//
// `RuleTable` is intentionally not `final` for testing subclasses (none are
// shipped, but the test fixture may derive from it to count lookups).
// All members are private; the public surface is `add_*` for the control
// plane and `lookup` for the data plane.
//
class RuleTable {
  public:
    using RuleId = RuleEntry::RuleId;

    struct RateLimitState {
        explicit RateLimitState(TokenBucket initial) noexcept;

        [[nodiscard]] bool try_consume(std::uint64_t bytes, std::uint64_t now_ns) noexcept;
        [[nodiscard]] std::uint64_t rate_bps() const noexcept { return rate_bps_; }
        [[nodiscard]] std::uint64_t burst_bytes() const noexcept { return burst_bytes_; }

      private:
        std::uint64_t rate_bps_;
        std::uint64_t burst_bytes_;
        std::uint64_t interval_reciprocal_q32_;
        std::uint64_t burst_window_ns_;
        std::atomic<std::uint64_t> scheduled_ns_;
        std::atomic<std::uint64_t> zero_rate_tokens_;
    };
    using RateLimitStatePtr = std::shared_ptr<RateLimitState>;

    RuleTable() = default;

    RuleTable(const RuleTable&) = delete;
    RuleTable& operator=(const RuleTable&) = delete;
    RuleTable(RuleTable&&) = delete;
    RuleTable& operator=(RuleTable&&) = delete;

    // -----------------------------------------------------------------------
    // Control-plane builders.  None of these locks: the caller (typically
    // the rule-schema loader, see Task 17) holds the build lock on this
    // table before publishing.
    // -----------------------------------------------------------------------

    /// Add an exact 5-tuple rule.  Returns false if the rule already exists
    /// or the table refuses the insert (over the load factor cap).
    [[nodiscard]] bool add_exact(const FiveTuple& tuple, const RuleEntry& entry) noexcept;

    /// Add an IPv4 CIDR rule.  `prefix_len` is in the inclusive range [0,32];
    /// values > 32 are clamped to 32.  Returns false on trie exhaustion.
    [[nodiscard]] bool add_cidr_v4(IPv4Addr prefix, std::uint8_t prefix_len,
                                   const RuleEntry& entry) noexcept;

    /// Add an IPv6 CIDR rule.  `prefix_len` is clamped to 128.  Returns
    /// false on trie exhaustion.
    [[nodiscard]] bool add_cidr_v6(IPv6Addr prefix, std::uint8_t prefix_len,
                                   const RuleEntry& entry) noexcept;

    /// Register the runtime byte-bucket for a rule whose action is
    /// `RATE_LIMIT`.  Overwrites any existing bucket for that id.
    /// Cold path -- control plane only.
    void add_rate_limit_state(RuleId id, TokenBucket bucket) noexcept;
    void add_rate_limit_state(RuleId id, RateLimitStatePtr state) noexcept;
    [[nodiscard]] RateLimitStatePtr
    matching_rate_limit_state(RuleId id, std::uint64_t rate_bps,
                              std::uint64_t burst_bytes) const noexcept;

    // -----------------------------------------------------------------------
    // Hot-path lookup.
    //
    // Precedence:
    //   1. Exact 5-tuple in `exact_`.
    //   2. CIDR longest-prefix match (v4 then v6) using the packet's
    //      destination address.
    //   3. Otherwise `std::nullopt`.
    //
    // On a `RATE_LIMIT` match, the bucket for the rule's id is consulted.
    // A successful consume returns `Action::RATE_LIMIT`; an exhausted
    // bucket returns `Action::DROP`.  Missing bucket state also returns
    // `Action::DROP` (fail-closed).
    // -----------------------------------------------------------------------
    /// Return the complete matched rule after rate-limit evaluation.  Keeping
    /// the entry (rather than only the action) lets the dataplane honor
    /// FORWARD's explicit backend id without a second table lookup.
    [[nodiscard]] std::optional<RuleEntry> lookup_entry(const ParsedPacket& pkt) const noexcept;
    [[nodiscard]] std::optional<RuleEntry> lookup_entry(const ParsedPacket& pkt,
                                                        std::uint64_t now_ns) const noexcept;

    /// Compatibility projection for callers interested only in the action.
    [[nodiscard]] std::optional<Action> lookup(const ParsedPacket& pkt) const noexcept;

    // -----------------------------------------------------------------------
    // Introspection -- cold path, used by tests and the metrics aggregator.
    // -----------------------------------------------------------------------
    [[nodiscard]] std::size_t exact_count() const noexcept { return exact_.size(); }
    [[nodiscard]] std::size_t cidr_v4_count() const noexcept { return ipv4_trie_.size(); }
    [[nodiscard]] std::size_t cidr_v6_count() const noexcept { return ipv6_trie_.size(); }
    [[nodiscard]] std::size_t rate_limit_count() const noexcept { return rate_limit_state_.size(); }

  private:
    /// Shared implementation: post-process a matched `RuleEntry` to produce
    /// the final `Action` (consumes a token bucket for RATE_LIMIT rules).
    [[nodiscard]] Action finalize_action_(const RuleEntry& entry, const ParsedPacket& pkt,
                                          std::uint64_t now_ns) const noexcept;

    // Hot-path structures -- populated by the control plane, read-only on
    // the data plane.
    OpenAddrHashTable<FiveTuple, RuleEntry, 65536> exact_{};
    CidrTrie<IPv4Addr, RuleEntry, 8192> ipv4_trie_{};
    CidrTrie<IPv6Addr, RuleEntry, 8192> ipv6_trie_{};

    // -----------------------------------------------------------------------
    // ⚠️  COLD PATH ONLY ⚠️
    //
    // This is the **only** data structure on the hot path that is allowed to
    // be an `std::unordered_map`, because it is read-only from the data
    // plane's perspective -- workers only `find()` existing entries, never
    // insert or resize.  The control plane populates it before publishing.
    //
    // Rate-limit state is shared safely across workers and identical live
    // reloads through its atomic byte-rate schedule.
    // -----------------------------------------------------------------------
    std::unordered_map<RuleId, RateLimitStatePtr> rate_limit_state_{};
};

// ---------------------------------------------------------------------------
// `RuleTableRegistry` -- atomic shared_ptr handle for the active rule set.
// ---------------------------------------------------------------------------
//
// The hot path uses `RuleTablePtr active() const`; the control plane uses
// `swap(new_table)`.  All operations on `active_` go through the standard
// `std::atomic<std::shared_ptr<T>>` interface introduced in C++20.
//
// The atomic shared pointer provides safe publication but is not guaranteed
// to be lock-free by the C++ standard.  Implementations may use an internal
// lock for reference-count updates; dataplane correctness does not depend on
// `is_lock_free()` returning true.
//
class RuleTableRegistry {
  public:
    RuleTableRegistry() = default;

    /// Construct with an initial empty rule set (matches return nullopt).
    explicit RuleTableRegistry(RuleTablePtr initial) noexcept;

    RuleTableRegistry(const RuleTableRegistry&) = delete;
    RuleTableRegistry& operator=(const RuleTableRegistry&) = delete;

    /// Acquire-load the active table pointer.  Callers may use the resulting
    /// shared_ptr for as long as they need; the registry keeps the old
    /// table alive exactly until the last reader drops its reference.
    [[nodiscard]] RuleTablePtr active() const noexcept;

    /// Publish a new rule table.  Replaces the active pointer with a
    /// release-store; old readers continue to observe the table they
    /// loaded before the swap, while new readers see `new_table`.
    ///
    /// `new_table` is moved in; ownership transfers to the registry, but
    /// the registry's copy may be dropped immediately if no concurrent
    /// reader holds a reference (reference counting handles that case
    /// without a use-after-free).
    void swap(RuleTablePtr new_table) noexcept;

    /// Convenience: hot-path lookup using the currently active table.
    /// Single acquire load and no allocation by this layer.
    [[nodiscard]] std::optional<Action> lookup(const ParsedPacket& pkt) const noexcept;

    /// Complete-rule variant used by the packet processor.
    [[nodiscard]] std::optional<RuleEntry> lookup_entry(const ParsedPacket& pkt) const noexcept;

    /// Returns true if the underlying atomic is lock-free.  Used by tests
    /// to verify we are getting the fast path.
    [[nodiscard]] static bool is_lock_free() noexcept {
        std::atomic<RuleTablePtr> probe{};
        return probe.is_lock_free();
    }

  private:
    std::atomic<RuleTablePtr> active_{};
};

namespace detail {

/// Build a `FiveTuple` view from a `ParsedPacket`.  Trivial helper exposed
/// here so the implementation file can stay header-free of knowledge about
/// `ParsedPacket`'s layout.
inline FiveTuple five_tuple_from(const ParsedPacket& pkt) noexcept {
    return FiveTuple{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto};
}

/// Steady-clock nanoseconds since the monotonic epoch.  Used by the rate
/// limiter's per-batch cache when the worker has not supplied a timestamp.
inline std::uint64_t steady_now_ns() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

} // namespace detail

} // namespace packet_engine
