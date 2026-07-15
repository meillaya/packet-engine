// SPDX-License-Identifier: MIT
//
// conntrack.hpp -- 5-tuple flow cache with TCP state tracking and idle eviction.
//
// Design notes
// ============
//
// * Hot path is `lookup_or_create(five_tuple, args) -> FlowEntry&`.  It is a
//   bounded-probe hash lookup against `OpenAddrHashTable<FiveTuple, FlowEntry,
//   65536>` from rule_hash.hpp (Task 13).  On a miss we create a `NEW` entry
//   with the supplied backend / endpoint identity and stamp `last_seen_ns =
//   now_ns`.  On a hit we refresh `last_seen_ns` and transition the TCP state
//   from the incoming TCP flags.
//
// * TCP state machine (mirrors the conntrack semantics required by the plan,
//   not the full RFC 9293 §3.5 super-set):
//
//       NEW --SYN----------> SYN_SENT
//       SYN_SENT --SYN|ACK--> ESTABLISHED
//       SYN_SENT --ACK------> ESTABLISHED
//       ESTABLISHED --FIN---> FIN_WAIT
//       FIN_WAIT --ACK------> CLOSED
//       ANY --RST-----------> CLOSED
//       CLOSED --*-----------> CLOSED   (terminal)
//
//   When multiple flags arrive on the same packet, RST dominates (terminal),
//   then FIN dominates SYN/ACK, then SYN+ACK > SYN > ACK (the canonical
//   "three-way handshake" response ordering).
//
// * Eviction is incremental.  `OpenAddrHashTable` does not expose its slots
//   for iteration, so the cache maintains a parallel `std::vector<FiveTuple>`
//   (the *eviction index*) that mirrors insertion order.  `evict_idle()`
//   sweeps a slice of the index per call, calling back into the hash table
//   for `last_seen_ns` reads; idle entries are erased from both stores.
//
// * The cache is a **single-writer** structure: the lookup hot path and
//   `evict_idle()` must be invoked from the same packet-worker thread.  The
//   runtime schedules bounded eviction slices from that loop, preserving the
//   table's synchronization contract without a background-thread race.
//
// References:
//   * Plan Task 20 (lines 1453-1506 of packet-engine.md).
//   * Linux nf_conntrack: https://docs.kernel.org/networking/nf_conntrack.html
//   * RFC 9293 §3.5 -- TCP state machine.
//
#pragma once

#include "packet-engine/backend_registry.hpp" // for BackendId
#include "packet-engine/rule_hash.hpp"
#include "packet-engine/types.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace packet_engine {

// ---------------------------------------------------------------------------
// TCP control-flag bitmask.  Matches the layout of the TCP header's flags
// byte; only the four flags we transition on are defined because the others
// (URG, ECE, CWR, PSH) do not drive conntrack state.
// ---------------------------------------------------------------------------
namespace TcpFlags {
constexpr std::uint8_t FIN = 0x01;
constexpr std::uint8_t SYN = 0x02;
constexpr std::uint8_t RST = 0x04;
constexpr std::uint8_t ACK = 0x10;
} // namespace TcpFlags

/// Coarse TCP lifecycle state used for the conntrack state machine.
///
/// The enum values are the canonical conntrack ordering; the numeric values
/// are not significant -- transitions are driven by the `transition_tcp_state`
/// helper below.
enum TcpState : std::uint8_t {
    NEW = 0,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED,
};

/// Per-flow record stored at every slot of the flow cache.
///
/// `alignas(8)` keeps the layout predictable relative to `FiveTuple` (which is
/// also `alignas(8)`) so that the two cache-line footprint in the hash table
/// remains stable.
struct alignas(8) FlowEntry {
    BackendId backend{0};          // selected backend identifier
    std::uint64_t client_ip{0};    // original client IPv4 (host byte order)
    std::uint16_t client_port{0};  // original client L4 port (host byte order)
    std::uint64_t backend_ip{0};   // chosen backend IPv4 (host byte order)
    std::uint16_t backend_port{0}; // chosen backend L4 port (host byte order)
    std::uint16_t engine_sport{0}; // engine-allocated source port (host byte order)
    std::uint16_t service_port{0}; // original destination port on the engine VIP (host byte order)
    MacAddr client_mac{};
    MacAddr engine_mac{};
    MacAddr backend_mac{};
    TcpState tcp_state{TcpState::NEW};
    std::uint64_t last_seen_ns{0}; // monotonic-clock ns since last packet
};

/// Create-on-miss arguments for `lookup_or_create()`.
///
/// On a cache hit only `tcp_flags` and `now_ns` are consulted (used to
/// refresh `last_seen_ns` and transition the TCP state).  On a miss every
/// field is consumed to populate the fresh `NEW` entry.
struct ConntrackLookupArgs {
    BackendId backend{0};
    std::uint64_t client_ip{0};
    std::uint16_t client_port{0};
    std::uint64_t backend_ip{0};
    std::uint16_t backend_port{0};
    std::uint16_t engine_sport{0}; // engine-allocated source port (forward-NAT)
    std::uint16_t service_port{0}; // original destination port on the engine VIP (host byte order)
    MacAddr client_mac{};
    MacAddr engine_mac{};
    MacAddr backend_mac{};
    std::uint8_t tcp_flags{0};
    std::uint64_t now_ns{0};
};

/// 5-tuple -> FlowEntry cache backed by `OpenAddrHashTable`.
///
/// Single-writer -- lookups and evictions must run on the same thread.
class ConntrackFlowCache {
  public:
    using EvictionHandler = void (*)(void* context, const FlowEntry& entry) noexcept;
    /// Default per-flow idle TTL: 120 seconds.  Matches the kernel conntrack
    /// default (`nf_conntrack_tcp_timeout_established`) and the plan's
    /// acceptance criterion verbatim.
    static constexpr std::uint64_t kDefaultIdleTimeoutNs = 120ULL * 1'000'000'000ULL;

    /// Default eviction slice size.  At ~100k active flows, scanning 1024
    /// entries per tick keeps each call comfortably under the 100 ms / scan
    /// acceptance budget (1024 probes -> ~50 us).
    static constexpr std::size_t kDefaultEvictionSlice = 1024;

    /// Number of slots in the underlying hash table.  Pinned by the plan to
    /// `2^16`; the cache's effective capacity is `kCapacity / 2 = 32768`
    /// entries due to the table's `kMaxSize = kLoadFactorCap` clamp.
    static constexpr std::size_t kCapacity = 65536;

    ConntrackFlowCache() noexcept = default;

    ConntrackFlowCache(const ConntrackFlowCache&) = delete;
    ConntrackFlowCache& operator=(const ConntrackFlowCache&) = delete;
    ConntrackFlowCache(ConntrackFlowCache&&) = delete;
    ConntrackFlowCache& operator=(ConntrackFlowCache&&) = delete;
    ~ConntrackFlowCache() = default;

    /// Look up `key` (and create it on miss), returning a reference to the
    /// stored entry.  Always succeeds:  the table reserves `kLoadFactorCap`
    /// slots before refusing, and the steady-state flow count under
    /// sustained 10 Gb/s is well under that cap.  The table will refuse only
    /// under pathological over-insert -- a defensive `std::abort` is the
    /// safest outcome at that point.
    [[nodiscard]] FlowEntry& lookup_or_create(const FiveTuple& key,
                                              const ConntrackLookupArgs& args) noexcept;

    [[nodiscard]] FlowEntry* try_lookup_or_create(const FiveTuple& key,
                                                  const ConntrackLookupArgs& args) noexcept;

    /// Inspect (but don't create) the entry for `key`.  Returns nullptr on
    /// miss.  Does not refresh `last_seen_ns` -- use `lookup_or_create()`
    /// from the per-packet path.
    [[nodiscard]] FlowEntry* peek(const FiveTuple& key) noexcept;
    [[nodiscard]] const FlowEntry* peek(const FiveTuple& key) const noexcept;
    [[nodiscard]] FlowEntry* touch(const FiveTuple& key, std::uint64_t now_ns,
                                   std::uint8_t tcp_flags) noexcept;

    [[nodiscard]] bool bind_translation(const FiveTuple& translated_key,
                                        const FiveTuple& original_key) noexcept;
    [[nodiscard]] FlowEntry* peek_translation(const FiveTuple& translated_key) noexcept;
    [[nodiscard]] const FlowEntry* peek_translation(const FiveTuple& translated_key) const noexcept;
    [[nodiscard]] FlowEntry* touch_translation(const FiveTuple& translated_key,
                                               std::uint64_t now_ns,
                                               std::uint8_t tcp_flags) noexcept;

    [[nodiscard]] bool erase(const FiveTuple& original_key) noexcept;

    void set_eviction_handler(void* context, EvictionHandler handler) noexcept;
    void clear_eviction_handler(void* context) noexcept;

    /// Incrementally evict idle flows.  Scans at most `slice` entries of the
    /// eviction index and erases those whose `last_seen_ns` is more than
    /// `idle_timeout_ns` in the past relative to `now_ns`.  Returns the
    /// number of entries removed by THIS call (useful for tests and metric
    /// exposition).  Cursor wraps at end-of-index, so a full table can be
    /// swept in `O(eviction_keys_.size() / slice)` calls.
    ///
    /// `slice = SIZE_MAX` means "scan the entire index in one call" (used by
    /// the perf test).  Internally we always cap `slice` at the remaining
    /// entries from the cursor to keep the sweeper amortised.
    std::size_t evict_idle(std::uint64_t now_ns,
                           std::uint64_t idle_timeout_ns = kDefaultIdleTimeoutNs,
                           std::size_t slice = kDefaultEvictionSlice) noexcept;

    /// Number of live entries in the cache (equal to `table_.size()`).
    [[nodiscard]] std::size_t size() const noexcept { return table_.size(); }

    [[nodiscard]] bool empty() const noexcept { return table_.empty(); }

    /// Live capacity available under the table's load-factor cap.  Useful
    /// for adaptive callers that want to stay ahead of the refusal threshold.
    [[nodiscard]] std::size_t remaining_capacity() const noexcept;

    /// Wipe both the hash table and the eviction index.
    void clear() noexcept;

    /// Apply the TCP state machine to `state` based on `flags`.  Exposed for
    /// tests that want to assert the function in isolation from the cache.
    /// `flags` is interpreted as the standard TCP header flags byte.
    static void transition_tcp_state(TcpState& state, std::uint8_t flags) noexcept;

  private:
    OpenAddrHashTable<FiveTuple, FlowEntry, kCapacity> table_;
    OpenAddrHashTable<FiveTuple, FiveTuple, kCapacity> translations_;

    // Auxiliary index used for incremental eviction.  Append-on-insert,
    // swap-remove-on-evict so the vector stays compact; the cursor wraps
    // freely.  Duplicating the keys costs 16 B per slot but avoids any need
    // to bolt iteration onto OpenAddrHashTable.  Thread-safety: only the
    // eviction sweep touches this from its writer thread.
    std::vector<FiveTuple> eviction_keys_;
    std::size_t evict_cursor_{0};

    void* eviction_context_{nullptr};
    EvictionHandler eviction_handler_{nullptr};
    void notify_eviction(const FlowEntry& entry) noexcept;
    void erase_translation(const FiveTuple& original_key, const FlowEntry& entry) noexcept;
};

} // namespace packet_engine
