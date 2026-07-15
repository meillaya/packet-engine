// SPDX-License-Identifier: MIT
//
// backend_dpdk.hpp -- one-queue DPDK ethdev backend.
//
// Design
// ======
//
// `DpdkBackend` is the optional alternative datapath for the packet engine.
// It mirrors `AfXdpBackend` so the rest of the engine does not need to know
// which backend is in use.
//
// Instead of talking to the kernel directly via AF_XDP, `DpdkBackend`
// initialises DPDK's EAL and a single named or numeric port, and exposes:
//
//   * `init(argc, argv)`     -- calls `rte_eal_init(argc, argv)`, allocates
//                               an mbuf pool, configures the port with one RX
//                               and one TX queue, and starts the port.
//   * `recv_batch(out, max)` -- wraps `rte_eth_rx_burst` and writes one
//                               `PacketDescriptor` per received mbuf.
//   * `send_batch(pkts, n)`  -- wraps `rte_eth_tx_burst`.
//
// Translation: DPDK mbufs are heap-resident (`rte_mbuf*`) rather than
// slice-into-UMEM descriptors, so the `PacketDescriptor::offset` field
// carries the mbuf pointer as `reinterpret_cast<std::uintptr_t>` -- see
// `mbuf_handle_to_desc()` / `desc_to_mbuf()` for the contract.  Length,
// queue_id, and timestamp_ns are propagated through the public descriptor
// type unchanged so downstream code paths remain backend-agnostic.
//
// Outstanding RX mbufs remain application-owned until `release_pending(n)`
// drops them or an accepted TX prefix transfers them to the PMD.  Teardown
// reclaims only application-owned mbufs.
//
// All public methods are wrapped in `#ifdef HAVE_DPDK` in the .cpp so the
// class definition can be included unconditionally by callers using an
// `#ifndef ENABLE_DPDK` build.  When DPDK is disabled the class is a
// no-op stub throwing `std::runtime_error` from `init()`.
//
// Threading
// =========
//
// Construction / `init()` / destruction are single-threaded.  Hot-path
// `recv_batch()` / `send_batch()` are intended for one worker thread per
// queue, matching `AfXdpBackend` exactly.
//
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "packet-engine/types.hpp"

#ifdef HAVE_DPDK
// Forward declarations for the few DPDK types we touch from the header.
// Keeping the full DPDK include out of the public header means callers
// can include `backend_dpdk.hpp` without dragging in the entire EAL
// surface.  The `.cpp` includes the full headers.
struct rte_mempool;
struct rte_mbuf;
#endif // HAVE_DPDK

namespace packet_engine {

// ---------------------------------------------------------------------------
// DpdkBackend
// ---------------------------------------------------------------------------
class DpdkBackend {
  public:
    /// Default mbuf pool capacity.  DPDK requires this to be a power-of-two
    /// minus 1 is *not* required; we use a comfortable round number that
    /// covers a typical burst load without overcommitting hugepages.
    static constexpr std::uint32_t NUM_MBUFS = 8192;

    /// Default data-room size for each mbuf.  Must be large enough for the
    /// longest frame the engine will see + L2 headers + headroom.
    /// 2048 covers a single 1500-byte Ethernet payload with headroom.
    static constexpr std::uint32_t MBUF_DATA_ROOM = 2048;

    /// Cache size for per-lcore mbuf pool caches.  Smaller than the pool
    /// capacity; tunes the trade-off between pool contention and per-lcore
    /// memory waste.
    static constexpr std::uint32_t MBUF_CACHE_SIZE = 250;

    /// Default batch size for `recv_batch` / `send_batch`.  64 is enough
    /// to keep the worker loop amortised across syscall overhead without
    /// crossing any of DPDK's divisibility-by-8 hints.
    static constexpr std::uint32_t BATCH_SIZE = 64;

    /// Construct without touching DPDK.  `port_id` and `queue_id` are the
    /// DPDK-side identifiers; `pool_name` is the human-readable name of
    /// the mbuf pool to allocate.  All DPDK resource allocation happens
    /// in `init()`.
    explicit DpdkBackend(std::uint16_t port_id = 0, std::uint16_t queue_id = 0,
                         std::string_view pool_name = "mbuf_pool") noexcept;

    /// Select a DPDK ethdev by its stable name after EAL creates the devices.
    explicit DpdkBackend(std::string_view port_name, std::uint16_t queue_id = 0,
                         std::string_view pool_name = "mbuf_pool") noexcept;

    ~DpdkBackend();

    DpdkBackend(const DpdkBackend&) = delete;
    DpdkBackend& operator=(const DpdkBackend&) = delete;
    DpdkBackend(DpdkBackend&&) = delete;
    DpdkBackend& operator=(DpdkBackend&&) = delete;

    /// Initialise DPDK EAL and bring the selected port up.
    ///
    /// @param argc  Forwarded to `rte_eal_init`; the main binary is
    ///              expected to supply a mutable argv whose first element is
    ///              a program name, followed only by EAL arguments.
    /// @param argv  Same forwarding convention as `argc`.
    ///
    /// Throws `std::runtime_error` on any DPDK failure.  Idempotent only
    /// in the cold sense; calling twice fails the second time.
    void init(int argc, char** argv);

    // ---------------------------------------------------------------------
    // RX path
    // ---------------------------------------------------------------------

    /// Drain up to `max` received packets into `out`.  Each output
    /// descriptor carries the mbuf pointer in its `offset` field (cast as
    /// `std::uintptr_t`) so the engine can free the mbuf later via
    /// `release_pending()`.  Returns the number of descriptors written.
    [[nodiscard]] std::uint32_t recv_batch(PacketDescriptor* out, std::uint32_t max);

    /// Borrow the bytes of an application-owned, single-segment packet.
    /// The view becomes invalid when TX accepts or release_pending frees it.
    [[nodiscard]] std::span<std::byte> packet_span(const PacketDescriptor& packet) noexcept;
    [[nodiscard]] std::span<const std::byte>
    packet_span(const PacketDescriptor& packet) const noexcept;

    /// Release up to `n` outstanding RX mbufs.  Mirrors
    /// `AfXdpBackend::recycle_completions`.  Returns the number actually
    /// released (may be less than `n` if the ring is short).
    [[nodiscard]] std::uint32_t release_pending(std::uint32_t n);

    /// Always false for DPDK: the `rte_eth_rx_burst` API is non-blocking
    /// and returns 0 when there is nothing to read.  Provided so the
    /// worker loop's "should we sleep?" branch has a uniform shape across
    /// both backends.
    [[nodiscard]] bool needs_wakeup_rx() const noexcept { return false; }

    // ---------------------------------------------------------------------
    // TX path
    // ---------------------------------------------------------------------

    /// Submit up to `n` outgoing packet descriptors.  Each `pkts[i].offset`
    /// is interpreted as a `rte_mbuf*` obtained from a prior `recv_batch`
    /// (the mbuf is reused as the TX frame).  Returns the number actually
    /// transmitted.  Only the accepted prefix transfers to the PMD; the
    /// rejected suffix remains application-owned for retry or release.
    [[nodiscard]] std::uint32_t send_batch(const PacketDescriptor* pkts, std::uint32_t n);

    /// Always false for DPDK: `rte_eth_tx_burst` drains its inputs; if
    /// the TX queue is full the surplus is returned for caller to retry.
    [[nodiscard]] bool needs_wakeup_tx() const noexcept { return false; }

    // ---------------------------------------------------------------------
    // Observers (used by metrics + tests)
    // ---------------------------------------------------------------------

    [[nodiscard]] bool is_initialised() const noexcept { return port_started_; }
    [[nodiscard]] std::uint16_t port_id() const noexcept { return port_id_; }
    [[nodiscard]] std::uint16_t queue_id() const noexcept { return queue_id_; }
    [[nodiscard]] const std::string& port_name() const noexcept { return port_name_; }
    [[nodiscard]] const std::string& pool_name() const noexcept { return pool_name_; }

    /// Number of mbufs currently held by the backend awaiting
    /// `release_pending()`.  Useful for tests and the `/metrics` exporter.
    [[nodiscard]] std::size_t pending_count() const noexcept { return pending_rx_mbufs_.size(); }

  private:
    void cleanup() noexcept;

#ifdef HAVE_DPDK
    [[nodiscard]] bool owns_mbuf(const rte_mbuf* mbuf) const noexcept;
    [[nodiscard]] bool track_mbuf(rte_mbuf* mbuf, std::uint32_t index) noexcept;
    [[nodiscard]] bool tracked_index(const rte_mbuf* mbuf, std::uint32_t& index) const noexcept;
    void untrack_mbuf(const rte_mbuf* mbuf) noexcept;
    void update_tracked_index(const rte_mbuf* mbuf, std::uint32_t index) noexcept;
    void compact_pending() noexcept;

    struct OwnershipSlot {
        rte_mbuf* mbuf{nullptr};
        std::uint32_t pending_index{0};
    };
    static constexpr std::size_t kOwnershipSlots = NUM_MBUFS * 2u;
#endif

    std::uint16_t port_id_{0};
    std::uint16_t queue_id_{0};
    std::string port_name_{};
    std::string pool_name_{};
    bool select_port_by_name_{false};

    // DPDK-managed; non-owned.  Touched only when `port_started_` is true.
#ifdef HAVE_DPDK
    rte_mempool* mbuf_pool_{nullptr};
#endif
    bool eal_initialised_{false};
    bool port_configured_{false};
    bool port_started_{false};

    // Outstanding RX mbufs that have been handed to the worker but not yet
    // released.  Bounded to NUM_MBUFS so we cannot leak more than the pool
    // size even if the worker never drains the ring.
    std::vector<
#ifdef HAVE_DPDK
        rte_mbuf*
#else
        void*
#endif
        >
        pending_rx_mbufs_{};

#ifdef HAVE_DPDK
    std::unique_ptr<std::array<OwnershipSlot, kOwnershipSlots>> ownership_slots_{};
#endif

    // TX scratch buffer for the mbuf pointers passed to `rte_eth_tx_burst`.
    // Allocated once on first send to keep the hot path allocation-free.
    std::vector<
#ifdef HAVE_DPDK
        rte_mbuf*
#else
        void*
#endif
        >
        tx_scratch_{};
};

} // namespace packet_engine
