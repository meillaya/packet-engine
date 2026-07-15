// SPDX-License-Identifier: MIT
//
// datapath_loop.hpp -- RX/TX polling loops with XDP_USE_NEED_WAKEUP and
// SPSC ring fan-out.
//
// Design
// ======
//
// Two thread entry points live here:
//
//   * `run_rx_loop` drains the AF_XDP RX ring in `BATCH_SIZE` chunks, hashes
//     each packet's 5-tuple to pick a worker SPSC ring, and pushes the
//     `PacketDescriptor` into that ring.  When a worker ring is full, the
//     packet is dropped and a counter is incremented.  Idle ticks honour
//     `XDP_USE_NEED_WAKEUP`: the kernel signals via the FILL ring's
//     `XDP_RING_NEED_WAKEUP` flag when it would benefit from a `poll()`.
//
//   * `run_tx_loop` pops up to `BATCH_SIZE` packets from a single SPSC
//     ring (workers feed it), submits them via the AF_XDP TX ring, and
//     recycles the resulting completions back to the `FrameAllocator`.
//
// Threading & hot-path constraints
// ================================
//
//   * No virtual dispatch per packet.  The hash, the ring push, and the
//     `xsk_ring_prod__needs_wakeup` check are all inlinable.
//   * No `sleep()` -- the idle path uses `sched_yield()` (and `poll()` when
//     the kernel asked for it).
//   * Prefetch is bounded: we look at most `PREFETCH_DISTANCE` packets
//     ahead, well inside the L1 streaming window.  Unbounded prefetch
//     is a known cache pollution hazard (Drepper, "What every programmer
//     should know about memory", sec. 6).
//
// Testability
// ===========
//
// The hot path is factored into single-iteration helpers
// (`run_rx_iteration`, `run_tx_iteration`) so unit tests can drive them
// deterministically without spawning a thread or racing on a stop flag.
// A `PollFn` function pointer lets tests substitute a counting stub for
// `::poll` without dragging the real syscall into a unit test -- the
// substitution only applies on idle ticks (when `recv_batch` returns 0),
// not on the hot per-packet path.
//
// The loops are templated on the SPSC ring capacity so tests can drive a
// small ring to overflow without pre-filling the production-sized
// 4096-slot ring.
//
#pragma once

#include <poll.h>
#include <sched.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

#include "packet-engine/backend_af_xdp.hpp"
#include "packet-engine/spsc_ring.hpp"
#include "packet-engine/types.hpp"

namespace packet_engine {

// ---------------------------------------------------------------------------
// Tunables.
// ---------------------------------------------------------------------------

/// Number of packets the RX/TX loops ask the kernel for per syscall.  Matches
/// the canonical xsk_fwd.c value and keeps the per-iteration ring-pressure
/// budget well under one L1 transaction.
inline constexpr std::uint32_t BATCH_SIZE = 64;

/// Bounded software prefetch distance: we look this many packets ahead when
/// pushing to worker rings.  Keeping it at 4 (less than 8 cache lines, the
/// typical L1 streaming window) prevents pollution when the data is not
/// actually consumed.
inline constexpr std::uint32_t PREFETCH_DISTANCE = 4;

// ---------------------------------------------------------------------------
// Hashing + worker selection.
// ---------------------------------------------------------------------------

/// XOR-based 5-tuple hash as specified by the plan:
///   `src_ip ^ dst_ip ^ ((src_port << 32) | dst_port) ^ proto`
/// All operands are promoted to `std::uint64_t` first so that the upper
/// 32 bits of the source ports actually participate.
[[nodiscard]] std::uint32_t hash_five_tuple(const FiveTuple& ft) noexcept;

/// Map a flow to a worker ring index.  `num_workers` must be > 0; passing
/// 0 returns 0 to keep the call branch-free in steady state.
[[nodiscard]] inline std::uint32_t select_worker(const FiveTuple& ft,
                                                 std::uint32_t num_workers) noexcept {
    return (num_workers == 0u) ? 0u : (hash_five_tuple(ft) % num_workers);
}

// ---------------------------------------------------------------------------
// Per-iteration statistics -- the loops return these so tests and metrics
// code can observe what happened without racing on shared counters.
// ---------------------------------------------------------------------------

struct RxIterationStats {
    std::uint32_t packets_received = 0;
    std::uint32_t packets_pushed = 0;
    std::uint32_t packets_dropped = 0; // ring-full
    bool poll_invoked = false;
    bool yield_invoked = false;
    bool fill_needs_wakeup = false;
};

struct TxIterationStats {
    std::uint32_t packets_popped = 0;
    std::uint32_t packets_submitted = 0;
    std::uint32_t completions_recycled = 0;
};

// ---------------------------------------------------------------------------
// Test-overridable poll().  Production callers leave this at its default
// (which dispatches to `::poll`); tests pass a counting stub.
// ---------------------------------------------------------------------------

using PollFn = int (*)(struct pollfd*, nfds_t, int);

inline int default_poll(struct pollfd* fds, nfds_t nfds, int timeout) noexcept {
    return ::poll(fds, nfds, timeout);
}

// ---------------------------------------------------------------------------
// Per-iteration RX loop body.  Returns the per-iteration stats.
// Templated on the SPSC capacity so tests can drive a small ring to
// overflow without pre-filling the production-sized 4096-slot ring.
// ---------------------------------------------------------------------------

template <std::size_t Capacity>
[[nodiscard]] RxIterationStats
run_rx_iteration(AfXdpBackend& backend, const FiveTuple* tuples,
                 std::vector<SpscRing<PacketDescriptor, Capacity>*>& worker_rings,
                 std::atomic<std::uint64_t>& drops_rx_ring_full, PollFn poll_fn = nullptr) {

    RxIterationStats stats{};

    (void)backend.service_fill_ring();

    const std::uint32_t num_workers = static_cast<std::uint32_t>(worker_rings.size());

    // 1) Pull a batch from the kernel.
    std::array<PacketDescriptor, BATCH_SIZE> descs{};
    const std::uint32_t rcvd = backend.recv_batch(descs.data(), BATCH_SIZE);

    if (rcvd == 0) {
        // 2) Idle branch.  Honour the wakeup contract before yielding.
        stats.fill_needs_wakeup = backend.needs_wakeup_fill();
        if (stats.fill_needs_wakeup) {
            const int fd = backend.xsk_fd();
            if (fd >= 0) {
                struct pollfd pfd{};
                pfd.fd = fd;
                pfd.events = POLLIN;
                const int rv = poll_fn ? poll_fn(&pfd, static_cast<nfds_t>(1), 0)
                                       : ::poll(&pfd, static_cast<nfds_t>(1), 0);
                (void)rv;
                stats.poll_invoked = true;
            }
        }
        sched_yield();
        stats.yield_invoked = true;
        return stats;
    }

    stats.packets_received = rcvd;
    std::array<PacketDescriptor, BATCH_SIZE> recycle{};
    std::uint32_t recycle_count = 0;

    // 3-4) Per-packet fan-out with bounded prefetch.
    for (std::uint32_t i = 0; i < rcvd; ++i) {
        if (i + PREFETCH_DISTANCE < rcvd) {
            __builtin_prefetch(&descs[i + PREFETCH_DISTANCE], 0, 0);
        }

        const FiveTuple& ft = (tuples != nullptr) ? tuples[i] : FiveTuple{};

        const std::uint32_t worker_id = select_worker(ft, num_workers);
        SpscRing<PacketDescriptor, Capacity>* ring =
            (worker_id < num_workers) ? worker_rings[worker_id] : nullptr;
        if (ring == nullptr) {
            recycle[recycle_count++] = descs[i];
            ++stats.packets_dropped;
            drops_rx_ring_full.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        if (!ring->push(descs[i])) {
            recycle[recycle_count++] = descs[i];
            ++stats.packets_dropped;
            drops_rx_ring_full.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        ++stats.packets_pushed;
    }

    backend.recycle_rx_addresses(recycle.data(), recycle_count);

    return stats;
}

// ---------------------------------------------------------------------------
// RX loop (thread entry point)
// ---------------------------------------------------------------------------

template <std::size_t Capacity>
void run_rx_loop(AfXdpBackend& backend, FiveTuple* tuple_scratch,
                 std::vector<SpscRing<PacketDescriptor, Capacity>*>& worker_rings,
                 std::atomic<bool>& stop, std::atomic<std::uint64_t>& drops_rx_ring_full,
                 PollFn poll_fn = nullptr) {

    // The relaxed load is intentional: `stop` is a latch, not a
    // synchronisation point, and a stale read merely costs one extra
    // iteration.  The signal fence prevents the compiler from hoisting
    // recv_batch above the loop condition.
    while (!stop.load(std::memory_order_relaxed)) {
        std::atomic_signal_fence(std::memory_order_acquire);
        (void)run_rx_iteration<Capacity>(backend, tuple_scratch, worker_rings, drops_rx_ring_full,
                                         poll_fn);
    }
}

// ---------------------------------------------------------------------------
// Per-iteration TX loop body.
// ---------------------------------------------------------------------------

template <std::size_t Capacity>
[[nodiscard]] TxIterationStats run_tx_iteration(AfXdpBackend& backend,
                                                SpscRing<PacketDescriptor, Capacity>& tx_ring) {
    TxIterationStats stats{};

    const std::uint32_t queued =
        std::min<std::uint32_t>(static_cast<std::uint32_t>(tx_ring.size_approx()), BATCH_SIZE);
    const std::uint32_t reserved = backend.reserve_tx(queued);
    if (reserved > 0) {
        std::array<PacketDescriptor, BATCH_SIZE> batch{};
        for (std::uint32_t i = 0; i < reserved; ++i) {
            (void)tx_ring.pop(batch[i]);
        }
        stats.packets_popped = reserved;
        stats.packets_submitted = backend.submit_reserved_tx(batch.data(), reserved);
    }

    stats.completions_recycled = backend.recycle_completions(BATCH_SIZE);

    return stats;
}

// ---------------------------------------------------------------------------
// TX loop (thread entry point)
// ---------------------------------------------------------------------------

template <std::size_t Capacity>
void run_tx_loop(AfXdpBackend& backend, SpscRing<PacketDescriptor, Capacity>& tx_ring,
                 std::atomic<bool>& stop) {

    while (!stop.load(std::memory_order_relaxed)) {
        std::atomic_signal_fence(std::memory_order_acquire);
        (void)run_tx_iteration<Capacity>(backend, tx_ring);
    }
}

} // namespace packet_engine
