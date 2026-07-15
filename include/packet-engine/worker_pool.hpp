// SPDX-License-Identifier: MIT
//
// worker_pool.hpp -- NUMA-aware worker thread pool.
//
// Purpose
// =======
//
// A packet engine over AF_XDP / DPDK pins a worker thread to a single CPU
// per NUMA node.  The reason is simple:
//
//   * NIC DMA lands in memory local to the RX queue's NUMA node.
//   * Per-frame latency stays bounded by the cross-socket interconnect
//     only when the worker that drains that queue lives on the same node.
//
// `WorkerPool` therefore does three things on `start()`:
//
//   1.  Spawns `num_workers` `std::jthread`s (C++20 cooperative cancel).
//   2.  For each worker `i`:
//         - picks node  = i % num_nodes
//         - pins the thread to the first CPU on that node via
//           `pthread_setaffinity_np`
//         - installs `set_mempolicy(MPOL_BIND, ...)` so any allocation the
//           worker performs stays on the local node (first-touch + VMA
//           policy, identical to the `FrameAllocator` recipe).
//   3.  Runs a user-supplied per-packet callback in a `sched_yield()`-spin
//       loop, exiting when the owning `jthread` is asked to stop.
//
// The callbacks are intentionally pluggable so that:
//   * the test suite can install a counter (and assert that workers
//     actually run);
//   * the real engine (Task 21) can install `parse → rule → action → TX`.
//
// Memory model
// ------------
//   `start()` synchronizes-with the worker's first observation of the
//   topology / callback state via the jthread constructor's happens-before.
//   `stop()` triggers the cooperative stop token and `join()`s; after
//   `stop()` returns no worker is still running.
//
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <thread>
#include <vector>

namespace packet_engine {

class NumaTopology;

/// Default worker count: half of the hardware concurrency, rounded down
/// to at least one.  Mirrors `nproc / 2` from the plan.
std::size_t default_worker_count() noexcept;

/// Lifecycle / per-packet hooks the worker thread invokes.
///
/// `on_packet` is invoked once per packet popped off the (optional) RX
/// ring.  When `rx_ring` is null the worker simply spins on the stop
/// token; that is the path the test suite uses to verify pinning
/// without having to wire a real backend.
struct WorkerHooks {
    /// Optional pointer to an SPSC ring the worker drains.  When null the
    /// worker just spins until the stop token fires.
    void* rx_ring = nullptr;

    /// Optional pointer to an SPSC ring the worker pushes results into.
    void* tx_ring = nullptr;

    /// Resolves a frame offset into a borrowed byte span.  Used by the
    /// parser hook; safe to leave null when the hooks don't parse.
    std::function<std::span<const std::byte>(std::uint64_t offset)> frame_accessor;

    /// Per-packet action invoked once parse is done.  Receives the worker
    /// id, the descriptor, and the borrowed frame bytes.
    std::function<void(std::size_t worker_id, const void* descriptor,
                       std::span<const std::byte> bytes)>
        on_packet;
};

/// Pool of NUMA-pinned worker threads.  See file-level docs.
///
/// Construction is cheap (it just reads the cached topology) and
/// `start()` is the only call that creates OS threads.
class WorkerPool {
  public:
    explicit WorkerPool(std::size_t num_workers = default_worker_count(), WorkerHooks hooks = {});
    ~WorkerPool();

    WorkerPool(const WorkerPool&) = delete;
    WorkerPool& operator=(const WorkerPool&) = delete;
    WorkerPool(WorkerPool&&) = delete;
    WorkerPool& operator=(WorkerPool&&) = delete;

    /// Number of workers the pool will spawn.
    [[nodiscard]] std::size_t num_workers() const noexcept { return num_workers_; }

    /// Spawn the worker threads.  Idempotent; calling `start()` twice is a
    /// no-op.
    void start();

    /// Cooperative stop: requests cancellation, joins every worker, and
    /// restores the mempolicy on each one.  Blocks until every worker has
    /// exited.  Safe to call from any thread.
    void stop();

    /// True between `start()` and a successful `stop()`.
    [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }

    /// Kernel TID of worker `i`.  Only meaningful after `start()`; before
    /// `start()` (or after `stop()`) returns 0.  Exposed for tests that
    /// probe `/proc/self/task/<tid>/status`.
    [[nodiscard]] std::int64_t worker_tid(std::size_t i) const noexcept;

    /// The CPU that worker `i` was pinned to.  Same lifetime caveat as
    /// `worker_tid()`.
    [[nodiscard]] int worker_cpu(std::size_t i) const noexcept;

    /// True once worker `i` has captured its TID + CPU (i.e. it's safe to
    /// query `worker_tid()` / `worker_cpu()`).  Useful for tests that need
    /// to wait for the kernel to apply affinity before reading
    /// `/proc/self/task/<tid>/status`.
    [[nodiscard]] bool worker_ready(std::size_t i) const noexcept;

  private:
    void worker_main(std::size_t id, std::stop_token stop, const NumaTopology& topo);

    const std::size_t num_workers_;
    WorkerHooks hooks_;
    std::atomic<bool> running_{false};
    std::vector<std::jthread> workers_;
    std::vector<std::atomic<std::int64_t>> tids_;
    std::vector<std::atomic<int>> cpus_;
};

} // namespace packet_engine