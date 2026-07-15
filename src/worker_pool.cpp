// SPDX-License-Identifier: MIT
//
// worker_pool.cpp -- NUMA-pinned worker thread pool implementation.
//
// Per-worker lifecycle (see `WorkerPool::worker_main`):
//
//   1.  Resolve NUMA node + first CPU for this worker via the cached
//       `NumaTopology` singleton.
//   2.  `pthread_setaffinity_np` to a single CPU on that node.  Once the
//       affinity mask is set, the kernel will not migrate the thread off
//       it for the rest of its lifetime -- that is the contract Task 11
//       imposes.
//   3.  `set_mempolicy(MPOL_BIND, ...)` so any subsequent allocation in
//       this thread lands on the same node (first-touch + VMA policy,
//       matching the recipe the FrameAllocator uses for the UMEM).
//   4.  Capture the kernel TID via `SYS_gettid` so the test harness can
//       inspect `/proc/self/task/<tid>/status` and verify the
//       `Cpus_allowed_list` field.
//   5.  Run the per-packet loop:
//         - If an RX ring was supplied, drain it with `sched_yield()`
//           back-pressure when empty.
//         - Else, spin on the stop token (used by the tests).
//   6.  On exit, restore `MPOL_DEFAULT` so the thread's mempolicy doesn't
//       leak into whatever OS-level work reaps it.
//
#include "packet-engine/worker_pool.hpp"

#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stop_token>
#include <thread>
#include <vector>

#include "packet-engine/logger.hpp"
#include "packet-engine/numa_topology.hpp"
#include "packet-engine/spsc_ring.hpp"
#include "packet-engine/types.hpp"

#ifdef HAVE_NUMACTL
#include <numa.h>
#include <numaif.h>
#endif

namespace packet_engine {

std::size_t default_worker_count() noexcept {
    const std::size_t hw = std::max<std::size_t>(std::thread::hardware_concurrency(), 1);
    return hw / 2 == 0 ? 1 : hw / 2;
}

namespace {

// Convert a libnuma `struct bitmask *` of NUMA node indices into the
// kernel `nodemask` array expected by `set_mempolicy(2)`.
//
// The kernel takes an array of `unsigned long` of sufficient size to hold
// `maxnode` bits.  We size the buffer from `numa_num_possible_nodes()`
// (the maximum node id the kernel could ever configure) and round up to a
// whole number of `unsigned long`s.
bool install_bind_policy(int node) {
#ifdef HAVE_NUMACTL
    if (numa_available() < 0) {
        // NUMA is not usable on this host -- silently skip the policy.
        return true;
    }

    const int max_node = std::max(1, numa_num_possible_nodes());
    constexpr int kBits = sizeof(unsigned long) * 8;
    const std::size_t words = static_cast<std::size_t>((max_node + kBits - 1) / kBits);
    std::vector<unsigned long> mask(words, 0UL);

    if (node >= 0 && node < max_node) {
        const std::size_t word = static_cast<std::size_t>(node) / kBits;
        const int bit = static_cast<int>(node) % kBits;
        mask[word] |= 1UL << bit;
    }

    if (::set_mempolicy(MPOL_BIND, mask.data(), max_node) != 0) {
        LOG_WARN("WorkerPool: set_mempolicy(MPOL_BIND, node=" << node << ") failed: "
                                                              << std::strerror(errno));
        return false;
    }
    return true;
#else
    (void)node;
    return true;
#endif
}

void restore_default_policy() noexcept {
#ifdef HAVE_NUMACTL
    if (numa_available() < 0) {
        return;
    }
    // Empty mask + MPOL_DEFAULT reverts to "inherit the process default".
    unsigned long mask[1] = {0};
    ::set_mempolicy(MPOL_DEFAULT, mask, sizeof(mask) * 8);
#endif
}

// Pin the calling thread to a single CPU.  Returns 0 on success and the
// errno from `pthread_setaffinity_np` on failure.  The mask is sized to
// `CPU_SETSIZE` so we can hand it to the kernel unchanged.
int pin_to_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    return ::pthread_setaffinity_np(::pthread_self(), sizeof(mask), &mask);
}

// Kernel TID for the calling thread.  Cheaper than going through
// `std::this_thread::get_id` because the latter is a userspace token.
std::int64_t current_tid() noexcept { return static_cast<std::int64_t>(::syscall(SYS_gettid)); }

// Drain a single packet from the RX ring when one is configured.  Returns
// `true` when a packet was processed.
bool process_one_packet(std::size_t worker_id, const WorkerHooks& hooks) {
    if (hooks.rx_ring == nullptr) {
        return false;
    }
    auto* rx = static_cast<SpscRing<PacketDescriptor>*>(hooks.rx_ring);
    PacketDescriptor desc{};
    if (!rx->pop(desc)) {
        return false;
    }
    std::span<const std::byte> bytes{};
    if (hooks.frame_accessor) {
        bytes = hooks.frame_accessor(desc.offset);
    }
    if (hooks.on_packet) {
        hooks.on_packet(worker_id, &desc, bytes);
    }
    return true;
}

} // namespace

WorkerPool::WorkerPool(std::size_t num_workers, WorkerHooks hooks)
    : num_workers_(std::max<std::size_t>(num_workers, 1)), hooks_(std::move(hooks)), workers_(),
      tids_(num_workers_), cpus_(num_workers_) {
    workers_.reserve(num_workers_);
}

WorkerPool::~WorkerPool() { stop(); }

void WorkerPool::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel,
                                          std::memory_order_acquire)) {
        return; // Already running.
    }

    const auto& topo = NumaTopology::instance();
    workers_.clear();
    workers_.reserve(num_workers_);

    for (std::size_t i = 0; i < num_workers_; ++i) {
        workers_.emplace_back([this, i, &topo](std::stop_token st) { worker_main(i, st, topo); });
    }
}

void WorkerPool::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running or already stopped.
    }

    for (auto& t : workers_) {
        if (t.joinable()) {
            t.request_stop();
        }
    }
    for (auto& t : workers_) {
        if (t.joinable()) {
            t.join();
        }
    }
    workers_.clear();
    // TIDs / CPUs stay observable (zeroed) for diagnostics after stop().
    for (auto& t : tids_) {
        t.store(0, std::memory_order_release);
    }
    for (auto& c : cpus_) {
        c.store(-1, std::memory_order_release);
    }
}

std::int64_t WorkerPool::worker_tid(std::size_t i) const noexcept {
    return i < tids_.size() ? tids_[i].load(std::memory_order_acquire) : 0;
}

int WorkerPool::worker_cpu(std::size_t i) const noexcept {
    return i < cpus_.size() ? cpus_[i].load(std::memory_order_acquire) : -1;
}

bool WorkerPool::worker_ready(std::size_t i) const noexcept {
    return i < tids_.size() && tids_[i].load(std::memory_order_acquire) != 0;
}

void WorkerPool::worker_main(std::size_t id, std::stop_token stop, const NumaTopology& topo) {
    const int node = topo.node_for_worker(id);
    const int cpu = topo.first_cpu(node);

    // ------------------------------------------------------------------
    // 1. Pin to a single CPU on the target node.
    // ------------------------------------------------------------------
    const int rc = pin_to_cpu(cpu);
    if (rc != 0) {
        LOG_WARN("WorkerPool: worker " << id << " pthread_setaffinity_np(cpu=" << cpu
                                       << ") failed: " << std::strerror(rc));
    }

    // ------------------------------------------------------------------
    // 2. Bind memory policy.  Best-effort: NUMA-less hosts silently skip.
    // ------------------------------------------------------------------
    install_bind_policy(node);

    // ------------------------------------------------------------------
    // 3. Capture TID for /proc inspection by tests / metrics.
    // ------------------------------------------------------------------
    tids_[id].store(current_tid(), std::memory_order_release);
    cpus_[id].store(cpu, std::memory_order_release);

    LOG_INFO("WorkerPool: worker " << id << " started on node=" << node << " cpu=" << cpu
                                   << " tid=" << tids_[id].load(std::memory_order_relaxed));

    // ------------------------------------------------------------------
    // 4. Main loop: drain RX ring (or idle) until stop is requested.
    // ------------------------------------------------------------------
    while (!stop.stop_requested()) {
        if (!process_one_packet(id, hooks_)) {
            // Empty ring -- back off without burning CPU.
            std::this_thread::yield();
        }
    }

    // ------------------------------------------------------------------
    // 5. Restore mempolicy so this thread doesn't leak policy into the
    //    OS thread cache after the pool releases it.
    // ------------------------------------------------------------------
    restore_default_policy();

    LOG_INFO("WorkerPool: worker " << id << " stopping (cpu=" << cpu << ")");
}

} // namespace packet_engine