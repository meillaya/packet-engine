// SPDX-License-Identifier: MIT
//
// numa_topology.hpp -- cached snapshot of the host's NUMA topology.
//
// Purpose
// =======
//
// `WorkerPool` and `FrameAllocator` both need to ask the same question:
//
//   "Given a worker index `i`, which NUMA node should it run on, and which
//    is the first CPU on that node?"
//
// libnuma's `numa_num_configured_nodes()` / `numa_node_to_cpus()` are cheap
// but they are not free: each call walks `/sys/devices/system/node/.../cpulist`
// and allocates a `numa_bitmask`.  Doing that once per worker spawn is fine;
// doing it on every packet would be a hot-path disaster.
//
// `NumaTopology` snapshots the answer at construction time (lazily, on first
// access) and exposes the same queries in O(1).  It is thread-safe because
// every member is `const` after construction.
//
// On hosts without libnuma (HAVE_NUMACTL is undefined) the helper degrades
// to a single-node / all-CPU model so the rest of the engine still links
// and runs; the NUMA pinning calls become no-ops in the worker pool.
//
#pragma once

#include <sched.h>

#include <cstddef>
#include <vector>

namespace packet_engine {

/// Cached view of the host NUMA topology.  See file-level docs.
///
/// One instance is exposed via `instance()`; constructing your own copy is
/// harmless and useful for tests.
class NumaTopology {
  public:
    /// Build a snapshot of the current host.  When `libnuma` is available
    /// we read `numa_num_configured_nodes()` + `numa_node_to_cpus()`; on
    /// NUMA-less builds we synthesize a single node that contains every
    /// CPU returned by `std::thread::hardware_concurrency()`.
    NumaTopology();

    NumaTopology(const NumaTopology&) = delete;
    NumaTopology& operator=(const NumaTopology&) = delete;
    NumaTopology(NumaTopology&&) = delete;
    NumaTopology& operator=(NumaTopology&&) = delete;

    /// Process-wide singleton.  Initialized on first call (Meyers singleton,
    /// thread-safe by C++11 magic statics).
    static const NumaTopology& instance() noexcept;

    /// Number of NUMA nodes the kernel reports (>= 1).
    [[nodiscard]] int num_nodes() const noexcept { return num_nodes_; }

    /// Total number of logical CPUs visible to the process.
    [[nodiscard]] int num_cpus() const noexcept { return num_cpus_; }

    /// Round-robin assignment of worker index to NUMA node.
    ///
    /// Mirrors the rule documented in Task 11 of the plan:
    ///     node = i % num_nodes()
    ///
    /// Returns 0 when `num_nodes_ == 1` (the common single-socket case).
    [[nodiscard]] int node_for_worker(std::size_t worker_index) const noexcept;

    /// First CPU on `node`.  Returns 0 when the node mask is empty.
    [[nodiscard]] int first_cpu(int node) const noexcept;

    /// Bitmask of CPUs on `node`.  Empty (all-zeros) for an out-of-range
    /// node.  The CPU set is sized to `CPU_SETSIZE` so callers can copy it
    /// straight into `pthread_setaffinity_np`.
    [[nodiscard]] const cpu_set_t& cpus_for_node(int node) const noexcept;

    /// Convenience: returns the first CPU on the node that `worker_index`
    /// should bind to.  Equivalent to `first_cpu(node_for_worker(i))`.
    [[nodiscard]] int first_cpu_for_worker(std::size_t worker_index) const noexcept;

  private:
    int num_nodes_;
    int num_cpus_;
    std::vector<cpu_set_t> per_node_cpus_;
};

} // namespace packet_engine