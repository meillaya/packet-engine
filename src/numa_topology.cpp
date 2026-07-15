// SPDX-License-Identifier: MIT
//
// numa_topology.cpp -- cached snapshot of the host's NUMA topology.
//
// Implementation
// ==============
//
// On HAVE_NUMACTL builds:
//   1.  `numa_num_configured_nodes()` -> `num_nodes_`.
//   2.  For each node `n`:
//         - `numa_node_to_cpus(n)` returns a `struct bitmask *` (a libnuma
//           abstraction over a CPU mask).  We translate it into a libc
//           `cpu_set_t` so callers can hand it straight to
//           `pthread_setaffinity_np`.
//         - `numa_bitmask_weight` lets us find the first set bit (the
//           lowest-indexed CPU on that node) without an O(N) scan.
//   3.  `numa_num_configured_cpus()` -> `num_cpus_`.
//
// On NUMA-less builds:
//   We synthesize `num_nodes_ = 1`, `num_cpus_ = hardware_concurrency()`,
//   and a single cpu_set with every bit set.  The rest of the engine
//   still runs; NUMA affinity becomes a no-op.
//
#include "packet-engine/numa_topology.hpp"

#include <algorithm>
#include <thread>
#include <vector>

#ifdef HAVE_NUMACTL
#include <numa.h>
#endif

namespace packet_engine {

namespace {

// Translate a libnuma `struct bitmask *` into a libc `cpu_set_t`.  We zero
// the destination up front so any CPU indices libnuma doesn't report stay
// cleared.  On NUMA-less builds this is unused (but kept readable).
cpu_set_t bitmask_to_cpuset(void* mask_ptr) {
    cpu_set_t out;
    CPU_ZERO(&out);

#ifdef HAVE_NUMACTL
    if (mask_ptr == nullptr) {
        return out;
    }
    const auto* mask = static_cast<struct bitmask*>(mask_ptr);
    const int max_cpu = std::min<int>(numa_num_configured_cpus(), CPU_SETSIZE);
    for (int cpu = 0; cpu < max_cpu; ++cpu) {
        if (numa_bitmask_isbitset(mask, cpu)) {
            CPU_SET(cpu, &out);
        }
    }
#else
    (void)mask_ptr;
#endif

    return out;
}

// Compute the first set bit of `set` without invoking any heavyweight
// iterator machinery -- a single linear scan is plenty for CPU_SETSIZE
// (typically 1024) and far easier to audit than `__sched_cpucount` loops.
int first_cpu_in_set(const cpu_set_t& set) noexcept {
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &set)) {
            return cpu;
        }
    }
    return -1;
}

} // namespace

NumaTopology::NumaTopology() {
#ifdef HAVE_NUMACTL
    // libnuma may not be initialised yet -- `numa_available()` is the
    // documented probe, and `numa_num_configured_nodes()` returns at
    // least 1 on a healthy system even without an explicit init.
    if (numa_available() < 0) {
        num_nodes_ = 1;
        num_cpus_ = static_cast<int>(std::max<std::size_t>(std::thread::hardware_concurrency(), 1));
    } else {
        num_nodes_ = std::max(1, numa_num_configured_nodes());
        num_cpus_ = std::max(1, numa_num_configured_cpus());
    }
#else
    num_nodes_ = 1;
    num_cpus_ = static_cast<int>(std::max<std::size_t>(std::thread::hardware_concurrency(), 1));
#endif

    per_node_cpus_.resize(static_cast<std::size_t>(num_nodes_));

#ifdef HAVE_NUMACTL
    if (numa_available() >= 0) {
        for (int node = 0; node < num_nodes_; ++node) {
            // libnuma 2.0+: caller allocates the destination bitmask.
            struct bitmask* mask = numa_allocate_cpumask();
            if (mask == nullptr) {
                CPU_ZERO(&per_node_cpus_[static_cast<std::size_t>(node)]);
                continue;
            }
            if (numa_node_to_cpus(node, mask) != 0) {
                CPU_ZERO(&per_node_cpus_[static_cast<std::size_t>(node)]);
                numa_bitmask_free(mask);
                continue;
            }
            per_node_cpus_[static_cast<std::size_t>(node)] = bitmask_to_cpuset(mask);
            numa_bitmask_free(mask);
        }
    } else {
        // Single-node fallback: every CPU belongs to node 0.
        for (int cpu = 0; cpu < num_cpus_ && cpu < CPU_SETSIZE; ++cpu) {
            CPU_SET(cpu, &per_node_cpus_[0]);
        }
    }
#else
    // Single-node fallback: every CPU belongs to node 0.
    for (int cpu = 0; cpu < num_cpus_ && cpu < CPU_SETSIZE; ++cpu) {
        CPU_SET(cpu, &per_node_cpus_[0]);
    }
#endif
}

const NumaTopology& NumaTopology::instance() noexcept {
    static const NumaTopology topo{};
    return topo;
}

int NumaTopology::node_for_worker(std::size_t worker_index) const noexcept {
    if (num_nodes_ <= 0) {
        return 0;
    }
    return static_cast<int>(worker_index % static_cast<std::size_t>(num_nodes_));
}

int NumaTopology::first_cpu(int node) const noexcept {
    if (node < 0 || node >= num_nodes_) {
        return 0;
    }
    const int cpu = first_cpu_in_set(per_node_cpus_[static_cast<std::size_t>(node)]);
    return cpu >= 0 ? cpu : 0;
}

const cpu_set_t& NumaTopology::cpus_for_node(int node) const noexcept {
    static const cpu_set_t kEmpty{};
    if (node < 0 || node >= num_nodes_) {
        return kEmpty;
    }
    return per_node_cpus_[static_cast<std::size_t>(node)];
}

int NumaTopology::first_cpu_for_worker(std::size_t worker_index) const noexcept {
    return first_cpu(node_for_worker(worker_index));
}

} // namespace packet_engine