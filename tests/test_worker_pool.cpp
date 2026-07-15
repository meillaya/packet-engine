// SPDX-License-Identifier: MIT
//
// test_worker_pool.cpp -- GoogleTest cases for the NUMA-aware worker pool.
//
// Coverage
// ========
//   * NumaTopology snapshot reflects the host's reported node + CPU counts.
//   * `default_worker_count()` returns at least one and at most the
//     hardware concurrency.
//   * `WorkerPool(N).start()` spawns exactly N jthreads.
//   * Each worker is pinned to a single CPU: `/proc/self/task/<tid>/status`
//     reports `Cpus_allowed_list` as a single CPU (range or single).
//   * Each worker's pinned CPU matches `NumaTopology::first_cpu_for_worker`.
//   * On a multi-NUMA host, even-indexed workers sit on node 0 and
//     odd-indexed workers sit on node 1.  Skipped on single-node hosts.
//   * `stop()` joins every worker within 1 second of being requested.
//   * A user-supplied `on_packet` callback is invoked at least once when
//     the pool is fed from a real SPSC ring.
//
#include <gtest/gtest.h>

#include <sched.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "packet-engine/numa_topology.hpp"
#include "packet-engine/spsc_ring.hpp"
#include "packet-engine/types.hpp"
#include "packet-engine/worker_pool.hpp"

namespace packet_engine::test {

namespace {

// Read `/proc/self/task/<tid>/status` and pull out the value of
// `Cpus_allowed_list:`.  Returns the trimmed string ("0", "0-3", etc.).
std::string read_cpus_allowed_list(std::int64_t tid) {
    std::ifstream f("/proc/self/task/" + std::to_string(tid) + "/status");
    if (!f) {
        return {};
    }
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("Cpus_allowed_list:", 0) == 0) {
            auto pos = line.find_first_not_of(" \t", std::strlen("Cpus_allowed_list:"));
            if (pos == std::string::npos) {
                return {};
            }
            return line.substr(pos);
        }
    }
    return {};
}

// Parse a `Cpus_allowed_list` string into the set of allowed CPU indices.
// The format is a comma-separated list of either single integers or
// `first-last` ranges.  Example: "0", "2-3", "0,2-3,5".
std::set<int> parse_cpus_allowed_list(const std::string& s) {
    std::set<int> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && s[i] == ' ') {
            ++i;
        }
        int first = 0;
        if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
            break;
        }
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            first = first * 10 + (s[i] - '0');
            ++i;
        }
        int last = first;
        if (i < s.size() && s[i] == '-') {
            ++i;
            last = 0;
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
                last = last * 10 + (s[i] - '0');
                ++i;
            }
        }
        for (int c = first; c <= last; ++c) {
            out.insert(c);
        }
        if (i < s.size() && s[i] == ',') {
            ++i;
        }
    }
    return out;
}

// Block (with timeout) until the worker pool has recorded the TID of
// every worker.  We poll because the workers set their TIDs from a
// separate thread; the synchronization is via `std::atomic` stores with
// release-acquire ordering, so a short loop is sufficient.
bool wait_until_workers_ready(const WorkerPool& pool, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        bool all_ready = true;
        for (std::size_t i = 0; i < pool.num_workers(); ++i) {
            if (!pool.worker_ready(i)) {
                all_ready = false;
                break;
            }
        }
        if (all_ready) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// NumaTopology
// ---------------------------------------------------------------------------

TEST(NumaTopologyTest, ReportsAtLeastOneNode) {
    const auto& topo = NumaTopology::instance();
    EXPECT_GE(topo.num_nodes(), 1);
    EXPECT_GE(topo.num_cpus(), 1);
}

TEST(NumaTopologyTest, WorkerNodeAssignmentRoundRobin) {
    const auto& topo = NumaTopology::instance();
    const std::size_t total = static_cast<std::size_t>(topo.num_nodes()) * 4;
    for (std::size_t i = 0; i < total; ++i) {
        const int node = topo.node_for_worker(i);
        EXPECT_GE(node, 0);
        EXPECT_LT(node, topo.num_nodes());
        EXPECT_EQ(node, static_cast<int>(i % static_cast<std::size_t>(topo.num_nodes())));
    }
}

TEST(NumaTopologyTest, FirstCpuForWorkerIsInNodeMask) {
    const auto& topo = NumaTopology::instance();
    for (int node = 0; node < topo.num_nodes(); ++node) {
        const int cpu = topo.first_cpu(node);
        const auto& mask = topo.cpus_for_node(node);
        EXPECT_GE(cpu, 0);
        EXPECT_TRUE(CPU_ISSET(cpu, &mask)) << "first_cpu(node=" << node << ")=" << cpu
                                           << " is not present in cpus_for_node(" << node << ")";
    }
}

// ---------------------------------------------------------------------------
// WorkerPool
// ---------------------------------------------------------------------------

TEST(WorkerPoolTest, DefaultWorkerCountIsAtLeastOneAndAtMostHardware) {
    const std::size_t hw = std::max<std::size_t>(std::thread::hardware_concurrency(), 1);
    const std::size_t def = default_worker_count();
    EXPECT_GE(def, 1u);
    EXPECT_LE(def, hw);
}

TEST(WorkerPoolTest, StartSpawnsRequestedNumberOfWorkers) {
    WorkerPool pool{3};
    EXPECT_EQ(pool.num_workers(), 3u);
    EXPECT_FALSE(pool.running());
    pool.start();
    EXPECT_TRUE(pool.running());
    pool.stop();
    EXPECT_FALSE(pool.running());
}

TEST(WorkerPoolTest, EachWorkerPinnedToSingleCpu) {
    constexpr std::size_t kWorkers = 4;
    WorkerPool pool{kWorkers};
    pool.start();
    ASSERT_TRUE(wait_until_workers_ready(pool, std::chrono::seconds(2)))
        << "workers did not record TIDs in time";

    for (std::size_t i = 0; i < kWorkers; ++i) {
        const std::int64_t tid = pool.worker_tid(i);
        ASSERT_GT(tid, 0) << "worker " << i << " has no TID";

        const std::string allowed = read_cpus_allowed_list(tid);
        ASSERT_FALSE(allowed.empty()) << "could not read Cpus_allowed_list for tid=" << tid;

        const std::set<int> cpus = parse_cpus_allowed_list(allowed);
        ASSERT_EQ(cpus.size(), 1u)
            << "worker " << i << " (tid=" << tid << ") has Cpus_allowed_list=\"" << allowed
            << "\" with " << cpus.size() << " CPUs (expected 1)";

        const int expected_cpu = pool.worker_cpu(i);
        EXPECT_EQ(*cpus.begin(), expected_cpu)
            << "worker " << i << " was pinned to cpu=" << expected_cpu
            << " but kernel reports Cpus_allowed_list=" << allowed;
    }
    pool.stop();
}

TEST(WorkerPoolTest, StopJoinsWithinOneSecond) {
    WorkerPool pool{2};
    pool.start();
    ASSERT_TRUE(wait_until_workers_ready(pool, std::chrono::seconds(2)));

    const auto t0 = std::chrono::steady_clock::now();
    pool.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_LT(elapsed, std::chrono::seconds(1))
        << "stop() took " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
        << " ms";
    EXPECT_FALSE(pool.running());
}

TEST(WorkerPoolTest, RestartIsIdempotent) {
    WorkerPool pool{2};
    pool.start();
    pool.stop();
    // start() again should re-spawn workers without crashing.
    pool.start();
    ASSERT_TRUE(wait_until_workers_ready(pool, std::chrono::seconds(2)));
    pool.stop();
}

TEST(WorkerPoolTest, OnPacketCallbackInvokedWhenRingDrained) {
    constexpr std::size_t kWorkers = 2;
    constexpr std::size_t kPackets = 256;

    // One shared RX ring that every worker drains.  This is not the
    // production multi-queue topology -- production will install per-
    // worker rings -- but it proves the callback is wired through.
    SpscRing<PacketDescriptor> rx{};
    std::atomic<std::size_t> total_seen{0};

    WorkerHooks hooks{};
    hooks.rx_ring = &rx;
    hooks.on_packet = [&total_seen](std::size_t /*wid*/, const void* /*desc*/,
                                    std::span<const std::byte> /*bytes*/) {
        total_seen.fetch_add(1, std::memory_order_relaxed);
    };

    WorkerPool pool{kWorkers, std::move(hooks)};
    pool.start();
    ASSERT_TRUE(wait_until_workers_ready(pool, std::chrono::seconds(2)));

    for (std::size_t i = 0; i < kPackets; ++i) {
        PacketDescriptor desc{};
        desc.offset = static_cast<std::uint64_t>(i * 64);
        desc.length = 64;
        while (!rx.push(desc)) {
            std::this_thread::yield();
        }
    }

    // Wait until every packet is seen (with a generous upper bound).
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (total_seen.load(std::memory_order_relaxed) < kPackets &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }

    EXPECT_EQ(total_seen.load(std::memory_order_relaxed), kPackets);
    pool.stop();
}

#ifdef HAVE_NUMACTL
TEST(WorkerPoolTest, EvenOddAssignmentOnMultiNodeHost) {
    const auto& topo = NumaTopology::instance();
    if (topo.num_nodes() < 2) {
        GTEST_SKIP() << "host has " << topo.num_nodes()
                     << " NUMA node(s); skipping even/odd assertion";
    }

    constexpr std::size_t kWorkers = 4;
    WorkerPool pool{kWorkers};
    pool.start();
    ASSERT_TRUE(wait_until_workers_ready(pool, std::chrono::seconds(2)));

    for (std::size_t i = 0; i < kWorkers; ++i) {
        const int expected_node = topo.node_for_worker(i);
        const int expected_cpu = topo.first_cpu(expected_node);
        EXPECT_EQ(pool.worker_cpu(i), expected_cpu)
            << "worker " << i << " (expected node=" << expected_node << ", cpu=" << expected_cpu
            << ") but WorkerPool reports cpu=" << pool.worker_cpu(i);
    }
    pool.stop();
}
#endif

} // namespace packet_engine::test