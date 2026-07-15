// SPDX-License-Identifier: MIT
//
// test_frame_allocator.cpp -- GoogleTest cases for the NUMA-aware
// UMEM frame allocator and the common value-type definitions.
//
// Coverage:
//   * Allocation count:        4096 acquires return 4096 distinct offsets
//   * Alignment:               every offset is a multiple of FRAME_SIZE
//   * NUMA bind verification:  get_mempolicy(MPOL_F_ADDR) reads MPOL_BIND
//                             on `FrameAllocator::base()`
//   * Exhaustion:              the (N+1)-th acquire returns nullopt
//   * Release semantics:       returned offsets can be reclaimed
//   * Type traits:             the zero-copy value-types in types.hpp
//                             satisfy the layout invariants the parser
//                             and the worker ring rely on
//
#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <thread>
#include <vector>

#include "packet-engine/frame_allocator.hpp"
#include "packet-engine/types.hpp"

#ifdef HAVE_NUMACTL
#include <numa.h>
#include <numaif.h>
#endif

using packet_engine::FiveTuple;
using packet_engine::FrameAllocator;
using packet_engine::IPv4Addr;
using packet_engine::IPv6Addr;
using packet_engine::L4Proto;
using packet_engine::MacAddr;
using packet_engine::PacketDescriptor;
using packet_engine::ParsedPacket;
using packet_engine::UmemHugetlbPreference;

TEST(FrameAllocatorTest, RejectsOutOfRangeNumaNode) {
    EXPECT_THROW((FrameAllocator{1, 4096, std::numeric_limits<int>::max()}), std::invalid_argument);
}

namespace {

constexpr std::uint32_t kNumFrames = FrameAllocator::DEFAULT_NUM_FRAMES;
constexpr std::uint32_t kFrameSize = FrameAllocator::DEFAULT_FRAME_SIZE;

// Shared guard so that test failures that throw still release the UMEM
// before the test process exits (the FrameAllocator destructor runs,
// but on Linux it is good hygiene to be explicit for leak detectors).
struct ScopedAllocator {
    std::unique_ptr<FrameAllocator> alloc;
};

// Some CI machines expose only the kernel without libnuma, in which case
// `HAVE_NUMACTL` is undefined and `verify_numa_bind()` degenerates to
// "false".  The suite still passes: the NUMA assertions become GTEST_SKIP.
bool numa_supported() {
#ifdef HAVE_NUMACTL
    return numa_available() >= 0;
#else
    return false;
#endif
}

} // namespace

// ============================================================================
// Type / layout invariants
// ============================================================================

TEST(PacketEngineTypes, IPv4AddrIsConstructibleAndComparable) {
    constexpr IPv4Addr a{};
    constexpr IPv4Addr b{1, 2, 3, 4};
    constexpr IPv4Addr c{1, 2, 3, 4};
    EXPECT_EQ(a.value, 0u);
    EXPECT_EQ(b.value, 0x01020304u);
    EXPECT_EQ(b, c);
    EXPECT_NE(a, b);
}

TEST(PacketEngineTypes, IPv6AndMacDefaultZeroed) {
    constexpr IPv6Addr v6{};
    constexpr MacAddr mac{};
    for (auto b : v6.bytes)
        EXPECT_EQ(b, 0u);
    for (auto b : mac.bytes)
        EXPECT_EQ(b, 0u);
}

TEST(PacketEngineTypes, PacketDescriptorIsCacheAlignedAndTrivial) {
    EXPECT_EQ(alignof(PacketDescriptor), 64u);
    // Exactly one cache line so adjacent ring slots cannot false-share.
    EXPECT_EQ(sizeof(PacketDescriptor), 64u);

    PacketDescriptor d{};
    d.offset = 0;
    d.length = 64;
    d.rx_queue_id = 1;
    d.timestamp_ns = 123456789ULL;
    EXPECT_EQ(d.offset, 0u);
    EXPECT_EQ(d.length, 64u);
    EXPECT_EQ(d.rx_queue_id, 1u);
    EXPECT_EQ(d.timestamp_ns, 123456789ULL);
}

TEST(PacketEngineTypes, ParsedPacketHoldsZeroCopyViews) {
    std::array<std::byte, 256> backing{};
    auto span_a = std::span<const std::byte>(backing.data(), 64);
    auto span_b = std::span<const std::byte>(backing.data() + 64, 128);

    ParsedPacket p{};
    p.raw = span_a;
    p.l2 = span_b;
    p.l3 = span_b.subspan(14, 100);
    p.l4 = span_b.subspan(34, 60);
    p.src_ip = IPv4Addr(192, 0, 2, 1);
    p.dst_ip = IPv4Addr(198, 51, 100, 1);
    p.src_port = 5555;
    p.dst_port = 80;
    p.proto = L4Proto::TCP;

    EXPECT_EQ(p.raw.size(), 64u);
    EXPECT_EQ(p.l3.size(), 100u);
    EXPECT_EQ(p.l4.size(), 60u);
    EXPECT_EQ(p.proto, L4Proto::TCP);
}

TEST(PacketEngineTypes, FiveTupleFiveFields) {
    FiveTuple ft{};
    ft.src_ip = IPv4Addr(10, 0, 0, 1);
    ft.dst_ip = IPv4Addr(10, 0, 0, 2);
    ft.src_port = 12345;
    ft.dst_port = 80;
    ft.proto = L4Proto::TCP;

    EXPECT_EQ(ft.src_ip, IPv4Addr(10, 0, 0, 1));
    EXPECT_EQ(ft.dst_port, 80);
    EXPECT_EQ(ft.proto, L4Proto::TCP);
}

// ============================================================================
// Allocation count + alignment
// ============================================================================

TEST(FrameAllocatorTest, AllocatesAllFramesAndExhausts) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    EXPECT_EQ(alloc.num_frames(), kNumFrames);
    EXPECT_EQ(alloc.frame_size(), kFrameSize);
    EXPECT_EQ(alloc.total_size(), static_cast<std::uint64_t>(kNumFrames) * kFrameSize);

    for (std::uint32_t i = 0; i < kNumFrames; ++i) {
        auto off = alloc.acquire();
        ASSERT_TRUE(off.has_value()) << "exhausted at i=" << i;
        EXPECT_EQ(*off, static_cast<std::uint64_t>(i) * kFrameSize) << "wrong offset at i=" << i;
    }
    EXPECT_FALSE(alloc.acquire().has_value()) << "acquire past num_frames must return nullopt";
}

TEST(FrameAllocatorTest, OffsetsAreFrameSizeMultiples) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    for (std::uint32_t i = 0; i < 64; ++i) {
        auto off = alloc.acquire();
        ASSERT_TRUE(off.has_value());
        EXPECT_EQ(*off % kFrameSize, 0u)
            << "offset " << *off << " is not a multiple of " << kFrameSize;
    }
}

TEST(FrameAllocatorTest, SequenceIsZeroThenStepped) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    auto first = alloc.acquire();
    auto second = alloc.acquire();
    auto third = alloc.acquire();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(third.has_value());
    EXPECT_EQ(*first, 0u);
    EXPECT_EQ(*second, kFrameSize);
    EXPECT_EQ(*third, 2u * kFrameSize);
}

TEST(FrameAllocatorTest, TotalSizeIsExactlyProduct) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    EXPECT_EQ(alloc.total_size(), 16ULL * 1024 * 1024); // 16 MiB
}

// ============================================================================
// Page alignment
// ============================================================================

TEST(FrameAllocatorTest, BaseIsPageAligned) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    void* base = alloc.base();
    ASSERT_NE(base, nullptr);

    const auto addr = reinterpret_cast<std::uintptr_t>(base);
    EXPECT_EQ(addr % 4096u, 0u) << "base pointer " << base << " is not 4 KiB-aligned";
}

TEST(FrameAllocatorTest, FrameSpanMatchesFrameSize) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    auto off = alloc.acquire();
    ASSERT_TRUE(off.has_value());

    auto bytes = alloc.frame_span(*off);
    EXPECT_EQ(bytes.size(), kFrameSize);
    EXPECT_FALSE(bytes.empty());

    auto cbytes = alloc.frame_cspan(*off);
    EXPECT_EQ(cbytes.size(), kFrameSize);
    EXPECT_TRUE(static_cast<const void*>(bytes.data()) == static_cast<const void*>(cbytes.data()));

    EXPECT_TRUE(alloc.frame_span(alloc.total_size()).empty());
    EXPECT_TRUE(alloc.frame_span(1).empty()); // misaligned
}

// ============================================================================
// Release semantics
// ============================================================================

TEST(FrameAllocatorTest, ReleaseReturnsFrameToPool) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    auto first = alloc.acquire();
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(alloc.in_use(), 1u);
    EXPECT_EQ(alloc.free_count(), 0u);

    EXPECT_TRUE(alloc.release(*first));
    EXPECT_EQ(alloc.free_count(), 1u);
    EXPECT_EQ(alloc.in_use(), 0u);

    // Re-releasing must be rejected (double-release).
    EXPECT_FALSE(alloc.release(*first));
    EXPECT_EQ(alloc.free_count(), 1u);

    // Misaligned / out-of-range releases are rejected.
    EXPECT_FALSE(alloc.release(1));
    EXPECT_FALSE(alloc.release(alloc.total_size()));
}

TEST(FrameAllocatorTest, ReleaseNeverAcquiredIsRejected) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    // Frame 0 was never acquired.
    EXPECT_FALSE(alloc.release(0));
}

TEST(FrameAllocatorTest, ReleasedFrameCanBeAcquiredAfterPoolExhaustion) {
    FrameAllocator alloc{2, kFrameSize, 0};
    const auto first = alloc.acquire();
    const auto second = alloc.acquire();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(alloc.release(*first));

    const auto recycled = alloc.acquire();
    ASSERT_TRUE(recycled.has_value());
    EXPECT_EQ(*recycled, *first);
    EXPECT_EQ(alloc.free_count(), 0u);
}

// ============================================================================
// NUMA bind verification
// ============================================================================

TEST(FrameAllocatorTest, NumaBindIsVerified) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    if (!numa_supported()) {
        GTEST_SKIP() << "libnuma not available in this environment";
    }
    EXPECT_TRUE(alloc.verify_numa_bind()) << "expected MPOL_BIND on node 0 for the UMEM region";
}

TEST(FrameAllocatorTest, VmaPolicyProbeMatchesMPOLBind) {
#ifdef HAVE_NUMACTL
    if (numa_available() < 0) {
        GTEST_SKIP() << "libnuma not active";
    }
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;
    const int maxnode = numa_num_configured_nodes() + 1;
    const std::size_t nlongs =
        (maxnode + (int)sizeof(unsigned long) * 8 - 1) / (sizeof(unsigned long) * 8);
    std::vector<unsigned long> mask(nlongs == 0 ? 1 : nlongs, 0UL);
    int mode = MPOL_DEFAULT;
    int rc = get_mempolicy(&mode, mask.data(), maxnode, alloc.base(), MPOL_F_ADDR);
    ASSERT_EQ(rc, 0) << "get_mempolicy failed";
    EXPECT_EQ(mode, MPOL_BIND);
    EXPECT_TRUE((mask[0] & 1UL) != 0UL) << "nodemask did not include node 0";
#else
    GTEST_SKIP() << "test built without libnuma";
#endif
}

// ============================================================================
// Concurrency: acquire() must be safe across threads.
// ============================================================================

TEST(FrameAllocatorTest, ConcurrentAcquireIsSafe) {
    ScopedAllocator g{std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0)};
    auto& alloc = *g.alloc;

    constexpr int kThreads = 4;
    constexpr int kPerThread = 128;

    std::vector<std::vector<std::uint64_t>> obtained(kThreads);
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};

    std::vector<std::jthread> workers;
    workers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&, t]() {
            obtained[t].reserve(kPerThread);
            ready.fetch_add(1);
            while (!go.load(std::memory_order_acquire)) { /*spin*/
            }
            for (int i = 0; i < kPerThread; ++i) {
                if (auto off = alloc.acquire()) {
                    obtained[t].push_back(*off);
                } else {
                    break;
                }
            }
        });
    }

    while (ready.load() < kThreads) { /*spin*/
    }
    go.store(true, std::memory_order_release);
    for (auto& w : workers)
        w.join();

    // All offsets must be distinct and a multiple of FRAME_SIZE.
    std::set<std::uint64_t> seen;
    for (auto& v : obtained) {
        for (auto o : v) {
            EXPECT_EQ(o % kFrameSize, 0u);
            EXPECT_TRUE(seen.insert(o).second) << "duplicate offset " << o << " across threads";
        }
    }
    // No two threads can collide on the same offset without violating
    // concurrent uniqueness and capacity accounting.
    const std::size_t total = kThreads * kPerThread;
    EXPECT_LE(seen.size(), total);
}
