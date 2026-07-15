// SPDX-License-Identifier: MIT

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>

#include <xdp/xsk.h>

#include "mocks/mock_xsk.h"
#include "packet-engine/backend_af_xdp.hpp"
#include "packet-engine/datapath_loop.hpp"
#include "packet-engine/frame_allocator.hpp"
#include "packet-engine/spsc_ring.hpp"
#include "packet-engine/types.hpp"

namespace {

using packet_engine::AfXdpBackend;
using packet_engine::BATCH_SIZE;
using packet_engine::FrameAllocator;
using packet_engine::PacketDescriptor;
using packet_engine::SpscRing;
using packet_engine::testing::MockXskOps;

constexpr std::uint32_t kNumFrames = AfXdpBackend::NUM_FRAMES;
constexpr std::uint32_t kFrameSize = FrameAllocator::DEFAULT_FRAME_SIZE;
constexpr std::size_t kQueueCapacity = 2;

struct Harness {
    FrameAllocator allocator{kNumFrames, kFrameSize, 0};
    MockXskOps ops;
    AfXdpBackend backend{allocator, "veth0", 0, &ops};
};

PacketDescriptor descriptor(std::uint64_t offset) {
    PacketDescriptor value{};
    value.offset = offset;
    value.length = 128;
    return value;
}

TEST(AfXdpSustainableRedTest, FillAddressesCycleForFiveUmemGenerationsWhenWorkerIsBackpressured) {
    Harness h;
    h.backend.init();

    SpscRing<PacketDescriptor, kQueueCapacity> full_worker;
    ASSERT_TRUE(full_worker.push(descriptor(0)));
    ASSERT_TRUE(full_worker.push(descriptor(kFrameSize)));
    std::vector<SpscRing<PacketDescriptor, kQueueCapacity>*> workers{&full_worker};
    std::atomic<std::uint64_t> drops{0};

    constexpr std::uint32_t kGenerations = 5;
    constexpr std::uint32_t kTargetPackets = kGenerations * kNumFrames;
    std::uint32_t delivered = 0;
    while (delivered < kTargetPackets) {
        const std::uint32_t produced = h.ops.produce_rx_from_fill(BATCH_SIZE);
        if (produced == 0)
            break;

        const auto stats = packet_engine::run_rx_iteration<kQueueCapacity>(h.backend, nullptr,
                                                                           workers, drops, nullptr);
        ASSERT_EQ(stats.packets_received, produced);
        ASSERT_EQ(stats.packets_dropped, produced);
        delivered += produced;
    }

    ASSERT_EQ(delivered, kTargetPackets)
        << "FILL starved before addresses completed five ownership cycles";
    ASSERT_EQ(h.ops.consumed_fill_addresses().size(), kTargetPackets);

    std::array<std::uint32_t, kNumFrames> generations{};
    for (const std::uint64_t address : h.ops.consumed_fill_addresses()) {
        ASSERT_EQ(address % kFrameSize, 0u);
        const std::uint64_t frame = address / kFrameSize;
        ASSERT_LT(frame, kNumFrames);
        ++generations[frame];
    }
    for (const std::uint32_t count : generations) {
        EXPECT_EQ(count, kGenerations);
    }
}

TEST(AfXdpSustainableRedTest, RxIterationNeverConsumesTxCompletionOwnership) {
    Harness h;
    h.backend.init();
    ASSERT_EQ(h.ops.produce_rx_from_fill(1), 1u);
    h.ops.preload_completions({0});

    SpscRing<PacketDescriptor, kQueueCapacity> worker;
    std::vector<SpscRing<PacketDescriptor, kQueueCapacity>*> workers{&worker};
    std::atomic<std::uint64_t> drops{0};

    const auto stats = packet_engine::run_rx_iteration<kQueueCapacity>(h.backend, nullptr, workers,
                                                                       drops, nullptr);

    ASSERT_EQ(stats.packets_received, 1u);
    EXPECT_EQ(h.ops.completion_consumer_index(), 0u)
        << "only the TX loop may consume the completion ring";
}

TEST(AfXdpSustainableRedTest, TxIterationRetainsDescriptorsWhenKernelTxRingHasNoReserve) {
    Harness h;
    h.backend.init();

    std::vector<PacketDescriptor> kernel_owned;
    kernel_owned.reserve(kNumFrames);
    for (std::uint32_t i = 0; i < kNumFrames; ++i) {
        kernel_owned.push_back(descriptor(static_cast<std::uint64_t>(i) * kFrameSize));
    }
    ASSERT_EQ(h.backend.send_batch(kernel_owned.data(), kNumFrames), kNumFrames);

    SpscRing<PacketDescriptor, kQueueCapacity> pending;
    ASSERT_TRUE(pending.push(descriptor(0)));
    ASSERT_TRUE(pending.push(descriptor(kFrameSize)));

    const auto stats = packet_engine::run_tx_iteration<kQueueCapacity>(h.backend, pending);

    ASSERT_EQ(stats.packets_submitted, 0u);
    EXPECT_EQ(pending.size_approx(), kQueueCapacity)
        << "reserve failure must not discard application-owned descriptors";
}

TEST(AfXdpSustainableRedTest, SocketCreationInhibitsLibxdpProgramAutoLoad) {
    Harness h;
    h.backend.init();

    EXPECT_NE(h.ops.socket_libxdp_flags() & XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD, 0u);
}

} // namespace
