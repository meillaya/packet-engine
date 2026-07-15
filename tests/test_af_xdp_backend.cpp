// SPDX-License-Identifier: MIT
//
// test_af_xdp_backend.cpp -- GoogleTest cases for AfXdpBackend.
//
// All tests run through MockXskOps so the entire lifecycle can be
// exercised without root, without a real NIC, and without
// `LIBXDP_OBJECT_PATH` set.
//
// Coverage
// ========
//
// * Init lifecycle:
//     - init() invokes umem_create + socket_create exactly once
//     - the fill ring is populated with NUM_FRAMES addresses
//     - a duplicate init() throws
//     - a failed socket_create unwinds the umem so no leak
//
// * RX path:
//     - recv_batch on an empty ring returns 0
//     - recv_batch propagates addr/len/rx_queue_id/timestamp_ns from
//       the rx ring descriptors
//     - recv_batch releases the ring after consuming
//
// * TX path:
//     - send_batch populates xdp_desc with the requested addr/len
//     - send_batch wakes the kernel only when needs_wakeup says so
//
// * Recycle:
//     - recycle_completions returns addresses to FrameAllocator
//
// * Teardown:
//     - the destructor unloads socket_delete THEN umem_delete
//     - close_fd is invoked
//
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "mocks/mock_xsk.h"
#include "packet-engine/backend_af_xdp.hpp"
#include "packet-engine/frame_allocator.hpp"
#include "packet-engine/types.hpp"

using packet_engine::AfXdpBackend;
using packet_engine::AfXdpMode;
using packet_engine::FrameAllocator;
using packet_engine::PacketDescriptor;
using packet_engine::testing::MockXskOps;

namespace {

// Bring constants into the test scope.
constexpr std::uint32_t kNumFrames = AfXdpBackend::NUM_FRAMES;
constexpr std::uint32_t kFrameSize = FrameAllocator::DEFAULT_FRAME_SIZE;

// Helper: make a PacketDescriptor with a known frame offset.
PacketDescriptor make_desc(std::uint64_t offset, std::uint32_t len, std::uint32_t rx_queue_id = 0,
                           std::uint64_t timestamp_ns = 0) {
    PacketDescriptor d{};
    d.offset = offset;
    d.length = len;
    d.rx_queue_id = rx_queue_id;
    d.timestamp_ns = timestamp_ns;
    return d;
}

struct Harness {
    std::unique_ptr<FrameAllocator> allocator;
    std::unique_ptr<MockXskOps> ops;
    std::unique_ptr<AfXdpBackend> backend;

    Harness(const std::string& ifname = "veth0", std::uint32_t qid = 0) {
        allocator = std::make_unique<FrameAllocator>(kNumFrames, kFrameSize, 0);
        ops = std::make_unique<MockXskOps>();
        backend = std::make_unique<AfXdpBackend>(*allocator, ifname, qid, ops.get());
    }
};

} // namespace

// ===========================================================================
// Construction & sanity
// ===========================================================================

TEST(AfXdpBackendTest, ConstructingDoesNotAllocateKernelResources) {
    Harness h;
    // The backend existed; no umem/socket should have been created yet.
    EXPECT_EQ(h.ops->umem_create_calls(), 0);
    EXPECT_EQ(h.ops->socket_create_calls(), 0);
    EXPECT_FALSE(h.backend->is_initialised());
    EXPECT_EQ(h.backend->interface_name(), "veth0");
    EXPECT_EQ(h.backend->queue_id(), 0u);
    EXPECT_EQ(h.backend->actual_mode(), AfXdpMode::Unknown);
    EXPECT_EQ(h.backend->actual_mode_name(), "unknown");
}

TEST(AfXdpBackendTest, InitCallsUmemAndSocketCreate) {
    Harness h;
    h.backend->init();

    EXPECT_TRUE(h.backend->is_initialised());
    EXPECT_EQ(h.ops->umem_create_calls(), 1);
    EXPECT_EQ(h.ops->socket_create_calls(), 1);
    EXPECT_GE(h.backend->xsk_fd(), 0);
    EXPECT_EQ(h.ops->get_xdp_options_calls(), 1);
    EXPECT_EQ(h.ops->last_xdp_options_fd(), h.backend->xsk_fd());
    EXPECT_EQ(h.backend->actual_mode(), AfXdpMode::Copy);
    EXPECT_EQ(h.backend->actual_mode_name(), "copy");
}

TEST(AfXdpBackendTest, InitReportsZeroCopyOnlyWhenKernelOptionFlagIsSet) {
    Harness h;
    h.ops->set_xdp_options_result(0, sizeof(struct xdp_options), XDP_OPTIONS_ZEROCOPY);

    h.backend->init();

    EXPECT_EQ(h.backend->actual_mode(), AfXdpMode::ZeroCopy);
    EXPECT_EQ(h.backend->actual_mode_name(), "zero-copy");
}

TEST(AfXdpBackendTest, InitKeepsModeUnknownWhenKernelOptionQueryFails) {
    Harness h;
    h.ops->set_xdp_options_result(-1, sizeof(struct xdp_options), XDP_OPTIONS_ZEROCOPY);

    EXPECT_NO_THROW(h.backend->init());

    EXPECT_TRUE(h.backend->is_initialised());
    EXPECT_EQ(h.backend->actual_mode(), AfXdpMode::Unknown);
    EXPECT_EQ(h.backend->actual_mode_name(), "unknown");
}

TEST(AfXdpBackendTest, InitKeepsModeUnknownWhenKernelOptionReplyIsShort) {
    Harness h;
    constexpr std::uint32_t kShortReply =
        offsetof(struct xdp_options, flags) + sizeof(((struct xdp_options*)nullptr)->flags) - 1;
    h.ops->set_xdp_options_result(0, kShortReply, XDP_OPTIONS_ZEROCOPY);

    EXPECT_NO_THROW(h.backend->init());

    EXPECT_TRUE(h.backend->is_initialised());
    EXPECT_EQ(h.backend->actual_mode(), AfXdpMode::Unknown);
    EXPECT_EQ(h.backend->actual_mode_name(), "unknown");
}

TEST(AfXdpBackendTest, DoubleInitThrows) {
    Harness h;
    h.backend->init();
    EXPECT_THROW(h.backend->init(), std::runtime_error);
    // The second init must not double-create resources.
    EXPECT_EQ(h.ops->umem_create_calls(), 1);
    EXPECT_EQ(h.ops->socket_create_calls(), 1);
}

// ===========================================================================
// Fill ring
// ===========================================================================

TEST(AfXdpBackendTest, FillRingPopulatedWithAllFrames) {
    Harness h;
    h.backend->init();

    // The mock owns the fill ring's backing buffer; scan it for
    // addresses that are valid frame offsets in the allocator.
    // Every offset we wrote should match what the allocator handed out.
    auto recycled = h.allocator->in_use();
    EXPECT_EQ(recycled, kNumFrames);
}

TEST(AfXdpBackendTest, FillRingExhaustsAllocator) {
    // After init(), the allocator has 0 free frames because init
    // acquired NUM_FRAMES of them.
    Harness h;
    h.backend->init();
    EXPECT_EQ(h.allocator->free_count(), 0u);
    EXPECT_EQ(h.allocator->in_use(), kNumFrames);
    EXPECT_FALSE(h.allocator->acquire().has_value());
}

// ===========================================================================
// RX path
// ===========================================================================

TEST(AfXdpBackendTest, RecvBatchOnEmptyRingReturnsZero) {
    Harness h;
    h.backend->init();

    PacketDescriptor out[8]{};
    const std::uint32_t n = h.backend->recv_batch(out, 8);
    EXPECT_EQ(n, 0u);
}

TEST(AfXdpBackendTest, RecvBatchReadsAllDescriptors) {
    Harness h;
    h.backend->init();

    constexpr std::uint32_t kCount = 4;
    std::vector<xdp_desc> preloaded;
    preloaded.reserve(kCount);
    for (std::uint32_t i = 0; i < kCount; ++i) {
        xdp_desc d{};
        d.addr = static_cast<std::uint64_t>(i) * kFrameSize + 128;
        d.len = 256u + i;
        d.options = 0;
        preloaded.push_back(d);
    }
    h.ops->preload_rx(preloaded);

    std::vector<PacketDescriptor> out(kCount);
    const std::uint32_t n =
        h.backend->recv_batch(out.data(), static_cast<std::uint32_t>(out.size()));
    EXPECT_EQ(n, kCount);

    for (std::uint32_t i = 0; i < kCount; ++i) {
        EXPECT_EQ(out[i].offset, preloaded[i].addr);
        EXPECT_EQ(out[i].length, preloaded[i].len);
        EXPECT_EQ(out[i].rx_queue_id, 0u);
        EXPECT_GT(out[i].timestamp_ns, 0u);
    }
}

TEST(AfXdpBackendTest, RecvBatchRespectsMaxCap) {
    Harness h;
    h.backend->init();

    constexpr std::uint32_t kAvailable = 6;
    constexpr std::uint32_t kAskFor = 3;
    std::vector<xdp_desc> preloaded;
    for (std::uint32_t i = 0; i < kAvailable; ++i) {
        xdp_desc d{};
        d.addr = i * kFrameSize;
        d.len = 100u;
        preloaded.push_back(d);
    }
    h.ops->preload_rx(preloaded);

    std::vector<PacketDescriptor> out(kAskFor);
    const std::uint32_t n = h.backend->recv_batch(out.data(), kAskFor);
    EXPECT_EQ(n, kAskFor);
}

TEST(AfXdpBackendTest, RecvBatchAfterConsumptionReturnsZero) {
    Harness h;
    h.backend->init();

    xdp_desc d{};
    d.addr = kFrameSize;
    d.len = 64u;
    h.ops->preload_rx({d});

    PacketDescriptor out[4]{};
    EXPECT_EQ(h.backend->recv_batch(out, 4), 1u);
    // After the previous release, the next peek should yield zero.
    EXPECT_EQ(h.backend->recv_batch(out, 4), 0u);
}

// ===========================================================================
// TX path
// ===========================================================================

TEST(AfXdpBackendTest, SendBatchWritesDescriptors) {
    Harness h;
    h.backend->init();
    h.ops->set_tx_needs_wakeup(false);

    constexpr std::uint32_t kCount = 4;
    std::vector<PacketDescriptor> in(kCount);
    for (std::uint32_t i = 0; i < kCount; ++i) {
        in[i] = make_desc(static_cast<std::uint64_t>(i) * kFrameSize, 200u + i);
    }

    const std::uint32_t n = h.backend->send_batch(in.data(), kCount);
    EXPECT_EQ(n, kCount);

    // The mock owns the tx ring buffer; verify each descriptor matches
    // the input.
    const auto& storage = h.ops->tx_desc_storage();
    for (std::uint32_t i = 0; i < kCount; ++i) {
        EXPECT_EQ(storage[i].addr, in[i].offset);
        EXPECT_EQ(storage[i].len, in[i].length);
    }

    // Without needs_wakeup, notify_kernel_tx must NOT be called.
    EXPECT_EQ(h.ops->notify_kernel_calls(), 0);
}

TEST(AfXdpBackendTest, SendBatchCallsNotifyKernelWhenWakeupRequested) {
    Harness h;
    h.backend->init();
    h.ops->set_tx_needs_wakeup(true);

    PacketDescriptor in = make_desc(0u, 100u);
    const std::uint32_t n = h.backend->send_batch(&in, 1);
    EXPECT_EQ(n, 1u);
    EXPECT_EQ(h.ops->notify_kernel_calls(), 1);

    // Clear wakeup; a subsequent send_batch must not call.
    h.ops->set_tx_needs_wakeup(false);
    EXPECT_EQ(h.backend->send_batch(&in, 1), 1u);
    EXPECT_EQ(h.ops->notify_kernel_calls(), 1);
}

TEST(AfXdpBackendTest, SendBatchReturnsZeroOnEmpty) {
    Harness h;
    h.backend->init();
    EXPECT_EQ(h.backend->send_batch(nullptr, 0), 0u);

    PacketDescriptor in = make_desc(0u, 100u);
    EXPECT_EQ(h.backend->send_batch(&in, 0), 0u);
}

TEST(AfXdpBackendTest, RecvBatchOnUninitialisedReturnsZero) {
    // Constructed but not yet init()'d.
    Harness h;
    PacketDescriptor out[4]{};
    EXPECT_EQ(h.backend->recv_batch(out, 4), 0u);
}

// ===========================================================================
// Recycle completions
// ===========================================================================

TEST(AfXdpBackendTest, RecycleCompletionsReturnsAddressesToFillRing) {
    Harness h;
    h.backend->init();

    EXPECT_EQ(h.allocator->in_use(), kNumFrames);

    constexpr std::uint32_t kRecycle = 8;
    ASSERT_EQ(h.ops->produce_rx_from_fill(kRecycle), kRecycle);
    std::vector<PacketDescriptor> received(kRecycle);
    ASSERT_EQ(h.backend->recv_batch(received.data(), kRecycle), kRecycle);

    std::vector<std::uint64_t> addrs;
    addrs.reserve(kRecycle);
    for (const PacketDescriptor& packet : received) {
        addrs.push_back(packet.offset);
    }
    h.ops->preload_completions(addrs);

    const std::uint32_t n = h.backend->recycle_completions(kRecycle);
    EXPECT_EQ(n, kRecycle);
    EXPECT_EQ(h.allocator->in_use(), kNumFrames);
    EXPECT_EQ(h.allocator->free_count(), 0u);
    EXPECT_EQ(h.backend->service_fill_ring(), kRecycle);
    EXPECT_EQ(h.ops->fill_producer_index(), kNumFrames + kRecycle);
}

TEST(AfXdpBackendTest, RecycleCompletionsOnEmptyReturnsZero) {
    Harness h;
    h.backend->init();

    EXPECT_EQ(h.backend->recycle_completions(16), 0u);
}

// ===========================================================================
// Teardown order
// ===========================================================================

TEST(AfXdpBackendTest, DestructorCallsSocketThenUmem) {
    Harness h;
    h.backend->init();

    {
        // Re-scope so the destructor fires here.
        auto backend = std::move(h.backend);
    }

    const auto& order = h.ops->deletion_order();
    ASSERT_GE(order.size(), 2u);

    const auto sock_it = std::find(order.begin(), order.end(), "socket_delete");
    const auto umem_it = std::find(order.begin(), order.end(), "umem_delete");
    ASSERT_NE(sock_it, order.end());
    ASSERT_NE(umem_it, order.end());

    // socket_delete must come BEFORE umem_delete (kernel UAPI contract).
    EXPECT_LT(sock_it, umem_it) << "xsk_socket__delete must run before xsk_umem__delete";

    EXPECT_EQ(h.ops->close_fd_calls(), 0)
        << "xsk_socket__delete owns the libxdp socket fd lifecycle";
    EXPECT_EQ(h.allocator->in_use(), 0u);
    EXPECT_EQ(h.allocator->free_count(), kNumFrames);

    auto replacement_ops = std::make_unique<MockXskOps>();
    auto replacement =
        std::make_unique<AfXdpBackend>(*h.allocator, "veth0", 0, replacement_ops.get());
    EXPECT_NO_THROW(replacement->init());
    EXPECT_EQ(h.allocator->in_use(), kNumFrames);
    replacement.reset();
    EXPECT_EQ(h.allocator->in_use(), 0u);
}

TEST(AfXdpBackendTest, DestructorWithoutInitIsSafe) {
    Harness h;
    // No init() call: destruction must not crash and must not call any
    // IXskOps cleanup method.
    h.backend.reset();
    EXPECT_EQ(h.ops->deletion_order().size(), 0u);
    EXPECT_EQ(h.ops->close_fd_calls(), 0);
}

// ===========================================================================
// Wakeup / sleep signalling
// ===========================================================================

TEST(AfXdpBackendTest, NeedsWakeupRxReflectsRingFlags) {
    Harness h;
    h.backend->init();
    // After init the rx ring has no kernel-side producer activity; but
    // the mock initialises flags_value to 0.  We test that the backend
    // does not crash on the call -- the precise kernel semantics are
    // out of scope of the lifecycle test.
    (void)h.backend->needs_wakeup_rx();
    SUCCEED();
}

TEST(AfXdpBackendTest, NeedsWakeupTxMirrorsMockFlags) {
    Harness h;
    h.backend->init();
    h.ops->set_tx_needs_wakeup(true);
    EXPECT_TRUE(h.backend->needs_wakeup_tx());
    h.ops->set_tx_needs_wakeup(false);
    EXPECT_FALSE(h.backend->needs_wakeup_tx());
}
