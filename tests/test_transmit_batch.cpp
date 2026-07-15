#include "packet-engine/transmit_batch.hpp"

#include <gtest/gtest.h>

#include <array>

namespace packet_engine {
namespace {

PacketDescriptor packet(std::uint64_t offset) {
    PacketDescriptor descriptor;
    descriptor.offset = offset;
    descriptor.length = 64;
    return descriptor;
}

TEST(TransmitBatchTest, GivenMixedActionsWhenOneTxIsAcceptedThenUnsentAndDroppedFramesRecycle) {
    const std::array<PacketDescriptor, 3> packets{{packet(10), packet(20), packet(30)}};
    std::array<PacketDescriptor, TransmitBatch::kCapacity> transmit_storage{};
    TransmitBatch batch{transmit_storage.data()};
    batch.forward(packets[0]);
    batch.drop(packets[1]);
    batch.forward(packets[2]);

    ASSERT_EQ(batch.transmit_count(), 2U);
    EXPECT_EQ(batch.transmit_descriptors()[0].offset, 10U);
    EXPECT_EQ(batch.transmit_descriptors()[1].offset, 30U);

    const auto outcome = batch.complete(1);

    EXPECT_EQ(outcome.transmitted, 1U);
    EXPECT_EQ(outcome.dropped, 2U);
    ASSERT_EQ(batch.recycle_count(), 2U);
    EXPECT_EQ(batch.recycle_addresses()[0], 20U);
    EXPECT_EQ(batch.recycle_addresses()[1], 30U);
}

TEST(TransmitBatchTest, GivenFullBurstWhenAllTxIsAcceptedThenNoFrameRecycles) {
    std::array<PacketDescriptor, TransmitBatch::kCapacity> transmit_storage{};
    TransmitBatch batch{transmit_storage.data()};
    for (std::uint64_t offset = 0; offset < TransmitBatch::kCapacity; ++offset) {
        batch.forward(packet(offset));
    }

    const auto outcome = batch.complete(TransmitBatch::kCapacity);

    EXPECT_EQ(outcome.transmitted, TransmitBatch::kCapacity);
    EXPECT_EQ(outcome.dropped, 0U);
    EXPECT_EQ(batch.recycle_count(), 0U);
}

TEST(TransmitBatchTest, GivenRxStorageAsScratchWhenCompactedThenUnreadDescriptorsStayIntact) {
    std::array<PacketDescriptor, TransmitBatch::kCapacity> packets{};
    packets[0] = packet(10);
    packets[1] = packet(20);
    packets[2] = packet(30);
    TransmitBatch batch{packets.data()};
    batch.drop(packets[0]);
    batch.forward(packets[1]);
    batch.forward(packets[2]);

    const auto outcome = batch.complete(2);

    EXPECT_EQ(outcome.transmitted, 2U);
    EXPECT_EQ(batch.transmit_descriptors()[0].offset, 20U);
    EXPECT_EQ(batch.transmit_descriptors()[1].offset, 30U);
    EXPECT_EQ(batch.recycle_addresses()[0], 10U);
}

} // namespace
} // namespace packet_engine
