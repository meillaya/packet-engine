#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>

#include "packet-engine/types.hpp"

namespace packet_engine {

struct TransmitOutcome {
    std::uint32_t transmitted = 0;
    std::uint32_t dropped = 0;
};

class TransmitBatch {
  public:
    static constexpr std::uint32_t kCapacity = 64;

    explicit TransmitBatch(PacketDescriptor* transmit_storage) noexcept
        : transmit_storage_{transmit_storage} {
        assert(transmit_storage_ != nullptr);
    }

    void forward(const PacketDescriptor& packet) noexcept {
        assert(total_count() < kCapacity);
        transmit_storage_[transmit_count_++] = packet;
    }

    void drop(const PacketDescriptor& packet) noexcept {
        assert(total_count() < kCapacity);
        recycle_addresses_[recycle_count_++] = packet.offset;
    }

    [[nodiscard]] const PacketDescriptor* transmit_descriptors() const noexcept {
        return transmit_storage_;
    }

    [[nodiscard]] const std::uint64_t* recycle_addresses() const noexcept {
        return recycle_addresses_.data();
    }

    [[nodiscard]] std::uint32_t transmit_count() const noexcept { return transmit_count_; }
    [[nodiscard]] std::uint32_t recycle_count() const noexcept { return recycle_count_; }

    [[nodiscard]] TransmitOutcome complete(std::uint32_t accepted) noexcept {
        accepted = std::min(accepted, transmit_count_);
        for (std::uint32_t index = accepted; index < transmit_count_; ++index) {
            recycle_addresses_[recycle_count_++] = transmit_storage_[index].offset;
        }
        return {.transmitted = accepted, .dropped = recycle_count_};
    }

  private:
    [[nodiscard]] std::uint32_t total_count() const noexcept {
        return transmit_count_ + recycle_count_;
    }

    PacketDescriptor* transmit_storage_;
    std::array<std::uint64_t, kCapacity> recycle_addresses_;
    std::uint32_t transmit_count_ = 0;
    std::uint32_t recycle_count_ = 0;
};

} // namespace packet_engine
