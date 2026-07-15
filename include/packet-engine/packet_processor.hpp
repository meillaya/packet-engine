// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "packet-engine/rule_entry.hpp"
#include "packet-engine/rule_table.hpp"

namespace packet_engine {

class NatEngine;

enum class DefaultPacketAction : std::uint8_t {
    ALLOW,
    DROP,
};

struct PacketProcessResult {
    bool parsed{false};
    Action action{Action::DROP};
};

class PacketProcessor {
  public:
    PacketProcessor(RuleTableRegistry& rules, NatEngine* nat = nullptr,
                    DefaultPacketAction default_action = DefaultPacketAction::DROP) noexcept;

    [[nodiscard]] PacketProcessResult process(std::span<std::byte> frame) const noexcept;
    [[nodiscard]] PacketProcessResult process(std::span<std::byte> frame,
                                              const RuleTable& rules) const noexcept;
    [[nodiscard]] PacketProcessResult process(std::span<std::byte> frame, const RuleTable& rules,
                                              std::uint64_t now_ns) const noexcept;
    [[nodiscard]] RuleTablePtr rules_snapshot() const noexcept;

  private:
    RuleTableRegistry& rules_;
    NatEngine* nat_;
    DefaultPacketAction default_action_;
};

} // namespace packet_engine
