// SPDX-License-Identifier: MIT
#include "packet-engine/packet_processor.hpp"

#include "packet-engine/nat.hpp"
#include "packet-engine/parser.hpp"
#include "packet-engine/rule_table.hpp"
#include "packet-engine/types.hpp"

#include <optional>

namespace packet_engine {

PacketProcessor::PacketProcessor(RuleTableRegistry& rules, NatEngine* nat,
                                 DefaultPacketAction default_action) noexcept
    : rules_{rules}, nat_{nat}, default_action_{default_action} {}

PacketProcessResult PacketProcessor::process(std::span<std::byte> frame) const noexcept {
    const auto rules = rules_snapshot();
    if (!rules)
        return {};
    return process(frame, *rules, detail::steady_now_ns());
}

RuleTablePtr PacketProcessor::rules_snapshot() const noexcept { return rules_.active(); }

PacketProcessResult PacketProcessor::process(std::span<std::byte> frame,
                                             const RuleTable& rules) const noexcept {
    return process(frame, rules, detail::steady_now_ns());
}

PacketProcessResult PacketProcessor::process(std::span<std::byte> frame, const RuleTable& rules,
                                             std::uint64_t now_ns) const noexcept {
    const auto parsed = parse_packet(std::span<const std::byte>{frame.data(), frame.size()});
    if (!parsed) {
        return {};
    }

    const bool is_ipv4 =
        !parsed->l3.empty() && (std::to_integer<std::uint8_t>(parsed->l3.front()) >> 4u) == 4u;
    Action action = default_action_ == DefaultPacketAction::ALLOW ? Action::ALLOW : Action::DROP;
    std::optional<BackendId> preferred_backend;
    MutablePacket mutable_packet{};
    const bool nat_eligible =
        is_ipv4 && nat_ != nullptr &&
        (parsed->five_tuple.proto == L4Proto::TCP || parsed->five_tuple.proto == L4Proto::UDP);

    if (nat_eligible) {
        mutable_packet.raw = frame;
        mutable_packet.src_ip = parsed->five_tuple.src_ip;
        mutable_packet.dst_ip = parsed->five_tuple.dst_ip;
        mutable_packet.src_port = parsed->five_tuple.src_port;
        mutable_packet.dst_port = parsed->five_tuple.dst_port;
        mutable_packet.proto = parsed->five_tuple.proto;
        mutable_packet.ipv4_ihl_bytes =
            static_cast<std::uint16_t>(parsed->l4.data() - parsed->l3.data());
        mutable_packet.ipv4_total_length = static_cast<std::uint16_t>(parsed->l3.size());
        mutable_packet.l4_offset =
            static_cast<std::uint16_t>(parsed->l4.data() - parsed->raw.data());
        mutable_packet.l4_total_length = static_cast<std::uint16_t>(parsed->l4.size());
        mutable_packet.ipv4_csum_offset =
            static_cast<std::uint16_t>(parsed->l3.data() - parsed->raw.data() + 10u);
        mutable_packet.l4_csum_offset = static_cast<std::uint16_t>(
            mutable_packet.l4_offset + (mutable_packet.proto == L4Proto::UDP
                                            ? static_cast<std::uint16_t>(6u)
                                            : static_cast<std::uint16_t>(16u)));
        if (mutable_packet.proto == L4Proto::TCP) {
            mutable_packet.tcp_flags = std::to_integer<std::uint8_t>(parsed->l4[13]);
        }

        if (const auto existing = nat_->process_existing(mutable_packet, now_ns)) {
            const bool transmitted = *existing == Action::TX_TO_BACKEND_INTERFACE ||
                                     *existing == Action::TX_TO_CLIENT_INTERFACE;
            return {true, transmitted ? *existing : Action::DROP};
        }
    }

    if (is_ipv4) {
        ParsedPacket packet{};
        packet.raw = parsed->raw;
        packet.l2 = parsed->l2;
        packet.l3 = parsed->l3;
        packet.l4 = parsed->l4;
        packet.src_ip = parsed->five_tuple.src_ip;
        packet.dst_ip = parsed->five_tuple.dst_ip;
        packet.src_port = parsed->five_tuple.src_port;
        packet.dst_port = parsed->five_tuple.dst_port;
        packet.proto = parsed->five_tuple.proto;
        if (const auto decision = rules.lookup_entry(packet, now_ns)) {
            action = decision->action;
            if (action == Action::FORWARD_TO_BACKEND && decision->has_backend_id) {
                preferred_backend = static_cast<BackendId>(decision->backend_id);
            }
        }
    }

    if (action != Action::FORWARD_TO_BACKEND) {
        return {true, action};
    }
    if (!nat_eligible) {
        return {true, Action::DROP};
    }
    const Action nat_action = nat_->process_forward(mutable_packet, preferred_backend, now_ns);
    if (nat_action != Action::TX_TO_BACKEND_INTERFACE &&
        nat_action != Action::TX_TO_CLIENT_INTERFACE) {
        return {true, Action::DROP};
    }
    return {true, nat_action};
}

} // namespace packet_engine
