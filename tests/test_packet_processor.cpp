// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "packet-engine/backend_registry.hpp"
#include "packet-engine/conntrack.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/nat.hpp"
#include "packet-engine/packet_processor.hpp"
#include "packet-engine/rule_table.hpp"
#include "packet-engine/token_bucket.hpp"

namespace pe = packet_engine;

namespace {

std::uint16_t internet_checksum(std::span<const std::byte> bytes, std::uint32_t sum = 0) noexcept {
    std::size_t index = 0;
    while (index + 1u < bytes.size()) {
        sum += (std::to_integer<std::uint32_t>(bytes[index]) << 8u) |
               std::to_integer<std::uint8_t>(bytes[index + 1u]);
        index += 2u;
    }
    if (index < bytes.size())
        sum += std::to_integer<std::uint32_t>(bytes[index]) << 8u;
    while ((sum >> 16u) != 0u)
        sum = (sum & 0xffffu) + (sum >> 16u);
    return static_cast<std::uint16_t>(~sum);
}

void write_be16(std::byte* destination, std::uint16_t value) noexcept {
    destination[0] = std::byte{static_cast<std::uint8_t>(value >> 8u)};
    destination[1] = std::byte{static_cast<std::uint8_t>(value)};
}

void finalize_ipv4_checksums(std::vector<std::byte>& frame, pe::L4Proto proto) {
    std::byte* ip = frame.data() + 14u;
    const std::size_t l4_size = frame.size() - 34u;
    ip[10] = std::byte{0};
    ip[11] = std::byte{0};
    write_be16(ip + 10u, internet_checksum({ip, 20u}));

    std::byte* l4 = ip + 20u;
    const std::size_t checksum_offset = proto == pe::L4Proto::TCP ? 16u : 6u;
    l4[checksum_offset] = std::byte{0};
    l4[checksum_offset + 1u] = std::byte{0};
    std::uint32_t sum = 0;
    for (std::size_t index = 12u; index < 20u; index += 2u) {
        sum += (std::to_integer<std::uint32_t>(ip[index]) << 8u) |
               std::to_integer<std::uint8_t>(ip[index + 1u]);
    }
    sum += static_cast<std::uint8_t>(proto);
    sum += static_cast<std::uint16_t>(l4_size);
    write_be16(l4 + checksum_offset, internet_checksum({l4, l4_size}, sum));
}

std::vector<std::byte> make_ipv4(pe::L4Proto proto) {
    const std::size_t l4_size = proto == pe::L4Proto::TCP ? 20u : 8u;
    std::vector<std::byte> frame(14u + 20u + l4_size, std::byte{0});
    frame[12] = std::byte{0x08};
    frame[13] = std::byte{0x00};
    frame[0] = std::byte{0x02};
    frame[5] = std::byte{0xEE};
    frame[6] = std::byte{0x02};
    frame[11] = std::byte{0xCC};
    std::byte* ip = frame.data() + 14;
    ip[0] = std::byte{0x45};
    const auto ip_size = static_cast<std::uint16_t>(20u + l4_size);
    ip[2] = std::byte{static_cast<std::uint8_t>(ip_size >> 8u)};
    ip[3] = std::byte{static_cast<std::uint8_t>(ip_size)};
    ip[8] = std::byte{64};
    ip[9] = std::byte{static_cast<std::uint8_t>(proto)};
    ip[12] = std::byte{10};
    ip[15] = std::byte{1};
    ip[16] = std::byte{10};
    ip[17] = std::byte{99};
    ip[19] = std::byte{1};
    std::byte* l4 = ip + 20;
    l4[0] = std::byte{0xC0};
    l4[1] = std::byte{0x00};
    l4[2] = std::byte{0x00};
    l4[3] = std::byte{0x50};
    if (proto == pe::L4Proto::TCP) {
        l4[12] = std::byte{0x50};
    } else {
        l4[4] = std::byte{0x00};
        l4[5] = std::byte{0x08};
    }
    finalize_ipv4_checksums(frame, proto);
    return frame;
}

pe::FiveTuple test_tuple(pe::L4Proto proto) {
    return {pe::IPv4Addr{10, 0, 0, 1}, pe::IPv4Addr{10, 99, 0, 1}, 49152, 80, proto};
}

std::shared_ptr<pe::RuleTable> table_with(pe::L4Proto proto, pe::Action action) {
    auto table = std::make_shared<pe::RuleTable>();
    EXPECT_TRUE(table->add_exact(test_tuple(proto), pe::RuleEntry{7, action}));
    if (action == pe::Action::RATE_LIMIT) {
        table->add_rate_limit_state(7, pe::TokenBucket{1, 4096, 0});
    }
    return table;
}

} // namespace

TEST(PacketProcessorTest, MalformedAndDefaultPolicyFailPredictably) {
    pe::RuleTableRegistry rules{std::make_shared<pe::RuleTable>()};
    pe::PacketProcessor allow{rules, nullptr, pe::DefaultPacketAction::ALLOW};
    pe::PacketProcessor drop{rules, nullptr, pe::DefaultPacketAction::DROP};
    std::vector<std::byte> malformed;
    auto frame = make_ipv4(pe::L4Proto::TCP);

    EXPECT_EQ(allow.process(malformed).action, pe::Action::DROP);
    EXPECT_FALSE(allow.process(malformed).parsed);
    EXPECT_EQ(allow.process(frame).action, pe::Action::ALLOW);
    EXPECT_EQ(drop.process(frame).action, pe::Action::DROP);
}

TEST(PacketProcessorTest, AllowDropAndAdmittedRateLimitPreserveFrame) {
    for (const pe::Action expected :
         {pe::Action::ALLOW, pe::Action::DROP, pe::Action::RATE_LIMIT}) {
        pe::RuleTableRegistry rules{table_with(pe::L4Proto::TCP, expected)};
        pe::PacketProcessor processor{rules, nullptr, pe::DefaultPacketAction::ALLOW};
        auto frame = make_ipv4(pe::L4Proto::TCP);
        const auto original = frame;
        const auto result = processor.process(frame);
        EXPECT_TRUE(result.parsed);
        EXPECT_EQ(result.action, expected);
        EXPECT_EQ(frame, original);
    }
}

TEST(PacketProcessorTest, ForwardWithoutNatDrops) {
    pe::RuleTableRegistry rules{table_with(pe::L4Proto::TCP, pe::Action::FORWARD_TO_BACKEND)};
    pe::PacketProcessor processor{rules};
    auto frame = make_ipv4(pe::L4Proto::TCP);
    EXPECT_EQ(processor.process(frame).action, pe::Action::DROP);
}

TEST(PacketProcessorTest, UdpForwardRoutesThroughNat) {
    pe::BackendRegistry backends;
    pe::Backend first_backend{};
    first_backend.id = 1;
    first_backend.authority = "10.10.0.10:8080";
    first_backend.next_hop_mac.bytes = {0x02, 0, 0, 0, 0, 1};
    backends.register_backend(first_backend);
    pe::Backend selected_backend{};
    selected_backend.id = 2;
    selected_backend.authority = "10.10.0.20:9090";
    selected_backend.next_hop_mac.bytes = {0x02, 0, 0, 0, 0, 2};
    backends.register_backend(selected_backend);
    std::vector<pe::KetamaBackend> entries{{1, "10.10.0.10:8080"}};
    pe::KetamaRing ketama{entries};
    pe::ConntrackFlowCache flows;
    pe::NatEngine nat{flows, backends, ketama, pe::IPv4Addr{10, 99, 0, 1}};
    auto forward_table = std::make_shared<pe::RuleTable>();
    ASSERT_TRUE(forward_table->add_exact(test_tuple(pe::L4Proto::UDP),
                                         pe::RuleEntry{7, pe::Action::FORWARD_TO_BACKEND, 0, 2}));
    pe::RuleTableRegistry rules{forward_table};
    pe::PacketProcessor processor{rules, &nat, pe::DefaultPacketAction::ALLOW};
    auto frame = make_ipv4(pe::L4Proto::UDP);

    const auto result = processor.process(frame);
    EXPECT_TRUE(result.parsed);
    EXPECT_EQ(result.action, pe::Action::TX_TO_BACKEND_INTERFACE);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[5]), 2u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[11]), 0xEEu);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 16]), 10u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 17]), 10u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 18]), 0u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 19]), 20u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 20 + 2]), 0x23u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(frame[14 + 20 + 3]), 0x82u);

    auto reply = frame;
    for (std::size_t index = 0; index < 6; ++index) {
        std::swap(reply[index], reply[index + 6]);
    }
    for (std::size_t index = 0; index < 4; ++index) {
        std::swap(reply[14 + 12 + index], reply[14 + 16 + index]);
    }
    for (std::size_t index = 0; index < 2; ++index) {
        std::swap(reply[14 + 20 + index], reply[14 + 20 + 2 + index]);
    }
    reply[14 + 10] = std::byte{0};
    reply[14 + 11] = std::byte{0};
    reply[14 + 20 + 6] = std::byte{0};
    reply[14 + 20 + 7] = std::byte{0};
    finalize_ipv4_checksums(reply, pe::L4Proto::UDP);

    const auto returned = processor.process(reply);
    EXPECT_TRUE(returned.parsed);
    EXPECT_EQ(returned.action, pe::Action::TX_TO_CLIENT_INTERFACE);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[5]), 0xCCu);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[11]), 0xEEu);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[14 + 12]), 10u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[14 + 13]), 99u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[14 + 16]), 10u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(reply[14 + 19]), 1u);

    rules.swap(std::make_shared<pe::RuleTable>());
    auto established = make_ipv4(pe::L4Proto::UDP);
    EXPECT_EQ(processor.process(established).action, pe::Action::TX_TO_BACKEND_INTERFACE);
}

TEST(PacketProcessorTest, TcpFlagsAdvanceEstablishedConntrackFlow) {
    pe::BackendRegistry backends;
    pe::Backend backend{};
    backend.id = 1;
    backend.authority = "10.10.0.10:8080";
    backend.next_hop_mac.bytes = {0x02, 0, 0, 0, 0, 1};
    backends.register_backend(backend);
    pe::KetamaRing ketama{{pe::KetamaBackend{1, backend.authority}}};
    pe::ConntrackFlowCache flows;
    pe::NatEngine nat{flows, backends, ketama, pe::IPv4Addr{10, 99, 0, 1}};
    pe::RuleTableRegistry rules{table_with(pe::L4Proto::TCP, pe::Action::FORWARD_TO_BACKEND)};
    pe::PacketProcessor processor{rules, &nat};

    auto syn = make_ipv4(pe::L4Proto::TCP);
    syn[14 + 20 + 13] = std::byte{static_cast<std::uint8_t>(pe::TcpFlags::SYN)};
    finalize_ipv4_checksums(syn, pe::L4Proto::TCP);
    EXPECT_EQ(processor.process(syn).action, pe::Action::TX_TO_BACKEND_INTERFACE);
    ASSERT_NE(flows.peek(test_tuple(pe::L4Proto::TCP)), nullptr);
    EXPECT_EQ(flows.peek(test_tuple(pe::L4Proto::TCP))->tcp_state, pe::TcpState::SYN_SENT);

    auto ack = make_ipv4(pe::L4Proto::TCP);
    ack[14 + 20 + 13] = std::byte{static_cast<std::uint8_t>(pe::TcpFlags::ACK)};
    finalize_ipv4_checksums(ack, pe::L4Proto::TCP);
    EXPECT_EQ(processor.process(ack).action, pe::Action::TX_TO_BACKEND_INTERFACE);
    EXPECT_EQ(flows.peek(test_tuple(pe::L4Proto::TCP))->tcp_state, pe::TcpState::ESTABLISHED);
}
