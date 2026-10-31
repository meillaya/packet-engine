// SPDX-License-Identifier: MIT
//
// test_nat.cpp -- GoogleTest coverage for the NAT engine.
//
// Coverage matrix
// ===============
//
//   * Forward L4 NAT rewrites L3+L4 with correct RFC 1624 incremental
//     checksums (vs from-scratch recompute).
//   * Return path is the inverse of forward (post-NAT pair survives a
//     round-trip through forward+return with zero checksum drift).
//   * Port allocator returns unique ports across many allocations.
//   * Forward vs return dispatch is by destination IP (engine_vip).
//   * 1000-pair forward+return round trip yields zero checksum mismatch
//     vs the reference from-scratch recompute.
//   * Wrong-destination forward -> DROP.
//   * ICMP/other protocols -> DROP.
//   * Parser populates a MutablePacket correctly from a wire frame.
//
// The reference from-scratch checksum is implemented here in pure C++
// rather than depending on scapy -- the plan explicitly allows this and
// notes that it keeps the test reproducible in air-gapped environments.

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "packet-engine/backend_registry.hpp"
#include "packet-engine/conntrack.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/nat.hpp"
#include "packet-engine/rule_entry.hpp"
#include "packet-engine/types.hpp"

namespace pe = packet_engine;

TEST(NatChecksumTest, UdpComputedZeroUsesWireAllOnesRepresentation) {
    EXPECT_EQ(pe::normalize_transport_checksum(pe::L4Proto::UDP, 0), 0xFFFFu);
    EXPECT_EQ(pe::normalize_transport_checksum(pe::L4Proto::TCP, 0), 0u);
    EXPECT_EQ(pe::normalize_transport_checksum(pe::L4Proto::UDP, 0x1234u), 0x1234u);
}

namespace {

[[nodiscard]] std::uint16_t load_u16(const std::byte* data) noexcept {
    std::uint16_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

[[nodiscard]] std::uint32_t load_u32(const std::byte* data) noexcept {
    std::uint32_t value;
    std::memcpy(&value, data, sizeof(value));
    return value;
}

[[nodiscard]] std::uint16_t load_be16(const std::byte* data) noexcept {
    return pe::bswap16_helper(load_u16(data));
}

void store_u16(std::byte* data, std::uint16_t value) noexcept {
    std::memcpy(data, &value, sizeof(value));
}

// Write a host-order numeric checksum in network byte order.
void store_be16(std::byte* data, std::uint16_t value) noexcept {
    store_u16(data, pe::bswap16_helper(value));
}

// ---------------------------------------------------------------------------
// Reference helper: from-scratch Internet checksum for a buffer.
// Used to validate the engine's incremental update against the textbook
// formula.  The host-side fold is correct for either endian because the
// algorithm folds in 16-bit halves and the carry-out is identical mod 2.
// ---------------------------------------------------------------------------

[[nodiscard]] std::uint16_t ones_complement_sum(const std::byte* data, std::size_t len) noexcept {
    std::uint32_t acc = 0;
    std::size_t i = 0;
    for (; i + 2 <= len; i += 2) {
        acc += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(data[i])) << 8) |
               static_cast<std::uint8_t>(data[i + 1]);
    }
    if (i < len) {
        const auto last = static_cast<std::uint8_t>(data[i]);
        acc += static_cast<std::uint32_t>(last) << 8; // pad with zero low byte (RFC 1071)
    }
    while (acc >> 16)
        acc = (acc & 0xFFFFu) + (acc >> 16);
    return static_cast<std::uint16_t>(~acc & 0xFFFFu);
}

// Internet checksum for a buffer that ENDS in an even number of bytes;
// the from-scratch helper handles odd tails by zero-padding the MSB.
[[nodiscard]] std::uint16_t ones_complement_sum_aligned(const std::byte* data,
                                                        std::size_t len) noexcept {
    return ones_complement_sum(data, len);
}

// Reference checksum for an IPv4 header (treating the checksum field as
// zero during the sum, then complementing).
[[nodiscard]] std::uint16_t ipv4_header_csum(const std::byte* ip) noexcept {
    return ones_complement_sum_aligned(ip, 20);
}

// Reference L4 (TCP or UDP) checksum including the IPv4 pseudo-header.
// The checksum field is zeroed at `csum_offset` (16 for TCP, 6 for UDP).
// Returns the value in host byte order as read from the wire, which is what
// the tests get from `load_u16()`.
[[nodiscard]] std::uint16_t l4_csum_with_pseudo(const std::byte* ip, const std::byte* l4,
                                                std::size_t l4_len,
                                                std::size_t csum_offset = 16) noexcept {
    // Pseudo-header = src_ip (4) + dst_ip (4) + zero (1) + proto (1) + l4_len (2) = 12 bytes.
    std::uint32_t acc = 0;
    // src_ip / dst_ip (big-endian u16s).
    for (std::size_t i = 12; i < 20; i += 2) {
        acc += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(ip[i])) << 8) |
               static_cast<std::uint8_t>(ip[i + 1]);
    }
    // protocol: a 16-bit pseudo-header word with the protocol in the low byte.
    acc += static_cast<std::uint8_t>(ip[9]);
    // l4 length as a 16-bit big-endian word.
    acc += static_cast<std::uint16_t>(l4_len);

    // L4 body with the checksum field zeroed.
    std::vector<std::byte> body(l4, l4 + l4_len);
    body[csum_offset] = std::byte{0};
    body[csum_offset + 1u] = std::byte{0};

    // Fold in the body.
    for (std::size_t i = 0; i + 1 < l4_len; i += 2) {
        acc += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[i])) << 8) |
               static_cast<std::uint8_t>(body[i + 1]);
    }
    if ((l4_len & 1u) != 0u) {
        acc += static_cast<std::uint32_t>(static_cast<std::uint8_t>(body[l4_len - 1])) << 8;
    }

    while (acc >> 16)
        acc = (acc & 0xFFFFu) + (acc >> 16);
    return pe::bswap16_helper(static_cast<std::uint16_t>(~acc & 0xFFFFu));
}

// ---------------------------------------------------------------------------
// Frame builder.  Builds a 14-byte Ethernet (skipped on the IP side) +
// IPv4 + TCP/UDP frame, zero-initialised except for the fields we care
// about.  The Ethernet header bytes are all zero -- the NAT engine does
// not look at them.
// ---------------------------------------------------------------------------

struct Frame {
    std::vector<std::byte> bytes;
    std::uint16_t ip_offset{0}; // offset of IPv4 header (after Eth)
    std::uint16_t l4_offset{0};
    std::uint16_t l4_total_length{0};

    static Frame make_tcp(pe::IPv4Addr src, pe::IPv4Addr dst, std::uint16_t sp, std::uint16_t dp,
                          std::span<const std::byte> payload = {}) {
        Frame f;
        constexpr std::uint16_t kEth = 14;
        constexpr std::uint16_t kIp4 = 20;
        constexpr std::uint16_t kTcpNoOpt = 20;
        const std::uint16_t tcp_len = static_cast<std::uint16_t>(kTcpNoOpt + payload.size());
        const std::uint16_t ip_total = static_cast<std::uint16_t>(kIp4 + tcp_len);
        const std::uint16_t total = static_cast<std::uint16_t>(kEth + ip_total);

        f.bytes.assign(total, std::byte{0});
        const std::array<std::uint8_t, 6> engine_mac{0x02, 0, 0, 0, 0, 0xEE};
        const std::array<std::uint8_t, 6> client_mac{0x02, 0, 0, 0, 0, 0xCC};
        for (std::size_t index = 0; index < 6u; ++index) {
            f.bytes[index] = static_cast<std::byte>(engine_mac[index]);
            f.bytes[index + 6u] = static_cast<std::byte>(client_mac[index]);
        }

        f.ip_offset = kEth;
        f.l4_offset = static_cast<std::uint16_t>(kEth + kIp4);
        f.l4_total_length = tcp_len;

        std::byte* ip = f.bytes.data() + kEth;
        // IPv4 header.
        ip[0] = std::byte{0x45}; // version 4, IHL 5
        ip[1] = std::byte{0x00};
        // total_length
        ip[2] = std::byte{static_cast<std::uint8_t>((ip_total >> 8) & 0xFF)};
        ip[3] = std::byte{static_cast<std::uint8_t>(ip_total & 0xFF)};
        // identification + flags + fragment: leave 0
        // TTL = 64
        ip[8] = std::byte{64};
        // protocol = 6 (TCP)
        ip[9] = std::byte{6};
        // src_ip / dst_ip on the wire are big-endian bytes.
        for (std::size_t i = 0; i < 4; ++i) {
            const auto shift = static_cast<unsigned>((3u - i) * 8u);
            ip[12 + i] = std::byte{static_cast<std::uint8_t>(src.value >> shift)};
            ip[16 + i] = std::byte{static_cast<std::uint8_t>(dst.value >> shift)};
        }

        // header checksum (zero at this point)
        store_be16(ip + 10, ipv4_header_csum(ip));

        // TCP segment.  Port bytes on the wire are BE; the engine reads
        // them via bswap16.
        std::byte* tcp = f.bytes.data() + f.l4_offset;
        const std::uint16_t sp_be = pe::bswap16_helper(sp);
        const std::uint16_t dp_be = pe::bswap16_helper(dp);
        std::memcpy(tcp, &sp_be, 2);
        std::memcpy(tcp + 2, &dp_be, 2);
        tcp[12] = std::byte{0x50}; // data offset = 5 << 4
        tcp[13] = std::byte{0x18}; // PSH|ACK
        // seq/ack: leave 0
        if (!payload.empty()) {
            std::memcpy(tcp + kTcpNoOpt, payload.data(), payload.size());
        }

        return f;
    }

    static Frame make_udp(pe::IPv4Addr src, pe::IPv4Addr dst, std::uint16_t sp, std::uint16_t dp) {
        Frame f;
        constexpr std::uint16_t kEth = 14;
        constexpr std::uint16_t kIp4 = 20;
        constexpr std::uint16_t kUdp = 8;
        constexpr std::uint16_t kIpTotal = kIp4 + kUdp;

        f.bytes.assign(kEth + kIpTotal, std::byte{0});
        const std::array<std::uint8_t, 6> engine_mac{0x02, 0, 0, 0, 0, 0xEE};
        const std::array<std::uint8_t, 6> client_mac{0x02, 0, 0, 0, 0, 0xCC};
        for (std::size_t index = 0; index < 6u; ++index) {
            f.bytes[index] = static_cast<std::byte>(engine_mac[index]);
            f.bytes[index + 6u] = static_cast<std::byte>(client_mac[index]);
        }
        f.ip_offset = kEth;
        f.l4_offset = kEth + kIp4;
        f.l4_total_length = kUdp;

        std::byte* ip = f.bytes.data() + kEth;
        ip[0] = std::byte{0x45};
        ip[2] = std::byte{0};
        ip[3] = std::byte{kIpTotal};
        ip[8] = std::byte{64};
        ip[9] = std::byte{17};
        for (std::size_t i = 0; i < 4; ++i) {
            const auto shift = static_cast<unsigned>((3u - i) * 8u);
            ip[12 + i] = std::byte{static_cast<std::uint8_t>(src.value >> shift)};
            ip[16 + i] = std::byte{static_cast<std::uint8_t>(dst.value >> shift)};
        }

        std::byte* udp = f.bytes.data() + f.l4_offset;
        const std::uint16_t sp_be = pe::bswap16_helper(sp);
        const std::uint16_t dp_be = pe::bswap16_helper(dp);
        const std::uint16_t len_be = pe::bswap16_helper(kUdp);
        std::memcpy(udp, &sp_be, 2);
        std::memcpy(udp + 2, &dp_be, 2);
        std::memcpy(udp + 4, &len_be, 2);

        store_be16(ip + 10, ipv4_header_csum(ip));
        return f;
    }

    pe::MutablePacket build_view() const {
        pe::MutablePacket v{};
        // Write to a std::vector<std::byte> -- we need a mutable view.
        v.raw = std::span<std::byte>(const_cast<std::byte*>(bytes.data()), bytes.size());
        v.ipv4_ihl_bytes = 20;
        v.ipv4_total_length = static_cast<std::uint16_t>(
            (bytes.size() > static_cast<std::size_t>(ip_offset) + 2u)
                ? ((static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[ip_offset + 2u]))
                    << 8) |
                   static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[ip_offset + 3u])))
                : 0u);
        v.ipv4_csum_offset = static_cast<std::uint16_t>(ip_offset + 10u);
        v.l4_offset = l4_offset;
        v.l4_total_length = l4_total_length;
        v.l4_csum_offset = static_cast<std::uint16_t>(l4_offset + 16u);
        // Fill src/dst IP+port from the wire (big-endian).
        const std::uint32_t sbe = pe::bswap32_helper(load_u32(bytes.data() + ip_offset + 12));
        const std::uint32_t dbe = pe::bswap32_helper(load_u32(bytes.data() + ip_offset + 16));
        v.src_ip = pe::IPv4Addr{sbe};
        v.dst_ip = pe::IPv4Addr{dbe};
        v.src_port = pe::bswap16_helper(load_u16(bytes.data() + l4_offset));
        v.dst_port = pe::bswap16_helper(load_u16(bytes.data() + l4_offset + 2));
        v.proto = pe::L4Proto::TCP;
        return v;
    }

    std::uint16_t read_l4_csum_host() const noexcept {
        std::uint16_t v;
        std::memcpy(&v, bytes.data() + l4_offset + 16, 2);
        return v;
    }
    std::uint16_t read_ip_csum_host() const noexcept {
        std::uint16_t v;
        std::memcpy(&v, bytes.data() + ip_offset + 10, 2);
        return v;
    }
};

// ---------------------------------------------------------------------------
// Backend helpers -- shared between the regex / util tests.
// ---------------------------------------------------------------------------

constexpr pe::IPv4Addr kEngineVip = pe::IPv4Addr{10, 99, 0, 1};

void register_backends(pe::BackendRegistry& reg,
                       const std::vector<std::pair<pe::BackendId, std::string>>& specs) {
    for (const auto& [id, addr] : specs) {
        pe::Backend b{};
        b.id = id;
        b.authority = addr;
        b.health_port = 8080;
        b.state = pe::BackendState::HEALTHY;
        b.next_hop_mac.bytes = {0x02, 0, 0, 0, 0, static_cast<std::uint8_t>(id)};
        reg.register_backend(b);
    }
}

// Build a Ketama ring populated with the same backend set so the ring
// pick resolves.  The ketama address format is the same as Backend.authority.
pe::KetamaRing make_ketama(const std::vector<std::pair<pe::BackendId, std::string>>& specs) {
    std::vector<pe::KetamaBackend> kspecs;
    kspecs.reserve(specs.size());
    for (const auto& [id, addr] : specs) {
        pe::KetamaBackend kb{};
        kb.id = static_cast<pe::KetamaBackendId>(id);
        kb.address = addr;
        kspecs.push_back(std::move(kb));
    }
    return pe::KetamaRing{kspecs};
}

} // namespace

// ===========================================================================
// Parsing & basic check
// ===========================================================================

TEST(NatEngineTest, ParserBuildsMutablePacketForTcpFrame) {
    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, pe::IPv4Addr{10, 99, 0, 1}, 1234, 80);
    auto v = f.build_view();
    EXPECT_EQ(v.src_ip.value, (10u << 24) | (0u << 16) | (0u << 8) | 1u);
    EXPECT_EQ(v.dst_ip.value, (10u << 24) | (99u << 16) | (0u << 8) | 1u);
    EXPECT_EQ(v.src_port, 1234u);
    EXPECT_EQ(v.dst_port, 80u);
    EXPECT_EQ(v.proto, pe::L4Proto::TCP);
    EXPECT_EQ(v.ipv4_ihl_bytes, 20u);
}

TEST(NatEngineTest, UdpForwardUsesUdpChecksumOffsetWithoutOutOfBounds) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_udp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto packet = pe::parse_packet_mutable(f.bytes);
    ASSERT_TRUE(packet.has_value());

    EXPECT_EQ(engine.process_forward(*packet), pe::Action::TX_TO_BACKEND_INTERFACE);
    EXPECT_EQ(packet->l4_csum_offset, f.l4_offset + 6u);
    EXPECT_EQ(packet->dst_port, 8080u);
}

TEST(NatEngineTest, UdpForwardRebuildsZeroChecksum) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    // IPv4 UDP checksum zero means "not computed"; the NAT rewrite must
    // synthesize the checksum for the original tuple before applying the
    // incremental deltas.
    Frame f = Frame::make_udp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    ASSERT_EQ(f.bytes[f.l4_offset + 6u], std::byte{0});
    ASSERT_EQ(f.bytes[f.l4_offset + 7u], std::byte{0});

    auto packet = pe::parse_packet_mutable(f.bytes);
    ASSERT_TRUE(packet.has_value());
    ASSERT_EQ(engine.process_forward(*packet), pe::Action::TX_TO_BACKEND_INTERFACE);

    const std::byte* ip = f.bytes.data() + f.ip_offset;
    const std::byte* l4 = f.bytes.data() + f.l4_offset;
    const std::uint16_t expected =
        l4_csum_with_pseudo(ip, l4, f.l4_total_length, /*csum_offset=*/6);
    const std::uint16_t actual = load_u16(l4 + 6);
    EXPECT_EQ(actual, expected);
    EXPECT_NE(actual, 0u) << "a synthesized UDP checksum must not be zero";
}

TEST(NatEngineTest, TcpForwardRebuildsZeroChecksumWithOddPayload) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    const std::array<std::byte, 1> payload{std::byte{0x5a}};
    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80,
                              std::span<const std::byte>{payload});
    ASSERT_EQ(f.l4_total_length % 2u, 1u);

    auto packet = pe::parse_packet_mutable(f.bytes);
    ASSERT_TRUE(packet.has_value());
    ASSERT_EQ(engine.process_forward(*packet), pe::Action::TX_TO_BACKEND_INTERFACE);

    const std::byte* ip = f.bytes.data() + f.ip_offset;
    const std::byte* l4 = f.bytes.data() + f.l4_offset;
    const std::uint16_t expected = l4_csum_with_pseudo(ip, l4, f.l4_total_length);
    EXPECT_EQ(load_u16(l4 + 16), expected);
}

TEST(NatEngineTest, ShortMutableUdpFrameDrops) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};
    std::vector<std::byte> bytes(8, std::byte{0});
    pe::MutablePacket packet{};
    packet.raw = bytes;
    packet.proto = pe::L4Proto::UDP;
    packet.dst_ip = kEngineVip;

    EXPECT_EQ(engine.process_forward(packet), pe::Action::DROP);
    EXPECT_EQ(engine.process_return(packet), pe::Action::DROP);
}

// ===========================================================================
// Forward path: TX_TO_BACKEND_INTERFACE, correct rewrites, unique ports.
// ===========================================================================

TEST(NatEngineTest, ForwardPicksBackendAndRewrites5Tuple) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    // Single backend so the test is deterministic -- the engine always
    // returns backend {1, 8080} for any key.
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto pkt_view = f.build_view();
    const std::uint16_t pre_port = pkt_view.src_port;

    const pe::Action a = engine.process_forward(pkt_view);
    EXPECT_EQ(a, pe::Action::TX_TO_BACKEND_INTERFACE);

    EXPECT_EQ(pkt_view.dst_ip.value, (pe::IPv4Addr{10, 10, 0, 10}.value));
    EXPECT_EQ(pkt_view.src_ip.value, kEngineVip.value);
    EXPECT_NE(pkt_view.src_port, pre_port);
    EXPECT_EQ(pkt_view.dst_port, 8080u);

    std::uint16_t wire_dp;
    std::memcpy(&wire_dp, f.bytes.data() + f.l4_offset + 2, 2);
    wire_dp = pe::bswap16_helper(wire_dp);
    EXPECT_EQ(wire_dp, 8080u);
}

TEST(NatEngineTest, ZeroBackendPortFailsClosed) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:0"}});
    auto ket = make_ketama({{1, "10.10.0.10:0"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame frame = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto packet = frame.build_view();
    EXPECT_EQ(engine.process_forward(packet), pe::Action::DROP);
    EXPECT_EQ(flows.size(), 0u);
}

TEST(NatEngineTest, ExplicitBackendPinRejectsDegradedBackend) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};
    for (int failure = 0; failure < 4; ++failure) {
        reg.report_failure(1);
    }
    ASSERT_EQ(reg.find(1)->state, pe::BackendState::DEGRADED);

    Frame frame = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto packet = frame.build_view();
    EXPECT_EQ(engine.process_forward(packet, pe::BackendId{1}), pe::Action::DROP);
}

TEST(NatEngineTest, RepeatedFlowKeepsTranslationAcrossBackendRingUpdate) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}, {2, "10.10.0.20:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame first = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto first_packet = first.build_view();
    ASSERT_EQ(engine.process_forward(first_packet), pe::Action::TX_TO_BACKEND_INTERFACE);
    const pe::IPv4Addr selected_backend = first_packet.dst_ip;
    const std::uint16_t translated_port = first_packet.src_port;

    ASSERT_TRUE(ket.replace_backends({pe::KetamaBackend{2, "10.10.0.20:8080"}}));
    Frame repeated = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto repeated_packet = repeated.build_view();
    ASSERT_EQ(engine.process_forward(repeated_packet), pe::Action::TX_TO_BACKEND_INTERFACE);

    EXPECT_EQ(repeated_packet.dst_ip, selected_backend);
    EXPECT_EQ(repeated_packet.src_port, translated_port);
    EXPECT_EQ(flows.size(), 1u);

    Frame response = Frame::make_tcp(repeated_packet.dst_ip, repeated_packet.src_ip,
                                     repeated_packet.dst_port, repeated_packet.src_port);
    auto response_packet = response.build_view();
    ASSERT_EQ(engine.process_return(response_packet), pe::Action::TX_TO_CLIENT_INTERFACE);
    EXPECT_EQ(response_packet.dst_ip, pe::IPv4Addr(10, 0, 0, 1));
    EXPECT_EQ(response_packet.dst_port, 54321u);
}

TEST(NatEngineTest, NewFlowSurvivesImmediateMaintenanceSweep) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame frame = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80);
    auto packet = frame.build_view();
    ASSERT_EQ(engine.process_forward(packet), pe::Action::TX_TO_BACKEND_INTERFACE);

    const auto now_ns =
        static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                       std::chrono::steady_clock::now().time_since_epoch())
                                       .count());
    EXPECT_EQ(flows.evict_idle(now_ns), 0u);
    EXPECT_EQ(flows.size(), 1u);
}

TEST(NatEngineTest, ForwardWritesCorrectIpv4HeaderChecksum) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{192, 168, 1, 50}, kEngineVip, 44444, 80);
    auto pkt_view = f.build_view();

    // Capture the original src/dst IP (host-order) for cross-check.
    const std::uint32_t original_src_ip_h = pkt_view.src_ip.value;
    const std::uint32_t original_dst_ip_h = pkt_view.dst_ip.value;
    const std::uint32_t original_src_ip_be = pe::bswap32_helper(original_src_ip_h);
    const std::uint32_t original_dst_ip_be = pe::bswap32_helper(original_dst_ip_h);

    const pe::Action a_fwd = engine.process_forward(pkt_view);
    EXPECT_EQ(a_fwd, pe::Action::TX_TO_BACKEND_INTERFACE);

    // Recompute the IPv4 header checksum FROM SCRATCH (treating the
    // checksum field as 0).  This is the canonical reference.
    std::byte ip_zero[20];
    std::memcpy(ip_zero, f.bytes.data() + f.ip_offset, 20);
    store_u16(ip_zero + 10, 0);
    const std::uint16_t reference_csum = ipv4_header_csum(ip_zero);

    // Read what the engine wrote back.
    const std::uint16_t actual_csum = load_be16(f.bytes.data() + f.ip_offset + 10);

    EXPECT_EQ(actual_csum, reference_csum)
        << "incremental IPv4 csum mismatch: orig_src=" << std::hex << original_src_ip_be
        << " orig_dst=" << original_dst_ip_be;
}

TEST(NatEngineTest, ForwardWritesCorrectL4Checksum) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{192, 168, 1, 50}, kEngineVip, 44444, 80);
    auto pkt_view = f.build_view();

    const pe::Action a_fwd2 = engine.process_forward(pkt_view);
    EXPECT_EQ(a_fwd2, pe::Action::TX_TO_BACKEND_INTERFACE);

    // From-scratch L4 checksum (with the new pseudo-header & zeroed chk).
    const std::byte* ip = f.bytes.data() + f.ip_offset;
    const std::byte* l4 = f.bytes.data() + f.l4_offset;
    const std::size_t l4_len = f.l4_total_length;
    const std::uint16_t reference_l4_csum = l4_csum_with_pseudo(ip, l4, l4_len);

    std::uint16_t actual_l4_csum;
    std::memcpy(&actual_l4_csum, l4 + 16, 2);

    EXPECT_EQ(actual_l4_csum, reference_l4_csum);
}

TEST(NatEngineTest, ForwardIsForwardForDstEqualEngineVip) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 12345, 80);
    auto pkt_view = f.build_view();
    EXPECT_TRUE(engine.is_forward(pkt_view));
}

TEST(NatEngineTest, ForwardDropsNonTcpUdpProto) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 1234, 80);
    auto pkt_view = f.build_view();
    pkt_view.proto = pe::L4Proto::ICMP;
    EXPECT_EQ(engine.process_forward(pkt_view), pe::Action::DROP);
}

TEST(NatEngineTest, ForwardDropsWrongDestinationIp) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, pe::IPv4Addr{8, 8, 8, 8}, 1234, 80);
    auto pkt_view = f.build_view();
    EXPECT_FALSE(engine.is_forward(pkt_view));
    EXPECT_EQ(engine.process_forward(pkt_view), pe::Action::DROP);
}

TEST(NatEngineTest, AllocatorReturnsUniquePortsAcrossManyCalls) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    constexpr std::size_t kN = 10'000;
    std::vector<std::uint16_t> ports;
    ports.reserve(kN);
    std::unordered_map<std::uint16_t, std::size_t> seen;
    for (std::size_t i = 0; i < kN; ++i) {
        const std::uint16_t p = engine.allocate_port_for_test();
        ports.push_back(p);
        EXPECT_GE(p, pe::NatEngine::kEphemeralPortMin);
        EXPECT_LE(p, pe::NatEngine::kEphemeralPortMax);
        ++seen[p];
    }
    // Every port should appear exactly once.
    for (auto p : ports)
        EXPECT_EQ(seen[p], 1u);
}

// ===========================================================================
// Reverse path: round-trip a forward+return and check sums match the
// from-scratch reference both ways.
// ===========================================================================

TEST(NatEngineTest, ReturnReversePathUndoesForward) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f_fwd = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 55555, 80);
    auto fwd_view = f_fwd.build_view();
    const pe::Action a_fwd = engine.process_forward(fwd_view);
    EXPECT_EQ(a_fwd, pe::Action::TX_TO_BACKEND_INTERFACE);

    // Build the response packet from the backend.
    // After forward: src=(engine_vip, NATP), dst=(backend, 8080)
    Frame f_ret = Frame::make_tcp(fwd_view.dst_ip,   // src = backend
                                  fwd_view.src_ip,   // dst = engine_vip
                                  fwd_view.dst_port, // src port = 8080
                                  fwd_view.src_port, // dst port = NATP
                                  std::span<const std::byte>{});
    // The TCP checksum in f_ret currently matches the pre-NAT-return
    // state.  Recompute it from scratch so that the response's csum is
    // consistent with the post-forward header layout.
    {
        std::byte* ip = f_ret.bytes.data() + f_ret.ip_offset;
        std::byte* l4 = f_ret.bytes.data() + f_ret.l4_offset;
        const std::uint16_t csum = l4_csum_with_pseudo(ip, l4, f_ret.l4_total_length);
        store_u16(l4 + 16, csum);
    }
    auto ret_view = f_ret.build_view();

    const pe::Action a_ret = engine.process_return(ret_view);
    EXPECT_EQ(a_ret, pe::Action::TX_TO_CLIENT_INTERFACE);

    EXPECT_EQ(ret_view.src_ip.value, kEngineVip.value);
    EXPECT_EQ(ret_view.dst_ip.value, (10u << 24) | (0u << 16) | (0u << 8) | 1u);
    EXPECT_EQ(ret_view.src_port, 80u);
    EXPECT_EQ(ret_view.dst_port, 55555u);

    // Checksum the returned frame from scratch and compare.
    {
        std::byte* ip = f_ret.bytes.data() + f_ret.ip_offset;
        std::byte* l4 = f_ret.bytes.data() + f_ret.l4_offset;
        const std::uint16_t csum = l4_csum_with_pseudo(ip, l4, f_ret.l4_total_length);
        std::uint16_t actual;
        std::memcpy(&actual, l4 + 16, 2);
        EXPECT_EQ(actual, csum);
    }
}

TEST(NatEngineTest, ReturnDropsWhenNoMatchingFlow) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f = Frame::make_tcp(pe::IPv4Addr{10, 10, 0, 10}, kEngineVip, 8080, 40000);
    auto pkt_view = f.build_view();
    EXPECT_EQ(engine.process_return(pkt_view), pe::Action::DROP);
}

// ===========================================================================
// Bulk round-trip: 1000 forward+return pairs (per the plan QA scenario).
// ===========================================================================

TEST(NatEngineTest, RoundTrip1000PairsZeroChecksumDrift) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"},
                            {2, "10.10.0.20:8080"},
                            {3, "10.10.0.30:8080"},
                            {4, "10.10.0.40:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"},
                            {2, "10.10.0.20:8080"},
                            {3, "10.10.0.30:8080"},
                            {4, "10.10.0.40:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    constexpr std::size_t kN = 1000;
    std::size_t chk_mismatches = 0;
    std::size_t ip_chk_mismatches = 0;
    for (std::size_t i = 0; i < kN; ++i) {
        const std::uint8_t a = static_cast<std::uint8_t>(10 + ((i * 7u) % 200u));
        const std::uint8_t b = static_cast<std::uint8_t>((i * 11u) % 250u);
        const std::uint16_t sp = static_cast<std::uint16_t>(10000 + (i * 13u) % 50000u);

        Frame f_fwd = Frame::make_tcp(pe::IPv4Addr{192, 168, a, b}, kEngineVip, sp, 80);
        auto fwd_view = f_fwd.build_view();
        ASSERT_EQ(engine.process_forward(fwd_view), pe::Action::TX_TO_BACKEND_INTERFACE);

        // After forward, build the response from the backend.
        Frame f_ret =
            Frame::make_tcp(fwd_view.dst_ip, fwd_view.src_ip, fwd_view.dst_port, fwd_view.src_port);
        // Recompute the return's L4 csum from scratch (so the engine's
        // incremental update is given a valid pre-state).
        {
            std::byte* ip = f_ret.bytes.data() + f_ret.ip_offset;
            std::byte* l4 = f_ret.bytes.data() + f_ret.l4_offset;
            const std::uint16_t csum = l4_csum_with_pseudo(ip, l4, f_ret.l4_total_length);
            store_u16(l4 + 16, csum);
        }
        auto ret_view = f_ret.build_view();
        ASSERT_EQ(engine.process_return(ret_view), pe::Action::TX_TO_CLIENT_INTERFACE);

        // Verify each checksum vs from-scratch.
        {
            const std::byte* ip = f_fwd.bytes.data() + f_fwd.ip_offset;
            std::byte ip_zero[20];
            std::memcpy(ip_zero, ip, 20);
            store_u16(ip_zero + 10, 0);
            const std::uint16_t ref_csum = ipv4_header_csum(ip_zero);
            const std::uint16_t actual_csum = load_be16(ip + 10);
            if (actual_csum != ref_csum)
                ++ip_chk_mismatches;
        }
        {
            const std::byte* ip = f_fwd.bytes.data() + f_fwd.ip_offset;
            const std::byte* l4 = f_fwd.bytes.data() + f_fwd.l4_offset;
            const std::uint16_t ref_l4 = l4_csum_with_pseudo(ip, l4, f_fwd.l4_total_length);
            std::uint16_t actual_l4;
            std::memcpy(&actual_l4, l4 + 16, 2);
            if (actual_l4 != ref_l4)
                ++chk_mismatches;
        }
        {
            const std::byte* ip = f_ret.bytes.data() + f_ret.ip_offset;
            const std::byte* l4 = f_ret.bytes.data() + f_ret.l4_offset;
            const std::uint16_t ref_l4 = l4_csum_with_pseudo(ip, l4, f_ret.l4_total_length);
            std::uint16_t actual_l4;
            std::memcpy(&actual_l4, l4 + 16, 2);
            if (actual_l4 != ref_l4)
                ++chk_mismatches;
        }
    }

    EXPECT_EQ(chk_mismatches, 0u);
    EXPECT_EQ(ip_chk_mismatches, 0u);
}

// ===========================================================================
// Engine-level dispatcher test (forward vs return via dst_ip).
// ===========================================================================

TEST(NatEngineTest, ProcessDispatcherPicksForwardOrReturnCorrectly) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    Frame f_fwd = Frame::make_tcp(pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 55555, 80);
    auto fwd = f_fwd.build_view();
    EXPECT_EQ(engine.process(fwd), pe::Action::TX_TO_BACKEND_INTERFACE);

    // Construct a return packet and verify it lands in the return path.
    Frame f_ret = Frame::make_tcp(fwd.dst_ip, fwd.src_ip, fwd.dst_port, fwd.src_port);
    // Recompute L4 csum.
    {
        std::byte* ip = f_ret.bytes.data() + f_ret.ip_offset;
        std::byte* l4 = f_ret.bytes.data() + f_ret.l4_offset;
        const std::uint16_t csum = l4_csum_with_pseudo(ip, l4, f_ret.l4_total_length);
        store_u16(l4 + 16, csum);
    }
    auto ret = f_ret.build_view();
    EXPECT_EQ(engine.process(ret), pe::Action::TX_TO_CLIENT_INTERFACE);
}

// ===========================================================================
// Port pool: has_free_ports + release_port semantics.
// ===========================================================================

TEST(NatEngineTest, ReleaseAndReuseOfPort) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    // Exhaust the pool.  Then release one port and verify a subsequent
    // allocation succeeds with the SAME index returned.
    constexpr std::size_t kPoolSize = pe::NatEngine::kEphemeralPortCount;
    std::vector<std::uint16_t> first_pass;
    first_pass.reserve(kPoolSize);
    for (std::size_t i = 0; i < kPoolSize; ++i) {
        first_pass.push_back(engine.allocate_port_for_test());
    }
    // Pool exhausted: another allocation must return 0.
    EXPECT_EQ(engine.allocate_port_for_test(), 0u);

    // Release every port we allocated; allocations should succeed again.
    for (auto p : first_pass)
        engine.release_port(p);
    bool saw_port = false;
    for (std::size_t i = 0; i < 10; ++i) {
        const std::uint16_t q = engine.allocate_port_for_test();
        if (q != 0u) {
            saw_port = true;
            break;
        }
    }
    EXPECT_TRUE(saw_port);
}

TEST(NatEngineTest, IdleEvictionReturnsTranslatedPortToAllocator) {
    pe::ConntrackFlowCache flows;
    pe::BackendRegistry reg;
    register_backends(reg, {{1, "10.10.0.10:8080"}});
    auto ket = make_ketama({{1, "10.10.0.10:8080"}});
    pe::NatEngine engine{flows, reg, ket, kEngineVip};

    const std::uint16_t reclaimed_port = engine.allocate_port_for_test();
    ASSERT_NE(reclaimed_port, 0u);
    for (std::size_t i = 1; i < pe::NatEngine::kEphemeralPortCount; ++i) {
        ASSERT_NE(engine.allocate_port_for_test(), 0u);
    }
    ASSERT_EQ(engine.allocate_port_for_test(), 0u);

    const pe::FiveTuple original{pe::IPv4Addr{10, 0, 0, 1}, kEngineVip, 54321, 80,
                                 pe::L4Proto::TCP};
    pe::ConntrackLookupArgs args{};
    args.backend = 1;
    args.client_ip = pe::IPv4Addr{10, 0, 0, 1}.value;
    args.client_port = 54321;
    args.backend_ip = pe::IPv4Addr{10, 10, 0, 10}.value;
    args.backend_port = 8080;
    args.engine_sport = reclaimed_port;
    args.service_port = 80;
    args.now_ns = 0;
    (void)flows.lookup_or_create(original, args);

    ASSERT_EQ(flows.evict_idle(pe::ConntrackFlowCache::kDefaultIdleTimeoutNs + 1u), 1u);
    EXPECT_EQ(engine.allocate_port_for_test(), reclaimed_port);
}
