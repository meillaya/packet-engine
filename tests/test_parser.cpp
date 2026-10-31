// SPDX-License-Identifier: MIT
//
// test_parser.cpp -- GoogleTest suite for the zero-copy packet parser.
//
// All packets are synthesised inline from byte arrays -- no PCAP file
// is required.  The tests cover the success path for every supported
// protocol (IPv4/TCP/UDP/ICMP, IPv6/TCP/UDP, VLAN, IPv6 ext headers)
// and the rejection path for each malformed-input class listed in the
// plan (truncated frames, bad IP version, bad IHL, double-VLAN,
// TCP data offset < 5, UDP length < header).
//

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include "packet-engine/parser.hpp"
#include "packet-engine/types.hpp"

namespace pe = packet_engine;

namespace {

// Convenience: wrap a vector<uint8_t> as a span<const std::byte> without
// copying.  The vector outlives every span it produces in these tests.
std::span<const std::byte> as_bytes(const std::vector<std::uint8_t>& v) {
    return {reinterpret_cast<const std::byte*>(v.data()), v.size()};
}

// Convenience overload for C arrays -- again, no copies.
template <std::size_t N> std::span<const std::byte> as_bytes(const std::uint8_t (&a)[N]) {
    return {reinterpret_cast<const std::byte*>(a), N};
}

// ---------------------------------------------------------------------------
// Synthetic Ethernet/IPv4/TCP SYN packet -- 54 bytes (14 eth + 20 ip +
// 20 tcp).  This is the canonical packet referenced in the plan.
// ---------------------------------------------------------------------------
constexpr std::uint8_t kIpv4TcpSyn[] = {
    // Ethernet
    0xDE,
    0xAD,
    0xBE,
    0xEF,
    0x00,
    0x01, // dst MAC
    0xCA,
    0xFE,
    0xBA,
    0xBE,
    0x00,
    0x02, // src MAC
    0x08,
    0x00, // ethertype IPv4
    // IPv4
    0x45,
    0x00, // ver=4, IHL=5, DSCP=0, ECN=0
    0x00,
    0x28, // total length = 40 (20 ip + 20 tcp)
    0x00,
    0x01,
    0x00,
    0x00, // id, flags, frag
    0x40,
    0x06,
    0x66,
    0xCD, // TTL=64, proto=TCP(6), checksum
    0x0A,
    0x00,
    0x00,
    0x01, // src IP 10.0.0.1
    0x0A,
    0x00,
    0x00,
    0x02, // dst IP 10.0.0.2
    // TCP
    0xC0,
    0x00,
    0x00,
    0x50, // src=49152, dst=80
    0x00,
    0x00,
    0x00,
    0x01, // seq=1
    0x00,
    0x00,
    0x00,
    0x00, // ack=0
    0x50,
    0x02, // data offset=5 (20 B), SYN
    0xFF,
    0xFF, // window
    0xDB,
    0x8E, // checksum
    0x00,
    0x00, // urgent ptr
};

// ---------------------------------------------------------------------------
// Synthetic IPv6/UDP packet -- 78 bytes (14 eth + 40 ipv6 + 8 udp + 16
// payload).  Plan acceptance criterion: 78-byte IPv6 UDP packet.
// ---------------------------------------------------------------------------
constexpr std::uint8_t kIpv6Udp[] = {
    // Ethernet
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    0x86,
    0xDD, // ethertype IPv6
    // IPv6
    0x60,
    0x00,
    0x00,
    0x00, // ver=6, tc=0, flow=0
    0x00,
    0x28, // payload length = 40 (8 udp + 32 pad)
    0x11, // next header = UDP (17)
    0x40, // hop limit = 64
    0x20,
    0x01,
    0x0D,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01, // src 2001:db8::1
    0x20,
    0x01,
    0x0D,
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02, // dst 2001:db8::2
    // UDP
    0x12,
    0xB5,
    0x00,
    0x35, // src=4789, dst=53
    0x00,
    0x28,
    0x18,
    0xB8, // length=40, checksum
    // 32-byte payload
    0xAA,
    0xBB,
    0xCC,
    0xDD,
    0xEE,
    0xFF,
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xAA,
    0xBB,
    0xCC,
    0xDD,
    0xEE,
    0xFF,
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
};

// ---------------------------------------------------------------------------
// Synthetic IPv4 ICMP echo-request -- 14 eth + 20 ip + 8 icmp = 42 bytes.
// ---------------------------------------------------------------------------
constexpr std::uint8_t kIcmpEcho[] = {
    // Ethernet
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // broadcast
    0xAA,
    0xBB,
    0xCC,
    0xDD,
    0xEE,
    0xFF,
    0x08,
    0x00,
    // IPv4
    0x45,
    0x00,
    0x00,
    0x1C, // IHL=5, total=28
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x01,
    0xF7,
    0x8C, // TTL=64, proto=ICMP(1)
    0xC0,
    0xA8,
    0x01,
    0x01, // 192.168.1.1
    0xC0,
    0xA8,
    0x01,
    0x02, // 192.168.1.2
    // ICMP
    0x08,
    0x00,
    0x19,
    0x51, // type=8 (echo req), code=0
    0xDE,
    0xAD,
    0x00,
    0x01, // checksum, id
};

// ---------------------------------------------------------------------------
// IPv6 TCP packet with a single Hop-by-Hop extension header.
// 14 eth + 40 ipv6 + 8 hbh + 20 tcp = 82 bytes.
// ---------------------------------------------------------------------------
constexpr std::uint8_t kIpv6TcpWithHbh[] = {
    // Ethernet
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0x02,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    0x86,
    0xDD,
    // IPv6
    0x60,
    0x00,
    0x00,
    0x00,
    0x00,
    0x1C, // payload = 28 (8 hbh + 20 tcp)
    0x00, // next = Hop-by-Hop (0)
    0x40,
    0xFE,
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
    0xFE,
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x02,
    // Hop-by-Hop (8 bytes: next=TCP, len=0, padding)
    0x06,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    // TCP
    0xC0,
    0x00,
    0x01,
    0xBB, // src=49152, dst=443
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x10, // offset=5, ACK
    0xFF,
    0xFF,
    0xF1,
    0x13,
    0x00,
    0x00,
};

// ---------------------------------------------------------------------------
// VLAN-tagged IPv4/TCP packet: 18-byte L2 (4-byte 802.1Q) + 40 L3+.
// ---------------------------------------------------------------------------
constexpr std::uint8_t kVlanIpv4Tcp[] = {
    // Ethernet
    0xDE,
    0xAD,
    0xBE,
    0xEF,
    0x00,
    0x01,
    0xCA,
    0xFE,
    0xBA,
    0xBE,
    0x00,
    0x02,
    0x81,
    0x00, // TPID 802.1Q
    0x00,
    0x64, // TCI = VLAN 100
    0x08,
    0x00, // real ethertype IPv4
    // IPv4
    0x45,
    0x00,
    0x00,
    0x28,
    0x00,
    0x01,
    0x00,
    0x00,
    0x40,
    0x06,
    0x66,
    0xCD,
    0x0A,
    0x00,
    0x00,
    0x01,
    0x0A,
    0x00,
    0x00,
    0x02,
    // TCP
    0xC0,
    0x00,
    0x00,
    0x50,
    0x00,
    0x00,
    0x00,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x50,
    0x02,
    0xFF,
    0xFF,
    0xDB,
    0x8E,
    0x00,
    0x00,
};

} // namespace

// ===========================================================================
// Positive path: successful parses
// ===========================================================================

TEST(ParserTest, Ipv4TcpSynExtractsFiveTuple) {
    auto p = pe::parse_packet(as_bytes(kIpv4TcpSyn));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->eth.ethertype, pe::parser_constants::ETH_P_IP);
    EXPECT_EQ(p->l2.size(), 14u);
    EXPECT_EQ(p->l3.size(), 40u);
    EXPECT_EQ(p->l4.size(), 20u);
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::TCP);
    EXPECT_EQ(p->five_tuple.src_port, 49152u);
    EXPECT_EQ(p->five_tuple.dst_port, 80u);
    const pe::IPv4Addr expected_src{10, 0, 0, 1};
    const pe::IPv4Addr expected_dst{10, 0, 0, 2};
    EXPECT_EQ(p->five_tuple.src_ip, expected_src);
    EXPECT_EQ(p->five_tuple.dst_ip, expected_dst);
}

TEST(ParserTest, Ipv4TcpSynSpansAreViewsIntoInput) {
    std::vector<std::uint8_t> buf(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    auto bytes = as_bytes(buf);
    auto p = pe::parse_packet(bytes);
    ASSERT_TRUE(p.has_value());

    // l2 must start at the input buffer.
    EXPECT_EQ(p->l2.data(), bytes.data());
    EXPECT_EQ(p->l2.size(), 14u); // bare Ethernet II, no VLAN

    // l3 must point into the same buffer, at offset 14.
    EXPECT_EQ(p->l3.data(), bytes.data() + 14);
    EXPECT_EQ(p->l3.size(), 40u); // 20 ip + 20 tcp

    // l4 must point at offset 34 (14 + 20 ip).
    EXPECT_EQ(p->l4.data(), bytes.data() + 34);
    EXPECT_EQ(p->l4.size(), 20u);

    // raw view == full input -- proof the parser never copied.
    EXPECT_EQ(p->raw.data(), bytes.data());
    EXPECT_EQ(p->raw.size(), bytes.size());
}

TEST(ParserTest, Ipv6UdpExtractsFiveTuple) {
    auto p = pe::parse_packet(as_bytes(kIpv6Udp));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->eth.ethertype, pe::parser_constants::ETH_P_IPV6);
    EXPECT_EQ(p->l2.size(), 14u);
    EXPECT_EQ(p->l3.size(), 80u); // 40 fixed + 8 udp + 32 payload
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::UDP);
    EXPECT_EQ(p->five_tuple.src_port, 4789u);
    EXPECT_EQ(p->five_tuple.dst_port, 53u);
}

TEST(ParserTest, Ipv6UdpL4CoversHeaderAndPayload) {
    auto p = pe::parse_packet(as_bytes(kIpv6Udp));
    ASSERT_TRUE(p.has_value());
    // L4 starts at offset 54 (14 eth + 40 ipv6 fixed).
    EXPECT_EQ(p->l4.data(), as_bytes(kIpv6Udp).data() + 54);
    // L4 length should be clamped to the UDP length field (40 bytes here).
    EXPECT_EQ(p->l4.size(), 40u);
}

TEST(ParserTest, IcmpEchoV4CarriesTypeCode) {
    auto p = pe::parse_packet(as_bytes(kIcmpEcho));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::ICMP);
    // No ports for ICMP.
    EXPECT_EQ(p->five_tuple.src_port, 0u);
    EXPECT_EQ(p->five_tuple.dst_port, 0u);
    EXPECT_EQ(p->l4.size(), 8u);
    // type=8, code=0 are visible at the start of the l4 span.
    ASSERT_GE(p->l4.size(), 2u);
    EXPECT_EQ(static_cast<std::uint8_t>(p->l4[0]), 8u);
    EXPECT_EQ(static_cast<std::uint8_t>(p->l4[1]), 0u);
}

TEST(ParserTest, Ipv6TcpWithHopByHopExtensionHeader) {
    auto p = pe::parse_packet(as_bytes(kIpv6TcpWithHbh));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::TCP);
    EXPECT_EQ(p->five_tuple.src_port, 49152u);
    EXPECT_EQ(p->five_tuple.dst_port, 443u);
    // l4 must skip the 8-byte Hop-by-Hop and land on the TCP header.
    EXPECT_EQ(p->l4.data(), as_bytes(kIpv6TcpWithHbh).data() + 14 + 40 + 8);
    EXPECT_EQ(p->l4.size(), 20u);
}

TEST(ParserTest, VlanTaggedEthernetIsAcceptedOnce) {
    auto p = pe::parse_packet(as_bytes(kVlanIpv4Tcp));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->eth.ethertype, pe::parser_constants::ETH_P_IP);
    // L2 includes the 4-byte VLAN tag.
    EXPECT_EQ(p->eth.dst.bytes[0], 0xDE);
    EXPECT_EQ(p->eth.src.bytes[5], 0x02);
    EXPECT_EQ(p->l2.size(), 18u); // 14 + 4
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::TCP);
}

// ===========================================================================
// Negative path: malformed / too-short inputs
// ===========================================================================

TEST(ParserTest, EmptyInputReturnsNullopt) {
    std::vector<std::uint8_t> empty;
    EXPECT_FALSE(pe::parse_packet(as_bytes(empty)).has_value());
}

TEST(ParserTest, TruncatedEthernetHeaderReturnsNullopt) {
    // Only 13 bytes -- one short of the minimum 14-byte L2.
    std::uint8_t pkt[13] = {};
    std::memcpy(pkt, kIpv4TcpSyn, 13);
    EXPECT_FALSE(pe::parse_packet(as_bytes(pkt)).has_value());
}

TEST(ParserTest, TruncatedIpHeaderReturnsNullopt) {
    // 14 eth + 19 ip -- one short of minimum 20-byte IPv4.
    std::uint8_t pkt[33] = {};
    std::memcpy(pkt, kIpv4TcpSyn, 33);
    EXPECT_FALSE(pe::parse_packet(as_bytes(pkt)).has_value());
}

TEST(ParserTest, TruncatedTcpHeaderReturnsNullopt) {
    // 14 eth + 20 ip + 19 tcp -- one short of minimum 20-byte TCP.
    std::uint8_t pkt[53] = {};
    std::memcpy(pkt, kIpv4TcpSyn, 53);
    EXPECT_FALSE(pe::parse_packet(as_bytes(pkt)).has_value());
}

TEST(ParserTest, MalformedIpv4VersionIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14] = 0x55; // version = 5 (forbidden)
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, MalformedIpv4IhlBelowMinimumIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14] = 0x44; // IHL=4 (< 5)
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, Ipv4IhlBeyondCapturedBytesIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14] = 0x4F;
    bad[16] = 0x00;
    bad[17] = 0x3C;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, Ipv4FragmentsCannotSupplyTransportPorts) {
    for (const std::array<std::uint8_t, 2> fragment_field :
         {std::array<std::uint8_t, 2>{0x20, 0x00}, std::array<std::uint8_t, 2>{0x00, 0x01}}) {
        std::vector<std::uint8_t> fragment(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
        fragment[20] = fragment_field[0];
        fragment[21] = fragment_field[1];
        EXPECT_FALSE(pe::parse_packet(as_bytes(fragment)).has_value());
    }
}

TEST(ParserTest, InvalidIpv4HeaderChecksumIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14 + 8] ^= 1u;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, InvalidTcpChecksumIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14 + 20 + 7] ^= 1u;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, ZeroIpv6UdpChecksumIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv6Udp), std::end(kIpv6Udp));
    bad[14 + 40 + 6] = 0;
    bad[14 + 40 + 7] = 0;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, MalformedIpv4TotalLengthBelowHeaderIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    // total_length = 10 < 20 (header)
    bad[16] = 0x00;
    bad[17] = 0x0A;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, Ipv4DeclaredLengthBeyondCapturedBytesIsRejected) {
    // Given: a complete minimum IPv4/TCP capture whose IP header declares one extra byte.
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[16] = 0x00;
    bad[17] = 0x29;

    // When/Then: a truncated IP datagram cannot supply trusted transport fields.
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, MalformedIpv6VersionIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv6Udp), std::end(kIpv6Udp));
    bad[14] = 0x40; // version = 4 in an IPv6 packet
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, Ipv6DeclaredPayloadBeyondCapturedBytesIsRejected) {
    // Given: the IPv6 payload length declares one byte beyond the capture.
    std::vector<std::uint8_t> bad(std::begin(kIpv6Udp), std::end(kIpv6Udp));
    bad[18] = 0x00;
    bad[19] = 0x29;

    // When/Then: the truncated datagram is rejected instead of parsed from a clamped view.
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, QinQDoubleVlanIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kVlanIpv4Tcp), std::end(kVlanIpv4Tcp));
    // Insert a second TPID where the inner ethertype used to be.
    bad[16] = 0x81;
    bad[17] = 0x00;
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, TcpDataOffsetBelowMinimumIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14 + 20 + 12] = 0x40; // data offset = 4 (instead of 5)
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, TcpDataOffsetBeyondDeclaredIpv4LengthIsRejected) {
    // Given: a 20-byte TCP segment that claims a 24-byte TCP header.
    std::vector<std::uint8_t> bad(std::begin(kIpv4TcpSyn), std::end(kIpv4TcpSyn));
    bad[14 + 20 + 12] = 0x60;

    // When/Then: TCP options may not extend beyond the enclosing IP datagram.
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, UdpLengthBelowHeaderIsRejected) {
    std::vector<std::uint8_t> bad(std::begin(kIpv6Udp), std::end(kIpv6Udp));
    // UDP length is at offset 14 + 40 + 4 = 58
    bad[58] = 0x00;
    bad[59] = 0x04; // length = 4 (< 8)
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, UdpLengthBeyondDeclaredIpv6PayloadIsRejected) {
    // Given: the UDP header declares one byte beyond the complete IPv6 payload.
    std::vector<std::uint8_t> bad(std::begin(kIpv6Udp), std::end(kIpv6Udp));
    bad[58] = 0x00;
    bad[59] = 0x29;

    // When/Then: UDP is rejected rather than silently clamped.
    EXPECT_FALSE(pe::parse_packet(as_bytes(bad)).has_value());
}

TEST(ParserTest, NonIpEthertypeYieldsOtherProto) {
    // ARP frame: 14 eth + 28 ARP bytes, ethertype 0x0806.
    std::uint8_t arp[42] = {};
    std::memcpy(arp, kIpv4TcpSyn, 6);         // dst MAC
    std::memcpy(arp + 6, kIpv4TcpSyn + 6, 6); // src MAC
    arp[12] = 0x08;
    arp[13] = 0x06; // ARP
    // Fill ARP payload with zeroes; parser doesn't chase it.
    auto p = pe::parse_packet(as_bytes(arp));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::OTHER);
    EXPECT_EQ(p->eth.ethertype, 0x0806);
}

// ===========================================================================
// Edge cases -- exact-boundary success
// ===========================================================================

TEST(ParserTest, ExactBoundaryIpv4WithZeroPayload) {
    // Minimum IPv4/TCP packet: 14 + 20 + 20 = 54 bytes, no payload.
    auto p = pe::parse_packet(as_bytes(kIpv4TcpSyn));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->l4.size(), 20u);
}

TEST(ParserTest, Ipv6ExtensionHeaderFragmentIsTransversed) {
    // 14 eth + 40 ipv6 + 8 frag + 8 udp = 70 bytes; next=44 (fragment).
    std::uint8_t pkt[70] = {};
    std::memcpy(pkt, kIpv6Udp, 14); // ethernet
    pkt[14] = 0x60;                 // ver=6
    pkt[14 + 4] = 0x00;
    pkt[14 + 5] = 0x10; // payload=16 (8+8)
    pkt[14 + 6] = 44;   // next=Fragment
    pkt[14 + 7] = 0x40; // hop limit
    // Source/dst IPv6 zero (acceptable).
    pkt[14 + 40] = 17; // frag next=UDP
    pkt[14 + 40 + 4] = 0x00;
    pkt[14 + 40 + 5] = 0x21; // frag offset/more=0
    // UDP at 14+40+8=62
    pkt[62] = 0x00;
    pkt[63] = 0x35;
    pkt[64] = 0x00;
    pkt[65] = 0x35;
    pkt[66] = 0x00;
    pkt[67] = 0x08; // length=8
    pkt[68] = 0xFF;
    pkt[69] = 0x74;

    auto p = pe::parse_packet(as_bytes(pkt));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::UDP);
    EXPECT_EQ(p->five_tuple.dst_port, 53u);
    EXPECT_EQ(p->l4.data(), as_bytes(pkt).data() + 62);
}

TEST(ParserTest, Ipv6NonInitialFragmentCannotSupplyTransportPorts) {
    // Given: an IPv6 fragment header with a non-zero fragment offset followed by UDP-like bytes.
    std::uint8_t pkt[70] = {};
    std::memcpy(pkt, kIpv6Udp, 14);
    pkt[14] = 0x60;
    pkt[14 + 4] = 0x00;
    pkt[14 + 5] = 0x10;
    pkt[14 + 6] = 44;
    pkt[14 + 40] = 17;
    pkt[14 + 40 + 2] = 0x00;
    pkt[14 + 40 + 3] = 0x08; // fragment offset = 1 (8 bytes)
    pkt[62] = 0x00;
    pkt[63] = 0x35;
    pkt[64] = 0x00;
    pkt[65] = 0x35;
    pkt[66] = 0x00;
    pkt[67] = 0x08;

    // When/Then: non-initial fragments cannot be mistaken for transport headers.
    EXPECT_FALSE(pe::parse_packet(as_bytes(pkt)).has_value());
}

TEST(ParserTest, Ipv6MoreFragmentsIsRejected) {
    // Given: a first fragment (offset 0) that declares more fragments.
    std::uint8_t pkt[70] = {};
    std::memcpy(pkt, kIpv6Udp, 14);
    pkt[14] = 0x60;
    pkt[14 + 4] = 0x00;
    pkt[14 + 5] = 0x10;
    pkt[14 + 6] = 44; // next = Fragment
    pkt[14 + 40] = 17;
    pkt[14 + 40 + 3] = 0x01; // fragment offset 0, M = 1

    // When/Then: no reassembly path exists, so the fragment fails closed.
    EXPECT_FALSE(pe::parse_packet(as_bytes(pkt)).has_value());
}

TEST(ParserTest, ReturnsZeroCopyViewsFromLargerBuffer) {
    // Wrap a 4 KiB buffer; embed a packet at offset 100.  Parser must
    // hand back spans pointing at the embedded offset, not at 0.
    constexpr std::size_t pad_before = 100;
    constexpr std::size_t pad_after = 2048;
    std::vector<std::uint8_t> buf(pad_before + sizeof(kIpv4TcpSyn) + pad_after, 0xAA);
    std::memcpy(buf.data() + pad_before, kIpv4TcpSyn, sizeof(kIpv4TcpSyn));
    auto bytes = as_bytes(buf).subspan(pad_before, sizeof(kIpv4TcpSyn));
    auto p = pe::parse_packet(bytes);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->l2.data(), bytes.data());
    EXPECT_EQ(p->l3.data(), bytes.data() + 14);
}

TEST(ParserTest, Ipv4UdpParsesCorrectly) {
    // 14 eth + 20 ip + 8 udp + 4 payload = 46 bytes.
    std::uint8_t pkt[46] = {};
    std::memcpy(pkt, kIpv4TcpSyn, 14);           // eth
    std::memcpy(pkt + 14, kIpv4TcpSyn + 14, 20); // ip
    pkt[14 + 9] = 17;                            // proto=UDP
    pkt[14 + 2] = 0x00;
    pkt[14 + 3] = 0x20; // total=32
    pkt[14 + 20] = 0x12;
    pkt[14 + 21] = 0xB5; // src=4789
    pkt[14 + 22] = 0x00;
    pkt[14 + 23] = 0x35; // dst=53
    pkt[14 + 24] = 0x00;
    pkt[14 + 25] = 0x0C; // length=12
    pkt[14 + 10] = 0x66;
    pkt[14 + 11] = 0xCA;
    auto p = pe::parse_packet(as_bytes(pkt));
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->five_tuple.proto, pe::L4Proto::UDP);
    EXPECT_EQ(p->five_tuple.src_port, 4789u);
    EXPECT_EQ(p->five_tuple.dst_port, 53u);
}

TEST(ParserTest, Ipv6NoNextHeaderMarksEmptyL4) {
    // 14 eth + 40 ipv6 + 0 (no next)
    std::uint8_t pkt[54] = {};
    std::memcpy(pkt, kIpv6Udp, 14);
    pkt[14] = 0x60;
    pkt[14 + 4] = 0x00;
    pkt[14 + 5] = 0x00; // payload = 0
    pkt[14 + 6] = 59;   // next = No Next Header
    auto p = pe::parse_packet(as_bytes(pkt));
    ASSERT_TRUE(p.has_value());
    EXPECT_TRUE(p->l4.empty());
}
