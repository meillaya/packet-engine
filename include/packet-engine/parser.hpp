// SPDX-License-Identifier: MIT
//
// parser.hpp -- zero-copy packet parser for Ethernet/IPv4/IPv6/TCP/UDP/ICMP.
//
// Design
// ======
//
// `parse_packet` is the single entry point used by the RX fast path.  It
// consumes a `std::span<const std::byte>` -- a non-owning view into the
// underlying UMEM frame -- and returns a `std::optional<ParsedPacket>`
// whose members are themselves spans *into the same buffer*.  The parser
// never allocates, never copies bytes, and never builds owning containers.
//
// Failure model
// =============
//
// A `std::nullopt` return means the buffer is malformed or too short for
// the claimed protocol.  The caller is responsible for incrementing a
// `drops_malformed` counter; the parser itself is silent because it
// runs in a hot loop.
//
// Protocol coverage
// =================
//
//   * Ethernet II: dst/src MAC + ethertype.  Up to one 802.1Q VLAN tag
//     is accepted; any second tag causes a `nullopt` (engine policy:
//     we do not chase QinQ stacks).
//   * IPv4: version=4, IHL >= 5 (20 B), total_length >= IHL * 4.
//   * IPv6: version=6, payload_length, plus extension-header walk for
//     Hop-by-Hop (0), Routing (43), and Fragment (44).  Other extension
//     headers terminate the walk because the engine does not understand
//     them yet.
//   * TCP: src/dst port, seq, ack, flags, data offset (must be >= 5).
//   * UDP: src/dst port, length.
//   * ICMP/ICMPv6: type and code.
//
// IPv4 header and supported transport checksums are verified in userspace.
// IPv4 UDP checksum zero is accepted as the protocol's "not provided" value;
// IPv6 UDP checksum zero and all other invalid supported checksums are rejected.
//
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "packet-engine/types.hpp"

namespace packet_engine {

// Wire-format constants -- shared so the implementation, tests, and the
// bench can all reference the same numbers.
namespace parser_constants {

// IEEE 802.3 / Ethernet II ethertypes we actually act on.
inline constexpr std::uint16_t ETH_P_IP = 0x0800;
inline constexpr std::uint16_t ETH_P_IPV6 = 0x86DD;
inline constexpr std::uint16_t ETH_P_VLAN = 0x8100; // 802.1Q
inline constexpr std::uint16_t ETH_P_QINQ = 0x88A8; // 802.1ad (Service VLAN)

// L4 protocol numbers (RFC 790 / IANA).
inline constexpr std::uint8_t IPPROTO_ICMP = 1;
inline constexpr std::uint8_t IPPROTO_TCP = 6;
inline constexpr std::uint8_t IPPROTO_UDP = 17;
inline constexpr std::uint8_t IPPROTO_ICMPV6 = 58;

// IPv6 extension-header next-header values (RFC 8200).
inline constexpr std::uint8_t IPV6_EXT_HOPBYHOP = 0;
inline constexpr std::uint8_t IPV6_EXT_ROUTING = 43;
inline constexpr std::uint8_t IPV6_EXT_FRAGMENT = 44;
inline constexpr std::uint8_t IPV6_EXT_ESP = 50;
inline constexpr std::uint8_t IPV6_EXT_AH = 51;
inline constexpr std::uint8_t IPV6_EXT_DSTOPTS = 60;
inline constexpr std::uint8_t IPV6_NO_NEXT = 59;

} // namespace parser_constants

/// Parsed Ethernet header.  The MACs are stored in network byte order so
/// that they can be compared with `memcmp` on the wire image if desired.
struct EthernetHeader {
    MacAddr dst{};
    MacAddr src{};
    std::uint16_t ethertype{0};
};

/// Result of a successful `parse_packet`.  The `raw`, `l2`, `l3`, and
/// `l4` spans are views into the caller's input buffer; the caller
/// retains ownership of the bytes.  This struct reuses `ParsedPacket`
/// from `types.hpp` for the on-the-wire view; we keep `EthernetHeader`
/// and `FiveTuple` as parsed convenience members.
struct ParseResult {
    EthernetHeader eth{};
    std::span<const std::byte> raw{}; // full input frame (== input span)
    std::span<const std::byte> l2{};  // L2 incl. any single VLAN tag
    std::span<const std::byte> l3{};  // L3 header + payload
    std::span<const std::byte> l4{};  // L4 header + payload
    FiveTuple five_tuple{};
};

/// Parse a single frame in place.  Returns `std::nullopt` if the buffer
/// is malformed or too short for the protocols it claims to carry.
///
/// Length validation is performed at every layer boundary -- the parser
/// does not trust length fields to be self-consistent.
std::optional<ParseResult> parse_packet(std::span<const std::byte> raw) noexcept;

} // namespace packet_engine
