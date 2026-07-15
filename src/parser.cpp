// SPDX-License-Identifier: MIT
//
// parser.cpp -- zero-copy implementation of the packet parser.
//
// The parser is built as a series of layered helpers, each taking a span
// and returning either the next-layer span + parsed fields or
// std::nullopt.  No helper allocates or copies bytes; the only writes are
// to the small `ParseResult` returned to the caller.
//
// All multi-byte fields are read with `read_be16/32` to avoid alignment
// pitfalls; the underlying UMEM frame is not guaranteed to be aligned
// for anything larger than a single byte.
//
// The implementation is intentionally branchy in the places where a
// malformed frame should be rejected, and tight everywhere else: the
// compiler can keep the success path in I-cache by collapsing the
// rejection paths into tail-returns.

#include "packet-engine/parser.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

namespace packet_engine {

namespace {

// ---------------------------------------------------------------------------
// Tiny unaligned big-endian readers.  These are deliberately scalar
// (no memcpy) so the optimiser can fold them into a single load on
// architectures that support unaligned access natively (x86_64, arm64).
// ---------------------------------------------------------------------------

[[gnu::always_inline]] inline std::uint16_t read_be16(const std::byte* p) noexcept {
    std::uint16_t v;
    std::memcpy(&v, p, sizeof(v));
    return __builtin_bswap16(v);
}

[[gnu::always_inline]] inline std::uint32_t read_be32(const std::byte* p) noexcept {
    std::uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return __builtin_bswap32(v);
}

std::uint32_t checksum_add(std::span<const std::byte> bytes, std::uint32_t sum = 0) noexcept {
    std::size_t index = 0;
    while (index + 1u < bytes.size()) {
        sum += (static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[index])) << 8u) |
               static_cast<std::uint8_t>(bytes[index + 1u]);
        index += 2u;
    }
    if (index < bytes.size()) {
        sum += static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[index])) << 8u;
    }
    return sum;
}

bool checksum_valid(std::span<const std::byte> bytes, std::uint32_t sum = 0) noexcept {
    sum = checksum_add(bytes, sum);
    while ((sum >> 16u) != 0u) {
        sum = (sum & 0xffffu) + (sum >> 16u);
    }
    return sum == 0xffffu;
}

std::uint32_t ipv4_pseudoheader_sum(std::span<const std::byte> ip, std::uint8_t protocol,
                                    std::size_t length) noexcept {
    std::uint32_t sum = checksum_add(ip.subspan(12u, 8u));
    sum += protocol;
    sum += static_cast<std::uint16_t>(length);
    return sum;
}

std::uint32_t ipv6_pseudoheader_sum(std::span<const std::byte> ip, std::uint8_t protocol,
                                    std::size_t length) noexcept {
    std::uint32_t sum = checksum_add(ip.subspan(8u, 32u));
    sum += static_cast<std::uint16_t>((length >> 16u) & 0xffffu);
    sum += static_cast<std::uint16_t>(length & 0xffffu);
    sum += protocol;
    return sum;
}

// Bounds-checked span consumer.  Returns a sub-span of the requested
// size or std::nullopt if the buffer is shorter.
[[gnu::always_inline]] inline std::optional<std::span<const std::byte>>
take(std::span<const std::byte> buf, std::size_t n) noexcept {
    if (buf.size() < n) {
        return std::nullopt;
    }
    return buf.first(n);
}

// ---------------------------------------------------------------------------
// L2: Ethernet II (with up to one 802.1Q VLAN tag).
//
//   +-----------+-----------+--------+
//   | dst MAC 6 | src MAC 6 | type 2 |
//   +-----------+-----------+--------+
//
// A 0x8100 TPID indicates a 4-byte 802.1Q tag follows the src MAC; the
// real ethertype is the 2-byte type field after the tag.  We accept one
// VLAN tag only -- double-tagging (QinQ) is rejected to keep the
// engine's policy flat.
// ---------------------------------------------------------------------------

constexpr std::size_t ETH_ALEN = 6;
constexpr std::size_t ETH_HLEN = 14;      // no VLAN
constexpr std::size_t ETH_VLAN_HLEN = 18; // 14 + 4-byte tag

struct L2Outcome {
    EthernetHeader hdr{};
    std::span<const std::byte> l2{}; // full L2 incl. any VLAN tag
    std::span<const std::byte> l3{}; // everything past L2
    std::uint16_t ethertype{0};
};

std::optional<L2Outcome> parse_l2(std::span<const std::byte> buf) noexcept {
    L2Outcome out{};

    // Try bare Ethernet II first.
    auto eth = take(buf, ETH_HLEN);
    if (!eth) {
        return std::nullopt;
    }

    const std::byte* p = eth->data();
    for (std::size_t i = 0; i < ETH_ALEN; ++i) {
        out.hdr.dst.bytes[i] = static_cast<std::uint8_t>(p[i]);
        out.hdr.src.bytes[i] = static_cast<std::uint8_t>(p[i + ETH_ALEN]);
    }
    std::uint16_t et = read_be16(p + 12);

    // VLAN tag?
    if (et == parser_constants::ETH_P_VLAN || et == parser_constants::ETH_P_QINQ) {
        auto tagged = take(buf, ETH_VLAN_HLEN);
        if (!tagged) {
            return std::nullopt; // truncated after TPID
        }
        const std::byte* q = tagged->data();
        // Re-extract using the longer span: bytes 0..5 dst, 6..11 src,
        // 12..13 TPID (0x8100), 14..15 TCI, 16..17 real ethertype.
        for (std::size_t i = 0; i < ETH_ALEN; ++i) {
            out.hdr.dst.bytes[i] = static_cast<std::uint8_t>(q[i]);
            out.hdr.src.bytes[i] = static_cast<std::uint8_t>(q[i + ETH_ALEN]);
        }
        std::uint16_t inner = read_be16(q + 16);

        // Reject QinQ / nested VLAN.  Engine policy: at most one tag.
        if (inner == parser_constants::ETH_P_VLAN || inner == parser_constants::ETH_P_QINQ) {
            return std::nullopt;
        }
        out.l2 = *tagged;
        out.l3 = buf.subspan(ETH_VLAN_HLEN);
        out.ethertype = inner;
        out.hdr.ethertype = inner;
        return out;
    }

    // No VLAN: ethertype is the type field at offset 12.
    out.l2 = *eth;
    out.l3 = buf.subspan(ETH_HLEN);
    out.ethertype = et;
    out.hdr.ethertype = et;
    return out;
}

// ---------------------------------------------------------------------------
// L3: IPv4 / IPv6 dispatch.
// ---------------------------------------------------------------------------

struct L3Outcome {
    std::span<const std::byte> l3{}; // L3 header + payload
    std::span<const std::byte> l4{}; // L4 header + payload
    std::uint8_t proto{0};           // next-layer protocol number
};

constexpr std::size_t IPV4_MIN_HEADER = 20;
constexpr std::size_t IPV6_HEADER = 40;
constexpr std::uint16_t IPV4_FRAGMENTED_MASK = 0x3FFF;

std::optional<L3Outcome> parse_ipv4(std::span<const std::byte> buf) noexcept {
    auto hdr = take(buf, IPV4_MIN_HEADER);
    if (!hdr) {
        return std::nullopt;
    }
    const std::byte* p = hdr->data();

    // Version (high nibble of byte 0) must be 4.
    const std::uint8_t ver_ihl = static_cast<std::uint8_t>(p[0]);
    if ((ver_ihl >> 4) != 4) {
        return std::nullopt;
    }
    const std::uint8_t ihl = ver_ihl & 0x0F;
    if (ihl < 5) {
        return std::nullopt; // RFC 791 minimum
    }
    const std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
    if (buf.size() < header_len) {
        return std::nullopt;
    }

    // Total length sanity: must cover the header.
    const std::uint16_t total_len = read_be16(p + 2);
    if (total_len < header_len) {
        return std::nullopt;
    }

    const std::uint8_t proto = static_cast<std::uint8_t>(p[9]);
    const bool has_transport_ports =
        proto == parser_constants::IPPROTO_TCP || proto == parser_constants::IPPROTO_UDP;
    if (has_transport_ports && (read_be16(p + 6) & IPV4_FRAGMENTED_MASK) != 0) {
        return std::nullopt;
    }

    if (buf.size() < total_len) {
        return std::nullopt;
    }

    auto full = take(buf, total_len);
    if (!full) {
        return std::nullopt;
    }

    // L4 begins at the header boundary.
    auto l4 = take(full->subspan(header_len), total_len - header_len);
    if (!l4) {
        return std::nullopt;
    }

    if (!checksum_valid(full->first(header_len))) {
        return std::nullopt;
    }

    L3Outcome out{};
    out.l3 = *full;
    out.l4 = *l4;
    out.proto = proto;
    return out;
}

std::optional<L3Outcome> parse_ipv6(std::span<const std::byte> buf) noexcept {
    auto hdr = take(buf, IPV6_HEADER);
    if (!hdr) {
        return std::nullopt;
    }
    const std::byte* p = hdr->data();

    // Version must be 6.
    if ((static_cast<std::uint8_t>(p[0]) >> 4) != 6) {
        return std::nullopt;
    }

    // Payload length includes everything past the 40-byte fixed header
    // (extension headers + L4 + payload).
    const std::uint16_t payload_len = read_be16(p + 4);
    const std::size_t datagram_len = static_cast<std::size_t>(payload_len) + IPV6_HEADER;
    if (buf.size() < datagram_len) {
        return std::nullopt;
    }
    auto full = take(buf, datagram_len);
    if (!full) {
        return std::nullopt;
    }

    // Walk extension headers.  We understand Hop-by-Hop (0), Routing (43),
    // and Fragment (44); anything else terminates the walk and the
    // parser still returns the L4 span using whatever follows.
    std::span<const std::byte> cursor = full->subspan(IPV6_HEADER);
    std::uint8_t next_proto = static_cast<std::uint8_t>(p[6]);

    while (true) {
        if (next_proto == parser_constants::IPV6_EXT_HOPBYHOP ||
            next_proto == parser_constants::IPV6_EXT_ROUTING ||
            next_proto == parser_constants::IPV6_EXT_DSTOPTS) {
            // HeaderLen is encoded in 8-byte units *beyond* the 8-byte
            // fixed prefix (RFC 8200 §4).
            if (cursor.size() < 2) {
                return std::nullopt;
            }
            const std::uint8_t len_units = static_cast<std::uint8_t>(cursor[1]);
            const std::size_t hdr_len = 8u + static_cast<std::size_t>(len_units) * 8u;
            if (cursor.size() < hdr_len) {
                return std::nullopt;
            }
            next_proto = static_cast<std::uint8_t>(cursor[0]);
            cursor = cursor.subspan(hdr_len);
        } else if (next_proto == parser_constants::IPV6_EXT_FRAGMENT) {
            // Fragment header is fixed 8 bytes, no length field beyond it.
            if (cursor.size() < 8) {
                return std::nullopt;
            }
            const std::uint16_t fragment_offset_and_flags = read_be16(cursor.data() + 2);
            if ((fragment_offset_and_flags & 0xFFF8u) != 0) {
                return std::nullopt;
            }
            next_proto = static_cast<std::uint8_t>(cursor[0]);
            cursor = cursor.subspan(8);
        } else {
            // L4 reached -- or unknown extension header that we should
            // not chase.
            break;
        }
    }

    if (next_proto == parser_constants::IPV6_NO_NEXT) {
        // No upper-layer header at all.
        L3Outcome out{};
        out.l3 = *full;
        out.l4 = {};
        out.proto = parser_constants::IPV6_NO_NEXT;
        return out;
    }

    L3Outcome out{};
    out.l3 = *full;
    out.l4 = cursor;
    out.proto = next_proto;
    return out;
}

// ---------------------------------------------------------------------------
// L4: TCP / UDP / ICMP.
// ---------------------------------------------------------------------------

struct L4Outcome {
    std::span<const std::byte> l4{}; // L4 header + payload
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
};

constexpr std::size_t TCP_MIN_HEADER = 20; // data offset = 5 words
constexpr std::size_t UDP_HEADER = 8;
constexpr std::size_t ICMP_HEADER = 8; // type+code+cksum+rest

std::optional<L4Outcome> parse_tcp(std::span<const std::byte> buf) noexcept {
    auto hdr = take(buf, TCP_MIN_HEADER);
    if (!hdr) {
        return std::nullopt;
    }
    const std::byte* p = hdr->data();

    // Data offset is the high nibble of byte 12, in 32-bit words.
    const std::uint8_t data_off = static_cast<std::uint8_t>(p[12]) >> 4;
    if (data_off < 5) {
        return std::nullopt;
    }
    const std::size_t header_len = static_cast<std::size_t>(data_off) * 4;
    auto full = take(buf, header_len);
    if (!full) {
        return std::nullopt; // header overruns the buffer
    }

    L4Outcome out{};
    out.l4 = buf;
    out.src_port = read_be16(p + 0);
    out.dst_port = read_be16(p + 2);
    return out;
}

std::optional<L4Outcome> parse_udp(std::span<const std::byte> buf) noexcept {
    auto hdr = take(buf, UDP_HEADER);
    if (!hdr) {
        return std::nullopt;
    }
    const std::byte* p = hdr->data();

    const std::uint16_t length = read_be16(p + 4);
    if (length < UDP_HEADER) {
        return std::nullopt;
    }
    auto full = take(buf, length);
    if (!full) {
        return std::nullopt;
    }

    L4Outcome out{};
    out.l4 = *full;
    out.src_port = read_be16(p + 0);
    out.dst_port = read_be16(p + 2);
    return out;
}

// ICMPv4 only: type, code, checksum, then 4 bytes of "rest".  We do not
// decompose the inner echo/quote/unreachable formats -- the engine only
// needs type/code to decide whether to forward, log, or rate-limit.
struct IcmpOutcome {
    std::span<const std::byte> l4{};
    std::uint8_t type{0};
    std::uint8_t code{0};
};

std::optional<IcmpOutcome> parse_icmp(std::span<const std::byte> buf) noexcept {
    auto hdr = take(buf, ICMP_HEADER);
    if (!hdr) {
        return std::nullopt;
    }
    const std::byte* p = hdr->data();
    IcmpOutcome out{};
    out.l4 = buf;
    out.type = static_cast<std::uint8_t>(p[0]);
    out.code = static_cast<std::uint8_t>(p[1]);
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

std::optional<ParseResult> parse_packet(std::span<const std::byte> raw) noexcept {
    ParseResult out{};
    out.raw = raw;

    auto l2 = parse_l2(raw);
    if (!l2) {
        return std::nullopt;
    }
    out.l2 = l2->l2;
    out.eth = l2->hdr;

    // Dispatch by ethertype.
    if (l2->ethertype == parser_constants::ETH_P_IP) {
        auto l3 = parse_ipv4(l2->l3);
        if (!l3) {
            return std::nullopt;
        }
        out.l3 = l3->l3;

        // Fill IPv4 src/dst.
        out.five_tuple.src_ip = IPv4Addr{read_be32(l3->l3.data() + 12)};
        out.five_tuple.dst_ip = IPv4Addr{read_be32(l3->l3.data() + 16)};

        switch (l3->proto) {
        case parser_constants::IPPROTO_TCP: {
            auto l4 = parse_tcp(l3->l4);
            if (!l4) {
                return std::nullopt;
            }
            if (!checksum_valid(l4->l4, ipv4_pseudoheader_sum(l3->l3, l3->proto, l4->l4.size()))) {
                return std::nullopt;
            }
            out.l4 = l4->l4;
            out.five_tuple.src_port = l4->src_port;
            out.five_tuple.dst_port = l4->dst_port;
            out.five_tuple.proto = L4Proto::TCP;
            return out;
        }
        case parser_constants::IPPROTO_UDP: {
            auto l4 = parse_udp(l3->l4);
            if (!l4) {
                return std::nullopt;
            }
            const bool checksum_is_zero = read_be16(l4->l4.data() + 6u) == 0u;
            if (!checksum_is_zero &&
                !checksum_valid(l4->l4, ipv4_pseudoheader_sum(l3->l3, l3->proto, l4->l4.size()))) {
                return std::nullopt;
            }
            out.l4 = l4->l4;
            out.five_tuple.src_port = l4->src_port;
            out.five_tuple.dst_port = l4->dst_port;
            out.five_tuple.proto = L4Proto::UDP;
            return out;
        }
        case parser_constants::IPPROTO_ICMP: {
            auto l4 = parse_icmp(l3->l4);
            if (!l4) {
                return std::nullopt;
            }
            if (!checksum_valid(l4->l4)) {
                return std::nullopt;
            }
            out.l4 = l4->l4;
            out.five_tuple.proto = L4Proto::ICMP;
            return out;
        }
        default:
            // Unknown L4 -- still a "valid" frame for our purposes.
            out.l4 = l3->l4;
            out.five_tuple.proto = L4Proto::OTHER;
            return out;
        }
    }

    if (l2->ethertype == parser_constants::ETH_P_IPV6) {
        auto l3 = parse_ipv6(l2->l3);
        if (!l3) {
            return std::nullopt;
        }
        out.l3 = l3->l3;

        // We don't store the 128-bit IPv6 endpoint in FiveTuple (which
        // is IPv4-shaped) but we do set proto and ports below.
        switch (l3->proto) {
        case parser_constants::IPPROTO_TCP: {
            auto l4 = parse_tcp(l3->l4);
            if (!l4) {
                return std::nullopt;
            }
            if (!checksum_valid(l4->l4, ipv6_pseudoheader_sum(l3->l3, l3->proto, l4->l4.size()))) {
                return std::nullopt;
            }
            out.l4 = l4->l4;
            out.five_tuple.src_port = l4->src_port;
            out.five_tuple.dst_port = l4->dst_port;
            out.five_tuple.proto = L4Proto::TCP;
            return out;
        }
        case parser_constants::IPPROTO_UDP: {
            auto l4 = parse_udp(l3->l4);
            if (!l4) {
                return std::nullopt;
            }
            if (read_be16(l4->l4.data() + 6u) == 0u ||
                !checksum_valid(l4->l4, ipv6_pseudoheader_sum(l3->l3, l3->proto, l4->l4.size()))) {
                return std::nullopt;
            }
            out.l4 = l4->l4;
            out.five_tuple.src_port = l4->src_port;
            out.five_tuple.dst_port = l4->dst_port;
            out.five_tuple.proto = L4Proto::UDP;
            return out;
        }
        case parser_constants::IPPROTO_ICMPV6: {
            if (l3->l4.size() < ICMP_HEADER ||
                !checksum_valid(l3->l4, ipv6_pseudoheader_sum(l3->l3, l3->proto, l3->l4.size()))) {
                return std::nullopt;
            }
            out.l4 = l3->l4;
            out.five_tuple.proto = L4Proto::ICMPv6;
            return out;
        }
        default:
            out.l4 = l3->l4;
            out.five_tuple.proto = L4Proto::OTHER;
            return out;
        }
    }

    // Non-IP ethertype (ARP, etc.): we don't currently classify them
    // beyond marking proto=OTHER so the rule engine can decide policy.
    out.l3 = l2->l3;
    out.l4 = l2->l3;
    out.five_tuple.proto = L4Proto::OTHER;
    return out;
}

} // namespace packet_engine
