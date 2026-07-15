// SPDX-License-Identifier: MIT
//
// types.hpp -- common zero-copy value types shared across the packet engine.
//
// Design notes
// ============
//
// * Zero-copy views are expressed as `std::span<const std::byte>` so that no
//   allocation, copy, or owning buffer is required when a frame is being
//   parsed in place.  Spans are *non-owning*; the lifetime of the bytes they
//   reference equals the lifetime of the underlying UMEM frame.
// * Hot per-packet structs are tagged with `alignas(...)` so that two of
//   them placed adjacently (e.g. in a ring slot) cannot share a cache line
//   -- the classic false-sharing pattern that cripples tail latency under
//   multi-producer / multi-consumer workloads.
// * `IPv4Addr`, `IPv6Addr`, and `MacAddr` are deliberately constexpr-friendly
//   simple aggregators.  All wire-format integers use host byte order so
//   that the parser can build them in registers without an endianness fixup
//   pass and so that the rest of the engine can compare them with regular
//   equality.  Conversions to/from network byte order are explicit helpers.
//
// This file is header-only and depends only on the C++23 standard library;
// it has no project-internal dependencies so that it can be included from
// the parser, the ring, and the unit tests alike.
//
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace packet_engine {

// ---------------------------------------------------------------------------
// L3 / L2 address types.  constexpr-friendly simple aggregates.
// ---------------------------------------------------------------------------

/// IPv4 address in host byte order.
///
/// We deliberately avoid network byte order to keep comparison a single
/// integer equality; conversions to/from `sockaddr_in` live in the parser
/// helpers rather than in this header to keep `types.hpp` allocation-free.
struct alignas(4) IPv4Addr {
    std::uint32_t value{0};

    constexpr IPv4Addr() noexcept = default;
    constexpr explicit IPv4Addr(std::uint32_t v) noexcept : value{v} {}
    constexpr explicit IPv4Addr(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                                std::uint8_t d) noexcept
        : value{(static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
                (static_cast<std::uint32_t>(c) << 8) | (static_cast<std::uint32_t>(d))} {}

    friend constexpr bool operator==(const IPv4Addr& lhs, const IPv4Addr& rhs) noexcept {
        return lhs.value == rhs.value;
    }
    friend constexpr bool operator!=(const IPv4Addr& lhs, const IPv4Addr& rhs) noexcept {
        return lhs.value != rhs.value;
    }
};

/// IPv6 address in network byte order (canonical RFC 4291 representation).
struct alignas(16) IPv6Addr {
    std::array<std::uint8_t, 16> bytes{};

    constexpr IPv6Addr() noexcept = default;
};

/// 48-bit Ethernet MAC address, transmitted low-byte-first on the wire.
/// We store the bytes in network order to keep drivers' memcpy paths easy.
struct alignas(2) MacAddr {
    std::array<std::uint8_t, 6> bytes{};

    constexpr MacAddr() noexcept = default;
};

// ---------------------------------------------------------------------------
// L4 protocol tag.
// ---------------------------------------------------------------------------

/// Identifies an L4 protocol as classified by the L3 parser.  Only the
/// values the engine actually understands are enumerated; unknown protocols
/// map to `OTHER`.
enum class L4Proto : std::uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
    OTHER = 255,
};

// ---------------------------------------------------------------------------
// Flow matching.
// ---------------------------------------------------------------------------

/// Five-tuple flow key: the canonical L3+L4 identifier used by conntrack,
/// NAT, the rule engine, and the LB hashing.
struct alignas(8) FiveTuple {
    IPv4Addr src_ip{};
    IPv4Addr dst_ip{};
    std::uint16_t src_port{0}; // host byte order
    std::uint16_t dst_port{0};
    L4Proto proto{L4Proto::OTHER};

    constexpr FiveTuple(IPv4Addr src_ip, IPv4Addr dst_ip, std::uint16_t src_port,
                        std::uint16_t dst_port, L4Proto proto) noexcept
        : src_ip{src_ip}, dst_ip{dst_ip}, src_port{src_port}, dst_port{dst_port}, proto{proto} {}

    constexpr FiveTuple() noexcept = default;

    friend constexpr bool operator==(const FiveTuple& lhs, const FiveTuple& rhs) noexcept {
        return lhs.src_ip.value == rhs.src_ip.value && lhs.dst_ip.value == rhs.dst_ip.value &&
               lhs.src_port == rhs.src_port && lhs.dst_port == rhs.dst_port &&
               lhs.proto == rhs.proto;
    }
};

// ---------------------------------------------------------------------------
// Per-packet fast-path descriptors.
//
// These live in the RX->worker ring slots and are therefore aligned and
// padded so that two slots never alias the same cache line.
// ---------------------------------------------------------------------------

/// `PacketDescriptor` is what the RX ring hands to a worker.
///
/// The struct is **64-byte aligned** and sized to exactly one cache line on
/// x86_64: with `alignas(64)`, two slots in a `alignas(64)` ring cannot
/// produce a false-sharing ping-pong even on a 16-core socket.
struct alignas(64) PacketDescriptor {
    /// UMEM frame offset in bytes.  Always a multiple of `FRAME_SIZE`
    /// (set by `FrameAllocator`) so that it can be fed back into the
    /// allocator unmodified.
    std::uint64_t offset{0};
    /// Valid byte length inside the frame.
    std::uint32_t length{0};
    /// Index of the RX queue the frame arrived on.  The control plane
    /// uses this to attribute traffic to a worker / RSS hash bucket.
    std::uint32_t rx_queue_id{0};
    /// Hardware or software RX timestamp in nanoseconds since the
    /// monotonic clock epoch (typically CLOCK_MONOTONIC).
    std::uint64_t timestamp_ns{0};

    constexpr PacketDescriptor() noexcept = default;
};

/// `ParsedPacket` is the post-parse view onto a single frame.
///
/// All `std::span<const std::byte>` members are **borrowed views** into
/// the underlying UMEM frame; nothing in this struct owns or copies the
/// bytes.  The struct is aligned to 128 bytes to ensure the next slot
/// in a per-CPU staging array does not land on the same line as `proto`
/// -- which would otherwise be hot on every packet.
struct alignas(128) ParsedPacket {
    /// Whole frame as received from the NIC.
    std::span<const std::byte> raw{};
    /// L2 header (Ethernet).
    std::span<const std::byte> l2{};
    /// L3 header + payload (IPv4/IPv6 + upper).
    std::span<const std::byte> l3{};
    /// L4 segment + payload (TCP/UDP/ICMP).
    std::span<const std::byte> l4{};

    /// Parsed endpoints -- IPv6 traffic would carry the IPv6 form too,
    /// but `FiveTuple`'s IPv4 path keeps the L4 LB hot path branch-light.
    IPv4Addr src_ip{};
    IPv4Addr dst_ip{};
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    L4Proto proto{L4Proto::OTHER};
};

} // namespace packet_engine
