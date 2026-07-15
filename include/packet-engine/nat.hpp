// SPDX-License-Identifier: MIT
//
// nat.hpp -- Layer-4 NAT (forward + return path) for the packet engine.
//
// Design
// ======
//
// `NatEngine` rewrites the L3+L4 headers of an in-flight UDP/TCP flow so
// that the client-facing VIP appears to terminate TCP/UDP locally while
// the actual conversation runs against a hashed backend selected from
// the Ketama ring.  Return traffic is reverse-rewritten through the
// conntrack cache that the forward path primed.
//
// Hot path
// --------
//
// `process_forward(MutablePacket&)` and `process_return(MutablePacket&)`
// are the only per-packet entry points.  Both
//
//   * Avoid heap allocation. The port pool is fixed at construction;
//     allocation never occurs on the data path.
//   * Use the **incremental** RFC 1624 checksum update instead of a
//     from-scratch recompute.  Both the L3 (IPv4 header) and L4 (TCP/
//     UDP) checksums fall out of one addition per changed 16-bit field.
//   * Consult the original-flow index on forward traffic and the translated
//     alias index on return traffic.
//
// Forward path contract
// ---------------------
//
// 1.  The packet's destination IP equals `engine_vip` (the VIP the
//     fleet exposes to clients).  If it does not, the engine returns
//     `Action::DROP` -- the caller almost certainly misrouted.
// 2.  If the original 5-tuple has a pre-existing entry, that entry
//     supplies the backend identity and the engine skips the
//     Ketama ring pick.
// 3.  For a NEW flow, `ketama_.pick(five_tuple)` selects a backend id;
//     the engine queries `backends_.find()` for the canonical IPv4+port
//     and allocates an ephemeral source port from the pool.
// 4.  The engine rewrites L3 (src/dst IP + header checksum) and L4
//     (src/dst port + checksum), and reports
//     `Action::TX_TO_BACKEND_INTERFACE` so the worker hands the frame
//     to the backend-side NIC.
//
// Return path contract
// --------------------
//
// 1.  The packet's source IP is the engine's own VIP-side IP and the
//     destination IP is the client IP from the original forward flow.
//     The reverse 5-tuple is fed to the translated-flow index for a metadata-only
//     lookup (no allocation, no new entry).
// 2.  L3+L4 are inverse-rewritten, with the same RFC 1624 incremental
//     update formula applied to both checksums.
// 3.  The action returned is `Action::TX_TO_CLIENT_INTERFACE`.
//
// Forward vs return dispatch
// --------------------------
//
// Per the plan's acceptance criteria the dispatch is by destination IP:
// `dst == engine_vip` runs the forward path; anything else runs the
// reverse path.  The engine exposes that decision via
// `classify_packet()` for tests and explicit router integration.
//
// References
// ==========
//
//   * RFC 1624 -- Incremental Update of the Internet checksum.
//   * RFC 1071 -- Computing the Internet checksum.
//   * RFC 9293 -- TCP (header layout).
//   * Plan Task 21 (lines 1508-1568 of packet-engine.md).
//   * nftables NAT semantics:
//     https://man7.org/linux/man-pages/man8-nft.8.html
//
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

#include "packet-engine/backend_registry.hpp"
#include "packet-engine/conntrack.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/rule_entry.hpp"
#include "packet-engine/types.hpp"

namespace packet_engine {

// ---------------------------------------------------------------------------
// Mutable packet view used by the worker thread to hand a frame to the NAT
// engine after the parser has classified it.  All spans are non-owning and
// point into the caller's UMEM frame buffer -- this struct never copies the
// payload.
// ---------------------------------------------------------------------------

struct MutablePacket {
    // The full UMEM frame, mutable.  `l3` and `l4` below alias into this.
    std::span<std::byte> raw{};

    // Cached IP-layer bookkeeping (computed once by `parse_packet_into`
    // or by the worker thread right after parsing -- NOT recomputed on
    // the rewrite path).  All offsets are byte offsets into `raw`.
    std::uint16_t ipv4_ihl_bytes{20};   // IHL * 4
    std::uint16_t ipv4_total_length{0}; // bytes, host byte order
    std::uint16_t ipv4_csum_offset{10}; // offset of the header-checksum field

    // L4 bookkeeping.
    std::uint16_t l4_offset{0};       // offset of the L4 header in `raw`
    std::uint16_t l4_total_length{0}; // bytes of L4 header + payload
    std::uint16_t l4_csum_offset{0};  // absolute TCP/UDP checksum field offset

    // Flow identity (host byte order).  Mirrors `ParsedPacket::five_tuple`.
    IPv4Addr src_ip{};
    IPv4Addr dst_ip{};
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint8_t tcp_flags{0};
    L4Proto proto{L4Proto::OTHER};
};

[[nodiscard]] constexpr std::uint16_t
normalize_transport_checksum(L4Proto proto, std::uint16_t checksum) noexcept {
    return proto == L4Proto::UDP && checksum == 0 ? 0xFFFFu : checksum;
}

// ---------------------------------------------------------------------------
// Construct a `MutablePacket` from the bytes a worker thread is about to
// rewrite.  The function is the canonical "rehydrate a freshly-parsed frame
// into a mutable descriptor" -- useful both for tests and for control-plane
// callers that want to feed the engine without going through the full
// AF_XDP RX path.
// ---------------------------------------------------------------------------
[[nodiscard]] std::optional<MutablePacket>
parse_packet_mutable(std::span<std::byte> frame) noexcept;

// ---------------------------------------------------------------------------
// Endian helpers used by the engine and exposed for tests that need to build
// wire-format frames.  `bswap*_helper` is `__builtin_bswap` when available
// and a portable fallback otherwise.
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr std::uint16_t bswap16_helper(std::uint16_t v) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(v);
#else
    return static_cast<std::uint16_t>((v << 8) | (v >> 8));
#endif
}

[[nodiscard]] constexpr std::uint32_t bswap32_helper(std::uint32_t v) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(v);
#else
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
#endif
}

// ---------------------------------------------------------------------------
// `NatEngine`
// ---------------------------------------------------------------------------

class NatEngine {
  public:
    // Ephemeral port pool bounds (matches Linux ip_local_port_range.
    // range[0] default = 32768, range[1] default = 60999 => 28232 ports).
    static constexpr std::uint16_t kEphemeralPortMin = 32768;
    static constexpr std::uint16_t kEphemeralPortMax = 60999;
    static constexpr std::size_t kEphemeralPortCount =
        static_cast<std::size_t>(kEphemeralPortMax) - kEphemeralPortMin + 1u;

    NatEngine(ConntrackFlowCache& flows, BackendRegistry& backends, KetamaRing& ketama,
              IPv4Addr engine_vip) noexcept;

    NatEngine(const NatEngine&) = delete;
    NatEngine& operator=(const NatEngine&) = delete;
    NatEngine(NatEngine&&) = delete;
    NatEngine& operator=(NatEngine&&) = delete;
    ~NatEngine();

    /// Classify `pkt` as forward (client -> engine_vip) or return
    /// (response from the engine's VIP back toward a client).  Pure
    /// header-based disambiguation is impossible because a return
    /// packet's destination is also the engine_vip -- the backend
    /// addressed the response to the same VIP it saw as the forward
    /// flow's source.  The convention here, mirroring nf_conntrack NAT,
    /// is the swapped-5-tuple conntrack presence: a return packet's
    /// swapped key is in the cache; a fresh forward packet's swapped
    /// key is not.  This needs the conntrack cache accessible, so it
    /// is potentially a hot-path call; production worker threads
    /// typically invoke `process_forward` / `process_return` directly
    /// based on the incoming NIC and skip this helper.
    [[nodiscard]] bool is_forward(const MutablePacket& pkt) const noexcept {
        if (pkt.dst_ip != engine_vip_) {
            return false;
        }
        const FiveTuple swap{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto};
        return flows_.peek_translation(swap) == nullptr;
    }

    [[nodiscard]] std::optional<Action> process_existing(MutablePacket& pkt,
                                                         std::uint64_t now_ns) noexcept;

    /// Allocate one ephemeral port.  Returns 0 when the pool is exhausted.
    /// Public so tests can drive the allocator and exercise uniqueness.
    [[nodiscard]] std::uint16_t allocate_port_for_test() noexcept { return allocate_port(); }

    /// Process a forward packet.  See header doc.
    [[nodiscard]] Action process_forward(MutablePacket& pkt,
                                         std::optional<BackendId> preferred_backend = std::nullopt,
                                         std::uint64_t now_ns = 0) noexcept;

    /// Process a return packet (response from a backend to the client).
    [[nodiscard]] Action process_return(MutablePacket& pkt, std::uint64_t now_ns = 0) noexcept;

    /// Convenience for the worker dispatcher: classify + dispatch in one
    /// call.  Returns `Action::DROP` on missing-flow or other failure.
    [[nodiscard]] Action process(MutablePacket& pkt,
                                 std::optional<BackendId> preferred_backend = std::nullopt,
                                 std::uint64_t now_ns = 0) noexcept {
        return is_forward(pkt) ? process_forward(pkt, preferred_backend, now_ns)
                               : process_return(pkt, now_ns);
    }

    /// Engine VIP (the address clients connect TO).
    [[nodiscard]] IPv4Addr engine_vip() const noexcept { return engine_vip_; }

    /// Reports whether the engine has free ephemeral ports.
    [[nodiscard]] bool has_free_ports() const noexcept;

    /// Number of flows currently tracked in the conntrack cache we were
    /// given.  Diagnostic only.
    [[nodiscard]] std::size_t flow_count() const noexcept { return flows_.size(); }

    /// Free an ephemeral port (used on flow teardown; not required for
    /// correctness in production because the eviction sweep will
    /// eventually recycle, but exposed so tests can hand back ports on
    /// demand).
    void release_port(std::uint16_t port) noexcept;

  private:
    [[nodiscard]] Action process_forward_impl(MutablePacket& pkt,
                                              std::optional<BackendId> preferred_backend,
                                              std::uint64_t now_ns,
                                              FlowEntry* existing_flow) noexcept;
    [[nodiscard]] Action process_return_impl(MutablePacket& pkt, std::uint64_t now_ns,
                                             FlowEntry* existing_flow) noexcept;

    // Allocate one ephemeral port, marking it used in the bitmap.  Returns
    // 0 when the pool is exhausted (0 is not a valid ephemeral port).
    [[nodiscard]] std::uint16_t allocate_port() noexcept;

    // Allocator cursor (next index to try), and the bitmap itself.  Plain
    // `std::array<bool, kEphemeralPortCount>` is bit enough -- 28 232 entries
    // weigh ~28 KB on the stack if you forget to heap-allocate, so we put
    // it on the heap (the engine itself is heap-allocated anyway).  See
    // the Task 13 perf fix in `.omo/notepads/packet-engine/learnings.md`.
    std::unique_ptr<std::array<std::atomic<bool>, kEphemeralPortCount>> port_bitmap_;
    std::atomic<std::uint32_t> next_cursor_{0};

    // References held by the engine (no ownership).  The lifetime of these
    // objects is the engine's lifetime plus a margin -- they must outlive
    // the engine.
    ConntrackFlowCache& flows_;
    BackendRegistry& backends_;
    KetamaRing& ketama_;
    IPv4Addr engine_vip_;

    static void reclaim_evicted_port(void* context, const FlowEntry& entry) noexcept;
};

} // namespace packet_engine
