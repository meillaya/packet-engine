// SPDX-License-Identifier: MIT
//
// nat.cpp -- NatEngine implementation.
//
// Hot path notes
// ==============
//
// The full per-packet path is:
//
//   1. MutablePacket::l3/l4 are guaranteed to be valid IPv4 + TCP/UDP
//      views of the frame.
//   2. Forward:
//      a. ketama_.pick + backends_.find + ephemeral-port allocation,
//         chosen using the ORIGINAL pre-NAT 5-tuple so the same upstream
//         flow always lands on the same backend.
//      b. flows_.try_lookup_or_create(original_key, args) stores the stable
//         backend and translated source port for later packets in the flow.
//      c. Bind the after-rewrite tuple to the original tuple for return lookup.
//      d. L3 + L4 rewrite (in-place byte writes) followed by L3 + L4
//         incremental-checksum updates per RFC 1624.
//   3. Return:
//      a. Build the post-NAT forward key by SWAPPING src/dst on the
//         observed response 5-tuple.  This is the canonical
//         nf_conntrack lookup pattern.
//      b. flows_.peek_translation(swapped_key) -- read-only lookup, no insertion.
//      c. Inverse L3 + L4 rewrite + incremental-checksum updates.
//
// No allocation on the hot path.  The port pool is a fixed ~28 KB
// bitmap heap-allocated once at engine construction (see Task 13's
// perf-fix note in `.omo/notepads/packet-engine/learnings.md`).

#include "packet-engine/nat.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

#include "packet-engine/conntrack.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/types.hpp"

namespace packet_engine {

namespace {

[[nodiscard]] std::uint64_t steady_now_ns() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                          std::chrono::steady_clock::now().time_since_epoch())
                                          .count());
}

// ---------------------------------------------------------------------------
// Endian helpers (host <-> network).
//
// `read_be16` / `read_be32`: copy the on-wire bytes to the host's native
// representation, so callers receive the BE value as a host-order integer.
//
// `write_be16` / `write_be32`: write the supplied host-order integer to
// the wire in network byte order.
//
// All intermediate values inside the engine's hot path are HOST-order u16s
// / u32s; the csum delta arithmetic therefore does not need any per-word
// bswap inside the helpers -- the bit-pattern fed into the sum is the
// value that the original Internet checksum algo would have summed if
// applied with the same endianness convention.
// ---------------------------------------------------------------------------

[[nodiscard]] constexpr std::uint16_t bswap16(std::uint16_t v) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap16(v);
#else
    return static_cast<std::uint16_t>((v << 8) | (v >> 8));
#endif
}

[[nodiscard]] constexpr std::uint32_t bswap32(std::uint32_t v) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(v);
#else
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
#endif
}

inline void write_be16(std::byte* dst, std::uint16_t v_host) noexcept {
    const std::uint16_t v_be = bswap16(v_host);
    std::memcpy(dst, &v_be, sizeof(v_be));
}

[[nodiscard]] inline std::uint16_t read_be16(const std::byte* p) noexcept {
    std::uint16_t v_native;
    std::memcpy(&v_native, p, sizeof(v_native));
    return bswap16(v_native);
}

[[nodiscard]] inline std::uint32_t read_be32(const std::byte* p) noexcept {
    std::uint32_t v_native;
    std::memcpy(&v_native, p, sizeof(v_native));
    return bswap32(v_native);
}

// ---------------------------------------------------------------------------
// Incremental Internet checksum update (RFC 1624).
//
// The Internet checksum is endian-invariant: as long as every 16-bit
// word is interpreted consistently, the bit-pattern of the final sum
// is identical.  We therefore load each word natively and treat the
// result as the source of truth -- the on-wire bytes (regardless of
// host endianness) are loaded back the same way they were written.
// ---------------------------------------------------------------------------

[[nodiscard]] inline std::uint32_t ones_complement_add(std::uint32_t a, std::uint32_t b) noexcept {
    std::uint32_t sum = a + b;
    return (sum & 0xFFFFu) + ((sum >> 16) & 0xFFFFu);
}

[[nodiscard]] inline std::uint16_t csum_replace_one16(std::uint16_t old_csum,
                                                      std::uint16_t old_value,
                                                      std::uint16_t new_value) noexcept {
    // RFC 1624: HC' = ~(~HC + ~m + m').  All operands are loaded natively
    // (LE on x86-64); the arithmetic preserves the bit-pattern that
    // equals the on-wire checksum value.  See header comment.
    const std::uint32_t not_csum = static_cast<std::uint32_t>(~old_csum) & 0xFFFFu;
    const std::uint32_t not_old = static_cast<std::uint32_t>(~old_value) & 0xFFFFu;

    std::uint32_t sum = ones_complement_add(not_csum, not_old);
    sum = ones_complement_add(sum, static_cast<std::uint32_t>(new_value));
    return static_cast<std::uint16_t>((~sum) & 0xFFFFu);
}

[[nodiscard]] inline std::uint16_t csum_replace_four16(std::uint16_t old_csum, std::uint16_t old_v1,
                                                       std::uint16_t new_v1, std::uint16_t old_v2,
                                                       std::uint16_t new_v2, std::uint16_t old_v3,
                                                       std::uint16_t new_v3, std::uint16_t old_v4,
                                                       std::uint16_t new_v4) noexcept {
    std::uint16_t mid = csum_replace_one16(old_csum, old_v1, new_v1);
    mid = csum_replace_one16(mid, old_v2, new_v2);
    mid = csum_replace_one16(mid, old_v3, new_v3);
    return csum_replace_one16(mid, old_v4, new_v4);
}

// Specialised 6-delta variant for L4 (TCP/UDP) checksum when ALL of
// {src_ip, dst_ip, src_port, dst_port} change.
[[nodiscard]] inline std::uint16_t csum_replace_six16(std::uint16_t old_csum, std::uint16_t old_v1,
                                                      std::uint16_t new_v1, std::uint16_t old_v2,
                                                      std::uint16_t new_v2, std::uint16_t old_v3,
                                                      std::uint16_t new_v3, std::uint16_t old_v4,
                                                      std::uint16_t new_v4, std::uint16_t old_v5,
                                                      std::uint16_t new_v5, std::uint16_t old_v6,
                                                      std::uint16_t new_v6) noexcept {
    std::uint16_t mid = csum_replace_one16(old_csum, old_v1, new_v1);
    mid = csum_replace_one16(mid, old_v2, new_v2);
    mid = csum_replace_one16(mid, old_v3, new_v3);
    mid = csum_replace_one16(mid, old_v4, new_v4);
    mid = csum_replace_one16(mid, old_v5, new_v5);
    return csum_replace_one16(mid, old_v6, new_v6);
}

// From-scratch L4 checksum over an IPv4 pseudo-header plus the L4 segment.
// The checksum field inside `l4` is assumed to be zero.  The returned value
// is byte-swapped relative to the numeric checksum, which is what the
// incremental helpers below expect from `read_be16()`.
//
// The parse path uses host-order numeric words, so this helper sums the
// little-endian byte pairs (the byte-swap of each big-endian word).  Two
// fields are single 16-bit values rather than byte pairs: the pseudo-header
// length must be byte-swapped before it is added, and an odd trailing byte
// is the byte-swapped form of `byte << 8`, which is just `byte`.
[[nodiscard]] inline std::uint16_t l4_csum_from_scratch(const std::byte* ip, const std::byte* l4,
                                                        std::uint16_t l4_len) noexcept {
    std::uint32_t acc = 0;
    for (std::uint16_t i = 0; i < 8; i += 2) {
        acc += static_cast<std::uint8_t>(ip[12 + i]) |
               (static_cast<std::uint8_t>(ip[12 + i + 1]) << 8);
    }
    acc += static_cast<std::uint16_t>(static_cast<std::uint8_t>(ip[9]) << 8);
    acc += bswap16(l4_len);
    for (std::uint16_t i = 0; i + 1 < l4_len; i += 2) {
        acc += static_cast<std::uint8_t>(l4[i]) | (static_cast<std::uint8_t>(l4[i + 1]) << 8);
    }
    if ((l4_len & 1u) != 0u) {
        acc += static_cast<std::uint16_t>(static_cast<std::uint8_t>(l4[l4_len - 1]));
    }
    while (acc >> 16)
        acc = (acc & 0xFFFFu) + (acc >> 16);
    return static_cast<std::uint16_t>(~acc & 0xFFFFu);
}

// Parse "A.B.C.D:port" -> { IPv4 host-order, port host-order }.
// Returns false on any malformed input.
[[nodiscard]] bool parse_authority(std::string_view addr, std::uint32_t& ip_h,
                                   std::uint16_t& port_h) noexcept {
    if (addr.empty())
        return false;
    const auto last_colon = addr.rfind(':');
    if (last_colon == std::string_view::npos || last_colon == 0u ||
        last_colon + 1u >= addr.size()) {
        return false;
    }
    const std::string_view ip_part = addr.substr(0u, last_colon);
    const std::string_view port_part = addr.substr(last_colon + 1u);

    std::uint32_t acc = 0;
    std::uint32_t seg = 0;
    std::uint32_t dots = 0;
    bool any_in_seg = false;
    for (char ch : ip_part) {
        if (ch == '.') {
            if (!any_in_seg || seg > 255u)
                return false;
            acc = (acc << 8) | seg;
            seg = 0;
            any_in_seg = false;
            ++dots;
        } else if (ch >= '0' && ch <= '9') {
            seg = seg * 10u + static_cast<std::uint32_t>(ch - '0');
            if (seg > 255u)
                return false;
            any_in_seg = true;
        } else {
            return false;
        }
    }
    if (!any_in_seg || dots != 3u)
        return false;
    acc = (acc << 8) | seg;
    ip_h = acc;

    std::uint32_t port_acc = 0;
    bool any_port = false;
    for (char ch : port_part) {
        if (ch < '0' || ch > '9')
            return false;
        port_acc = port_acc * 10u + static_cast<std::uint32_t>(ch - '0');
        if (port_acc > 0xFFFFu)
            return false;
        any_port = true;
    }
    if (!any_port || port_acc == 0) {
        return false;
    }
    port_h = static_cast<std::uint16_t>(port_acc);
    return true;
}

[[nodiscard]] constexpr std::uint16_t l4_checksum_relative_offset(L4Proto proto) noexcept {
    return proto == L4Proto::UDP ? 6u : 16u;
}

[[nodiscard]] bool has_safe_rewrite_bounds(const MutablePacket& pkt) noexcept {
    constexpr std::size_t kEthHdr = 14;
    const auto checksum_offset =
        static_cast<std::size_t>(pkt.l4_offset) + l4_checksum_relative_offset(pkt.proto);
    return pkt.ipv4_ihl_bytes >= 20u && pkt.ipv4_total_length >= pkt.ipv4_ihl_bytes &&
           pkt.raw.size() >= kEthHdr + pkt.ipv4_total_length &&
           pkt.l4_offset == kEthHdr + pkt.ipv4_ihl_bytes &&
           pkt.l4_total_length == pkt.ipv4_total_length - pkt.ipv4_ihl_bytes &&
           pkt.l4_total_length >= (pkt.proto == L4Proto::UDP ? 8u : 20u) &&
           pkt.ipv4_csum_offset == kEthHdr + 10u && pkt.l4_csum_offset == checksum_offset &&
           checksum_offset + sizeof(std::uint16_t) <= pkt.raw.size();
}

[[nodiscard]] bool is_zero_mac(const MacAddr& mac) noexcept {
    for (const std::uint8_t byte : mac.bytes) {
        if (byte != 0u)
            return false;
    }
    return true;
}

MacAddr read_mac(const std::byte* source) noexcept {
    MacAddr mac{};
    for (std::size_t index = 0; index < mac.bytes.size(); ++index)
        mac.bytes[index] = static_cast<std::uint8_t>(source[index]);
    return mac;
}

void write_mac(std::byte* destination, const MacAddr& mac) noexcept {
    for (std::size_t index = 0; index < mac.bytes.size(); ++index)
        destination[index] = static_cast<std::byte>(mac.bytes[index]);
}

} // namespace

// ---------------------------------------------------------------------------
// `parse_packet_mutable`
// ---------------------------------------------------------------------------

std::optional<MutablePacket> parse_packet_mutable(std::span<std::byte> frame) noexcept {
    constexpr std::size_t kEthHdr = 14;
    if (frame.size() < kEthHdr + 20) {
        return std::nullopt;
    }
    const std::byte* p = frame.data();

    const std::uint8_t ver_ihl = static_cast<std::uint8_t>(p[kEthHdr]);
    const std::uint8_t version = (ver_ihl >> 4) & 0x0F;
    if (version != 4) {
        return std::nullopt;
    }
    const std::uint8_t ihl = ver_ihl & 0x0F;
    if (ihl < 5) {
        return std::nullopt;
    }
    const std::uint16_t ihl_bytes = static_cast<std::uint16_t>(ihl) * 4u;
    if (frame.size() < kEthHdr + ihl_bytes) {
        return std::nullopt;
    }
    const std::uint16_t total_length = read_be16(p + kEthHdr + 2);
    if (total_length < ihl_bytes) {
        return std::nullopt;
    }
    if (frame.size() < kEthHdr + total_length) {
        return std::nullopt;
    }
    const std::uint8_t ip_proto = static_cast<std::uint8_t>(p[kEthHdr + 9]);
    if ((read_be16(p + kEthHdr + 6) & 0x3FFFu) != 0u) {
        return std::nullopt;
    }
    const std::uint32_t src_ip_be = read_be32(p + kEthHdr + 12);
    const std::uint32_t dst_ip_be = read_be32(p + kEthHdr + 16);

    const std::uint16_t l4_offset = static_cast<std::uint16_t>(kEthHdr) + ihl_bytes;
    if (frame.size() < static_cast<std::size_t>(l4_offset) + 4u) {
        return std::nullopt;
    }

    MutablePacket out{};
    out.raw = frame;
    out.ipv4_ihl_bytes = ihl_bytes;
    out.ipv4_total_length = total_length;
    out.ipv4_csum_offset = static_cast<std::uint16_t>(kEthHdr + 10);

    out.src_ip = IPv4Addr{src_ip_be};
    out.dst_ip = IPv4Addr{dst_ip_be};

    out.proto = static_cast<L4Proto>(ip_proto);
    switch (out.proto) {
    case L4Proto::TCP:
    case L4Proto::UDP: {
        const std::uint16_t l4_length = static_cast<std::uint16_t>(total_length - ihl_bytes);
        const std::uint16_t minimum_length = out.proto == L4Proto::UDP ? 8u : 20u;
        if (l4_length < minimum_length) {
            return std::nullopt;
        }
        out.src_port = read_be16(p + l4_offset);
        out.dst_port = read_be16(p + l4_offset + 2);
        out.l4_offset = l4_offset;
        out.l4_total_length = l4_length;
        out.l4_csum_offset =
            static_cast<std::uint16_t>(l4_offset + l4_checksum_relative_offset(out.proto));
        if (out.proto == L4Proto::TCP) {
            out.tcp_flags = static_cast<std::uint8_t>(p[l4_offset + 13u]);
        }
        break;
    }
    default:
        // NAT in this engine covers TCP and UDP only (Task 21).
        return std::nullopt;
    }

    return out;
}

// ---------------------------------------------------------------------------
// `NatEngine`
// ---------------------------------------------------------------------------

NatEngine::NatEngine(ConntrackFlowCache& flows, BackendRegistry& backends, KetamaRing& ketama,
                     IPv4Addr engine_vip) noexcept
    : flows_(flows), backends_(backends), ketama_(ketama), engine_vip_(engine_vip) {
    port_bitmap_ = std::make_unique<std::array<std::atomic<bool>, kEphemeralPortCount>>();
    for (auto& cell : *port_bitmap_) {
        cell.store(false, std::memory_order_relaxed);
    }
    flows_.set_eviction_handler(this, &NatEngine::reclaim_evicted_port);
}

NatEngine::~NatEngine() { flows_.clear_eviction_handler(this); }

void NatEngine::reclaim_evicted_port(void* context, const FlowEntry& entry) noexcept {
    static_cast<NatEngine*>(context)->release_port(entry.engine_sport);
}

bool NatEngine::has_free_ports() const noexcept {
    const std::uint32_t start = next_cursor_.load(std::memory_order_relaxed);
    for (std::uint32_t i = 0; i < kEphemeralPortCount; ++i) {
        const std::uint32_t idx = (start + i) % kEphemeralPortCount;
        bool expected = false;
        if ((*port_bitmap_)[idx].compare_exchange_strong(expected, true,
                                                         std::memory_order_acq_rel)) {
            (*port_bitmap_)[idx].store(false, std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}

std::uint16_t NatEngine::allocate_port() noexcept {
    const std::uint32_t start = next_cursor_.load(std::memory_order_relaxed);
    for (std::uint32_t i = 0; i < kEphemeralPortCount; ++i) {
        const std::uint32_t idx = (start + i) % kEphemeralPortCount;
        bool expected = false;
        if ((*port_bitmap_)[idx].compare_exchange_strong(expected, true,
                                                         std::memory_order_acq_rel)) {
            next_cursor_.store((idx + 1u) % kEphemeralPortCount, std::memory_order_relaxed);
            return static_cast<std::uint16_t>(kEphemeralPortMin + idx);
        }
    }
    return 0; // pool exhausted
}

void NatEngine::release_port(std::uint16_t port) noexcept {
    if (port < kEphemeralPortMin || port > kEphemeralPortMax) {
        return;
    }
    const std::size_t idx = static_cast<std::size_t>(port) - kEphemeralPortMin;
    (*port_bitmap_)[idx].store(false, std::memory_order_relaxed);
}

Action NatEngine::process_forward(MutablePacket& pkt, std::optional<BackendId> preferred_backend,
                                  std::uint64_t now_ns) noexcept {
    return process_forward_impl(pkt, preferred_backend, now_ns, nullptr);
}

std::optional<Action> NatEngine::process_existing(MutablePacket& pkt,
                                                  std::uint64_t now_ns) noexcept {
    const auto timestamp = now_ns == 0 ? steady_now_ns() : now_ns;
    const FiveTuple translated_key{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto};
    if (FlowEntry* flow = flows_.touch_translation(translated_key, timestamp, pkt.tcp_flags)) {
        return process_return_impl(pkt, timestamp, flow);
    }
    if (pkt.dst_ip != engine_vip_) {
        return std::nullopt;
    }
    const FiveTuple original_key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto};
    if (FlowEntry* flow = flows_.touch(original_key, timestamp, pkt.tcp_flags)) {
        return process_forward_impl(pkt, std::nullopt, timestamp, flow);
    }
    return std::nullopt;
}

Action NatEngine::process_forward_impl(MutablePacket& pkt,
                                       std::optional<BackendId> preferred_backend,
                                       std::uint64_t now_ns, FlowEntry* existing_flow) noexcept {
    if (pkt.proto != L4Proto::TCP && pkt.proto != L4Proto::UDP) {
        return Action::DROP;
    }
    if (!has_safe_rewrite_bounds(pkt)) {
        return Action::DROP;
    }
    if (pkt.dst_ip != engine_vip_) {
        return Action::DROP;
    }

    const FiveTuple original_key{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto};
    ConntrackLookupArgs args{};
    args.tcp_flags = pkt.tcp_flags;
    args.now_ns = now_ns == 0 ? steady_now_ns() : now_ns;
    FlowEntry* flow = existing_flow;
    if (flow == nullptr) {
        flow = flows_.touch(original_key, args.now_ns, args.tcp_flags);
    }
    if (flow == nullptr) {
        BackendId bid = 0;
        if (preferred_backend) {
            bid = *preferred_backend;
        } else {
            const KetamaBackendId kid = ketama_.pick(original_key);
            if (kid == INVALID_KETAMA_BACKEND_ID) {
                return Action::DROP;
            }
            bid = static_cast<BackendId>(kid);
        }
        auto be = backends_.find(bid);
        if (be && be->state != BackendState::HEALTHY) {
            be.reset();
        }
        if (!be && !preferred_backend) {
            const KetamaBackendId retry = ketama_.pick(original_key);
            if (retry != INVALID_KETAMA_BACKEND_ID) {
                bid = static_cast<BackendId>(retry);
                be = backends_.find(bid);
                if (be && be->state != BackendState::HEALTHY) {
                    be.reset();
                }
            }
        }
        if (!be) {
            return Action::DROP;
        }
        if (is_zero_mac(be->next_hop_mac)) {
            return Action::DROP;
        }
        std::uint32_t backend_ip_h = 0;
        std::uint16_t backend_port_h = 0;
        if (!parse_authority(be->authority, backend_ip_h, backend_port_h)) {
            return Action::DROP;
        }
        const std::uint16_t engine_sport = allocate_port();
        if (engine_sport == 0) {
            return Action::DROP;
        }

        args.backend = bid;
        args.client_ip = pkt.src_ip.value;
        args.client_port = pkt.src_port;
        args.backend_ip = backend_ip_h;
        args.backend_port = backend_port_h;
        args.engine_sport = engine_sport;
        args.service_port = pkt.dst_port;
        args.client_mac = read_mac(pkt.raw.data() + 6u);
        args.engine_mac = read_mac(pkt.raw.data());
        args.backend_mac = be->next_hop_mac;
        flow = flows_.try_lookup_or_create(original_key, args);
        if (flow == nullptr) {
            release_port(engine_sport);
            return Action::DROP;
        }
        const FiveTuple translated_key{engine_vip_, IPv4Addr{backend_ip_h}, engine_sport,
                                       backend_port_h, pkt.proto};
        if (!flows_.bind_translation(translated_key, original_key)) {
            (void)flows_.erase(original_key);
            return Action::DROP;
        }
    }
    if (flow == nullptr) {
        return Action::DROP;
    }

    write_mac(pkt.raw.data(), flow->backend_mac);
    write_mac(pkt.raw.data() + 6u, flow->engine_mac);

    // Rewrite L3 (IPv4) header + checksum.
    constexpr std::uint16_t kEthHdr = 14;
    const std::byte* ip = pkt.raw.data() + kEthHdr;

    const std::uint16_t old_ip_csum = read_be16(ip + 10);
    const std::uint16_t old_src_ip_hi = read_be16(ip + 12);
    const std::uint16_t old_src_ip_lo = read_be16(ip + 14);
    const std::uint16_t old_dst_ip_hi = read_be16(ip + 16);
    const std::uint16_t old_dst_ip_lo = read_be16(ip + 18);

    // Capture L4 header (and the original L4 checksum) before any rewrite.
    // If the incoming L4 checksum field is zero, compute the checksum that
    // the segment would have had with the original addresses and ports so
    // the incremental update below starts from a valid value.
    const std::byte* l4 = pkt.raw.data() + pkt.l4_offset;
    std::uint16_t old_l4_csum = read_be16(pkt.raw.data() + pkt.l4_csum_offset);
    if (old_l4_csum == 0) {
        old_l4_csum = bswap16(l4_csum_from_scratch(ip, l4, pkt.l4_total_length));
    }
    const std::uint16_t old_l4_sport = read_be16(l4);
    const std::uint16_t old_l4_dport = read_be16(l4 + 2);

    // New IP fields (host-order; the helpers convert to wire order on
    // write).  The IPv4Addr value format is the same convention the
    // parser uses -- the bytes as a u32 are the BE pattern.
    const std::uint16_t new_src_ip_hi = static_cast<std::uint16_t>(engine_vip_.value >> 16);
    const std::uint16_t new_src_ip_lo = static_cast<std::uint16_t>(engine_vip_.value & 0xFFFFu);
    const std::uint32_t backend_ip_u32 = static_cast<std::uint32_t>(flow->backend_ip);
    const std::uint16_t new_dst_ip_hi = static_cast<std::uint16_t>(backend_ip_u32 >> 16);
    const std::uint16_t new_dst_ip_lo = static_cast<std::uint16_t>(backend_ip_u32 & 0xFFFFu);

    write_be16(pkt.raw.data() + kEthHdr + 12, new_src_ip_hi);
    write_be16(pkt.raw.data() + kEthHdr + 14, new_src_ip_lo);
    write_be16(pkt.raw.data() + kEthHdr + 16, new_dst_ip_hi);
    write_be16(pkt.raw.data() + kEthHdr + 18, new_dst_ip_lo);

    const std::uint16_t new_ip_csum =
        csum_replace_four16(old_ip_csum, old_src_ip_hi, new_src_ip_hi, old_src_ip_lo, new_src_ip_lo,
                            old_dst_ip_hi, new_dst_ip_hi, old_dst_ip_lo, new_dst_ip_lo);
    write_be16(pkt.raw.data() + kEthHdr + 10, new_ip_csum);

    // Rewrite L4 (TCP/UDP) header + checksum.

    const std::uint16_t engine_sport_used = static_cast<std::uint16_t>(flow->engine_sport);
    const std::uint16_t backend_port_used = static_cast<std::uint16_t>(flow->backend_port);

    write_be16(pkt.raw.data() + pkt.l4_offset, engine_sport_used);
    write_be16(pkt.raw.data() + pkt.l4_offset + 2, backend_port_used);

    const std::uint16_t new_l4_csum = normalize_transport_checksum(
        pkt.proto,
        csum_replace_six16(old_l4_csum, old_src_ip_hi, new_src_ip_hi, old_src_ip_lo, new_src_ip_lo,
                           old_dst_ip_hi, new_dst_ip_hi, old_dst_ip_lo, new_dst_ip_lo, old_l4_sport,
                           engine_sport_used, old_l4_dport, backend_port_used));
    write_be16(pkt.raw.data() + pkt.l4_csum_offset, new_l4_csum);

    // Mirror post-NAT state into `pkt`.
    pkt.src_ip = engine_vip_;
    pkt.dst_ip = IPv4Addr{backend_ip_u32};
    pkt.src_port = engine_sport_used;
    pkt.dst_port = backend_port_used;

    return Action::TX_TO_BACKEND_INTERFACE;
}

Action NatEngine::process_return(MutablePacket& pkt, std::uint64_t now_ns) noexcept {
    return process_return_impl(pkt, now_ns, nullptr);
}

Action NatEngine::process_return_impl(MutablePacket& pkt, std::uint64_t now_ns,
                                      FlowEntry* existing_flow) noexcept {

    if (pkt.proto != L4Proto::TCP && pkt.proto != L4Proto::UDP) {

        return Action::DROP;
    }
    if (!has_safe_rewrite_bounds(pkt)) {
        return Action::DROP;
    }

    // Reverse 5-tuple: the conntrack entry is keyed by the post-NAT
    // forward tuple.  The response's observed 5-tuple is the mirrored
    // form, so swap src/dst to recover the key.
    const FiveTuple forward_key{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.proto};

    const std::uint8_t tcp_flags = pkt.proto == L4Proto::TCP ? pkt.tcp_flags : 0u;
    const FlowEntry* flow = existing_flow;
    if (flow == nullptr) {
        flow = flows_.touch_translation(forward_key, now_ns == 0 ? steady_now_ns() : now_ns,
                                        tcp_flags);
    }
    if (flow == nullptr) {

        return Action::DROP;
    }

    write_mac(pkt.raw.data(), flow->client_mac);
    write_mac(pkt.raw.data() + 6u, flow->engine_mac);

    constexpr std::uint16_t kEthHdr = 14;
    const std::byte* ip = pkt.raw.data() + kEthHdr;

    const std::uint16_t old_ip_csum = read_be16(ip + 10);
    const std::uint16_t old_src_ip_hi = read_be16(ip + 12);
    const std::uint16_t old_src_ip_lo = read_be16(ip + 14);
    const std::uint16_t old_dst_ip_hi = read_be16(ip + 16);
    const std::uint16_t old_dst_ip_lo = read_be16(ip + 18);

    // Capture L4 header (and the original L4 checksum) before any rewrite.
    const std::byte* l4 = pkt.raw.data() + pkt.l4_offset;
    std::uint16_t old_l4_csum = read_be16(pkt.raw.data() + pkt.l4_csum_offset);
    if (old_l4_csum == 0) {
        old_l4_csum = bswap16(l4_csum_from_scratch(ip, l4, pkt.l4_total_length));
    }
    const std::uint16_t old_l4_sport = read_be16(l4);
    const std::uint16_t old_l4_dport = read_be16(l4 + 2);

    const std::uint32_t client_ip_u32 = static_cast<std::uint32_t>(flow->client_ip);
    const std::uint16_t new_src_ip_hi = static_cast<std::uint16_t>(engine_vip_.value >> 16);
    const std::uint16_t new_src_ip_lo = static_cast<std::uint16_t>(engine_vip_.value & 0xFFFFu);
    const std::uint16_t new_dst_ip_hi = static_cast<std::uint16_t>(client_ip_u32 >> 16);
    const std::uint16_t new_dst_ip_lo = static_cast<std::uint16_t>(client_ip_u32 & 0xFFFFu);

    write_be16(pkt.raw.data() + kEthHdr + 12, new_src_ip_hi);
    write_be16(pkt.raw.data() + kEthHdr + 14, new_src_ip_lo);
    write_be16(pkt.raw.data() + kEthHdr + 16, new_dst_ip_hi);
    write_be16(pkt.raw.data() + kEthHdr + 18, new_dst_ip_lo);

    const std::uint16_t new_ip_csum =
        csum_replace_four16(old_ip_csum, old_src_ip_hi, new_src_ip_hi, old_src_ip_lo, new_src_ip_lo,
                            old_dst_ip_hi, new_dst_ip_hi, old_dst_ip_lo, new_dst_ip_lo);
    write_be16(pkt.raw.data() + kEthHdr + 10, new_ip_csum);

    const std::uint16_t client_port_used = static_cast<std::uint16_t>(flow->client_port);
    const std::uint16_t service_port_used = static_cast<std::uint16_t>(flow->service_port);

    write_be16(pkt.raw.data() + pkt.l4_offset, service_port_used);
    write_be16(pkt.raw.data() + pkt.l4_offset + 2, client_port_used);

    const std::uint16_t new_l4_csum = normalize_transport_checksum(
        pkt.proto,
        csum_replace_six16(old_l4_csum, old_src_ip_hi, new_src_ip_hi, old_src_ip_lo, new_src_ip_lo,
                           old_dst_ip_hi, new_dst_ip_hi, old_dst_ip_lo, new_dst_ip_lo, old_l4_sport,
                           service_port_used, old_l4_dport, client_port_used));
    write_be16(pkt.raw.data() + pkt.l4_csum_offset, new_l4_csum);

    pkt.src_ip = engine_vip_;
    pkt.dst_ip = IPv4Addr{client_ip_u32};
    pkt.src_port = service_port_used;
    pkt.dst_port = client_port_used;

    return Action::TX_TO_CLIENT_INTERFACE;
}

} // namespace packet_engine
