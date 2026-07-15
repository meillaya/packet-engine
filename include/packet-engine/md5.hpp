// SPDX-License-Identifier: MIT
//
// md5.hpp -- allocation-free MD5 helper for consistent hashing.
//
// Design notes
// ============
//
// `md5_digest` is exactly the 16-byte MD5 output (RFC 1321).  It is
// trivially-copyable and `alignas(16)` so it can be passed in registers and
// safely memcpy'd for network transport.  The struct carries no
// pointer-to-internals, no OpenSSL types, and no manual memory management --
// it is a pure byte carrier.
//
// `compute_md5(data, len)` -> `md5_digest`:
//   Stateless, allocation-free one-shot helper for the hot path.
//
// `md5_hash32(data, len)` -> `std::uint32_t`:
//   Convenience wrapper for users who only need 32 bits of MD5 output (the
//   Ketama continuum only operates on 32-bit points extracted from the
//   128-bit digest).  Returns the first 4 bytes interpreted as a host-order
//   unsigned integer -- the Ketama algorithm depends on a *uniform*
//   projection onto the 32-bit space, and MD5 is well-distributed on the
//   low 32 bits.
//
// Hot-path discipline
// -------------------
//
// All public functions are `noexcept` and use fixed-size stack storage only.
//
// References
// ==========
//
//   * RFC 1321 (MD5): https://datatracker.ietf.org/doc/html/rfc1321
//   * libketama:      https://github.com/RJ/ketama/blob/master/libketama/ketama.c
//
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace packet_engine {

/// MD5 raw digest (16 bytes, RFC 1321).  Trivially-copyable aggregate.
struct alignas(16) md5_digest {
    std::array<std::uint8_t, 16> bytes{};

    friend constexpr bool operator==(const md5_digest& a, const md5_digest& b) noexcept {
        for (std::size_t i = 0; i < a.bytes.size(); ++i) {
            if (a.bytes[i] != b.bytes[i])
                return false;
        }
        return true;
    }
    friend constexpr bool operator!=(const md5_digest& a, const md5_digest& b) noexcept {
        return !(a == b);
    }
};

/// Compute an MD5 digest of an arbitrary byte range.  Returns the 16-byte
/// digest on success. A null pointer with a non-zero length returns zeroes.
[[nodiscard]] md5_digest compute_md5(const void* data, std::size_t len) noexcept;

/// Compute MD5 and project the first 32 bits onto a host-order unsigned int.
/// Equivalent to `compute_md5(data,len).bytes[0..4]` reinterpreted little-
/// endian-as-u32 (host order on this platform).
[[nodiscard]] std::uint32_t md5_hash32(const void* data, std::size_t len) noexcept;

} // namespace packet_engine
