// SPDX-License-Identifier: MIT
#include "packet-engine/md5.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace packet_engine {
namespace {

constexpr std::array<std::uint32_t, 64> kShift = {
    7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
    14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
    4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
};

constexpr std::array<std::uint32_t, 64> kConstant = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

std::uint32_t load_le32(const std::uint8_t* data) noexcept {
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8u) |
           (static_cast<std::uint32_t>(data[2]) << 16u) |
           (static_cast<std::uint32_t>(data[3]) << 24u);
}

void store_le32(std::uint8_t* data, std::uint32_t value) noexcept {
    data[0] = static_cast<std::uint8_t>(value);
    data[1] = static_cast<std::uint8_t>(value >> 8u);
    data[2] = static_cast<std::uint8_t>(value >> 16u);
    data[3] = static_cast<std::uint8_t>(value >> 24u);
}

void transform(const std::uint8_t* block, std::array<std::uint32_t, 4>& state) noexcept {
    std::array<std::uint32_t, 16> words{};
    for (std::size_t i = 0; i < words.size(); ++i) {
        words[i] = load_le32(block + i * 4u);
    }

    std::uint32_t a = state[0];
    std::uint32_t b = state[1];
    std::uint32_t c = state[2];
    std::uint32_t d = state[3];
    for (std::uint32_t i = 0; i < 64; ++i) {
        std::uint32_t function = 0;
        std::uint32_t index = 0;
        if (i < 16) {
            function = (b & c) | (~b & d);
            index = i;
        } else if (i < 32) {
            function = (d & b) | (~d & c);
            index = (5u * i + 1u) & 15u;
        } else if (i < 48) {
            function = b ^ c ^ d;
            index = (3u * i + 5u) & 15u;
        } else {
            function = c ^ (b | ~d);
            index = (7u * i) & 15u;
        }
        const std::uint32_t previous_d = d;
        d = c;
        c = b;
        b += std::rotl(a + function + kConstant[i] + words[index], static_cast<int>(kShift[i]));
        a = previous_d;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

} // namespace

md5_digest compute_md5(const void* data, std::size_t len) noexcept {
    md5_digest result{};
    if (data == nullptr && len != 0) {
        return result;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::array<std::uint32_t, 4> state{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    std::size_t offset = 0;
    while (len - offset >= 64u) {
        transform(bytes + offset, state);
        offset += 64u;
    }

    std::array<std::uint8_t, 128> tail{};
    const std::size_t remaining = len - offset;
    if (remaining != 0) {
        std::memcpy(tail.data(), bytes + offset, remaining);
    }
    tail[remaining] = 0x80;
    const std::size_t padded = remaining < 56u ? 64u : 128u;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(len) * 8u;
    for (std::size_t i = 0; i < 8; ++i) {
        tail[padded - 8u + i] = static_cast<std::uint8_t>(bit_length >> (8u * i));
    }
    transform(tail.data(), state);
    if (padded == 128u) {
        transform(tail.data() + 64u, state);
    }
    for (std::size_t i = 0; i < state.size(); ++i) {
        store_le32(result.bytes.data() + i * 4u, state[i]);
    }
    return result;
}

std::uint32_t md5_hash32(const void* data, std::size_t len) noexcept {
    const auto digest = compute_md5(data, len);
    return load_le32(digest.bytes.data());
}

} // namespace packet_engine
