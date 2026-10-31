// SPDX-License-Identifier: MIT
//
// test_cidr_trie.cpp -- GoogleTest coverage for CidrTrie LPM.
//
// Coverage matrix
// ===============
//
//   * Empty trie lookup returns nullopt
//   * Insert /8, /16, /24 and verify longest-prefix match for each address
//   * IPv6 /16, /32, /48, /64, /128 LPM
//   * Update-on-insert semantics
//   * Erase leaf and interior prefixes
//   * Exhausted node pool returns false
//   * Default route (prefix length 0) matches everything
//
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>

#include "packet-engine/cidr_trie.hpp"
#include "packet-engine/types.hpp"

using packet_engine::CidrTrie;
using packet_engine::IPv4Addr;
using packet_engine::IPv6Addr;

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

constexpr IPv4Addr ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) noexcept {
    return IPv4Addr{a, b, c, d};
}

constexpr IPv6Addr ipv6(std::uint8_t a0, std::uint8_t a1, std::uint8_t a2, std::uint8_t a3,
                        std::uint8_t a4, std::uint8_t a5, std::uint8_t a6,
                        std::uint8_t a7) noexcept {
    IPv6Addr addr{};
    addr.bytes[0] = a0;
    addr.bytes[1] = a1;
    addr.bytes[2] = a2;
    addr.bytes[3] = a3;
    addr.bytes[4] = a4;
    addr.bytes[5] = a5;
    addr.bytes[6] = a6;
    addr.bytes[7] = a7;
    return addr;
}

} // namespace

// ---------------------------------------------------------------------------
// IPv4 tests
// ---------------------------------------------------------------------------

TEST(CidrTrieTest, IPv4_EmptyReturnsNullopt) {
    CidrTrie<IPv4Addr> trie;
    EXPECT_EQ(trie.size(), 0u);
    EXPECT_FALSE(trie.lookup(ipv4(10, 1, 1, 5)).has_value());
}

TEST(CidrTrieTest, IPv4_LongestPrefixMatch_8_16_24) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(10, 0, 0, 0), 8, 8));
    ASSERT_TRUE(trie.insert(ipv4(10, 1, 0, 0), 16, 16));
    ASSERT_TRUE(trie.insert(ipv4(10, 1, 1, 0), 24, 24));

    EXPECT_EQ(trie.lookup(ipv4(10, 1, 1, 5)), 24);
    EXPECT_EQ(trie.lookup(ipv4(10, 1, 1, 200)), 24);
    EXPECT_EQ(trie.lookup(ipv4(10, 1, 2, 1)), 16);
    EXPECT_EQ(trie.lookup(ipv4(10, 2, 0, 1)), 8);
    EXPECT_FALSE(trie.lookup(ipv4(192, 168, 1, 1)).has_value());
}

TEST(CidrTrieTest, IPv4_UpdateOnInsert) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(192, 168, 0, 0), 16, 100));
    ASSERT_TRUE(trie.insert(ipv4(192, 168, 0, 0), 16, 200));
    EXPECT_EQ(trie.lookup(ipv4(192, 168, 1, 1)), 200);
    EXPECT_EQ(trie.size(), 1u);
}

TEST(CidrTrieTest, IPv4_DefaultRouteMatchesAll) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(0, 0, 0, 0), 0, 1));
    EXPECT_EQ(trie.lookup(ipv4(0, 0, 0, 0)), 1);
    EXPECT_EQ(trie.lookup(ipv4(255, 255, 255, 255)), 1);
}

TEST(CidrTrieTest, IPv4_EraseDefaultRouteReleasesRoot) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(0, 0, 0, 0), 0, 1));
    ASSERT_TRUE(trie.erase(ipv4(0, 0, 0, 0), 0));
    EXPECT_TRUE(trie.empty());
    EXPECT_FALSE(trie.lookup(ipv4(10, 0, 0, 1)).has_value());

    // The root node was freed.  A later insert must not reuse it while the
    // trie still points at it, and unrelated addresses must not match.
    ASSERT_TRUE(trie.insert(ipv4(192, 168, 0, 0), 16, 2));
    EXPECT_EQ(trie.lookup(ipv4(192, 168, 1, 1)), 2);
    EXPECT_FALSE(trie.lookup(ipv4(10, 0, 0, 1)).has_value());
    EXPECT_FALSE(trie.lookup(ipv4(172, 16, 0, 1)).has_value());
    // These two addresses followed the dangling root's reused child before
    // the root was cleared and matched the /16 rule.
    EXPECT_FALSE(trie.lookup(ipv4(2, 160, 0, 1)).has_value());
    EXPECT_FALSE(trie.lookup(ipv4(129, 80, 0, 1)).has_value());

    ASSERT_TRUE(trie.insert(ipv4(0, 0, 0, 0), 0, 3));
    EXPECT_EQ(trie.lookup(ipv4(10, 0, 0, 1)), 3);
}

TEST(CidrTrieTest, IPv4_EraseLeafAndInterior) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(10, 0, 0, 0), 8, 8));
    ASSERT_TRUE(trie.insert(ipv4(10, 1, 0, 0), 16, 16));
    ASSERT_TRUE(trie.insert(ipv4(10, 1, 1, 0), 24, 24));

    EXPECT_TRUE(trie.erase(ipv4(10, 1, 1, 0), 24));
    EXPECT_EQ(trie.lookup(ipv4(10, 1, 1, 5)), 16);

    EXPECT_TRUE(trie.erase(ipv4(10, 0, 0, 0), 8));
    EXPECT_FALSE(trie.lookup(ipv4(10, 2, 0, 1)).has_value());
    EXPECT_EQ(trie.lookup(ipv4(10, 1, 2, 1)), 16);
}

TEST(CidrTrieTest, IPv4_EraseNonExistent) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(10, 0, 0, 0), 8, 8));
    EXPECT_FALSE(trie.erase(ipv4(10, 0, 0, 0), 16));
    EXPECT_FALSE(trie.erase(ipv4(192, 168, 0, 0), 16));
}

// ---------------------------------------------------------------------------
// IPv6 tests
// ---------------------------------------------------------------------------

TEST(CidrTrieTest, IPv6_EmptyReturnsNullopt) {
    CidrTrie<IPv6Addr> trie;
    EXPECT_FALSE(trie.lookup(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0)).has_value());
}

TEST(CidrTrieTest, IPv6_LongestPrefixMatch) {
    CidrTrie<IPv6Addr> trie;
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0), 16, 16));
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0), 32, 32));
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0), 48, 48));
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x42), 64, 64));

    EXPECT_EQ(trie.lookup(ipv6(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x42)), 64);
    EXPECT_EQ(trie.lookup(ipv6(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00)), 48);
    EXPECT_EQ(trie.lookup(ipv6(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00)), 32);
    EXPECT_EQ(trie.lookup(ipv6(0x20, 0x01, 0xff, 0xff, 0, 0, 0, 0)), 16);
    EXPECT_FALSE(trie.lookup(ipv6(0xfe, 0x80, 0, 0, 0, 0, 0, 0)).has_value());
}

TEST(CidrTrieTest, IPv6_DefaultRouteMatchesAll) {
    CidrTrie<IPv6Addr> trie;
    ASSERT_TRUE(trie.insert(IPv6Addr{}, 0, 1));
    EXPECT_EQ(trie.lookup(IPv6Addr{}), 1);
    EXPECT_EQ(trie.lookup(ipv6(0xff, 0x02, 0, 0, 0, 0, 0, 0x01)), 1);
}

TEST(CidrTrieTest, IPv6_EraseAndReuse) {
    CidrTrie<IPv6Addr, std::uint32_t, 128> trie;
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0), 16, 16));
    ASSERT_TRUE(trie.erase(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0), 16));
    ASSERT_TRUE(trie.empty());
    // After erase the freed node should be reused; subsequent inserts must work.
    ASSERT_TRUE(trie.insert(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0), 16, 17));
    EXPECT_EQ(trie.lookup(ipv6(0x20, 0x01, 0, 0, 0, 0, 0, 0)), 17);
}

TEST(CidrTrieTest, IPv6_PoolExhaustion) {
    CidrTrie<IPv6Addr, std::uint32_t, 4> trie;
    // Only enough nodes for a handful of prefix bits.  Insert a /1 and a /2,
    // then a distinct /2 should fail because the pool is exhausted.
    ASSERT_TRUE(trie.insert(IPv6Addr{}, 1, 1));
    ASSERT_TRUE(trie.insert(IPv6Addr{}, 2, 2));
    EXPECT_FALSE(trie.insert(ipv6(0x80, 0, 0, 0, 0, 0, 0, 0), 2, 3));
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

TEST(CidrTrieTest, ClearResetsTrie) {
    CidrTrie<IPv4Addr> trie;
    ASSERT_TRUE(trie.insert(ipv4(10, 0, 0, 0), 8, 8));
    trie.clear();
    EXPECT_TRUE(trie.empty());
    EXPECT_FALSE(trie.lookup(ipv4(10, 1, 1, 1)).has_value());
    ASSERT_TRUE(trie.insert(ipv4(10, 0, 0, 0), 8, 9));
    EXPECT_EQ(trie.lookup(ipv4(10, 1, 1, 1)), 9);
}
