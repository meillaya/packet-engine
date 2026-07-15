// SPDX-License-Identifier: MIT
//
// cidr_trie.hpp -- longest-prefix-match (LPM) binary trie for IPv4/IPv6 CIDRs.
//
// Design notes
// ============
//
// * Simple standard binary trie, NOT path-compressed / Patricia.  Each insert
//   walks exactly `prefix_len` bits and creates at most one node per bit.
//   This keeps the implementation small, predictable, and fast enough for
//   the rule engine's CIDR matches.
// * Nodes live in a single pre-allocated pool (`std::array<Node, MAX_NODES+1>`).
//   Index 0 is the permanent null sentinel.  No per-insert heap allocation.
// * Erased nodes are pushed onto a free list so the pool can be reused.
// * Lookup walks up to `AddrBits` bits and returns the value associated with
//   the deepest node that has `has_value == true` -- the longest prefix match.
//
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>

#include "packet-engine/types.hpp"

namespace packet_engine {

namespace detail {

/// Number of address bits for each supported address type.
template <typename Addr> struct AddrBits;

template <> struct AddrBits<IPv4Addr> : std::integral_constant<std::size_t, 32> {};

template <> struct AddrBits<IPv6Addr> : std::integral_constant<std::size_t, 128> {};

/// Extract bit at position `bit` (0 = MSB) from an address.
inline constexpr bool addr_bit(const IPv4Addr& addr, std::size_t bit) noexcept {
    return ((addr.value >> (31 - bit)) & 1U) != 0;
}

inline constexpr bool addr_bit(const IPv6Addr& addr, std::size_t bit) noexcept {
    const std::size_t byte = bit / 8;
    const std::size_t local = bit % 8;
    return ((addr.bytes[byte] >> (7 - local)) & 1U) != 0;
}

} // namespace detail

/// Longest-prefix-match binary trie for CIDR prefixes.
///
/// @tparam Addr      Address type: IPv4Addr or IPv6Addr.
/// @tparam V         Value type stored at each prefix (default uint32_t).
/// @tparam MAX_NODES Maximum trie nodes (default 8192).  Index 0 is reserved
///                   as the null sentinel, so the pool holds MAX_NODES usable
///                   nodes plus the sentinel.
template <typename Addr, typename V = std::uint32_t, std::size_t MAX_NODES = 8192> class CidrTrie {
  public:
    static_assert(std::is_same_v<Addr, IPv4Addr> || std::is_same_v<Addr, IPv6Addr>,
                  "CidrTrie only supports IPv4Addr and IPv6Addr");
    static_assert(MAX_NODES > 0, "MAX_NODES must be positive");

    static constexpr std::size_t kAddrBits = detail::AddrBits<Addr>::value;
    static constexpr std::size_t kPoolSize = MAX_NODES + 1; // +1 for null sentinel

  private:
    struct Node {
        std::array<std::uint32_t, 2> child{}; // 0 = null sentinel
        std::optional<V> value{};
        bool has_value{false};
    };

    std::array<Node, kPoolSize> nodes_{};
    std::uint32_t root_{0};
    std::uint32_t next_free_{1}; // next never-used node index
    std::uint32_t free_list_{0}; // head of erased-node free list (0 = empty)
    std::size_t size_{0};

    /// Allocate a fresh zero-initialized node, preferring the free list.
    std::uint32_t allocate_node() {
        if (free_list_ != 0) {
            const std::uint32_t idx = free_list_;
            free_list_ = nodes_[idx].child[0];
            nodes_[idx].child = {};
            nodes_[idx].value.reset();
            nodes_[idx].has_value = false;
            return idx;
        }
        if (next_free_ >= kPoolSize) {
            return 0; // pool exhausted
        }
        return next_free_++;
    }

    /// Return a node to the free list.  Caller must unlink it from the trie.
    void release_node(std::uint32_t idx) noexcept {
        if (idx == 0 || idx >= next_free_)
            return;
        nodes_[idx].child[0] = free_list_;
        nodes_[idx].child[1] = 0;
        nodes_[idx].value.reset();
        nodes_[idx].has_value = false;
        free_list_ = idx;
    }

  public:
    CidrTrie() = default;

    /// Insert or update a value for the given prefix.
    ///
    /// @return true on success, false if the node pool is exhausted.
    bool insert(Addr prefix, std::size_t prefix_len, V value) {
        if (prefix_len > kAddrBits) {
            prefix_len = kAddrBits;
        }
        if (root_ == 0) {
            root_ = allocate_node();
            if (root_ == 0)
                return false;
        }
        std::uint32_t node = root_;
        for (std::size_t i = 0; i < prefix_len; ++i) {
            const bool bit = detail::addr_bit(prefix, i);
            std::uint32_t next = nodes_[node].child[bit ? 1 : 0];
            if (next == 0) {
                next = allocate_node();
                if (next == 0)
                    return false;
                nodes_[node].child[bit ? 1 : 0] = next;
            }
            node = next;
        }
        if (!nodes_[node].has_value) {
            ++size_;
        }
        nodes_[node].value = std::move(value);
        nodes_[node].has_value = true;
        return true;
    }

    /// Look up the longest-prefix match for `addr`.
    ///
    /// @return std::optional<V> with the value of the longest matching prefix,
    ///         or std::nullopt if no prefix matches.
    [[nodiscard]] std::optional<V> lookup(const Addr& addr) const noexcept {
        std::optional<V> best;
        std::uint32_t node = root_;
        if (node == 0)
            return best;
        if (nodes_[node].has_value) {
            best = nodes_[root_].value;
        }
        for (std::size_t i = 0; i < kAddrBits; ++i) {
            const bool bit = detail::addr_bit(addr, i);
            node = nodes_[node].child[bit ? 1 : 0];
            if (node == 0)
                break;
            if (nodes_[node].has_value) {
                best = nodes_[node].value;
            }
        }
        return best;
    }

    /// Remove an exact prefix, returning true if it existed.
    bool erase(Addr prefix, std::size_t prefix_len) {
        if (prefix_len > kAddrBits) {
            prefix_len = kAddrBits;
        }
        if (root_ == 0)
            return false;

        // Path bookkeeping: remember parent and bit for each traversed node.
        std::array<std::uint32_t, kAddrBits + 1> path{};
        std::array<std::uint8_t, kAddrBits + 1> bits{};
        std::size_t path_len = 0;

        std::uint32_t node = root_;
        path[path_len] = 0;
        bits[path_len] = 0;
        ++path_len;

        for (std::size_t i = 0; i < prefix_len; ++i) {
            const bool bit = detail::addr_bit(prefix, i);
            path[path_len] = node;
            bits[path_len] = bit ? 1 : 0;
            ++path_len;
            node = nodes_[node].child[bit ? 1 : 0];
            if (node == 0)
                return false;
        }

        if (!nodes_[node].has_value)
            return false;

        nodes_[node].value.reset();
        nodes_[node].has_value = false;
        --size_;

        // Prune leaf chains that no longer hold any value and have no children.
        if (nodes_[node].child[0] == 0 && nodes_[node].child[1] == 0) {
            release_node(node);
            while (path_len > 1) {
                const std::uint32_t parent = path[path_len - 1];
                const std::uint8_t b = bits[path_len - 1];
                nodes_[parent].child[b] = 0;
                if (nodes_[parent].has_value || nodes_[parent].child[0] != 0 ||
                    nodes_[parent].child[1] != 0) {
                    break;
                }
                if (parent == root_) {
                    release_node(root_);
                    root_ = 0;
                    break;
                }
                release_node(parent);
                --path_len;
            }
        }
        return true;
    }

    /// Number of stored prefixes.
    [[nodiscard]] std::size_t size() const noexcept { return size_; }

    /// True if no prefixes are stored.
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    /// Clear all prefixes and reset the node pool.
    void clear() noexcept {
        nodes_ = {};
        root_ = 0;
        next_free_ = 1;
        free_list_ = 0;
        size_ = 0;
    }
};

} // namespace packet_engine
