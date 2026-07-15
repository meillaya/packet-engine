// SPDX-License-Identifier: MIT
//
// rule_table.cpp -- RuleTable and RuleTableRegistry implementation, plus the
// explicit CidrTrie<> instantiations that carry `RuleEntry` as their value
// type so the hot path can read the matched entry directly out of the trie
// without any secondary lookup.
//
#include "packet-engine/rule_table.hpp"

#include <algorithm>
#include <cstddef>
#include <limits>
#include <utility>

namespace packet_engine {

namespace {

constexpr std::uint64_t kFixedPointShift = 32;
constexpr std::uint64_t kFixedPointOne = std::uint64_t{1} << kFixedPointShift;

std::uint64_t interval_reciprocal(std::uint64_t rate_bps) noexcept {
    if (rate_bps == 0) {
        return 0;
    }
    const auto numerator = static_cast<__uint128_t>(1'000'000'000u) * kFixedPointOne;
    const auto reciprocal = (numerator + rate_bps - 1u) / rate_bps;
    return reciprocal > std::numeric_limits<std::uint64_t>::max()
               ? std::numeric_limits<std::uint64_t>::max()
               : static_cast<std::uint64_t>(reciprocal);
}

std::uint64_t scaled_interval_ns(std::uint64_t bytes, std::uint64_t reciprocal) noexcept {
    const auto product = static_cast<__uint128_t>(bytes) * reciprocal;
    const auto interval = (product + kFixedPointOne - 1u) >> kFixedPointShift;
    return interval > std::numeric_limits<std::uint64_t>::max()
               ? std::numeric_limits<std::uint64_t>::max()
               : static_cast<std::uint64_t>(interval);
}

std::uint64_t saturated_add(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs
               ? std::numeric_limits<std::uint64_t>::max()
               : lhs + rhs;
}

std::uint64_t initial_token_count(const TokenBucket& bucket) noexcept {
    const auto tokens = static_cast<long double>(bucket.tokens());
    if (tokens <= 0) {
        return 0;
    }
    if (tokens >= static_cast<long double>(std::numeric_limits<std::uint64_t>::max())) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return static_cast<std::uint64_t>(tokens);
}

} // namespace

RuleTable::RateLimitState::RateLimitState(TokenBucket initial) noexcept
    : rate_bps_{initial.rate_bps()}, burst_bytes_{initial.burst_bytes()},
      interval_reciprocal_q32_{interval_reciprocal(rate_bps_)},
      burst_window_ns_{scaled_interval_ns(burst_bytes_, interval_reciprocal_q32_)},
      scheduled_ns_{initial.last_refill_ns()}, zero_rate_tokens_{initial_token_count(initial)} {}

bool RuleTable::RateLimitState::try_consume(std::uint64_t bytes, std::uint64_t now_ns) noexcept {
    if (rate_bps_ == 0) {
        auto available = zero_rate_tokens_.load(std::memory_order_relaxed);
        while (available >= bytes) {
            if (zero_rate_tokens_.compare_exchange_weak(available, available - bytes,
                                                        std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    const auto increment = scaled_interval_ns(bytes, interval_reciprocal_q32_);
    const auto deadline = saturated_add(now_ns, burst_window_ns_);
    auto scheduled = scheduled_ns_.load(std::memory_order_relaxed);
    for (;;) {
        const auto base = std::max(scheduled, now_ns);
        const auto replacement = saturated_add(base, increment);
        if (replacement > deadline) {
            return false;
        }
        if (scheduled_ns_.compare_exchange_weak(scheduled, replacement,
                                                std::memory_order_relaxed)) {
            return true;
        }
    }
}

// ---------------------------------------------------------------------------
// RuleTable: control-plane builders
// ---------------------------------------------------------------------------

bool RuleTable::add_exact(const FiveTuple& tuple, const RuleEntry& entry) noexcept {
    return exact_.insert(tuple, entry);
}

bool RuleTable::add_cidr_v4(IPv4Addr prefix, std::uint8_t prefix_len,
                            const RuleEntry& entry) noexcept {
    return ipv4_trie_.insert(prefix, prefix_len, entry);
}

bool RuleTable::add_cidr_v6(IPv6Addr prefix, std::uint8_t prefix_len,
                            const RuleEntry& entry) noexcept {
    return ipv6_trie_.insert(prefix, prefix_len, entry);
}

void RuleTable::add_rate_limit_state(RuleId id, TokenBucket bucket) noexcept {
    add_rate_limit_state(id, std::make_shared<RateLimitState>(std::move(bucket)));
}

void RuleTable::add_rate_limit_state(RuleId id, RateLimitStatePtr state) noexcept {
    rate_limit_state_.insert_or_assign(id, std::move(state));
}

RuleTable::RateLimitStatePtr
RuleTable::matching_rate_limit_state(RuleId id, std::uint64_t rate_bps,
                                     std::uint64_t burst_bytes) const noexcept {
    const auto found = rate_limit_state_.find(id);
    if (found == rate_limit_state_.end() || !found->second)
        return {};
    if (found->second->rate_bps() != rate_bps || found->second->burst_bytes() != burst_bytes) {
        return {};
    }
    return found->second;
}

// ---------------------------------------------------------------------------
// RuleTable: hot-path lookup
// ---------------------------------------------------------------------------

Action RuleTable::finalize_action_(const RuleEntry& entry, const ParsedPacket& pkt,
                                   std::uint64_t now_ns) const noexcept {
    if (entry.action != Action::RATE_LIMIT) {
        return entry.action;
    }

    // RATE_LIMIT handling -- the only path that touches
    // `rate_limit_state_`.  Anything else on the hot path skips the
    // unordered_map entirely.
    auto it = rate_limit_state_.find(entry.id);
    if (it == rate_limit_state_.end() || !it->second) {
        // Fail-closed: a rate-limited rule without a configured bucket is
        // denied.  This guards against a control-plane mistake where a
        // rule's RATE_LIMIT action is published without a backing bucket.
        return Action::DROP;
    }

    if (!it->second->try_consume(pkt.raw.size(), now_ns)) {
        return Action::DROP;
    }
    return Action::RATE_LIMIT;
}

std::optional<RuleEntry> RuleTable::lookup_entry(const ParsedPacket& pkt) const noexcept {
    return lookup_entry(pkt, detail::steady_now_ns());
}

std::optional<RuleEntry> RuleTable::lookup_entry(const ParsedPacket& pkt,
                                                 std::uint64_t now_ns) const noexcept {
    const FiveTuple tuple = detail::five_tuple_from(pkt);

    // 1. Exact 5-tuple -- the per-packet fast path.
    if (const auto* entry = exact_.find(tuple); entry != nullptr) {
        RuleEntry decision = *entry;
        decision.action = finalize_action_(*entry, pkt, now_ns);
        return decision;
    }

    // 2. IPv4 CIDR longest-prefix match on the destination address.
    if (auto entry = ipv4_trie_.lookup(pkt.dst_ip); entry.has_value()) {
        entry->action = finalize_action_(*entry, pkt, now_ns);
        return entry;
    }

    // 3. IPv6 CIDR lookup is intentionally NOT invoked here: the engine's
    // current `ParsedPacket` only carries IPv4 endpoints
    // (see include/packet-engine/types.hpp).  IPv6 traffic follows a
    // dedicated parse path (Task 10/follow-up) which will hand a fully
    // populated IPv6 packet to `lookup_v6()` once available.  The
    // `ipv6_trie_` member is still kept live and buildable so the storage
    // surface matches the plan and so IPv6 control-plane rules can be
    // inserted ahead of the datapath.

    return std::nullopt;
}

std::optional<Action> RuleTable::lookup(const ParsedPacket& pkt) const noexcept {
    const auto entry = lookup_entry(pkt);
    return entry ? std::optional<Action>{entry->action} : std::nullopt;
}

// ---------------------------------------------------------------------------
// RuleTableRegistry: atomic-shared-ptr handle for the active rule set.
// ---------------------------------------------------------------------------
//
// C++20's std::atomic<std::shared_ptr<T>> is the synchronization
// primitive.  acquire on load, release on store.  No mutexes on the hot
// path, no RuleTable copies on swap -- the shared_ptr increments the
// refcount of the new table and decrements the refcount of the old table
// when the last reader drops it.

RuleTableRegistry::RuleTableRegistry(RuleTablePtr initial) noexcept {
    active_.store(std::move(initial), std::memory_order_release);
}

RuleTablePtr RuleTableRegistry::active() const noexcept {
    return active_.load(std::memory_order_acquire);
}

void RuleTableRegistry::swap(RuleTablePtr new_table) noexcept {
    active_.store(std::move(new_table), std::memory_order_release);
}

std::optional<Action> RuleTableRegistry::lookup(const ParsedPacket& pkt) const noexcept {
    const auto entry = lookup_entry(pkt);
    return entry ? std::optional<Action>{entry->action} : std::nullopt;
}

std::optional<RuleEntry> RuleTableRegistry::lookup_entry(const ParsedPacket& pkt) const noexcept {
    auto t = active_.load(std::memory_order_acquire);
    if (!t)
        return std::nullopt;
    return t->lookup_entry(pkt);
}

// ---------------------------------------------------------------------------
// Explicit template instantiations
// ---------------------------------------------------------------------------
//
// `CidrTrie<IPv4Addr, RuleEntry, 8192>` and `CidrTrie<IPv6Addr,
// RuleEntry, 8192>` are not used by any other translation unit, so we
// instantiate them here to keep the linker inputs small.  The default
// `std::uint32_t` instantiations live in `cidr_trie.cpp` (Task 14).
//
// Pool size 8192 nodes carries the full `RuleEntry` per slot; at ~64 bytes
// per populated node this is roughly 512 KB per trie, comfortably under
// even the conservative UMEM fill budget and small enough to map into the
// data cache footprint of a single worker.

template class CidrTrie<IPv4Addr, RuleEntry, 8192>;
template class CidrTrie<IPv6Addr, RuleEntry, 8192>;

} // namespace packet_engine
