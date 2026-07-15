// SPDX-License-Identifier: MIT
//
// rule_entry.hpp -- value type stored in the open-addressing hash table.
//
// A `RuleEntry` is what the rule engine associates with a 5-tuple key:
// on a hit the worker thread reads the `Action` and acts accordingly
// (drop / allow / rate-limit / forward to a backend).  The struct is
// kept tiny so that the open-addressing hash table slots remain a
// single cache line wide when the value is held inline via
// `std::optional<RuleEntry>`.
//
// The type is trivially copyable and trivially destructible: we treat
// it as a POD so that open-addressing probe loops stay branch-free
// and the prefetched `__builtin_prefetch` on the hot lookup path
// cannot race with an arbitrary destructor.
//
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

namespace packet_engine {

/// Action to take on a flow that matches a rule.
enum class Action : std::uint8_t {
    ALLOW = 0,
    DROP = 1,
    RATE_LIMIT = 2,
    FORWARD_TO_BACKEND = 3,
    TX_TO_BACKEND_INTERFACE = 4,
    TX_TO_CLIENT_INTERFACE = 5,
};

using RuleEntryAction = Action;

/// Per-rule metadata stored alongside the 5-tuple key.
///
/// `id` is the rule's identifier as known to the control plane.
/// `action` drives the worker's fast-path decision.  `rate_limit_bps`
/// and `backend_id` are only meaningful for `RATE_LIMIT` and
/// `FORWARD_TO_BACKEND` respectively; both are kept inline so the
/// table layout is uniform regardless of action.
///
/// The struct is deliberately small (~24 bytes) so that the per-slot
/// `(std::optional<FiveTuple>, std::optional<RuleEntry>)` pair fits
/// in two cache lines and a probe touch loads them atomically from the
/// caller's perspective.
struct alignas(8) RuleEntry {
    using RuleId = std::uint64_t;

    RuleId id{0};
    Action action{Action::DROP};
    std::uint32_t rate_limit_bps{0}; // RATE_LIMIT
    std::uint32_t backend_id{0};     // FORWARD_TO_BACKEND
    std::uint32_t priority{0};
    bool has_backend_id{false};

    constexpr RuleEntry() noexcept = default;

    constexpr RuleEntry(RuleId rid, Action act) noexcept : id{rid}, action{act} {}

    constexpr RuleEntry(RuleId rid, Action act, std::uint32_t rate_bps,
                        std::uint32_t backend) noexcept
        : id{rid}, action{act}, rate_limit_bps{rate_bps}, backend_id{backend},
          has_backend_id{true} {}

    friend constexpr bool operator==(const RuleEntry& a, const RuleEntry& b) noexcept {
        return a.id == b.id && a.action == b.action && a.rate_limit_bps == b.rate_limit_bps &&
               a.backend_id == b.backend_id && a.priority == b.priority &&
               a.has_backend_id == b.has_backend_id;
    }
    friend constexpr bool operator!=(const RuleEntry& a, const RuleEntry& b) noexcept {
        return !(a == b);
    }
};

static_assert(sizeof(RuleEntry) <= 32, "RuleEntry must remain small for cache-friendly slots");

} // namespace packet_engine
