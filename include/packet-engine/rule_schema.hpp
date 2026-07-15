// SPDX-License-Identifier: MIT
//
// rule_schema.hpp -- JSON rule schema serialization, deserialization, and
// validation for the packet-engine control plane.
//
// This header defines the public API used by Task 24 (REST control API) and
// any other control-plane surface that needs to ingest or emit rule sets as
// JSON.  All error handling uses C++23 std::expected so that no exception is
// thrown across module boundaries.
//
#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "packet-engine/types.hpp"

namespace packet_engine {

// ---------------------------------------------------------------------------
// Action types (mirrors rule_entry.hpp / Task 13 intent).
// ---------------------------------------------------------------------------

enum class SchemaAction : std::uint8_t {
    DROP = 0,
    FORWARD = 1,
    RATE_LIMIT = 2,
    ALLOW = 3,
};

using RuleSchemaAction = SchemaAction;

// ---------------------------------------------------------------------------
// CIDR address block.
// ---------------------------------------------------------------------------

/// IPv4 CIDR prefix used for L3 matching.
///
/// `prefix_len` is in host byte order and in the inclusive range [0, 32].
struct Cidr {
    IPv4Addr addr{};
    std::uint8_t prefix_len{0};

    constexpr Cidr() noexcept = default;
    constexpr Cidr(IPv4Addr a, std::uint8_t p) noexcept : addr{a}, prefix_len{p} {}

    friend constexpr bool operator==(const Cidr& lhs, const Cidr& rhs) noexcept {
        return lhs.addr == rhs.addr && lhs.prefix_len == rhs.prefix_len;
    }
};

// ---------------------------------------------------------------------------
// Rule schema.
// ---------------------------------------------------------------------------

/// Human- or control-plane-managed rule.
///
/// A rule matches by either a concrete five-tuple or a CIDR block. Validation
/// requires exactly one matcher. Action-specific optional fields are validated per
// Action:
//   - RATE_LIMIT requires `rate_bps`.
//   - FORWARD    hashes across healthy backends unless `backend_id` pins it.
struct Rule {
    std::string id;
    std::optional<FiveTuple> tuple;
    std::optional<Cidr> cidr;
    SchemaAction action{SchemaAction::DROP};
    std::optional<std::uint64_t> rate_bps;
    std::optional<std::uint64_t> burst_bytes;
    std::optional<std::string> backend_id;

    friend constexpr bool operator==(const Rule& lhs, const Rule& rhs) noexcept {
        return lhs.id == rhs.id && lhs.tuple == rhs.tuple && lhs.cidr == rhs.cidr &&
               lhs.action == rhs.action && lhs.rate_bps == rhs.rate_bps &&
               lhs.burst_bytes == rhs.burst_bytes && lhs.backend_id == rhs.backend_id;
    }
};

// ---------------------------------------------------------------------------
// Error handling.
// ---------------------------------------------------------------------------

/// Structured parse / validation error.
///
/// Carries an opaque message suitable for logging or returning through the
/// REST API.  No exception is thrown.
struct ParseError {
    std::string message;
};

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// Parse a JSON array of rule objects into validated Rule structs.
///
/// Returns std::expected<std::vector<Rule>, ParseError>.  On failure the
/// unexpected value contains a human-readable error message.
[[nodiscard]] std::expected<std::vector<Rule>, ParseError> parse_rules_json(std::string_view json);

/// Serialize a vector of Rule structs into a compact JSON string.
///
/// The output is a JSON array of rule objects.  This function never fails for
/// well-formed Rule values; malformed optional states are impossible by
/// construction.
[[nodiscard]] std::string serialize_rules_json(const std::vector<Rule>& rules);

} // namespace packet_engine
