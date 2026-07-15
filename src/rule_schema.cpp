// SPDX-License-Identifier: MIT
//
// rule_schema.cpp -- JSON rule schema serialization, deserialization, and
// validation using nlohmann/json.
//

#include "packet-engine/rule_schema.hpp"

#include <nlohmann/json.hpp>

#include <charconv>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace packet_engine {

namespace {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// String helpers.
// ---------------------------------------------------------------------------

[[nodiscard]] std::optional<std::uint32_t> parse_u32(std::string_view s) noexcept {
    std::uint64_t value{0};
    const char* first = s.data();
    const char* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, value);
    if (ec != std::errc() || ptr != last || value > 0xFFFFFFFFU) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

[[nodiscard]] std::expected<std::uint64_t, ParseError> parse_json_u64(const json& value,
                                                                      std::string_view field) {
    if (value.is_number_unsigned()) {
        return value.get_ref<const json::number_unsigned_t&>();
    }
    if (value.is_number_integer()) {
        const auto parsed = value.get_ref<const json::number_integer_t&>();
        if (parsed >= 0) {
            return static_cast<std::uint64_t>(parsed);
        }
    }
    return std::unexpected(
        ParseError{"field '" + std::string(field) + "' must be a non-negative integer"});
}

[[nodiscard]] std::string action_to_string(SchemaAction a) {
    switch (a) {
    case SchemaAction::ALLOW:
        return "ALLOW";
    case SchemaAction::DROP:
        return "DROP";
    case SchemaAction::FORWARD:
        return "FORWARD";
    case SchemaAction::RATE_LIMIT:
        return "RATE_LIMIT";
    }
    return "DROP"; // LCOV_EXCL_LINE
}

[[nodiscard]] std::expected<SchemaAction, ParseError> action_from_string(std::string_view s) {
    if (s == "ALLOW")
        return SchemaAction::ALLOW;
    if (s == "DROP")
        return SchemaAction::DROP;
    if (s == "FORWARD")
        return SchemaAction::FORWARD;
    if (s == "RATE_LIMIT")
        return SchemaAction::RATE_LIMIT;
    return std::unexpected(ParseError{std::string("unknown action: ") + std::string(s)});
}

// ---------------------------------------------------------------------------
// Address parsing / serialization.
// ---------------------------------------------------------------------------

[[nodiscard]] std::expected<IPv4Addr, ParseError> parse_ipv4(std::string_view s) {
    std::uint32_t octets[4] = {0, 0, 0, 0};
    std::size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        std::size_t dot = s.find('.', start);
        std::string_view part;
        if (i == 3) {
            part = s.substr(start);
        } else {
            if (dot == std::string_view::npos) {
                return std::unexpected(ParseError{"IPv4 address has too few octets"});
            }
            part = s.substr(start, dot - start);
        }
        auto v = parse_u32(part);
        if (!v || *v > 255) {
            return std::unexpected(ParseError{"invalid IPv4 octet"});
        }
        octets[i] = *v;
        start = dot + 1;
    }
    return IPv4Addr{static_cast<std::uint8_t>(octets[0]), static_cast<std::uint8_t>(octets[1]),
                    static_cast<std::uint8_t>(octets[2]), static_cast<std::uint8_t>(octets[3])};
}

[[nodiscard]] std::string ipv4_to_string(const IPv4Addr& addr) {
    return std::to_string((addr.value >> 24) & 0xFF) + "." +
           std::to_string((addr.value >> 16) & 0xFF) + "." +
           std::to_string((addr.value >> 8) & 0xFF) + "." + std::to_string((addr.value) & 0xFF);
}

[[nodiscard]] std::expected<Cidr, ParseError> parse_cidr(std::string_view s) {
    const std::size_t slash = s.find('/');
    if (slash == std::string_view::npos) {
        return std::unexpected(ParseError{"CIDR must be in address/prefix form"});
    }
    auto addr = parse_ipv4(s.substr(0, slash));
    if (!addr) {
        return std::unexpected(addr.error());
    }
    auto prefix = parse_u32(s.substr(slash + 1));
    if (!prefix || *prefix > 32) {
        return std::unexpected(ParseError{"invalid CIDR prefix length"});
    }
    return Cidr{*addr, static_cast<std::uint8_t>(*prefix)};
}

[[nodiscard]] std::string cidr_to_string(const Cidr& cidr) {
    return ipv4_to_string(cidr.addr) + "/" + std::to_string(cidr.prefix_len);
}

// ---------------------------------------------------------------------------
// L4 protocol helpers.
// ---------------------------------------------------------------------------

[[nodiscard]] std::string proto_to_string(L4Proto p) {
    switch (p) {
    case L4Proto::ICMP:
        return "icmp";
    case L4Proto::TCP:
        return "tcp";
    case L4Proto::UDP:
        return "udp";
    case L4Proto::ICMPv6:
        return "icmpv6";
    case L4Proto::OTHER:
        return "other";
    }
    return "other"; // LCOV_EXCL_LINE
}

[[nodiscard]] std::expected<L4Proto, ParseError> proto_from_string(std::string_view s) {
    if (s == "icmp")
        return L4Proto::ICMP;
    if (s == "tcp")
        return L4Proto::TCP;
    if (s == "udp")
        return L4Proto::UDP;
    if (s == "icmpv6")
        return L4Proto::ICMPv6;
    if (s == "other")
        return L4Proto::OTHER;
    return std::unexpected(ParseError{std::string("unknown protocol: ") + std::string(s)});
}

// ---------------------------------------------------------------------------
// nlohmann/json conversions.
// ---------------------------------------------------------------------------

[[nodiscard]] json five_tuple_to_json(const FiveTuple& ft) {
    json j;
    j["src_ip"] = ipv4_to_string(ft.src_ip);
    j["dst_ip"] = ipv4_to_string(ft.dst_ip);
    j["src_port"] = ft.src_port;
    j["dst_port"] = ft.dst_port;
    j["proto"] = proto_to_string(ft.proto);
    return j;
}

[[nodiscard]] std::expected<FiveTuple, ParseError> five_tuple_from_json(const json& j) {
    FiveTuple ft;

    auto require_string = [](const json& obj,
                             std::string_view key) -> std::expected<std::string_view, ParseError> {
        auto it = obj.find(key);
        if (it == obj.end()) {
            return std::unexpected(ParseError{std::string("missing field: ") + std::string(key)});
        }
        if (!it->is_string()) {
            return std::unexpected(
                ParseError{std::string("field must be a string: ") + std::string(key)});
        }
        return it->get_ref<const std::string&>();
    };

    auto require_u16 = [](const json& obj,
                          std::string_view key) -> std::expected<std::uint16_t, ParseError> {
        auto it = obj.find(key);
        if (it == obj.end()) {
            return std::unexpected(ParseError{std::string("missing field: ") + std::string(key)});
        }
        auto parsed = parse_json_u64(*it, key);
        if (!parsed || *parsed > std::numeric_limits<std::uint16_t>::max()) {
            return std::unexpected(
                ParseError{std::string("field out of uint16 range: ") + std::string(key)});
        }
        return static_cast<std::uint16_t>(*parsed);
    };

    auto src_ip = require_string(j, "src_ip");
    if (!src_ip)
        return std::unexpected(src_ip.error());
    auto parsed_src = parse_ipv4(*src_ip);
    if (!parsed_src)
        return std::unexpected(parsed_src.error());
    ft.src_ip = *parsed_src;

    auto dst_ip = require_string(j, "dst_ip");
    if (!dst_ip)
        return std::unexpected(dst_ip.error());
    auto parsed_dst = parse_ipv4(*dst_ip);
    if (!parsed_dst)
        return std::unexpected(parsed_dst.error());
    ft.dst_ip = *parsed_dst;

    auto src_port = require_u16(j, "src_port");
    if (!src_port)
        return std::unexpected(src_port.error());
    ft.src_port = *src_port;

    auto dst_port = require_u16(j, "dst_port");
    if (!dst_port)
        return std::unexpected(dst_port.error());
    ft.dst_port = *dst_port;

    auto proto = require_string(j, "proto");
    if (!proto)
        return std::unexpected(proto.error());
    auto parsed_proto = proto_from_string(*proto);
    if (!parsed_proto)
        return std::unexpected(parsed_proto.error());
    ft.proto = *parsed_proto;

    return ft;
}

[[nodiscard]] std::expected<Rule, ParseError> rule_from_json(const json& j) {
    if (!j.is_object()) {
        return std::unexpected(ParseError{"rule must be an object"});
    }

    Rule rule;

    auto id_it = j.find("id");
    if (id_it == j.end() || !id_it->is_string()) {
        return std::unexpected(ParseError{"rule missing required string field 'id'"});
    }
    rule.id = id_it->get<std::string>();

    auto action_it = j.find("action");
    if (action_it == j.end() || !action_it->is_string()) {
        return std::unexpected(ParseError{"rule missing required string field 'action'"});
    }
    auto action = action_from_string(action_it->get_ref<const std::string&>());
    if (!action)
        return std::unexpected(action.error());
    rule.action = *action;

    auto tuple_it = j.find("tuple");
    if (tuple_it != j.end() && !tuple_it->is_null()) {
        auto ft = five_tuple_from_json(*tuple_it);
        if (!ft)
            return std::unexpected(ft.error());
        rule.tuple = *ft;
    }

    auto cidr_it = j.find("cidr");
    if (cidr_it != j.end() && !cidr_it->is_null()) {
        if (!cidr_it->is_string()) {
            return std::unexpected(ParseError{"field 'cidr' must be a string"});
        }
        auto cidr = parse_cidr(cidr_it->get_ref<const std::string&>());
        if (!cidr)
            return std::unexpected(cidr.error());
        rule.cidr = *cidr;
    }

    auto rate_bps_it = j.find("rate_bps");
    if (rate_bps_it != j.end() && !rate_bps_it->is_null()) {
        auto parsed = parse_json_u64(*rate_bps_it, "rate_bps");
        if (!parsed)
            return std::unexpected(parsed.error());
        rule.rate_bps = *parsed;
    }

    auto burst_bytes_it = j.find("burst_bytes");
    if (burst_bytes_it != j.end() && !burst_bytes_it->is_null()) {
        auto parsed = parse_json_u64(*burst_bytes_it, "burst_bytes");
        if (!parsed)
            return std::unexpected(parsed.error());
        rule.burst_bytes = *parsed;
    }

    auto backend_id_it = j.find("backend_id");
    if (backend_id_it != j.end() && !backend_id_it->is_null()) {
        if (!backend_id_it->is_string()) {
            return std::unexpected(ParseError{"field 'backend_id' must be a string"});
        }
        rule.backend_id = backend_id_it->get<std::string>();
    }

    if (rule.tuple.has_value() == rule.cidr.has_value()) {
        return std::unexpected(ParseError{"rule must specify exactly one of 'tuple' or 'cidr'"});
    }

    // Validation: action-specific required fields.
    if (rule.action == SchemaAction::RATE_LIMIT) {
        if (!rule.rate_bps.has_value()) {
            return std::unexpected(ParseError{"RATE_LIMIT rule requires 'rate_bps'"});
        }
        if (*rule.rate_bps == 0) {
            return std::unexpected(ParseError{"RATE_LIMIT rule requires positive 'rate_bps'"});
        }
        if (!rule.burst_bytes.has_value()) {
            return std::unexpected(ParseError{"RATE_LIMIT rule requires 'burst_bytes'"});
        }
        if (*rule.burst_bytes == 0) {
            return std::unexpected(ParseError{"RATE_LIMIT rule requires positive 'burst_bytes'"});
        }
    }
    return rule;
}

[[nodiscard]] json rule_to_json(const Rule& rule) {
    json j;
    j["id"] = rule.id;
    j["action"] = action_to_string(rule.action);

    if (rule.tuple.has_value()) {
        j["tuple"] = five_tuple_to_json(*rule.tuple);
    }
    if (rule.cidr.has_value()) {
        j["cidr"] = cidr_to_string(*rule.cidr);
    }
    if (rule.rate_bps.has_value()) {
        j["rate_bps"] = *rule.rate_bps;
    }
    if (rule.burst_bytes.has_value()) {
        j["burst_bytes"] = *rule.burst_bytes;
    }
    if (rule.backend_id.has_value()) {
        j["backend_id"] = *rule.backend_id;
    }
    return j;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API implementation.
// ---------------------------------------------------------------------------

std::expected<std::vector<Rule>, ParseError> parse_rules_json(std::string_view json_text) {
    try {
        json root = json::parse(json_text);

        if (!root.is_array()) {
            return std::unexpected(ParseError{"expected JSON array of rules"});
        }

        std::vector<Rule> rules;
        rules.reserve(root.size());

        for (std::size_t i = 0; i < root.size(); ++i) {
            auto rule = rule_from_json(root[i]);
            if (!rule) {
                return std::unexpected(
                    ParseError{"rule[" + std::to_string(i) + "]: " + rule.error().message});
            }
            rules.push_back(*rule);
        }

        return rules;
    } catch (const json::exception& e) {
        return std::unexpected(ParseError{std::string("JSON parse error: ") + e.what()});
    }
}

std::string serialize_rules_json(const std::vector<Rule>& rules) {
    json root = json::array();
    for (const auto& rule : rules) {
        root.push_back(rule_to_json(rule));
    }
    return root.dump();
}

} // namespace packet_engine
