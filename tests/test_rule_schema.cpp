// SPDX-License-Identifier: MIT
//
// test_rule_schema.cpp -- GoogleTest coverage for JSON rule schema parsing,
// serialization, and validation.
//

#include <gtest/gtest.h>

#include "packet-engine/rule_schema.hpp"

#include <string>
#include <vector>

namespace pe = packet_engine;

namespace {

pe::Rule make_drop_tuple_rule() {
    pe::Rule r;
    r.id = "drop-ssh";
    r.action = pe::SchemaAction::DROP;
    r.tuple = pe::FiveTuple{
        pe::IPv4Addr{10, 0, 0, 1}, pe::IPv4Addr{10, 0, 0, 2}, 12345, 22, pe::L4Proto::TCP,
    };
    return r;
}

pe::Rule make_forward_rule() {
    pe::Rule r;
    r.id = "fwd-web";
    r.action = pe::SchemaAction::FORWARD;
    r.cidr = pe::Cidr{pe::IPv4Addr{192, 168, 0, 0}, 24};
    r.backend_id = "be-1";
    return r;
}

pe::Rule make_rate_limit_rule() {
    pe::Rule r;
    r.id = "rate-dns";
    r.action = pe::SchemaAction::RATE_LIMIT;
    r.tuple = pe::FiveTuple{
        pe::IPv4Addr{0, 0, 0, 0}, pe::IPv4Addr{8, 8, 8, 8}, 0, 53, pe::L4Proto::UDP,
    };
    r.rate_bps = 1'000'000;
    r.burst_bytes = 10'000;
    return r;
}

} // anonymous namespace

TEST(RuleSchemaTest, RoundTripDropTupleRule) {
    const auto original = make_drop_tuple_rule();
    const std::string json = pe::serialize_rules_json({original});
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), 1U);
    EXPECT_EQ((*parsed)[0], original);
}

TEST(RuleSchemaTest, RoundTripForwardCidrRule) {
    const auto original = make_forward_rule();
    const std::string json = pe::serialize_rules_json({original});
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), 1U);
    EXPECT_EQ((*parsed)[0], original);
}

TEST(RuleSchemaTest, RoundTripRateLimitRule) {
    const auto original = make_rate_limit_rule();
    const std::string json = pe::serialize_rules_json({original});
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), 1U);
    EXPECT_EQ((*parsed)[0], original);
}

TEST(RuleSchemaTest, AllowRuleRoundTrips) {
    const std::string json = R"([{"id":"allow-dns","action":"ALLOW","cidr":"10.0.0.0/8"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), 1U);
    EXPECT_NE(pe::serialize_rules_json(*parsed).find(R"("action":"ALLOW")"), std::string::npos);
}

TEST(RuleSchemaTest, RoundTripMultipleRules) {
    std::vector<pe::Rule> rules{make_drop_tuple_rule(), make_forward_rule(),
                                make_rate_limit_rule()};
    const std::string json = pe::serialize_rules_json(rules);
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->size(), rules.size());
    for (std::size_t i = 0; i < rules.size(); ++i) {
        EXPECT_EQ((*parsed)[i], rules[i]);
    }
}

TEST(RuleSchemaTest, EmptyArrayRoundTrip) {
    const std::string json = pe::serialize_rules_json({});
    EXPECT_EQ(json, "[]");
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->empty());
}

TEST(RuleSchemaTest, MalformedJsonReturnsError) {
    const auto parsed = pe::parse_rules_json("[{\"id\": \"x\"");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("JSON parse error"), std::string::npos);
}

TEST(RuleSchemaTest, NonArrayTopLevelReturnsError) {
    const auto parsed = pe::parse_rules_json("{\"rules\": []}");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().message, "expected JSON array of rules");
}

TEST(RuleSchemaTest, MissingMatcherReturnsError) {
    const std::string json = R"([{"id": "no-match", "action": "DROP"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("tuple"), std::string::npos);
}

TEST(RuleSchemaTest, MultipleMatchersReturnError) {
    const auto parsed = pe::parse_rules_json(
        R"([{"id":"ambiguous","action":"DROP","cidr":"10.0.0.0/8","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1,"dst_port":2,"proto":"tcp"}}])");
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("exactly one"), std::string::npos);
}

TEST(RuleSchemaTest, RateLimitMissingRateBpsReturnsError) {
    const std::string json = R"([{"id": "rl", "action": "RATE_LIMIT", "cidr": "10.0.0.0/8"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("rate_bps"), std::string::npos);
}

TEST(RuleSchemaTest, RateLimitRequiresPositiveRateAndBurst) {
    for (
        const char* json :
        {R"([{"id":"rl","action":"RATE_LIMIT","cidr":"10.0.0.0/8","rate_bps":1000}])",
         R"([{"id":"rl","action":"RATE_LIMIT","cidr":"10.0.0.0/8","rate_bps":0,"burst_bytes":1000}])",
         R"([{"id":"rl","action":"RATE_LIMIT","cidr":"10.0.0.0/8","rate_bps":1000,"burst_bytes":0}])"}) {
        const auto parsed = pe::parse_rules_json(json);
        EXPECT_FALSE(parsed.has_value()) << json;
    }
}

TEST(RuleSchemaTest, InvalidNumericFieldsReturnErrorsWithoutThrowing) {
    EXPECT_NO_THROW({
        const auto parsed = pe::parse_rules_json(
            R"([{"id":"rl","action":"RATE_LIMIT","cidr":"10.0.0.0/8","rate_bps":1e100,"burst_bytes":1000}])");
        EXPECT_FALSE(parsed.has_value());
    });
    EXPECT_NO_THROW({
        const auto parsed = pe::parse_rules_json(
            R"([{"id":"tuple","action":"DROP","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":18446744073709551615,"dst_port":80,"proto":"tcp"}}])");
        EXPECT_FALSE(parsed.has_value());
    });
}

TEST(RuleSchemaTest, ForwardWithoutBackendIdUsesLoadBalancer) {
    const std::string json =
        R"([{"id": "fwd", "action": "FORWARD", "tuple": {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "src_port": 1, "dst_port": 2, "proto": "tcp"}}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->size(), 1u);
    EXPECT_FALSE(parsed->front().backend_id.has_value());
}

TEST(RuleSchemaTest, InvalidActionReturnsError) {
    const std::string json = R"([{"id": "bad", "action": "REJECT", "cidr": "0.0.0.0/0"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("unknown action"), std::string::npos);
}

TEST(RuleSchemaTest, InvalidCidrPrefixReturnsError) {
    const std::string json = R"([{"id": "bad", "action": "DROP", "cidr": "192.168.0.0/33"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("prefix"), std::string::npos);
}

TEST(RuleSchemaTest, InvalidIpv4OctetReturnsError) {
    const std::string json = R"([{"id": "bad", "action": "DROP", "cidr": "256.0.0.0/24"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("octet"), std::string::npos);
}

TEST(RuleSchemaTest, NegativeRateBpsReturnsError) {
    const std::string json =
        R"([{"id": "bad", "action": "RATE_LIMIT", "cidr": "0.0.0.0/0", "rate_bps": -1}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("rate_bps"), std::string::npos);
}

TEST(RuleSchemaTest, MissingIdReturnsError) {
    const std::string json = R"([{"action": "DROP", "cidr": "0.0.0.0/0"}])";
    const auto parsed = pe::parse_rules_json(json);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_NE(parsed.error().message.find("id"), std::string::npos);
}
