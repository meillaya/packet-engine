#include "packet-engine/prometheus_client.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmath>
#include <cstring>

using ::testing::HasSubstr;

class PrometheusClientTest : public ::testing::Test {};

TEST_F(PrometheusClientTest, CounterTextFormat) {
    pe::MetricsRegistry registry;
    auto& c = registry.counter("test", "help");
    c.inc();
    EXPECT_EQ(registry.expose_text(), "# HELP test help\n"
                                      "# TYPE test counter\n"
                                      "test 1\n");
}

TEST_F(PrometheusClientTest, CounterMultipleIncrements) {
    pe::MetricsRegistry registry;
    auto& c = registry.counter("requests_total", "Total requests");
    c.inc(7);
    c.inc(3);
    const std::string out = registry.expose_text();
    EXPECT_THAT(out, HasSubstr("requests_total 10\n"));
}

TEST_F(PrometheusClientTest, GaugeTextFormat) {
    pe::MetricsRegistry registry;
    auto& g = registry.gauge("temperature", "Current temperature");
    g.set(42);
    g.add(-3);
    const std::string out = registry.expose_text();
    EXPECT_THAT(out, HasSubstr("# TYPE temperature gauge\n"));
    EXPECT_THAT(out, HasSubstr("temperature 39\n"));
}

TEST_F(PrometheusClientTest, HistogramBucketsAndInf) {
    pe::MetricsRegistry registry;
    auto& h = registry.histogram("latency_us", "Request latency", std::vector<double>{1, 10, 100});
    h.observe(0.5);
    h.observe(5);
    h.observe(50);
    h.observe(500);
    h.observe(5000);

    const std::string out = registry.expose_text();
    EXPECT_THAT(out, HasSubstr("# TYPE latency_us histogram\n"));
    EXPECT_THAT(out, HasSubstr("latency_us_bucket{le=\"1\"} 1\n"));
    EXPECT_THAT(out, HasSubstr("latency_us_bucket{le=\"10\"} 2\n"));
    EXPECT_THAT(out, HasSubstr("latency_us_bucket{le=\"100\"} 3\n"));
    EXPECT_THAT(out, HasSubstr("latency_us_bucket{le=\"+Inf\"} 5\n"));
    EXPECT_THAT(out, HasSubstr("latency_us_count 5\n"));
    EXPECT_NEAR(std::stod(out.substr(out.find("latency_us_sum ") + std::strlen("latency_us_sum "))),
                5555.5, 1e-6);
}

TEST_F(PrometheusClientTest, LabelEscaping) {
    pe::MetricsRegistry registry;
    auto& c = registry.counter("metric_with_labels", "Help text");
    c.inc();
    (void)c;

    // Expose text does not currently expose arbitrary labels, but the escape
    // helper is exercised via a private detail function. We verify the public
    // behavior of the registry remains valid and include an inline escape check.
    std::string raw = "path=\"quoted\"\nline";
    std::string escaped = pe::detail::escape_label_value(raw);
    EXPECT_EQ(escaped, "path=\\\"quoted\\\"\\nline");
}

TEST_F(PrometheusClientTest, EmptyRegistry) {
    pe::MetricsRegistry registry;
    EXPECT_TRUE(registry.expose_text().empty());
}
