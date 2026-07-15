#include "packet-engine/metrics_aggregator.hpp"
#include "packet-engine/metrics_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <future>
#include <string>
#include <thread>

#include <gtest/gtest.h>

namespace pe {
namespace {

class MetricsEndpointTest : public ::testing::Test {
  protected:
    void SetUp() override {
        registry_ = std::make_unique<MetricsRegistry>();
        // Port 0 lets the OS assign an ephemeral loopback port.
        endpoint_ = std::make_unique<MetricsEndpoint>(*registry_, 0);
        ASSERT_TRUE(endpoint_->start());
        port_ = endpoint_->port();
        ASSERT_GT(port_, 0);
    }

    void TearDown() override {
        endpoint_->stop();
        endpoint_.reset();
        registry_.reset();
    }

    [[nodiscard]] std::string http_get(const std::string& path, int& status_code,
                                       std::string& content_type) const {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_GE(fd, 0);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(static_cast<uint16_t>(port_));

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return {};
        }

        std::string request =
            "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        send(fd, request.data(), request.size(), MSG_NOSIGNAL);

        shutdown(fd, SHUT_WR);

        std::string response;
        char buffer[4096];
        ssize_t n = 0;
        while ((n = recv(fd, buffer, sizeof(buffer), 0)) > 0) {
            response.append(buffer, static_cast<size_t>(n));
        }
        close(fd);

        status_code = parse_status(response);
        content_type = parse_header(response, "Content-Type");
        return extract_body(response);
    }

    [[nodiscard]] std::string http_get(const std::string& path) const {
        int status_code = 0;
        std::string content_type;
        return http_get(path, status_code, content_type);
    }

    [[nodiscard]] std::string delayed_http_get(const std::string& path,
                                               std::chrono::milliseconds delay) const {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_GE(fd, 0);
        const int receive_buffer_bytes = 4096;
        EXPECT_EQ(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes,
                             sizeof(receive_buffer_bytes)),
                  0);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(static_cast<uint16_t>(port_));
        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            return {};
        }

        const std::string request =
            "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if (send(fd, request.data(), request.size(), MSG_NOSIGNAL) < 0) {
            close(fd);
            return {};
        }
        std::this_thread::sleep_for(delay);

        std::string response;
        std::array<char, 8192> buffer{};
        ssize_t received = 0;
        while ((received = recv(fd, buffer.data(), buffer.size(), 0)) > 0) {
            response.append(buffer.data(), static_cast<std::size_t>(received));
        }
        close(fd);
        return extract_body(response);
    }

  protected:
    [[nodiscard]] static int parse_status(const std::string& response) {
        const std::string prefix = "HTTP/1.1 ";
        if (response.compare(0, prefix.size(), prefix) != 0) {
            return 0;
        }
        size_t end = response.find(' ', prefix.size());
        if (end == std::string::npos) {
            return 0;
        }
        return std::stoi(response.substr(prefix.size(), end - prefix.size()));
    }

    [[nodiscard]] static std::string parse_header(const std::string& response,
                                                  const std::string& name) {
        std::string look_for = "\n" + name + ": ";
        size_t pos = response.find(look_for);
        if (pos == std::string::npos) {
            look_for = "\r\n" + name + ": ";
            pos = response.find(look_for);
        }
        if (pos == std::string::npos) {
            return {};
        }
        pos += look_for.size();
        size_t end = response.find_first_of("\r\n", pos);
        return response.substr(pos, end - pos);
    }

    [[nodiscard]] static std::string extract_body(const std::string& response) {
        size_t pos = response.find("\r\n\r\n");
        if (pos == std::string::npos) {
            pos = response.find("\n\n");
            if (pos == std::string::npos) {
                return {};
            }
            return response.substr(pos + 2);
        }
        return response.substr(pos + 4);
    }

    std::unique_ptr<MetricsRegistry> registry_;
    std::unique_ptr<MetricsEndpoint> endpoint_;
    int port_ = 0;
};

TEST_F(MetricsEndpointTest, HealthReturnsOk) {
    int status = 0;
    std::string content_type;
    std::string body = http_get("/health", status, content_type);

    EXPECT_EQ(status, 200);
    EXPECT_NE(content_type.find("application/json"), std::string::npos);
    EXPECT_EQ(body, R"({"status":"ok"})");
}

TEST_F(MetricsEndpointTest, MetricsReturnsExposition) {
    registry_->counter("engine_rx_packets_total", "Total received packets").inc(42);
    registry_->histogram("engine_latency_seconds", "Latency in seconds", {0.001}).observe(0.000123);

    int status = 0;
    std::string content_type;
    std::string body = http_get("/metrics", status, content_type);

    EXPECT_EQ(status, 200);
    EXPECT_NE(content_type.find("text/plain"), std::string::npos);
    EXPECT_NE(content_type.find("version=0.0.4"), std::string::npos);
    EXPECT_NE(body.find("engine_rx_packets_total 42"), std::string::npos);
    EXPECT_NE(body.find("engine_latency_seconds_bucket{le=\"0.001\"} 1"), std::string::npos);
}

TEST_F(MetricsEndpointTest, UnknownPathReturns404) {
    int status = 0;
    std::string content_type;
    std::string body = http_get("/foo", status, content_type);

    EXPECT_EQ(status, 404);
    EXPECT_EQ(body, "Not Found\n");
}

TEST_F(MetricsEndpointTest, AggregatorPublishesRequiredMetrics) {
    MetricsAggregator aggregator(1, registry_.get());
    aggregator.record_rx(0, 100);
    aggregator.record_drop(0, 5);
    aggregator.record_latency_us(0, 25);
    aggregator.record_latency_us(0, 75);
    aggregator.publish();

    int status = 0;
    std::string content_type;
    std::string body = http_get("/metrics", status, content_type);

    EXPECT_EQ(status, 200);
    EXPECT_NE(body.find("engine_rx_packets_total 100"), std::string::npos);
    EXPECT_NE(body.find("engine_drops_total 5"), std::string::npos);
    EXPECT_NE(body.find("engine_latency_seconds_bucket"), std::string::npos);
    EXPECT_NE(body.find("engine_latency_seconds_count 2"), std::string::npos);
    EXPECT_EQ(body.find("engine_latency_p50_us"), std::string::npos);
    EXPECT_EQ(body.find("engine_latency_p99_us"), std::string::npos);
}

TEST_F(MetricsEndpointTest, IdleClientDoesNotBlockConcurrentScrape) {
    // Given: an idle client occupies one accepted connection without sending a request.
    int idle_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(idle_fd, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    ASSERT_EQ(connect(idle_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);

    // When: another client scrapes the endpoint.
    auto scrape = std::async(std::launch::async, [this] {
        int status = 0;
        std::string content_type;
        static_cast<void>(http_get("/metrics", status, content_type));
        return status;
    });

    // Then: the scrape completes within a bounded interval despite the idle peer.
    const auto readiness = scrape.wait_for(std::chrono::milliseconds(250));
    EXPECT_EQ(readiness, std::future_status::ready);

    shutdown(idle_fd, SHUT_RDWR);
    close(idle_fd);
    EXPECT_EQ(scrape.get(), 200);
}

TEST_F(MetricsEndpointTest, LargeExpositionIsNotTruncatedAfterPartialSend) {
    // Given: an exposition larger than the TCP send buffer and a temporarily slow reader.
    const std::string help(128, 'h');
    for (int metric = 0; metric < 20'000; ++metric) {
        registry_->counter("bulk_metric_" + std::to_string(metric), help).inc();
    }
    registry_->counter("zzzz_final_metric", help).inc(7);

    // When: the endpoint must resume a partial send after the client starts reading.
    const std::string body = delayed_http_get("/metrics", std::chrono::milliseconds(150));

    // Then: the lexicographically final metric proves the response reached its tail.
    EXPECT_NE(body.find("zzzz_final_metric 7\n"), std::string::npos);
}

TEST_F(MetricsEndpointTest, RepeatedStopAndStartKeepsListenerHealthy) {
    // Given: a metrics endpoint stopped and restarted repeatedly.
    for (int iteration = 0; iteration < 20; ++iteration) {
        endpoint_->stop();

        // When: the same endpoint starts another accept loop.
        ASSERT_TRUE(endpoint_->start());
        port_ = endpoint_->port();

        // Then: a live health request completes on the restarted listener.
        int status = 0;
        std::string content_type;
        static_cast<void>(http_get("/health", status, content_type));
        EXPECT_EQ(status, 200);
    }
}

} // namespace
} // namespace pe
