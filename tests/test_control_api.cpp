// SPDX-License-Identifier: MIT
//
// test_control_api.cpp -- GoogleTest for the Unix-socket REST control API.
//

#include "packet-engine/control_api.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

namespace pe = packet_engine;

namespace {

std::string make_socket_path() {
    return "/tmp/packet-engine-test-" + std::to_string(::getpid()) + ".sock";
}

int unix_connect(const std::string& path) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::string http_request(const std::string& path, const std::string& method,
                         const std::string& body, const std::string& socket_path) {
    int fd = unix_connect(socket_path);
    EXPECT_GE(fd, 0) << "connect failed: " << std::strerror(errno);
    if (fd < 0)
        return {};

    std::string request;
    request += method + " " + path + " HTTP/1.1\r\n";
    request += "Host: localhost\r\n";
    request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    request += "\r\n";
    request += body;

    ssize_t sent = ::send(fd, request.data(), request.size(), MSG_NOSIGNAL);
    EXPECT_EQ(sent, static_cast<ssize_t>(request.size()));

    std::string response;
    std::array<char, 4096> buf{};
    while (true) {
        ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0)
            break;
        response.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(fd);
    return response;
}

std::string segmented_http_request(const std::string& path, const std::string& method,
                                   const std::string& body, const std::string& socket_path) {
    int fd = unix_connect(socket_path);
    EXPECT_GE(fd, 0) << "connect failed: " << std::strerror(errno);
    if (fd < 0)
        return {};

    std::string headers;
    headers += method + " " + path + " HTTP/1.1\r\n";
    headers += "Host: localhost\r\n";
    headers += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    headers += "\r\n";

    const ssize_t header_bytes = ::send(fd, headers.data(), headers.size(), MSG_NOSIGNAL);
    EXPECT_EQ(header_bytes, static_cast<ssize_t>(headers.size()));

    pollfd readiness{fd, POLLIN, 0};
    const int poll_result = ::poll(&readiness, 1, 50);
    EXPECT_GE(poll_result, 0);
    if (poll_result == 0) {
        const ssize_t body_bytes = ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
        EXPECT_EQ(body_bytes, static_cast<ssize_t>(body.size()));
    }

    std::string response;
    std::array<char, 4096> buf{};
    while (true) {
        const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0)
            break;
        response.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(fd);
    return response;
}

std::string body_of(const std::string& response) {
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos)
        return {};
    return response.substr(pos + 4);
}

bool json_equal(const std::string& a, const std::string& b) {
    try {
        return nlohmann::json::parse(a) == nlohmann::json::parse(b);
    } catch (...) {
        return false;
    }
}

bool wait_for_server(const std::string& path, int timeout_ms = 2000) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        int fd = unix_connect(path);
        if (fd >= 0) {
            ::close(fd);
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

pe::ParsedPacket rate_limited_packet() {
    static const std::array<std::byte, 64> frame{};
    pe::ParsedPacket packet{};
    packet.raw = frame;
    packet.src_ip = pe::IPv4Addr{10, 0, 0, 1};
    packet.dst_ip = pe::IPv4Addr{10, 0, 0, 2};
    packet.src_port = 1234;
    packet.dst_port = 80;
    packet.proto = pe::L4Proto::TCP;
    return packet;
}

class TestKetamaAdapter final : public pe::IKetamaRebuildCallback {
  public:
    explicit TestKetamaAdapter(pe::KetamaRing& ring) : ring_{ring} {}

    void rebuild(const std::vector<pe::Backend>& backends) override {
        std::vector<pe::KetamaBackend> replacement;
        replacement.reserve(backends.size());
        for (const auto& backend : backends) {
            replacement.push_back(
                {static_cast<pe::KetamaBackendId>(backend.id), backend.authority});
        }
        static_cast<void>(ring_.replace_backends(std::move(replacement)));
    }

  private:
    pe::KetamaRing& ring_;
};

} // namespace

class ControlApiTest : public ::testing::Test {
  protected:
    ControlApiTest()
        : rules_{std::make_shared<pe::RuleTable>()}, ketama_{}, adapter_{ketama_},
          backends_{&adapter_}, api_{rules_, backends_, ketama_, make_socket_path()} {}

    ~ControlApiTest() override { api_.stop(); }

    void SetUp() override {
        ASSERT_TRUE(api_.start());
        ASSERT_TRUE(wait_for_server(api_.socket_path()));
    }

    void TearDown() override {
        api_.stop();
        ::unlink(api_.socket_path().c_str());
    }

    pe::RuleTableRegistry rules_;
    pe::KetamaRing ketama_;
    TestKetamaAdapter adapter_;
    pe::BackendRegistry backends_;
    pe::ControlApi api_;
};

TEST_F(ControlApiTest, GetHealthReturnsOk) {
    auto resp = http_request("/health", "GET", "", api_.socket_path());
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_EQ(body_of(resp), R"({"status":"ok"})");
}

TEST_F(ControlApiTest, SocketIsOwnerOnly) {
    // Given: a live control-plane Unix socket.
    struct stat socket_stat{};

    // When: its filesystem permissions are inspected.
    ASSERT_EQ(::lstat(api_.socket_path().c_str(), &socket_stat), 0);

    // Then: only the owning user may connect through the pathname.
    EXPECT_EQ(socket_stat.st_mode & 0777, 0600);
}

TEST_F(ControlApiTest, RepeatedStopAndStartKeepsListenerHealthy) {
    // Given: a running endpoint that is stopped and restarted repeatedly.
    for (int iteration = 0; iteration < 20; ++iteration) {
        api_.stop();

        // When: the same endpoint claims its socket path again.
        ASSERT_TRUE(api_.start());
        ASSERT_TRUE(wait_for_server(api_.socket_path()));

        // Then: the accept loop serves a complete health response.
        EXPECT_NE(http_request("/health", "GET", "", api_.socket_path()).find("200 OK"),
                  std::string::npos);
    }
}

TEST_F(ControlApiTest, GetRulesInitiallyEmpty) {
    auto resp = http_request("/rules", "GET", "", api_.socket_path());
    EXPECT_NE(resp.find("200 OK"), std::string::npos);
    EXPECT_EQ(body_of(resp), "[]");
}

TEST_F(ControlApiTest, PutRulesThenGetRulesReturnsSameJson) {
    const char* json =
        R"([{"id":"1","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";

    auto put_resp = http_request("/rules", "PUT", json, api_.socket_path());
    EXPECT_NE(put_resp.find("200 OK"), std::string::npos);

    auto get_resp = http_request("/rules", "GET", "", api_.socket_path());
    EXPECT_NE(get_resp.find("200 OK"), std::string::npos);
    EXPECT_TRUE(json_equal(body_of(get_resp), json));
}

TEST_F(ControlApiTest, PutRulesReadsBodySplitAfterHeaders) {
    // Given: a valid rule update whose body is sent separately from its headers.
    const char* json =
        R"([{"id":"1","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";

    // When: the complete Content-Length body arrives in a later socket write.
    const auto put_resp = segmented_http_request("/rules", "PUT", json, api_.socket_path());

    // Then: framing completes before dispatch and the new rules are published.
    EXPECT_NE(put_resp.find("200 OK"), std::string::npos);
    const auto get_resp = http_request("/rules", "GET", "", api_.socket_path());
    EXPECT_TRUE(json_equal(body_of(get_resp), json));
}

TEST_F(ControlApiTest, PutRulesAtomicallySwapsRuleTable) {
    const char* first =
        R"([{"id":"1","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";
    const char* second =
        R"([{"id":"2","tuple":{"src_ip":"192.168.1.1","dst_ip":"192.168.1.2","src_port":53,"dst_port":53,"proto":"udp"},"action":"DROP"}])";

    EXPECT_NE(http_request("/rules", "PUT", first, api_.socket_path()).find("200 OK"),
              std::string::npos);
    EXPECT_TRUE(json_equal(body_of(http_request("/rules", "GET", "", api_.socket_path())), first));

    EXPECT_NE(http_request("/rules", "PUT", second, api_.socket_path()).find("200 OK"),
              std::string::npos);
    EXPECT_TRUE(json_equal(body_of(http_request("/rules", "GET", "", api_.socket_path())), second));

    auto table = rules_.active();
    ASSERT_NE(table, nullptr);
    EXPECT_EQ(table->exact_count(), 1u);
}

TEST_F(ControlApiTest, PutRateLimitInstallsBucketThatAdmitsThenDrops) {
    const char* json =
        R"([{"id":"7","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"RATE_LIMIT","rate_bps":1,"burst_bytes":64}])";

    const auto response = http_request("/rules", "PUT", json, api_.socket_path());

    EXPECT_NE(response.find("200 OK"), std::string::npos);
    const auto table = rules_.active();
    ASSERT_NE(table, nullptr);
    EXPECT_EQ(table->rate_limit_count(), 1u);
    const auto packet = rate_limited_packet();
    EXPECT_EQ(table->lookup(packet), pe::Action::RATE_LIMIT);
    EXPECT_EQ(table->lookup(packet), pe::Action::DROP);
}

TEST_F(ControlApiTest, IdenticalRateLimitReloadPreservesExhaustedBucket) {
    const char* json =
        R"([{"id":"7","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"RATE_LIMIT","rate_bps":1,"burst_bytes":64}])";
    ASSERT_NE(http_request("/rules", "PUT", json, api_.socket_path()).find("200 OK"),
              std::string::npos);
    const auto packet = rate_limited_packet();
    ASSERT_EQ(rules_.active()->lookup(packet), pe::Action::RATE_LIMIT);
    ASSERT_EQ(rules_.active()->lookup(packet), pe::Action::DROP);

    ASSERT_NE(http_request("/rules", "PUT", json, api_.socket_path()).find("200 OK"),
              std::string::npos);
    EXPECT_EQ(rules_.active()->lookup(packet), pe::Action::DROP);
}

TEST_F(ControlApiTest, DuplicateRuleIdsAreRejected) {
    const char* json =
        R"([{"id":"7","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1,"dst_port":80,"proto":"tcp"},"action":"ALLOW"},{"id":"7","tuple":{"src_ip":"10.0.0.3","dst_ip":"10.0.0.4","src_port":2,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";
    EXPECT_NE(http_request("/rules", "PUT", json, api_.socket_path()).find("400 Bad Request"),
              std::string::npos);
}

TEST_F(ControlApiTest, DuplicateExactMatchersAreRejected) {
    const char* json =
        R"([{"id":"7","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1,"dst_port":80,"proto":"tcp"},"action":"ALLOW"},{"id":"8","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";
    EXPECT_NE(http_request("/rules", "PUT", json, api_.socket_path()).find("400 Bad Request"),
              std::string::npos);
}

TEST_F(ControlApiTest, DuplicateCidrMatchersAreRejected) {
    const char* json =
        R"([{"id":"7","cidr":"10.0.0.1/24","action":"ALLOW"},{"id":"8","cidr":"10.0.0.2/24","action":"DROP"}])";
    EXPECT_NE(http_request("/rules", "PUT", json, api_.socket_path()).find("400 Bad Request"),
              std::string::npos);
}

TEST_F(ControlApiTest, RuleValidationErrorIsValidJson) {
    // The unknown action contains a quote; the error response must escape it
    // instead of splicing the raw parser message into the JSON body.
    const char* body = R"([{"id":"1","action":"BAD\"","cidr":"10.0.0.0/8"}])";
    const auto response = http_request("/rules", "PUT", body, api_.socket_path());
    const auto separator = response.find("\r\n\r\n");
    ASSERT_NE(separator, std::string::npos);
    const auto document = nlohmann::json::parse(response.substr(separator + 4), nullptr, false);
    ASSERT_FALSE(document.is_discarded());
    ASSERT_TRUE(document.contains("error"));
    EXPECT_NE(document.at("error").get<std::string>().find("BAD\""), std::string::npos);
}

TEST_F(ControlApiTest, PutBackendsAtomicallyReplacesRegistryAndKetama) {
    const char* first =
        R"([{"id":1,"authority":"10.0.0.11:8080","health_port":9080},{"id":2,"authority":"10.0.0.12:8080","health_port":9081}])";

    const auto first_response = http_request("/backends", "PUT", first, api_.socket_path());

    EXPECT_NE(first_response.find("200 OK"), std::string::npos);
    ASSERT_EQ(backends_.size(), 2u);
    ASSERT_TRUE(backends_.find(1));
    EXPECT_EQ(backends_.find(1)->authority, "10.0.0.11:8080");
    EXPECT_EQ(ketama_.backend_count(), 2u);
    EXPECT_TRUE(
        json_equal(body_of(http_request("/backends", "GET", "", api_.socket_path())), first));

    const char* second = R"([{"id":7,"authority":"10.0.0.17:8080","health_port":9087}])";
    const auto second_response = http_request("/backends", "PUT", second, api_.socket_path());

    EXPECT_NE(second_response.find("200 OK"), std::string::npos);
    EXPECT_EQ(backends_.size(), 1u);
    EXPECT_FALSE(backends_.find(1));
    ASSERT_TRUE(backends_.find(7));
    EXPECT_EQ(backends_.find(7)->health_port, 9087u);
    EXPECT_EQ(ketama_.backend_count(), 1u);
    EXPECT_EQ(ketama_.pick_hash(0), 7u);
    EXPECT_TRUE(
        json_equal(body_of(http_request("/backends", "GET", "", api_.socket_path())), second));
}

TEST_F(ControlApiTest, BackendMacRoundTripsForRoutableForwarding) {
    const char* json =
        R"([{"id":9,"authority":"10.0.0.19:8080","health_port":9089,"mac":"02:00:00:00:00:09"}])";
    EXPECT_NE(http_request("/backends", "PUT", json, api_.socket_path()).find("200 OK"),
              std::string::npos);
    ASSERT_TRUE(backends_.find(9));
    EXPECT_EQ(backends_.find(9)->next_hop_mac.bytes[5], 9u);
    EXPECT_TRUE(
        json_equal(body_of(http_request("/backends", "GET", "", api_.socket_path())), json));
}

TEST_F(ControlApiTest, OversizedContentLengthIsRejectedAndListenerSurvives) {
    const auto response = segmented_http_request("/rules", "PUT", "", api_.socket_path());
    EXPECT_NE(response.find("400 Bad Request"), std::string::npos);

    int fd = unix_connect(api_.socket_path());
    ASSERT_GE(fd, 0);
    const std::string request =
        "PUT /rules HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65536\r\n\r\n";
    ASSERT_EQ(::send(fd, request.data(), request.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(request.size()));
    std::array<char, 512> buffer{};
    const ssize_t count = ::recv(fd, buffer.data(), buffer.size(), 0);
    ASSERT_GT(count, 0);
    EXPECT_NE(
        std::string_view(buffer.data(), static_cast<std::size_t>(count)).find("400 Bad Request"),
        std::string_view::npos);
    ::close(fd);
    EXPECT_NE(http_request("/health", "GET", "", api_.socket_path()).find("200 OK"),
              std::string::npos);
}

TEST_F(ControlApiTest, InvalidBackendUpdateLeavesPreviousStateUnchanged) {
    const char* valid = R"([{"id":5,"authority":"10.0.0.15:8080","health_port":9005}])";
    ASSERT_NE(http_request("/backends", "PUT", valid, api_.socket_path()).find("200 OK"),
              std::string::npos);
    const auto previous_ring = ketama_.snapshot();

    const char* invalid =
        R"([{"id":6,"authority":"10.0.0.16:8080","health_port":9006},{"id":"7","authority":"10.0.0.17:8080","health_port":9007}])";
    const auto response = http_request("/backends", "PUT", invalid, api_.socket_path());

    EXPECT_NE(response.find("400 Bad Request"), std::string::npos);
    EXPECT_EQ(backends_.size(), 1u);
    ASSERT_TRUE(backends_.find(5));
    EXPECT_FALSE(backends_.find(6));
    EXPECT_EQ(ketama_.snapshot(), previous_ring);
    EXPECT_TRUE(
        json_equal(body_of(http_request("/backends", "GET", "", api_.socket_path())), valid));
}

TEST_F(ControlApiTest, UnknownPathReturns404) {
    auto resp = http_request("/not-a-path", "GET", "", api_.socket_path());
    EXPECT_NE(resp.find("404 Not Found"), std::string::npos);
}

TEST(ControlApiProcessSafetyTest, InvalidNumericRuleIdDoesNotTerminateServer) {
    GTEST_FLAG_SET(death_test_style, "threadsafe");
    EXPECT_EXIT(
        ([] {
            pe::RuleTableRegistry rules{std::make_shared<pe::RuleTable>()};
            pe::BackendRegistry backends;
            pe::KetamaRing ketama;
            const std::string socket_path = make_socket_path() + ".invalid-id";
            pe::ControlApi api{rules, backends, ketama, socket_path};
            if (!api.start() || !wait_for_server(socket_path)) {
                _exit(10);
            }

            const char* invalid =
                R"([{"id":"not-a-number","tuple":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"proto":"tcp"},"action":"DROP"}])";
            const auto response = http_request("/rules", "PUT", invalid, socket_path);
            const auto health = http_request("/health", "GET", "", socket_path);
            const bool survived = response.find("400 Bad Request") != std::string::npos &&
                                  health.find("200 OK") != std::string::npos;
            api.stop();
            ::unlink(socket_path.c_str());
            _exit(survived ? 0 : 11);
        }()),
        ::testing::ExitedWithCode(0), "");
}

TEST(ControlApiSocketOwnershipTest, SecondServerCannotReplaceLiveSocketOwner) {
    // Given: one live server owns and serves a Unix socket pathname.
    pe::RuleTableRegistry rules{std::make_shared<pe::RuleTable>()};
    pe::BackendRegistry backends;
    pe::KetamaRing ketama;
    const std::string socket_path = make_socket_path() + ".owner";
    pe::ControlApi first{rules, backends, ketama, socket_path};
    pe::ControlApi second{rules, backends, ketama, socket_path};
    ASSERT_TRUE(first.start());
    ASSERT_TRUE(wait_for_server(socket_path));

    // When: a second server attempts to claim the same live pathname.
    EXPECT_FALSE(second.start());
    second.stop();

    // Then: the original owner's pathname remains reachable and under its control.
    const int owner_fd = unix_connect(socket_path);
    EXPECT_GE(owner_fd, 0);
    if (owner_fd >= 0) {
        ::close(owner_fd);
    }
    first.stop();
    ::unlink(socket_path.c_str());
}
