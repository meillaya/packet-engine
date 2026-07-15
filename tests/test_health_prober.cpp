// SPDX-License-Identifier: MIT
//
// test_health_prober.cpp -- unit tests for HealthProber.
//
// We deliberately exercise the prober via two routes:
//   1. The `probe_round_for_test(predicate)` hook -- fast, deterministic
//      state-machine tests using a `MockBackendRegistry` that
//      approximates the real BackendRegistry threshold logic.
//   2. Direct `probe_one()` calls against a real loopback TCP listener --
//      end-to-end test of the EINPROGRESS + poll(POLLOUT) path.
//
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <packet-engine/backend_registry.hpp>
#include <packet-engine/health_prober.hpp>

using namespace packet_engine;
using namespace std::chrono_literals;

namespace {

/// Spin up a TCP listener on 127.0.0.1 that accepts connections and
/// closes them immediately.  Used to validate the real socket probe
/// path.  One accept per probe is enough -- we only care that the
/// connect(2) succeeds.
class LoopbackListener {
  public:
    LoopbackListener() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_GE(fd_, 0) << "socket() failed";

        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // ephemeral
        const int bind_rc = ::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        EXPECT_EQ(bind_rc, 0) << "bind() failed";

        socklen_t len = sizeof(addr);
        const int rc = ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        EXPECT_EQ(rc, 0);
        port_ = ntohs(addr.sin_port);

        const int lst = ::listen(fd_, 16);
        EXPECT_EQ(lst, 0);

        // Accept in a side thread so we don't block here.
        running_.store(true);
        acceptor_ = std::thread([this] {
            while (running_.load()) {
                sockaddr_in caddr{};
                socklen_t clen = sizeof(caddr);
                int cfd = ::accept(fd_, reinterpret_cast<sockaddr*>(&caddr), &clen);
                if (cfd >= 0) {
                    ::close(cfd);
                } else if (!running_.load()) {
                    return;
                }
            }
        });
    }

    ~LoopbackListener() {
        running_.store(false);
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        if (acceptor_.joinable()) {
            acceptor_.join();
        }
    }

    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] std::string authority() const { return "127.0.0.1:" + std::to_string(port_); }

  private:
    int fd_{-1};
    std::uint16_t port_{0};
    std::atomic<bool> running_{false};
    std::thread acceptor_;
};

/// Mock IBackendRegistry that records every report_* call and applies
/// the same passive-health threshold logic the real BackendRegistry
/// does, so transitions happen at predictable counts.
class MockBackendRegistry : public IBackendRegistry {
  public:
    void add_backend(Backend backend) {
        std::lock_guard lock{mu_};
        backend.state = BackendState::HEALTHY;
        records_[backend.id] = backend;
        failures_.erase(backend.id);
    }

    void remove(BackendId id) {
        std::lock_guard lock{mu_};
        records_.erase(id);
        failures_.erase(id);
    }

    [[nodiscard]] BackendState state(BackendId id) const {
        std::lock_guard lock{mu_};
        auto it = records_.find(id);
        return it == records_.end() ? BackendState::DOWN : it->second.state;
    }

    std::optional<Backend> find(BackendId id) const override {
        std::lock_guard lock{mu_};
        auto it = records_.find(id);
        return it == records_.end() ? std::nullopt : std::optional<Backend>{it->second};
    }

    std::vector<Backend> healthy_snapshot() const override {
        std::lock_guard lock{mu_};
        std::vector<Backend> result;
        for (const auto& [id, b] : records_) {
            if (b.state == BackendState::DOWN)
                continue;
            result.push_back(b);
        }
        return result;
    }

    void report_failure(BackendId id) override {
        std::lock_guard lock{mu_};
        reports_.push_back({id, false});
        auto it = records_.find(id);
        if (it == records_.end())
            return;
        auto& rec = failures_[id];
        rec.push_back(std::chrono::steady_clock::now());
        // Mirror BackendRegistry's `failure_count > threshold` rule.
        if (rec.size() > kFailureThreshold && it->second.state == BackendState::HEALTHY) {
            it->second.state = BackendState::DEGRADED;
        }
    }

    void report_success(BackendId id) override {
        std::lock_guard lock{mu_};
        reports_.push_back({id, true});
        auto it = records_.find(id);
        if (it == records_.end())
            return;
        failures_.erase(id);
        it->second.state = BackendState::HEALTHY;
    }

    struct ReportCall {
        BackendId id{0};
        bool success{false};
    };

    [[nodiscard]] std::vector<ReportCall> reports() const {
        std::lock_guard lock{mu_};
        return reports_;
    }

    [[nodiscard]] std::size_t report_count(bool success) const {
        std::lock_guard lock{mu_};
        std::size_t n = 0;
        for (const auto& r : reports_) {
            if (r.success == success)
                ++n;
        }
        return n;
    }

    static constexpr std::size_t kFailureThreshold{3};

  private:
    mutable std::mutex mu_;
    std::unordered_map<BackendId, Backend> records_;
    std::unordered_map<BackendId, std::vector<std::chrono::steady_clock::time_point>> failures_;
    std::vector<ReportCall> reports_;
};

/// Exposes `probe_round_for_test` and gives the test author a hook to
/// override `probe_one` with a deterministic verdict.
class TestableProber : public HealthProber {
  public:
    TestableProber(IBackendRegistry& r, std::chrono::seconds interval = 1s,
                   std::chrono::seconds timeout = 1s)
        : HealthProber(r, interval, timeout) {}

    using HealthProber::probe_one;
    using HealthProber::probe_round_for_test;
};

// ---------------------------------------------------------------------------
// Defaults + construction
// ---------------------------------------------------------------------------

TEST(HealthProberTest, DefaultsMatchTaskSpec) {
    EXPECT_EQ(HealthProber::kDefaultProbeInterval, 5s);
    EXPECT_EQ(HealthProber::kDefaultProbeTimeout, 1s);
    EXPECT_EQ(HealthProber::kDefaultHealthPort, static_cast<std::uint16_t>(8080));

    MockBackendRegistry reg;
    HealthProber prober{reg};
    EXPECT_EQ(prober.probe_interval(), 5s);
    EXPECT_EQ(prober.probe_timeout(), 1s);
    EXPECT_FALSE(prober.running());
}

TEST(HealthProberTest, ConfigurationForwardedToProber) {
    MockBackendRegistry reg;
    TestableProber prober{reg, 2s, 3s};
    EXPECT_EQ(prober.probe_interval(), 2s);
    EXPECT_EQ(prober.probe_timeout(), 3s);
}

// ---------------------------------------------------------------------------
// Behavioural tests via probe_round_for_test + MockBackendRegistry
// ---------------------------------------------------------------------------

TEST(HealthProberTest, SuccessfulProbeReportsSuccess) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "10.0.0.1:80", 8081});
    reg.add_backend(Backend{2, "10.0.0.2:80", 8082});

    TestableProber prober{reg};
    const auto ok = prober.probe_round_for_test({1, 2}, [](BackendId) { return true; });

    EXPECT_EQ(ok, 2u);
    EXPECT_EQ(reg.state(1), BackendState::HEALTHY);
    EXPECT_EQ(reg.state(2), BackendState::HEALTHY);
    EXPECT_EQ(reg.report_count(true), 2u);
    EXPECT_EQ(reg.report_count(false), 0u);

    const auto m = prober.metrics();
    EXPECT_EQ(m.probes_attempted.load(), 2u);
    EXPECT_EQ(m.probes_succeeded.load(), 2u);
    EXPECT_EQ(m.probes_failed.load(), 0u);
    EXPECT_EQ(m.success_to_degraded.load(), 0u);
    EXPECT_EQ(m.degraded_to_healthy.load(), 0u);
}

TEST(HealthProberTest, FailedProbeReportsFailure) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "10.0.0.1:80", 8081});
    TestableProber prober{reg};

    const auto ok = prober.probe_round_for_test({1}, [](BackendId) { return false; });
    EXPECT_EQ(ok, 0u);
    EXPECT_EQ(reg.report_count(false), 1u);

    const auto m = prober.metrics();
    EXPECT_EQ(m.probes_attempted.load(), 1u);
    EXPECT_EQ(m.probes_failed.load(), 1u);
}

TEST(HealthProberTest, RepeatedFailuresTransitionHealthyToDegraded) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "10.0.0.1:80", 8081});

    TestableProber prober{reg};
    // Threshold for demotion is 3 in MockBackendRegistry, meaning the
    // 4th failure inside the window flips HEALTHY -> DEGRADED.  Issue
    // 4 failed probes.
    for (int i = 0; i < 4; ++i) {
        prober.probe_round_for_test({1}, [](BackendId) { return false; });
    }
    EXPECT_EQ(reg.state(1), BackendState::DEGRADED);

    const auto m = prober.metrics();
    EXPECT_GE(m.probes_attempted.load(), 4u);
    EXPECT_EQ(m.success_to_degraded.load(), 1u);
    EXPECT_EQ(m.probes_failed.load(), 4u);
}

TEST(HealthProberTest, SuccessAfterDemotionRestoresHealthy) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "10.0.0.1:80", 8081});

    TestableProber prober{reg};
    // Drive to DEGRADED.
    for (int i = 0; i < 4; ++i) {
        prober.probe_round_for_test({1}, [](BackendId) { return false; });
    }
    ASSERT_EQ(reg.state(1), BackendState::DEGRADED);

    // One success should restore HEALTHY.
    prober.probe_round_for_test({1}, [](BackendId) { return true; });
    EXPECT_EQ(reg.state(1), BackendState::HEALTHY);

    const auto m = prober.metrics();
    EXPECT_EQ(m.degraded_to_healthy.load(), 1u);
}

TEST(HealthProberTest, UnknownIdsAreSkipped) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "10.0.0.1:80", 8081});
    TestableProber prober{reg};

    // id=42 is not registered: must be a no-op (no report calls).
    prober.probe_round_for_test({1, 42, 99}, [](BackendId) { return true; });
    EXPECT_EQ(reg.reports().size(), 1u);
    EXPECT_EQ(reg.reports()[0].id, 1u);
}

// ---------------------------------------------------------------------------
// Worker-thread lifecycle
// ---------------------------------------------------------------------------

TEST(HealthProberTest, StartStopLifecycle) {
    MockBackendRegistry reg;
    TestableProber prober{reg, 1s, 1s};

    EXPECT_FALSE(prober.running());
    prober.start();
    EXPECT_TRUE(prober.running());
    prober.stop();
    EXPECT_FALSE(prober.running());
}

TEST(HealthProberTest, StartIsIdempotent) {
    MockBackendRegistry reg;
    TestableProber prober{reg};
    prober.start();
    prober.start(); // second call must not crash
    EXPECT_TRUE(prober.running());
    prober.stop();
    EXPECT_FALSE(prober.running());
}

TEST(HealthProberTest, DestructorStopsWorker) {
    MockBackendRegistry reg;
    auto prober = std::make_unique<TestableProber>(reg, 1s, 1s);
    prober->start();
    EXPECT_TRUE(prober->running());
    prober.reset(); // ~HealthProber -> stop()
}

// ---------------------------------------------------------------------------
// Real-socket probe path
// ---------------------------------------------------------------------------

TEST(HealthProberTest, ProbeOneSucceedsAgainstLoopbackListener) {
    MockBackendRegistry reg;
    LoopbackListener listener;
    reg.add_backend(Backend{1, listener.authority(), 0});

    TestableProber prober{reg, 1s, 1s};
    const auto backend = reg.find(1);
    ASSERT_TRUE(backend);

    std::string err;
    const bool ok = prober.probe_one(*backend, std::chrono::milliseconds{500}, &err);
    EXPECT_TRUE(ok) << "probe_one failed: " << err;
}

TEST(HealthProberTest, ProbeOneFailsWhenNoListener) {
    MockBackendRegistry reg;
    // Use a high port that (almost certainly) has no listener.
    reg.add_backend(Backend{1, "127.0.0.1:1", 1});

    TestableProber prober{reg};
    const auto backend = reg.find(1);
    ASSERT_TRUE(backend);

    std::string err;
    const bool ok = prober.probe_one(*backend, std::chrono::milliseconds{200}, &err);
    EXPECT_FALSE(ok);
    // The prober should never hang.  We measure elapsed wall clock to
    // prove the timeout actually fires.
    auto t0 = std::chrono::steady_clock::now();
    std::string err2;
    prober.probe_one(*backend, std::chrono::milliseconds{200}, &err2);
    auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(elapsed, 2s) << "probe_one ignored timeout";
}

TEST(HealthProberTest, ProbeOneRejectsMalformedAuthority) {
    MockBackendRegistry reg;
    reg.add_backend(Backend{1, "not-a-valid-host:abc", 8080});
    TestableProber prober{reg};

    const auto backend = reg.find(1);
    ASSERT_TRUE(backend);
    std::string err;
    // Backends with no port and no colon should still default to 8080
    // -- so use an authority with a non-numeric port to trigger the
    // malformed branch.
    reg.remove(1);
    reg.add_backend(Backend{2, "::not::a::port", 8080});
    const auto b2 = reg.find(2);
    ASSERT_TRUE(b2);
    EXPECT_FALSE(prober.probe_one(*b2, std::chrono::milliseconds{50}, &err));
}

// ---------------------------------------------------------------------------
// End-to-end via worker thread against a real listener
// ---------------------------------------------------------------------------

TEST(HealthProberTest, WorkerProbesRealBackendSuccessfully) {
    MockBackendRegistry reg;
    LoopbackListener listener;
    reg.add_backend(Backend{1, listener.authority(), 0});

    // Very tight interval so we hit at least one probe round.
    TestableProber prober{reg, 1s, 1s};
    prober.start();

    // Wait up to 2s for at least one probe_succeeded to be recorded.
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto m = prober.metrics();
        if (m.probes_succeeded.load() > 0)
            break;
        std::this_thread::sleep_for(50ms);
    }

    prober.stop();

    const auto m = prober.metrics();
    EXPECT_GE(m.probes_succeeded.load(), 1u);
    EXPECT_GE(reg.report_count(true), 1u);
}

} // namespace
