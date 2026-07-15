// SPDX-License-Identifier: MIT
//
// test_backend_registry.cpp -- unit tests for BackendRegistry.
//

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

#include <packet-engine/backend_registry.hpp>

#include <gtest/gtest.h>

using namespace packet_engine;

class MockKetamaCallback : public IKetamaRebuildCallback {
  public:
    void rebuild(const std::vector<Backend>& backends) override {
        last_backends_.store(std::make_shared<std::vector<Backend>>(backends));
        ++rebuild_count;
    }

    std::vector<Backend> last() const {
        auto ptr = last_backends_.load();
        return ptr ? *ptr : std::vector<Backend>{};
    }

    std::atomic<std::size_t> rebuild_count{0};

  private:
    std::atomic<std::shared_ptr<const std::vector<Backend>>> last_backends_;
};

class BackendRegistryTest : public ::testing::Test {
  protected:
    MockKetamaCallback mock_callback_;
    BackendRegistry registry_{&mock_callback_};
};

TEST_F(BackendRegistryTest, RegisterSetsHealthyAndRebuilds) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});

    EXPECT_EQ(registry_.size(), 1u);
    const auto b = registry_.find(1);
    ASSERT_TRUE(b);
    EXPECT_EQ(b->id, 1u);
    EXPECT_EQ(b->authority, "127.0.0.1:8080");
    EXPECT_EQ(b->health_port, 8081u);
    EXPECT_EQ(b->state, BackendState::HEALTHY);

    EXPECT_EQ(mock_callback_.rebuild_count.load(), 1u);
    auto last = mock_callback_.last();
    ASSERT_EQ(last.size(), 1u);
    EXPECT_EQ(last[0].id, 1u);
}

TEST_F(BackendRegistryTest, UnregisterRemovesAndRebuilds) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});
    registry_.register_backend(Backend{2, "127.0.0.1:8082", 8083});
    ASSERT_EQ(mock_callback_.rebuild_count.load(), 2u);

    registry_.unregister_backend(1);
    EXPECT_EQ(registry_.size(), 1u);
    EXPECT_FALSE(registry_.find(1));
    EXPECT_TRUE(registry_.find(2));
    EXPECT_EQ(mock_callback_.rebuild_count.load(), 3u);

    auto last = mock_callback_.last();
    ASSERT_EQ(last.size(), 1u);
    EXPECT_EQ(last[0].id, 2u);
}

TEST_F(BackendRegistryTest, FailureThresholdDemotesToDegraded) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});

    registry_.report_failure(1);
    registry_.report_failure(1);
    registry_.report_failure(1);
    EXPECT_EQ(registry_.find(1)->state, BackendState::HEALTHY);

    registry_.report_failure(1);
    EXPECT_EQ(registry_.find(1)->state, BackendState::DEGRADED);
    EXPECT_TRUE(mock_callback_.last().empty());

    std::size_t rebuilds_after_demotion = mock_callback_.rebuild_count.load();
    registry_.report_failure(1);
    EXPECT_EQ(registry_.find(1)->state, BackendState::DEGRADED);
    EXPECT_EQ(mock_callback_.rebuild_count.load(), rebuilds_after_demotion);
}

TEST_F(BackendRegistryTest, SuccessResetsFailureCountAndRestoresHealthy) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});

    registry_.report_failure(1);
    registry_.report_failure(1);
    registry_.report_success(1);

    EXPECT_EQ(registry_.find(1)->state, BackendState::HEALTHY);

    // Failures should start from zero again.
    registry_.report_failure(1);
    registry_.report_failure(1);
    EXPECT_EQ(registry_.find(1)->state, BackendState::HEALTHY);
}

TEST_F(BackendRegistryTest, SuccessAfterDemotionRestoresHealthy) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});

    registry_.report_failure(1);
    registry_.report_failure(1);
    registry_.report_failure(1);
    registry_.report_failure(1);
    ASSERT_EQ(registry_.find(1)->state, BackendState::DEGRADED);

    registry_.report_success(1);
    EXPECT_EQ(registry_.find(1)->state, BackendState::HEALTHY);
    ASSERT_EQ(mock_callback_.last().size(), 1u);
}

TEST_F(BackendRegistryTest, FailuresOutsideWindowDoNotCount) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});

    registry_.report_failure(1);
    registry_.report_failure(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    registry_.report_failure(1);

    EXPECT_EQ(registry_.find(1)->state, BackendState::HEALTHY);
}

TEST_F(BackendRegistryTest, HealthySnapshotExcludesDown) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});
    registry_.register_backend(Backend{2, "127.0.0.1:8082", 8083});

    auto healthy = registry_.healthy_snapshot();
    ASSERT_EQ(healthy.size(), 2u);

    // Mark one DEGRADED: still eligible.
    registry_.report_failure(1);
    registry_.report_failure(1);
    registry_.report_failure(1);
    healthy = registry_.healthy_snapshot();
    EXPECT_EQ(healthy.size(), 2u);
}

TEST_F(BackendRegistryTest, SnapshotIsStable) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});
    auto snap = registry_.snapshot();
    ASSERT_EQ(snap.size(), 1u);

    // Mutating the snapshot must not affect the registry.
    snap[0].authority = "mutated";
    EXPECT_EQ(registry_.find(1)->authority, "127.0.0.1:8080");
}

TEST_F(BackendRegistryTest, FindReturnsStableValueAcrossLiveReplacement) {
    registry_.register_backend(Backend{1, "127.0.0.1:8080", 8081});
    const auto found = registry_.find(1);
    ASSERT_TRUE(found);

    registry_.register_backend(Backend{1, "127.0.0.2:9090", 9091});

    EXPECT_EQ(found->authority, "127.0.0.1:8080");
    EXPECT_EQ(registry_.find(1)->authority, "127.0.0.2:9090");
}

TEST_F(BackendRegistryTest, ConcurrentReadersAndWriterNoDataRace) {
    constexpr int kBackends = 4;
    for (int i = 0; i < kBackends; ++i) {
        registry_.register_backend(Backend{static_cast<BackendId>(i),
                                           "127.0.0.1:" + std::to_string(8000 + i),
                                           static_cast<std::uint64_t>(9000 + i)});
    }

    std::atomic<bool> stop{false};
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r) {
        readers.emplace_back([this, &stop] {
            while (!stop.load()) {
                for (int i = 0; i < 4; ++i) {
                    (void)registry_.find(static_cast<BackendId>(i));
                }
                (void)registry_.snapshot();
                (void)registry_.healthy_snapshot();
            }
        });
    }

    std::thread writer([this, &stop] {
        while (!stop.load()) {
            registry_.report_failure(0);
            registry_.report_success(0);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    stop.store(true);
    for (auto& t : readers) {
        t.join();
    }
    writer.join();

    // Final state should be consistent: backend 0 healthy, all present.
    EXPECT_EQ(registry_.size(), static_cast<std::size_t>(kBackends));
    EXPECT_EQ(registry_.find(0)->state, BackendState::HEALTHY);
}

TEST_F(BackendRegistryTest, MissingBackendReportsAreNoOps) {
    registry_.report_failure(42);
    registry_.report_success(42);
    registry_.unregister_backend(42);
    EXPECT_EQ(registry_.size(), 0u);
}
