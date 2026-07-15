#include <packet-engine/signal_handler.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <csignal>
#include <thread>

using packet_engine::install_signal_handlers;
using packet_engine::stop_flag;

class SignalHandlerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        stop_flag().store(false, std::memory_order_release);
        ASSERT_TRUE(install_signal_handlers());
    }

    void TearDown() override {
        // Reinstall default handlers to avoid cross-test side effects.
        std::signal(SIGINT, SIG_DFL);
        std::signal(SIGTERM, SIG_DFL);
    }
};

TEST_F(SignalHandlerTest, SigtermSetsStopFlagWithin100ms) {
    EXPECT_FALSE(stop_flag().load(std::memory_order_acquire));

    const auto start = std::chrono::steady_clock::now();
    std::raise(SIGTERM);

    while (!stop_flag().load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::milliseconds(100));
}

TEST_F(SignalHandlerTest, SigintSetsStopFlagWithin100ms) {
    EXPECT_FALSE(stop_flag().load(std::memory_order_acquire));

    const auto start = std::chrono::steady_clock::now();
    std::raise(SIGINT);

    while (!stop_flag().load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::milliseconds(100));
}
