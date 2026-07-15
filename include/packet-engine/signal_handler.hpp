#pragma once

#include <atomic>
#include <csignal>
#include <cstring>

namespace packet_engine {

inline std::atomic<bool>& stop_flag() noexcept {
    static std::atomic<bool> flag{false};
    return flag;
}

inline const char* signal_name(int sig) noexcept {
    switch (sig) {
    case SIGINT:
        return "SIGINT";
    case SIGTERM:
        return "SIGTERM";
    default:
        return "UNKNOWN";
    }
}

namespace detail {

// Async-signal-safe: only write to volatile/atomic storage.
// No malloc, no printf, no std::cerr, no LOG_* here.
extern "C" inline void signal_handler(int sig) {
    (void)sig;
    stop_flag().store(true, std::memory_order_release);
}

} // namespace detail

inline bool install_signal_handlers() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = detail::signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, nullptr) != 0) {
        return false;
    }
    if (sigaction(SIGTERM, &sa, nullptr) != 0) {
        return false;
    }
    return true;
}

} // namespace packet_engine
