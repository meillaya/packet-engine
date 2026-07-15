#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <string_view>
#include <syncstream>
#include <thread>
#include <type_traits>
#include <unistd.h>

namespace packet_engine::detail {

enum class LogLevel : std::uint8_t { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

inline std::atomic<LogLevel>& global_log_level() noexcept {
    static std::atomic<LogLevel> level{LogLevel::INFO};
    return level;
}

inline const char* level_name(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::DEBUG:
        return "DEBUG";
    case LogLevel::INFO:
        return "INFO";
    case LogLevel::WARN:
        return "WARN";
    case LogLevel::ERROR:
        return "ERROR";
    }
    return "UNKNOWN";
}

inline std::int64_t current_tid() noexcept {
    static thread_local const std::thread::id id = std::this_thread::get_id();
    static thread_local const std::int64_t tid =
        static_cast<std::int64_t>(std::hash<std::thread::id>{}(id));
    return tid;
}

inline bool should_log(LogLevel level) noexcept {
    return static_cast<std::uint8_t>(level) >=
           static_cast<std::uint8_t>(global_log_level().load(std::memory_order_relaxed));
}

template <typename T> std::string to_string_for_log(const T& value) {
    if constexpr (std::is_arithmetic_v<T>) {
        return std::to_string(value);
    } else if constexpr (std::is_same_v<std::decay_t<T>, std::string_view> ||
                         std::is_same_v<std::decay_t<T>, const char*>) {
        return std::string(value);
    } else {
        return std::string(value);
    }
}

class LogBuffer {
  public:
    explicit LogBuffer(LogLevel level, const char* file, int line) {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        gmtime_r(&t, &tm);
        head_ = buf_;
        head_ +=
            std::snprintf(head_, capacity_left(), "[%02d:%02d:%02d] [%s] pid=%d tid=%ld %s:%d ",
                          tm.tm_hour, tm.tm_min, tm.tm_sec, level_name(level),
                          static_cast<int>(getpid()), current_tid(), file, line);
    }

    ~LogBuffer() {
        if (head_ >= buf_ + sizeof(buf_)) {
            head_ = buf_ + sizeof(buf_) - 1;
        }
        *head_++ = '\n';
        std::osyncstream sync(std::cerr);
        sync.write(buf_, static_cast<std::streamsize>(head_ - buf_));
    }

    template <typename T> LogBuffer& operator<<(const T& value) {
        if constexpr (std::is_same_v<std::decay_t<T>, std::string_view> ||
                      std::is_same_v<std::decay_t<T>, const char*>) {
            const std::string_view sv(value);
            const std::size_t n = std::min(sv.size(), static_cast<std::size_t>(capacity_left()));
            std::memcpy(head_, sv.data(), n);
            head_ += n;
        } else {
            const std::string s = to_string_for_log(value);
            const std::size_t n = std::min(s.size(), static_cast<std::size_t>(capacity_left()));
            std::memcpy(head_, s.data(), n);
            head_ += n;
        }
        return *this;
    }

  private:
    [[nodiscard]] std::size_t capacity_left() const noexcept {
        const std::ptrdiff_t left = (buf_ + sizeof(buf_)) - head_ - 1; // reserve 1 for newline
        return left > 0 ? static_cast<std::size_t>(left) : 0;
    }

    char buf_[4096];
    char* head_ = buf_;
};

} // namespace packet_engine::detail

#define LOG_IMPL(level, ...)                                                                       \
    do {                                                                                           \
        if (::packet_engine::detail::should_log(level)) {                                          \
            ::packet_engine::detail::LogBuffer(level, __FILE__, __LINE__) << __VA_ARGS__;          \
        }                                                                                          \
    } while (0)

#ifdef PACKET_ENGINE_DEBUG
#define LOG_DEBUG(...) LOG_IMPL(::packet_engine::detail::LogLevel::DEBUG, __VA_ARGS__)
#else
#define LOG_DEBUG(...)                                                                             \
    do {                                                                                           \
    } while (0)
#endif

#define LOG_INFO(...) LOG_IMPL(::packet_engine::detail::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...) LOG_IMPL(::packet_engine::detail::LogLevel::WARN, __VA_ARGS__)
#define LOG_ERROR(...) LOG_IMPL(::packet_engine::detail::LogLevel::ERROR, __VA_ARGS__)
