#pragma once

#include <atomic>
#include <boost/lockfree/spsc_queue.hpp>
#include <cstddef>
#include <type_traits>

namespace packet_engine {

template <typename T, std::size_t Capacity = 4096>
    requires std::is_trivially_copyable_v<T>
class SpscRing {
  public:
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two");

    SpscRing() = default;
    ~SpscRing() = default;

    SpscRing(const SpscRing&) = delete;
    SpscRing& operator=(const SpscRing&) = delete;
    SpscRing(SpscRing&&) = delete;
    SpscRing& operator=(SpscRing&&) = delete;

    [[nodiscard]] bool push(const T& value) {
        const bool was_empty_before = queue_.empty();
        const bool pushed = queue_.push(value);
        if (pushed && was_empty_before) {
            was_empty_.store(false, std::memory_order_release);
        }
        return pushed;
    }

    [[nodiscard]] bool pop(T& value) {
        const bool popped = queue_.pop(value);
        if (popped && queue_.empty()) {
            was_empty_.store(true, std::memory_order_release);
        }
        return popped;
    }

    [[nodiscard]] bool was_empty() const noexcept {
        return was_empty_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::size_t size_approx() const noexcept { return queue_.read_available(); }

  private:
    boost::lockfree::spsc_queue<T, boost::lockfree::capacity<Capacity>> queue_;
    std::atomic<bool> was_empty_{true};
};

} // namespace packet_engine
