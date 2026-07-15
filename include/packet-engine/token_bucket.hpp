// SPDX-License-Identifier: MIT
//
// token_bucket.hpp -- per-rule token bucket rate limiter.
//
// Design notes
// ============
//
// * Each TokenBucket is independent state for a single rate-limit rule.
//   The primitive is non-atomic; RuleTable serializes concurrent access.
//
// * `try_consume()` receives a monotonic timestamp from its caller and does
//   not query a clock itself.
//
// * Tokens are tracked as `double` to allow fractional accumulation over
//   short time intervals.  Refill clamps to `burst_bytes`.
//
// * The implementation is intentionally simple and non-atomic. Callers that
//   share one bucket across workers must provide synchronization.
//
#pragma once

#include <cstdint>

namespace packet_engine {

/// Per-rule token bucket for byte-rate limiting.
///
/// State is per-instance and not internally synchronized.
class TokenBucket {
  public:
    /// Construct a bucket.
    ///
    /// @param rate_bps    Sustained rate in bytes per second.  Must be > 0.
    /// @param burst_bytes Maximum bucket capacity in bytes.  Zero disables
    ///                    all non-zero consumption.
    /// @param now_ns      Initial timestamp in nanoseconds (e.g. batch start).
    TokenBucket(std::uint64_t rate_bps, std::uint64_t burst_bytes, std::uint64_t now_ns) noexcept;

    /// Attempt to consume @p bytes from the bucket.
    ///
    /// Refills the bucket based on elapsed nanoseconds since the last call,
    /// clamps to burst, then subtracts @p bytes if enough tokens exist.
    ///
    /// @param bytes  Number of bytes requested.
    /// @param now_ns Current monotonic timestamp in nanoseconds.
    ///               Callers should cache this once per batch.
    /// @return true if the consume succeeded, false if rate-limited.
    [[nodiscard]] bool try_consume(std::uint64_t bytes, std::uint64_t now_ns) noexcept;

    /// Current token count (primarily for tests and diagnostics).
    [[nodiscard]] double tokens() const noexcept { return tokens_; }

    /// Last refill timestamp in nanoseconds.
    [[nodiscard]] std::uint64_t last_refill_ns() const noexcept { return last_refill_ns_; }

    /// Sustained rate in bytes per second.
    [[nodiscard]] std::uint64_t rate_bps() const noexcept { return rate_bps_; }

    /// Burst capacity in bytes.
    [[nodiscard]] std::uint64_t burst_bytes() const noexcept { return burst_bytes_; }

  private:
    // Per-rule state exactly as specified by the plan.
    double tokens_;                ///< Current token balance (bytes).
    std::uint64_t rate_bps_;       ///< Bytes per second refill rate.
    std::uint64_t burst_bytes_;    ///< Maximum token balance.
    std::uint64_t last_refill_ns_; ///< Last refill timestamp (nanoseconds).
};

} // namespace packet_engine
