// SPDX-License-Identifier: MIT
//
// token_bucket.cpp -- per-rule token bucket rate limiter.
//

#include "packet-engine/token_bucket.hpp"

#include <algorithm>
#include <cstdint>

namespace packet_engine {

TokenBucket::TokenBucket(std::uint64_t rate_bps, std::uint64_t burst_bytes,
                         std::uint64_t now_ns) noexcept
    : tokens_(static_cast<double>(burst_bytes)), rate_bps_(rate_bps), burst_bytes_(burst_bytes),
      last_refill_ns_(now_ns) {}

bool TokenBucket::try_consume(std::uint64_t bytes, std::uint64_t now_ns) noexcept {
    if (now_ns < last_refill_ns_) {
        return false;
    }

    // Refill based on elapsed time.  The multiplication is done in double
    // to preserve fractional bytes accumulated over short intervals.
    const double elapsed_s = static_cast<double>(now_ns - last_refill_ns_) / 1'000'000'000.0;
    const double refill = elapsed_s * static_cast<double>(rate_bps_);

    const double cap = static_cast<double>(burst_bytes_);

    tokens_ = std::min(cap, tokens_ + refill);
    last_refill_ns_ = now_ns;

    if (tokens_ >= static_cast<double>(bytes)) {
        tokens_ -= static_cast<double>(bytes);
        return true;
    }
    return false;
}

} // namespace packet_engine
