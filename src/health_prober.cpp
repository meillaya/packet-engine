// SPDX-License-Identifier: MIT
//
// health_prober.cpp -- implementation of HealthProber.
//
// Threading
// =========
//
// `start()` spawns one `std::jthread`.  The thread body waits on a
// `std::stop_token` between probe rounds so the destructor can join it
// quickly without polling.  Each round:
//   1. Snapshots the registry's `healthy_snapshot()`.
//   2. For each backend, opens a non-blocking TCP socket against
//      `authority` and waits up to `probe_timeout` for `connect(2)` to
//      complete.
//   3. Reports the outcome via `report_success` / `report_failure`.
//   4. Sleeps for `probe_interval` (or until shutdown).
//
// Probe socket
// ============
//
// We use the documented `connect(2)` EINPROGRESS pattern:
//   * `socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)`
//   * `connect()` -> returns -1 with errno == EINPROGRESS
//   * `poll(POLLOUT)` with the configured timeout
//   * `getsockopt(SOL_SOCKET, SO_ERROR)` to read the final connect status
//
// Any other errno, a non-POLLOUT poll result, or a non-zero SO_ERROR is
// classified as a failure and routed through `registry_.report_failure`.
// We deliberately do NOT send a payload or read from the socket: TCP
// accept-queue is sufficient as a liveness signal for this task and keeps
// the prober footprint to one socket-pair per backend per probe round.
//
#include "packet-engine/health_prober.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <string_view>
#include <utility>

#include "packet-engine/logger.hpp"

namespace packet_engine {

namespace {

/// Parse `text` as a non-negative integer.  Returns false on overflow,
/// non-digit input, or empty strings.
bool parse_uint16(std::string_view text, std::uint16_t* out) {
    if (text.empty() || out == nullptr) {
        return false;
    }
    std::uint32_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const std::uint32_t next = value * 10u + static_cast<std::uint32_t>(c - '0');
        if (next > 0xFFFFu) {
            return false;
        }
        value = next;
    }
    *out = static_cast<std::uint16_t>(value);
    return true;
}

} // namespace

HealthProber::HealthProber(IBackendRegistry& registry, std::chrono::seconds probe_interval,
                           std::chrono::seconds probe_timeout, std::uint16_t default_health_port)
    : registry_{registry}, probe_interval_{probe_interval}, probe_timeout_{probe_timeout},
      default_health_port_{default_health_port} {}

HealthProber::~HealthProber() { stop(); }

void HealthProber::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return; // Already running.
    }
    thread_ =
        std::make_unique<std::jthread>([this](std::stop_token st) { probe_loop(std::move(st)); });
}

void HealthProber::stop() {
    if (thread_) {
        thread_->request_stop();
        if (thread_->joinable()) {
            thread_->join();
        }
        thread_.reset();
    }
    running_.store(false);
}

bool HealthProber::running() const noexcept { return running_.load(std::memory_order_acquire); }

HealthProberMetrics HealthProber::metrics() const {
    HealthProberMetrics snapshot;
    snapshot.success_to_degraded.store(
        metrics_.success_to_degraded.load(std::memory_order_relaxed));
    snapshot.degraded_to_healthy.store(
        metrics_.degraded_to_healthy.load(std::memory_order_relaxed));
    snapshot.probes_attempted.store(metrics_.probes_attempted.load(std::memory_order_relaxed));
    snapshot.probes_succeeded.store(metrics_.probes_succeeded.load(std::memory_order_relaxed));
    snapshot.probes_failed.store(metrics_.probes_failed.load(std::memory_order_relaxed));
    return snapshot;
}

bool HealthProber::parse_authority(const std::string& authority, std::string* host,
                                   std::uint16_t* port) const {
    if (host == nullptr || port == nullptr) {
        return false;
    }
    const auto colon = authority.rfind(':');
    if (colon == std::string::npos) {
        *host = authority;
        *port = default_health_port_;
        return !host->empty();
    }
    *host = authority.substr(0, colon);
    const std::string_view port_text{authority.c_str() + colon + 1, authority.size() - colon - 1};
    if (!parse_uint16(port_text, port)) {
        return false;
    }
    if (*port == 0) {
        *port = default_health_port_;
    }
    return !host->empty();
}

bool HealthProber::probe_one(const Backend& backend, std::chrono::milliseconds timeout,
                             std::string* error_out) {
    std::string host;
    std::uint16_t port = default_health_port_;
    if (!parse_authority(backend.authority, &host, &port)) {
        if (error_out) {
            *error_out = "malformed authority '" + backend.authority + "'";
        }
        return false;
    }
    if (backend.health_port != 0) {
        port = static_cast<std::uint16_t>(backend.health_port);
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    const int gai_rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gai_rc != 0 || res == nullptr) {
        if (error_out) {
            *error_out = std::string{"getaddrinfo: "} + gai_strerror(gai_rc);
        }
        return false;
    }

    int fd = -1;
    int last_errno = 0;
    bool tried = false;
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        tried = true;

        const int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            ::close(fd);
            freeaddrinfo(res);
            return true;
        }
        if (errno != EINPROGRESS) {
            last_errno = errno;
            ::close(fd);
            continue;
        }

        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        const int poll_rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
        if (poll_rc <= 0) {
            last_errno = (poll_rc == 0) ? ETIMEDOUT : errno;
            ::close(fd);
            continue;
        }

        int so_err = 0;
        socklen_t so_len = sizeof(so_err);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) != 0) {
            last_errno = errno;
            ::close(fd);
            continue;
        }
        ::close(fd);
        freeaddrinfo(res);
        if (so_err != 0) {
            if (error_out) {
                *error_out = std::string{"connect: "} + std::strerror(so_err);
            }
            return false;
        }
        return true;
    }
    freeaddrinfo(res);
    if (error_out) {
        if (tried && last_errno != 0) {
            *error_out = std::string{"connect: "} + std::strerror(last_errno);
        } else {
            *error_out = "no usable address";
        }
    }
    return false;
}

void HealthProber::observe_transition(BackendId id, bool /*ok*/, BackendState before,
                                      BackendState after) {
    if (before == after) {
        return;
    }
    if (before == BackendState::HEALTHY && after == BackendState::DEGRADED) {
        metrics_.success_to_degraded.fetch_add(1, std::memory_order_relaxed);
        LOG_WARN("health_prober: backend id=" << id << " transitioned HEALTHY -> DEGRADED");
    } else if (before == BackendState::DEGRADED && after == BackendState::HEALTHY) {
        metrics_.degraded_to_healthy.fetch_add(1, std::memory_order_relaxed);
        LOG_INFO("health_prober: backend id=" << id << " transitioned DEGRADED -> HEALTHY");
    }
}

std::size_t HealthProber::probe_round_for_test(const std::vector<BackendId>& ids,
                                               const ProbePredicate& predicate) {
    std::size_t ok_count = 0;
    for (BackendId id : ids) {
        const auto before = registry_.find(id);
        if (!before) {
            continue;
        }
        const BackendState before_state = before->state;
        metrics_.probes_attempted.fetch_add(1, std::memory_order_relaxed);
        const bool ok = predicate ? predicate(id) : false;
        if (ok) {
            registry_.report_success(id);
            metrics_.probes_succeeded.fetch_add(1, std::memory_order_relaxed);
        } else {
            registry_.report_failure(id);
            metrics_.probes_failed.fetch_add(1, std::memory_order_relaxed);
        }
        const auto after = registry_.find(id);
        const BackendState after_state = after ? after->state : before_state;
        observe_transition(id, ok, before_state, after_state);
        if (ok) {
            ++ok_count;
        }
    }
    return ok_count;
}

void HealthProber::run_probe_round(std::stop_token st) {
    if (st.stop_requested()) {
        return;
    }
    const auto backends = registry_.healthy_snapshot();
    for (const auto& backend : backends) {
        if (st.stop_requested()) {
            return;
        }
        if (backend.state == BackendState::DOWN) {
            continue;
        }
        const auto before_record = registry_.find(backend.id);
        if (!before_record) {
            continue;
        }
        const BackendState before_state = before_record->state;

        metrics_.probes_attempted.fetch_add(1, std::memory_order_relaxed);
        std::string err;
        const bool ok =
            probe_one(*before_record,
                      std::chrono::duration_cast<std::chrono::milliseconds>(probe_timeout_), &err);
        if (ok) {
            metrics_.probes_succeeded.fetch_add(1, std::memory_order_relaxed);
            registry_.report_success(backend.id);
        } else {
            metrics_.probes_failed.fetch_add(1, std::memory_order_relaxed);
            if (!err.empty()) {
                LOG_DEBUG("health_prober: probe failed for id=" << backend.id << ": " << err);
            }
            registry_.report_failure(backend.id);
        }
        const auto after_record = registry_.find(backend.id);
        const BackendState after_state = after_record ? after_record->state : before_state;
        observe_transition(backend.id, ok, before_state, after_state);
    }
}

void HealthProber::probe_loop(std::stop_token st) {
    while (!st.stop_requested()) {
        run_probe_round(st);
        if (st.stop_requested()) {
            break;
        }
        // Sleep in 100ms slices so `stop()` honours shutdown quickly.
        const int slice_ms = 100;
        const auto total_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(probe_interval_).count();
        for (auto elapsed = 0; elapsed < total_ms; elapsed += slice_ms) {
            if (st.stop_requested()) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(slice_ms));
        }
    }
}

} // namespace packet_engine
