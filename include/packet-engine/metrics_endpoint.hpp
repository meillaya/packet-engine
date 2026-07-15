#pragma once

#include "packet-engine/prometheus_client.hpp"

#include <atomic>
#include <thread>

namespace pe {

//
// Minimal TCP Prometheus /metrics endpoint.
//
// Listens on a configurable TCP port (default 9090) and serves:
//   GET /metrics  -> 200 + Prometheus text exposition from the registry
//   GET /health   -> 200 + {"status":"ok"}
//   anything else -> 404
//
// Implementation uses raw BSD sockets (socket/bind/listen/accept) and a
// single acceptor jthread.  Per-connection work is handled synchronously with
// a bounded I/O deadline, so an idle peer cannot starve later scrapes.
//

class MetricsEndpoint {
  public:
    MetricsEndpoint(MetricsRegistry& registry, int port = 9090);
    ~MetricsEndpoint();

    MetricsEndpoint(const MetricsEndpoint&) = delete;
    MetricsEndpoint& operator=(const MetricsEndpoint&) = delete;
    MetricsEndpoint(MetricsEndpoint&&) = delete;
    MetricsEndpoint& operator=(MetricsEndpoint&&) = delete;

    // Start the acceptor thread.  Returns false if bind/listen fails.
    bool start();

    // Stop accepting and join the thread.  Called by destructor.
    void stop() noexcept;

    int port() const noexcept { return port_; }
    bool running() const noexcept { return running_.load(std::memory_order_acquire); }

  private:
    void accept_loop(std::stop_token st);
    void handle_connection(int client_fd);

    static std::string build_http_response(int code, const char* content_type,
                                           std::string_view body);

    MetricsRegistry& registry_;
    int port_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::jthread thread_;
};

} // namespace pe
