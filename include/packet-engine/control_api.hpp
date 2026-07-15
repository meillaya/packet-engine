// SPDX-License-Identifier: MIT
//
// control_api.hpp -- Unix-socket REST/JSON control API for the packet engine.
//
// Design summary
// ==============
//
// `ControlApi` exposes a minimal HTTP/1.1-like surface over an AF_UNIX socket
// for control-plane operations:
//
//   * `GET  /rules`    -> 200 + current rules JSON
//   * `PUT  /rules`    -> parse, validate, atomic-swap RuleTableRegistry
//   * `GET  /backends` -> 200 + current backends JSON
//   * `PUT  /backends` -> update BackendRegistry (triggers Ketama rebuild via
//                         the registry's IKetamaRebuildCallback plumbing)
//   * `GET  /health`   -> 200 + {"status":"ok"}
//   * anything else    -> 404
//
// Threading
// ---------
//
// `start()` spawns a single `std::jthread` that owns the accept loop.  All
// per-connection work is performed synchronously inside the accept loop --
// no per-request thread creation, no external HTTP library.  The control
// plane is expected to issue requests at low rates (rule / backend set
// edits, health checks); per-packet work goes through the datapath, not
// this socket.
//
// Atomic rule reload
// ------------------
//
// `PUT /rules` parses the request body via `parse_rules_json`, builds a fresh
// `std::shared_ptr<const RuleTable>`, and publishes it through the supplied
// `RuleTableRegistry::swap`.  Workers reading the registry observe either
// the old or the new table -- never a torn snapshot.  The canonical
// C++20 `std::atomic<std::shared_ptr<T>>` pattern, mirroring the test
// stress pattern from `RuleTableTest::ConcurrentSwapsWhileWorkersLookUp`.
//
// Backend updates
// ---------------
//
// `PUT /backends` accepts a JSON array of `{id, authority, health_port}`
// objects.  Each entry is registered through `BackendRegistry::register_backend`,
// which forces the backend to `HEALTHY` and invokes the registry's Ketama
// rebuild callback (supplied by the caller; KetamaRing integrates via the
// `IKetamaRebuildCallback` interface in production).
//
// Socket lifecycle
// ----------------
//
// `start()` refuses an active owner and only replaces a verified stale Unix
// socket.  `stop()` unlinks the pathname only when its device/inode still
// match the socket created by this instance.  The destructor calls `stop()`.
//
// Note on naming
// --------------
//
// The plan task spec writes "Constructor: takes RuleTable&" but explicitly
// requires atomic shared_ptr swap semantics for the hot reload.  The atomic
// shared_ptr handle lives on `RuleTableRegistry` (Task 16); `RuleTable` is
// the immutable snapshot.  We therefore take a `RuleTableRegistry&` so that
// `swap()` actually publishes atomically.  The plan's other dependencies
// (`BackendRegistry`, `KetamaRing`) are unchanged.
//
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "packet-engine/backend_registry.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/rule_schema.hpp"
#include "packet-engine/rule_table.hpp"

namespace packet_engine {

class ControlApi {
  public:
    /// Default socket path used when the caller does not supply one.
    static constexpr const char* kDefaultSocketPath = "/tmp/packet-engine.sock";

    /// Construct the control API.  All references must outlive the
    /// `ControlApi` instance.  `socket_path` may be overridden (tests
    /// use an ephemeral path under `/tmp` keyed by `getpid()`).
    explicit ControlApi(RuleTableRegistry& rules, BackendRegistry& backends, KetamaRing& ketama,
                        std::string socket_path = kDefaultSocketPath);

    ~ControlApi();

    ControlApi(const ControlApi&) = delete;
    ControlApi& operator=(const ControlApi&) = delete;
    ControlApi(ControlApi&&) = delete;
    ControlApi& operator=(ControlApi&&) = delete;

    /// Open the socket, `bind`, `listen`, and spawn the accept thread.
    /// Returns false on any socket setup failure; on success the listener
    /// is live and serving requests.
    bool start();

    /// Stop the accept loop, join the thread, close the listener, and
    /// idempotently `unlink` the socket file.  Safe to call multiple
    /// times and from the destructor.
    void stop() noexcept;

    /// True between a successful `start()` and the next `stop()`.
    [[nodiscard]] bool running() const noexcept { return running_.load(std::memory_order_acquire); }

    /// Effective socket path (whatever the constructor was given).
    [[nodiscard]] const std::string& socket_path() const noexcept { return socket_path_; }

  private:
    void accept_loop(std::stop_token st);
    void handle_connection(int client_fd);

    // HTTP-like request handlers.  Each returns a fully-formed HTTP/1.1
    // response string (headers + body), ready to send back over the socket.
    [[nodiscard]] std::string handle_request(std::string_view method, std::string_view path,
                                             std::string_view body) const;

    // Build a fixed HTTP/1.1 response with status line, Content-Type,
    // Content-Length, and `Connection: close`.
    [[nodiscard]] static std::string build_http_response(int code, const char* content_type,
                                                         std::string_view body);

    // Atomic-shared-ptr handle for the canonical Rule schema snapshot
    // (used to serialize current rules for GET /rules).  Held alongside
    // the registry so that GET /rules can always re-emit the rules that
    // were last published.
    using RuleListPtr = std::shared_ptr<const std::vector<Rule>>;

    void publish_rule_table_(std::shared_ptr<const RuleTable> table, RuleListPtr rules);
    void unlink_owned_socket_() noexcept;

    RuleTableRegistry& rules_;
    BackendRegistry& backends_;
    std::string socket_path_;

    int listen_fd_ = -1;
    bool owns_socket_path_ = false;
    std::uint64_t socket_device_ = 0;
    std::uint64_t socket_inode_ = 0;
    std::atomic<bool> running_{false};
    std::jthread thread_;

    std::atomic<RuleListPtr> active_rules_{};
};

} // namespace packet_engine
