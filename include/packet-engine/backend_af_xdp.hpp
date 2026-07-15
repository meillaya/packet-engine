// SPDX-License-Identifier: MIT
//
// backend_af_xdp.hpp -- AF_XDP UMEM + socket lifecycle for the packet engine.
//
// Design
// ======
//
// `AfXdpBackend` owns the lifecycle of an AF_XDP UMEM region and a single
// `xsk_socket` bound to one (interface, queue_id) pair.  The UMEM bytes
// themselves live in a caller-supplied `FrameAllocator` -- the backend
// never owns or unmaps the region: it only plumbs it through libxdp.
//
// All libxdp entry points are funnelled through the `IXskOps` abstract
// interface.  In production the `LibXdpOps` implementation calls the real
// `<xdp/xsk.h>` functions; in unit tests a GoogleMock-friendly fake
// (`tests/mocks/mock_xsk.h`) substitutes so the entire backend lifecycle
// can be exercised without root, without a real NIC, and without
// `LIBXDP_OBJECT_PATH` set.
//
// Threading
// =========
//
// The hot RX/TX rings are single-producer / single-consumer.  The backend
// does not internally serialise calls to `recv_batch()` / `send_batch()` /
// `recycle_completions()`; the caller (worker thread) is expected to call
// each one at most once per scheduler tick.  Construction, `init()`, and
// destruction are single-threaded.
//
//
// Lifetimes
// =========
//
// * Constructor: holds references to the `FrameAllocator` and configures
//   `bind_flags` (XDP_USE_NEED_WAKEUP by default); does **not** allocate.
// * `init()`: calls `xsk_umem__create` + `xsk_socket__create` and populates
//   the fill ring from `FrameAllocator::acquire()`.
// * Destructor: `xsk_socket__delete` THEN `xsk_umem__delete` (order is
//   required by the kernel).  Acquired frames that were never recycled
//   are returned to the `FrameAllocator` so the bitmap stays consistent.
//
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include <xdp/xsk.h>

#include "packet-engine/frame_allocator.hpp"
#include "packet-engine/spsc_ring.hpp"
#include "packet-engine/types.hpp"

namespace packet_engine {

enum class AfXdpMode : std::uint8_t {
    Unknown,
    Copy,
    ZeroCopy,
};

// Forward declarations of the libxdp opaque types so the public header
// does not need to drag in the entire libbpf/libxdp dependency tree.
// `struct xsk_umem` / `struct xsk_socket` are already forward-declared by
// `<xdp/xsk.h>` above; we only redeclare `IXskOps` here.

// ---------------------------------------------------------------------------
// Abstract libxdp operations interface.
//
// Every libxdp call site that the backend uses is exposed as a pure virtual
// method.  The production backend (`LibXdpOps`) forwards to the symbols in
// `libxdp.so`; tests substitute a mock implementation that synthesizes
// kernel-shaped rings in process-local memory.
// ---------------------------------------------------------------------------
class IXskOps {
  public:
    virtual ~IXskOps() = default;

    // ---- UMEM (libxdp) --------------------------------------------------
    virtual int umem_create(struct xsk_umem** umem, void* umem_area, std::uint64_t size,
                            struct xsk_ring_prod* fill, struct xsk_ring_cons* comp,
                            const struct xsk_umem_config* cfg) = 0;
    virtual int umem_delete(struct xsk_umem* umem) = 0;
    virtual int umem_fd(const struct xsk_umem* umem) = 0;

    // ---- Socket (libxdp) ------------------------------------------------
    virtual int socket_create(struct xsk_socket** xsk, const char* ifname, std::uint32_t queue_id,
                              struct xsk_umem* umem, struct xsk_ring_cons* rx,
                              struct xsk_ring_prod* tx, const struct xsk_socket_config* cfg) = 0;
    virtual void socket_delete(struct xsk_socket* xsk) = 0;
    virtual int socket_fd(const struct xsk_socket* xsk) = 0;
    virtual int get_xdp_options(int fd, struct xdp_options* options, std::uint32_t* length) = 0;

    // ---- XSKMAP update (libxdp) ----------------------------------------
    //
    // Register `xsk` in the BPF `xsks_map` (a BPF_MAP_TYPE_XSKMAP) so that
    // the XDP datapath can redirect packets into this socket.  Production
    // wraps `xsk_socket__update_xskmap`.  Tests stub this to a counter.
    virtual int update_xskmap(struct xsk_socket* xsk, int xsks_map_fd) = 0;

    // ---- Syscall hooks --------------------------------------------------
    //
    // Wake the kernel when `xsk_ring_prod__needs_wakeup` indicates that
    // userland owes it a kick.  Production wraps `sendto(fd, NULL, 0,
    // MSG_DONTWAIT, NULL, 0)`.  Tests stub this to a counter.
    virtual int notify_kernel_tx(int fd) = 0;

    // Close an OS file descriptor the backend obtained from libxdp.
    // Production wraps ::close(); tests can leave it as a no-op.
    virtual int close_fd(int fd) = 0;
};

// Concrete libxdp-backed implementation of `IXskOps`.
// The backend owns one of these by default.
class LibXdpOps final : public IXskOps {
  public:
    int umem_create(struct xsk_umem** umem, void* umem_area, std::uint64_t size,
                    struct xsk_ring_prod* fill, struct xsk_ring_cons* comp,
                    const struct xsk_umem_config* cfg) override;

    int umem_delete(struct xsk_umem* umem) override;

    int umem_fd(const struct xsk_umem* umem) override;

    int socket_create(struct xsk_socket** xsk, const char* ifname, std::uint32_t queue_id,
                      struct xsk_umem* umem, struct xsk_ring_cons* rx, struct xsk_ring_prod* tx,
                      const struct xsk_socket_config* cfg) override;

    void socket_delete(struct xsk_socket* xsk) override;

    int socket_fd(const struct xsk_socket* xsk) override;

    int get_xdp_options(int fd, struct xdp_options* options, std::uint32_t* length) override;

    int notify_kernel_tx(int fd) override;

    int update_xskmap(struct xsk_socket* xsk, int xsks_map_fd) override;

    int close_fd(int fd) override;
};

// ---------------------------------------------------------------------------
// AfXdpBackend
// ---------------------------------------------------------------------------
class AfXdpBackend {
  public:
    /// Number of frames in the UMEM. Matches FrameAllocator::DEFAULT_NUM_FRAMES.
    /// Used both to size the fill ring and to know how many addresses the
    /// fill ring should hold at steady state.
    static constexpr std::uint32_t NUM_FRAMES = FrameAllocator::DEFAULT_NUM_FRAMES;

    /// Construct the backend without allocating any kernel resources.
    ///
    /// @param allocator     Owns the UMEM region.  Must outlive the backend.
    /// @param interface_name Network interface to bind to (e.g. "eth0",
    ///                       "veth0").  Copied internally so the caller's
    ///                       buffer can go out of scope.
    /// @param queue_id      RX/TX queue index inside the interface.
    /// @param ops           Dependency injection point for libxdp calls.
    ///                       When nullptr, a `LibXdpOps` instance is used.
    explicit AfXdpBackend(FrameAllocator& allocator, std::string_view interface_name,
                          std::uint32_t queue_id, IXskOps* ops = nullptr);

    ~AfXdpBackend();

    AfXdpBackend(const AfXdpBackend&) = delete;
    AfXdpBackend& operator=(const AfXdpBackend&) = delete;

    // Non-movable: owns raw pointers, multiple kernel resources.
    AfXdpBackend(AfXdpBackend&&) = delete;
    AfXdpBackend& operator=(AfXdpBackend&&) = delete;

    /// Allocate kernel-side UMEM + socket and pre-fill the fill ring.
    ///
    /// Throws `std::runtime_error` on any libxdp failure.  Idempotent only
    /// in the cold (already-initialised) sense; calling twice fails the
    /// second time with a "already initialised" error.
    void init();

    // ---------------------------------------------------------------------
    // RX path
    // ---------------------------------------------------------------------

    /// Drain up to `max` received packet descriptors into `out`.
    /// Returns the number actually written into `out`.  Zero means
    /// "nothing to read; the kernel did not deliver any frames".
    [[nodiscard]] std::uint32_t recv_batch(PacketDescriptor* out, std::uint32_t max);

    /// Whether `recv_batch()` would currently sleep, i.e. the kernel has
    /// no work for us and `poll()` / `epoll()` should block.  The runner
    /// is expected to honour this flag rather than spin.
    [[nodiscard]] bool needs_wakeup_rx() const noexcept;

    /// Whether the fill ring's producer is flagged with `XDP_RING_NEED_WAKEUP`.
    /// When the bind was created with `XDP_USE_NEED_WAKEUP`, the kernel sets
    /// this on the FILL ring whenever it has consumed a fill address but
    /// would still be waiting for a user-space kick.  The RX loop consults
    /// this flag on idle ticks and `poll()`s the XSK fd when it is set --
    /// strictly cheaper than spinning `recv_batch()` in a tight loop.
    [[nodiscard]] bool needs_wakeup_fill() const noexcept;

    // ---------------------------------------------------------------------
    // TX path
    // ---------------------------------------------------------------------

    /// Submit up to `n` outgoing packet descriptors into the TX ring.
    /// Returns the number actually submitted (capped by free TX slots).
    /// May invoke `sendto()` to wake the kernel when `needs_wakeup_tx()`
    /// is true after the submission.
    [[nodiscard]] std::uint32_t send_batch(const PacketDescriptor* pkts, std::uint32_t n);

    [[nodiscard]] std::uint32_t reserve_tx(std::uint32_t n);
    [[nodiscard]] std::uint32_t submit_reserved_tx(const PacketDescriptor* pkts, std::uint32_t n);

    /// Whether the kernel asked us to send a wake-up after `send_batch`.
    [[nodiscard]] bool needs_wakeup_tx() const noexcept;

    // ---------------------------------------------------------------------
    // Completions (recycle TX frames back to UMEM)
    // ---------------------------------------------------------------------

    /// Pop up to `n` completed TX addresses from the completion ring and
    /// transfer them to the RX-owned FILL producer through an SPSC queue.
    [[nodiscard]] std::uint32_t recycle_completions(std::uint32_t n);

    void recycle_rx_addresses(const PacketDescriptor* pkts, std::uint32_t n);
    void recycle_rx_addresses(const std::uint64_t* addresses, std::uint32_t n);
    [[nodiscard]] std::uint32_t service_fill_ring();

    // ---------------------------------------------------------------------
    // Observers (used by metrics + tests)
    // ---------------------------------------------------------------------

    [[nodiscard]] bool is_initialised() const noexcept { return umem_ != nullptr; }
    [[nodiscard]] const std::string& interface_name() const noexcept { return ifname_; }
    [[nodiscard]] std::uint32_t queue_id() const noexcept { return queue_id_; }
    [[nodiscard]] int xsk_fd() const noexcept { return xsk_fd_; }
    [[nodiscard]] struct xsk_socket* xsk() const noexcept { return xsk_; }
    [[nodiscard]] FrameAllocator& allocator() const noexcept { return allocator_; }
    [[nodiscard]] AfXdpMode actual_mode() const noexcept { return actual_mode_; }
    [[nodiscard]] std::string_view actual_mode_name() const noexcept {
        switch (actual_mode_) {
        case AfXdpMode::Unknown:
            return "unknown";
        case AfXdpMode::Copy:
            return "copy";
        case AfXdpMode::ZeroCopy:
            return "zero-copy";
        }
        return "unknown";
    }

  private:
    // Populate the fill ring with addresses for NUM_FRAMES frames obtained
    // from the allocator.  Called once from `init()`.
    void populate_fill_ring();

    // Acquire-and-track helper.  Holds the offsets so the destructor can
    // recycle any that were never returned via `recycle_completions()`.
    std::optional<std::uint64_t> acquire_for_fill();
    [[nodiscard]] bool queue_for_fill(std::uint64_t address) noexcept;
    [[nodiscard]] bool dequeue_for_fill(std::uint64_t& address) noexcept;
    void release_owned_offsets() noexcept;

    // Construction-time references / config.
    FrameAllocator& allocator_;
    std::string ifname_;
    std::uint32_t queue_id_;
    std::unique_ptr<IXskOps> owned_ops_; // created when ops==nullptr
    IXskOps* ops_;                       // never null after ctor

    // Lazy-created default ops when no DI was supplied.
    std::unique_ptr<LibXdpOps> default_ops_;

    // xsk state.
    struct xsk_umem* umem_{nullptr};
    struct xsk_socket* xsk_{nullptr};
    int xsk_fd_{-1};
    AfXdpMode actual_mode_{AfXdpMode::Unknown};

    // Rings (storage is owned by libxdp on production; mocks own it).
    struct xsk_ring_prod fill_ring_{};
    struct xsk_ring_cons comp_ring_{};
    struct xsk_ring_cons rx_ring_{};
    struct xsk_ring_prod tx_ring_{};

    SpscRing<std::uint64_t, NUM_FRAMES> completion_to_fill_;
    std::array<std::uint64_t, NUM_FRAMES> pending_fill_addresses_{};
    std::uint32_t pending_fill_head_{0};
    std::uint32_t pending_fill_size_{0};
    std::array<std::uint64_t, NUM_FRAMES> owned_offsets_{};
    std::uint32_t owned_offset_count_{0};

    std::uint32_t tx_reservation_index_{0};
    std::uint32_t tx_reserved_{0};

    // Configurations passed to libxdp.
    struct xsk_umem_config umem_cfg_{};
    struct xsk_socket_config xsk_cfg_{};
};

} // namespace packet_engine
