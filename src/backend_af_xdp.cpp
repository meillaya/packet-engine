// SPDX-License-Identifier: MIT
//
// backend_af_xdp.cpp -- AF_XDP UMEM + socket lifecycle implementation.
//
// Architecture
// ============
//
// The backend is intentionally thin: it owns four rings (fill, comp, rx,
// tx) and the two opaque libxdp handles (umem, xsk).  All libxdp calls
// go through `IXskOps*`, which the production `LibXdpOps` forwards to the
// symbols in `libxdp.so`.  Unit tests substitute their own `IXskOps` so
// no kernel involvement is required.
//
// RX/TX ring sizes match `FrameAllocator::DEFAULT_NUM_FRAMES` so that
// `populate_fill_ring()` can pre-fill the entire UMEM in one pass.

#include "packet-engine/backend_af_xdp.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>

#include "packet-engine/logger.hpp"

namespace packet_engine {

// ===========================================================================
// LibXdpOps -- production forwarder.  Thin shims around the C ABI of
// <xdp/xsk.h>.  Wrapped so the backend can be unit-tested without real
// XSK sockets.
// ===========================================================================

int LibXdpOps::umem_create(struct xsk_umem** umem, void* umem_area, std::uint64_t size,
                           struct xsk_ring_prod* fill, struct xsk_ring_cons* comp,
                           const struct xsk_umem_config* cfg) {
    return ::xsk_umem__create(umem, umem_area, size, fill, comp, cfg);
}

int LibXdpOps::umem_delete(struct xsk_umem* umem) { return ::xsk_umem__delete(umem); }

int LibXdpOps::umem_fd(const struct xsk_umem* umem) { return ::xsk_umem__fd(umem); }

int LibXdpOps::socket_create(struct xsk_socket** xsk, const char* ifname, std::uint32_t queue_id,
                             struct xsk_umem* umem, struct xsk_ring_cons* rx,
                             struct xsk_ring_prod* tx, const struct xsk_socket_config* cfg) {
    return ::xsk_socket__create(xsk, ifname, queue_id, umem, rx, tx, cfg);
}

void LibXdpOps::socket_delete(struct xsk_socket* xsk) { ::xsk_socket__delete(xsk); }

int LibXdpOps::socket_fd(const struct xsk_socket* xsk) { return ::xsk_socket__fd(xsk); }

int LibXdpOps::get_xdp_options(int fd, struct xdp_options* options, std::uint32_t* length) {
    if (options == nullptr || length == nullptr) {
        errno = EINVAL;
        return -1;
    }
    socklen_t native_length = static_cast<socklen_t>(*length);
    const int rc = ::getsockopt(fd, SOL_XDP, XDP_OPTIONS, options, &native_length);
    *length = static_cast<std::uint32_t>(native_length);
    return rc;
}

int LibXdpOps::notify_kernel_tx(int fd) {
    // Per xsk_fwd.c: sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0) is the
    // standard wake-up signal the kernel recognises.
    return ::sendto(fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
}

int LibXdpOps::update_xskmap(struct xsk_socket* xsk, int xsks_map_fd) {
    return ::xsk_socket__update_xskmap(xsk, xsks_map_fd);
}

int LibXdpOps::close_fd(int fd) {
    if (fd < 0)
        return 0;
    return ::close(fd);
}

// ===========================================================================
// AfXdpBackend
// ===========================================================================

namespace {

constexpr std::uint16_t kBindFlags = XDP_USE_NEED_WAKEUP;

} // namespace

AfXdpBackend::AfXdpBackend(FrameAllocator& allocator, std::string_view interface_name,
                           std::uint32_t queue_id, IXskOps* ops)
    : allocator_(allocator), ifname_(interface_name), queue_id_(queue_id), ops_(ops) {
    if (ops_ == nullptr) {
        default_ops_ = std::make_unique<LibXdpOps>();
        ops_ = default_ops_.get();
    }

    // Configure the UMEM rings so the whole NUM_FRAMES pool can be
    // reserved in one call (kernel rounds the sizes up to power-of-two).
    umem_cfg_.fill_size = NUM_FRAMES;
    umem_cfg_.comp_size = NUM_FRAMES;
    umem_cfg_.frame_size = FrameAllocator::DEFAULT_FRAME_SIZE;
    umem_cfg_.frame_headroom = 0;
    umem_cfg_.flags = 0;

    // Configure the socket: rx/tx rings sized to the fill ring; bind with
    // NEED_WAKEUP so the kernel signals when it actually wants a kick.
    xsk_cfg_.rx_size = NUM_FRAMES;
    xsk_cfg_.tx_size = NUM_FRAMES;
    xsk_cfg_.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg_.xdp_flags = 0;
    xsk_cfg_.bind_flags = kBindFlags;
}

AfXdpBackend::~AfXdpBackend() {
    // Destruction order: xsk first, then umem (the kernel will EBUSY
    // otherwise).  Errors during init may have left either half
    // unallocated; the nullptr guards cover both cases.
    if (xsk_ != nullptr) {
        ops_->socket_delete(xsk_);
        xsk_ = nullptr;
        xsk_fd_ = -1;
    }
    if (umem_ != nullptr) {
        ops_->umem_delete(umem_);
        umem_ = nullptr;
    }
    release_owned_offsets();
}

void AfXdpBackend::init() {
    if (umem_ != nullptr || xsk_ != nullptr) {
        throw std::runtime_error("AfXdpBackend: init() called twice without an intervening "
                                 "destruction; backend is single-shot per lifetime");
    }

    // 1) UMEM.  Backing storage is the FrameAllocator's mmap'd region;
    //    the two rings get filled in by libxdp on success.
    const int rc_umem = ops_->umem_create(&umem_, allocator_.base(),
                                          static_cast<std::uint64_t>(allocator_.total_size()),
                                          &fill_ring_, &comp_ring_, &umem_cfg_);
    if (rc_umem != 0) {
        const int err = errno;
        umem_ = nullptr;
        throw std::runtime_error("AfXdpBackend: xsk_umem__create failed: " +
                                 std::string(std::strerror(err)));
    }

    // 2) Socket.  Picks up the umem and fills in rx/tx rings.
    const int rc_xsk = ops_->socket_create(&xsk_, ifname_.c_str(), queue_id_, umem_, &rx_ring_,
                                           &tx_ring_, &xsk_cfg_);
    if (rc_xsk != 0) {
        const int err = errno;
        // Clean up the UMEM we just created so we do not leak.
        ops_->umem_delete(umem_);
        umem_ = nullptr;
        throw std::runtime_error("AfXdpBackend: xsk_socket__create failed (" + ifname_ + "/q" +
                                 std::to_string(queue_id_) + "): " + std::strerror(err));
    }

    xsk_fd_ = ops_->socket_fd(xsk_);
    if (xsk_fd_ < 0) {
        // Best-effort unwind so we are never left with a half-initialised
        // backend.
        ops_->socket_delete(xsk_);
        ops_->umem_delete(umem_);
        xsk_ = nullptr;
        umem_ = nullptr;
        throw std::runtime_error("AfXdpBackend: xsk_socket__fd returned < 0");
    }

    struct xdp_options options{};
    std::uint32_t options_length = sizeof(options);
    const int options_rc = ops_->get_xdp_options(xsk_fd_, &options, &options_length);
    constexpr std::uint32_t kFlagsEnd = offsetof(struct xdp_options, flags) + sizeof(options.flags);
    if (options_rc == 0 && options_length >= kFlagsEnd) {
        actual_mode_ =
            (options.flags & XDP_OPTIONS_ZEROCOPY) != 0 ? AfXdpMode::ZeroCopy : AfXdpMode::Copy;
    } else {
        actual_mode_ = AfXdpMode::Unknown;
    }

    try {
        populate_fill_ring();
    } catch (...) {
        ops_->socket_delete(xsk_);
        ops_->umem_delete(umem_);
        xsk_ = nullptr;
        umem_ = nullptr;
        xsk_fd_ = -1;
        release_owned_offsets();
        throw;
    }

    LOG_INFO(std::string("AfXdpBackend: initialised on ") + ifname_ +
             " q=" + std::to_string(queue_id_) + " fd=" + std::to_string(xsk_fd_) +
             " mode=" + std::string(actual_mode_name()) +
             " umem=" + std::to_string(allocator_.total_size()) + " bytes");
}

std::optional<std::uint64_t> AfXdpBackend::acquire_for_fill() {
    auto offset = allocator_.acquire();
    if (offset && owned_offset_count_ < NUM_FRAMES) {
        owned_offsets_[owned_offset_count_++] = *offset;
    }
    return offset;
}

bool AfXdpBackend::queue_for_fill(std::uint64_t address) noexcept {
    if (pending_fill_size_ == NUM_FRAMES) {
        return false;
    }
    const auto tail = (pending_fill_head_ + pending_fill_size_) % NUM_FRAMES;
    pending_fill_addresses_[tail] = address;
    ++pending_fill_size_;
    return true;
}

bool AfXdpBackend::dequeue_for_fill(std::uint64_t& address) noexcept {
    if (pending_fill_size_ == 0) {
        return false;
    }
    address = pending_fill_addresses_[pending_fill_head_];
    pending_fill_head_ = (pending_fill_head_ + 1u) % NUM_FRAMES;
    --pending_fill_size_;
    return true;
}

void AfXdpBackend::release_owned_offsets() noexcept {
    for (std::uint32_t index = 0; index < owned_offset_count_; ++index) {
        static_cast<void>(allocator_.release(owned_offsets_[index]));
    }
    owned_offset_count_ = 0;
}

void AfXdpBackend::populate_fill_ring() {
    // Reserve exactly NUM_FRAMES slots in one call.  `xsk_ring_prod__reserve`
    // either reserves the full requested count or returns 0 without a partial
    // state -- there is nothing to cancel.
    std::uint32_t idx = 0;
    const std::uint32_t reserved = ::xsk_ring_prod__reserve(&fill_ring_, NUM_FRAMES, &idx);
    if (reserved == 0) {
        throw std::runtime_error("AfXdpBackend: fill ring initially empty after xsk_umem__create");
    }

    for (std::uint32_t i = 0; i < reserved; ++i) {
        const auto offset = acquire_for_fill();
        if (!offset.has_value()) {
            throw std::runtime_error("AfXdpBackend: FrameAllocator exhausted during fill populate");
        }
        *::xsk_ring_prod__fill_addr(&fill_ring_, idx + i) = *offset;
    }

    ::xsk_ring_prod__submit(&fill_ring_, reserved);

    LOG_DEBUG(std::string("AfXdpBackend: fill ring populated with ") + std::to_string(reserved) +
              " / " + std::to_string(NUM_FRAMES) + " addresses");
}

std::uint32_t AfXdpBackend::recv_batch(PacketDescriptor* out, std::uint32_t max) {
    if (!is_initialised() || out == nullptr || max == 0)
        return 0;

    std::uint32_t idx = 0;
    const std::uint32_t rcvd = ::xsk_ring_cons__peek(&rx_ring_, max, &idx);
    if (rcvd == 0)
        return 0;

    // Stamp wall-clock monotonic once per batch; reading the per-descriptor
    // hardware timestamp would require XDP_RX_HW_TIMESTAMP support, which is
    // out of scope for the lifecycle in this task.
    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();

    for (std::uint32_t i = 0; i < rcvd; ++i) {
        const struct xdp_desc* d = ::xsk_ring_cons__rx_desc(&rx_ring_, idx + i);
        out[i].offset = d->addr;
        out[i].length = d->len;
        out[i].rx_queue_id = queue_id_;
        out[i].timestamp_ns = static_cast<std::uint64_t>(now_ns);
    }

    ::xsk_ring_cons__release(&rx_ring_, rcvd);
    return rcvd;
}

bool AfXdpBackend::needs_wakeup_rx() const noexcept {
    if (!is_initialised())
        return false;
    // AF_XDP backend uses rx_ring_'s flags field via inline helpers; the
    // libxdp convention is that RX wakeups are signalled by the kernel in
    // the rx ring's flags via XDP_RING_NEED_WAKEUP.  The inline
    // `xsk_ring_prod__needs_wakeup` is producer-only; the RX-side flags
    // must be read directly.
    if (rx_ring_.flags == nullptr)
        return true;
    return (*rx_ring_.flags & XDP_RING_NEED_WAKEUP) != 0;
}

bool AfXdpBackend::needs_wakeup_fill() const noexcept {
    if (!is_initialised())
        return false;
    // The FILL ring is a producer ring from the kernel's perspective
    // (userspace produces addresses; kernel consumes them), so the
    // libxdp-provided `xsk_ring_prod__needs_wakeup` is exactly the right
    // accessor.  It is a static inline that reads the ring's cached
    // flags -- zero virtual dispatch, branch-predictable.
    return ::xsk_ring_prod__needs_wakeup(&fill_ring_) != 0;
}

std::uint32_t AfXdpBackend::send_batch(const PacketDescriptor* pkts, std::uint32_t n) {
    if (!is_initialised() || pkts == nullptr || n == 0)
        return 0;

    const std::uint32_t reserved = reserve_tx(n);
    if (reserved == 0)
        return 0;
    return submit_reserved_tx(pkts, reserved);
}

std::uint32_t AfXdpBackend::reserve_tx(std::uint32_t n) {
    if (!is_initialised() || n == 0 || tx_reserved_ != 0)
        return 0;

    std::uint32_t idx = 0;
    const std::uint32_t reserved = ::xsk_ring_prod__reserve(&tx_ring_, n, &idx);
    if (reserved == 0)
        return 0;

    tx_reservation_index_ = idx;
    tx_reserved_ = reserved;
    return reserved;
}

std::uint32_t AfXdpBackend::submit_reserved_tx(const PacketDescriptor* pkts, std::uint32_t n) {
    if (pkts == nullptr || n == 0 || n != tx_reserved_)
        return 0;

    for (std::uint32_t i = 0; i < n; ++i) {
        struct xdp_desc* d = ::xsk_ring_prod__tx_desc(&tx_ring_, tx_reservation_index_ + i);
        d->addr = pkts[i].offset;
        d->len = pkts[i].length;
        // xdp_desc.options is reserved for XDP_TX_METADATA; leave 0 for now.
        d->options = 0;
    }

    ::xsk_ring_prod__submit(&tx_ring_, n);
    tx_reservation_index_ = 0;
    tx_reserved_ = 0;

    // Honour the wakeup contract: if the kernel is asleep and wants to be
    // poked, sendto() it.  Failing to do so would cause the TX ring to
    // stall.
    if (::xsk_ring_prod__needs_wakeup(&tx_ring_) && xsk_fd_ >= 0) {
        // Discard the result -- per xsk_fwd.c, an EAGAIN here is benign;
        // the next iteration of the worker loop will retry naturally.
        (void)ops_->notify_kernel_tx(xsk_fd_);
    }

    return n;
}

bool AfXdpBackend::needs_wakeup_tx() const noexcept {
    if (!is_initialised())
        return false;
    return ::xsk_ring_prod__needs_wakeup(&tx_ring_) != 0;
}

std::uint32_t AfXdpBackend::recycle_completions(std::uint32_t n) {
    if (!is_initialised() || n == 0)
        return 0;

    const std::size_t queued = completion_to_fill_.size_approx();
    if (queued >= NUM_FRAMES)
        return 0;
    const std::uint32_t space = NUM_FRAMES - static_cast<std::uint32_t>(queued);
    const std::uint32_t requested = std::min(n, space);

    std::uint32_t idx = 0;
    const std::uint32_t avail = ::xsk_ring_cons__peek(&comp_ring_, requested, &idx);
    if (avail == 0)
        return 0;

    std::uint32_t transferred = 0;
    for (; transferred < avail; ++transferred) {
        const std::uint64_t addr = *::xsk_ring_cons__comp_addr(&comp_ring_, idx + transferred);
        if (!completion_to_fill_.push(addr))
            break;
    }
    ::xsk_ring_cons__release(&comp_ring_, transferred);
    return transferred;
}

void AfXdpBackend::recycle_rx_addresses(const PacketDescriptor* pkts, std::uint32_t n) {
    if (!is_initialised() || pkts == nullptr || n == 0)
        return;
    for (std::uint32_t i = 0; i < n; ++i) {
        if (!queue_for_fill(pkts[i].offset)) {
            throw std::runtime_error{"AfXdpBackend: duplicate frame ownership overflow"};
        }
    }
    (void)service_fill_ring();
}

void AfXdpBackend::recycle_rx_addresses(const std::uint64_t* addresses, std::uint32_t n) {
    if (!is_initialised() || addresses == nullptr || n == 0)
        return;
    for (std::uint32_t i = 0; i < n; ++i) {
        if (!queue_for_fill(addresses[i])) {
            throw std::runtime_error{"AfXdpBackend: duplicate frame ownership overflow"};
        }
    }
    (void)service_fill_ring();
}

std::uint32_t AfXdpBackend::service_fill_ring() {
    if (!is_initialised())
        return 0;

    std::uint64_t completed = 0;
    while (pending_fill_size_ < NUM_FRAMES && completion_to_fill_.pop(completed)) {
        static_cast<void>(queue_for_fill(completed));
    }
    if (pending_fill_size_ == 0)
        return 0;

    const std::uint32_t requested = pending_fill_size_;
    std::uint32_t idx = 0;
    const std::uint32_t reserved = ::xsk_ring_prod__reserve(&fill_ring_, requested, &idx);
    if (reserved == 0)
        return 0;

    for (std::uint32_t i = 0; i < reserved; ++i) {
        std::uint64_t address = 0;
        static_cast<void>(dequeue_for_fill(address));
        *::xsk_ring_prod__fill_addr(&fill_ring_, idx + i) = address;
    }
    ::xsk_ring_prod__submit(&fill_ring_, reserved);
    return reserved;
}

} // namespace packet_engine
