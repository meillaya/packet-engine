// SPDX-License-Identifier: MIT
//
// mock_xsk.h -- libxdp abstraction mock for unit-testing AfXdpBackend.
//
// Why an `IXskOps` mock + in-process rings
// =========================================
//
// `libxdp` requires a real NIC and CAP_NET_RAW; we cannot use it in CI.
// Instead, `AfXdpBackend` calls libxdp through the `IXskOps` interface
// (see `backend_af_xdp.hpp`).  This header supplies `MockXskOps` -- an
// `IXskOps` implementation that allocates the kernel-shaped rings in
// process-local memory so the inline accessors in `<xdp/xsk.h>`
// (`xsk_ring_prod__reserve`, `xsk_ring_cons__peek`, etc.) can run
// verbatim against mock state.
//
// What the mock owns
// ------------------
//
// * A `MockXskRing` per ring (fill, comp, rx, tx).  Each mock ring
//   reserves a small buffer for `xdp_desc` / `__u64` entries plus an
//   `__u32 flags_page` to simulate the shared memory the kernel would
//   normally map in.  The kernel-side counters live in
//   `std::vector<std::uint32_t>` so that `xsk_ring_prod__reserve` etc.
//   read/write them via `__atomic_load_n` / `__atomic_store_n`, which
//   accept raw `std::uint32_t*`.
// * `notify_kernel_calls_`, `close_fd_calls_`, `deletion_order_`
//   counters so tests can assert the order of `socket_delete` vs
//   `umem_delete`, the number of notified wake-ups, etc.
//
// Header-only
// -----------
// The whole mock is inline; no `.cpp` to wire into the build.  This keeps
// the parallel Wave-2 glob at `tests/CMakeLists.txt` simple.
//
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <linux/if_xdp.h>
#include <xdp/xsk.h>

#include "packet-engine/backend_af_xdp.hpp"

namespace packet_engine::testing {

// ---------------------------------------------------------------------------
// Mock ring
//
// Each `MockXskRing` holds the producer/consumer counters that libxdp's
// inline helpers (`xsk_ring_prod__reserve`, `xsk_ring_cons__peek`, ...)
// operate on.  The struct passed to the AfXdpBackend gets its
// `producer`/`consumer`/`ring`/`flags` pointers pointing into this
// storage so the inline code can run unmodified against the mock.
// ---------------------------------------------------------------------------
struct MockXskRing {
    // Producer / consumer counters live in the kernel in real AF_XDP; we
    // allocate them in process memory and hand pointers to them through
    // the ring struct.
    std::vector<std::uint32_t> prod_storage{1};
    std::vector<std::uint32_t> cons_storage{1};
    std::uint32_t flags_value{0};

    // Two buffers: one for `__u64`-style fill/comp rings, one for
    // `xdp_desc`-style rx/tx rings.  We size them generously so any
    // reasonable test set fits.
    std::vector<std::uint64_t> addr_storage; // fill, comp
    std::vector<xdp_desc> desc_storage;      // rx, tx
    std::uint32_t size{0};
    std::uint32_t mask{0};
    bool is_producer{false};

    MockXskRing() {
        prod_storage[0] = 0;
        cons_storage[0] = 0;
    }
};

// ---------------------------------------------------------------------------
// MockXskOps
// ---------------------------------------------------------------------------
class MockXskOps final : public IXskOps {
  public:
    struct MockUmem {
        int fd = 999;
    };
    struct MockSocket {
        int fd = 42;
    };

    MockXskOps() = default;
    ~MockXskOps() override = default;

    // ---- Defaults shared with the header -------------------------------
    static constexpr std::uint32_t kFramesFallback = 4096;
    static constexpr std::uint32_t kRingDefault = 4096;

    // -----------------------------------------------------------------
    // IXskOps -- UMEM
    // -----------------------------------------------------------------
    int umem_create(struct xsk_umem** umem, void* umem_area, std::uint64_t size,
                    struct xsk_ring_prod* fill, struct xsk_ring_cons* comp,
                    const struct xsk_umem_config* cfg) override {
        (void)umem_area;
        (void)size;

        umem_storage_ = std::make_unique<MockUmem>();

        const std::uint32_t fill_sz = cfg ? cfg->fill_size : kFramesFallback;
        const std::uint32_t comp_sz = cfg ? cfg->comp_size : kFramesFallback;

        fill_ring_ = std::make_unique<MockXskRing>();
        comp_ring_ = std::make_unique<MockXskRing>();
        install_ring(*fill_ring_, fill, fill_sz, true, /*desc_layout=*/false);
        install_ring(*comp_ring_, comp, comp_sz, false, /*desc_layout=*/false);

        *umem = reinterpret_cast<struct xsk_umem*>(umem_storage_.get());
        ++umem_create_calls_;
        return 0;
    }

    int umem_delete(struct xsk_umem* umem) override {
        (void)umem;
        deletion_order_.emplace_back("umem_delete");
        umem_storage_.reset();
        fill_ring_.reset();
        comp_ring_.reset();
        return 0;
    }

    int umem_fd(const struct xsk_umem* umem) override {
        const auto* m = reinterpret_cast<const MockUmem*>(umem);
        return m ? m->fd : -1;
    }

    // -----------------------------------------------------------------
    // IXskOps -- Socket
    // -----------------------------------------------------------------
    int socket_create(struct xsk_socket** xsk, const char* ifname, std::uint32_t queue_id,
                      struct xsk_umem* umem, struct xsk_ring_cons* rx, struct xsk_ring_prod* tx,
                      const struct xsk_socket_config* cfg) override {
        (void)umem;
        (void)ifname;
        (void)queue_id;

        if (cfg != nullptr) {
            last_socket_config_ = *cfg;
        }

        socket_storage_ = std::make_unique<MockSocket>();
        rx_ring_ = std::make_unique<MockXskRing>();
        tx_ring_ = std::make_unique<MockXskRing>();
        install_ring(*rx_ring_, rx, kRingDefault, false, /*desc_layout=*/true);
        install_ring(*tx_ring_, tx, kRingDefault, true, /*desc_layout=*/true);

        *xsk = reinterpret_cast<struct xsk_socket*>(socket_storage_.get());
        ++socket_create_calls_;
        return 0;
    }

    void socket_delete(struct xsk_socket* xsk) override {
        (void)xsk;
        deletion_order_.emplace_back("socket_delete");
        socket_storage_.reset();
        rx_ring_.reset();
        tx_ring_.reset();
    }

    int socket_fd(const struct xsk_socket* xsk) override {
        const auto* s = reinterpret_cast<const MockSocket*>(xsk);
        return s ? s->fd : -1;
    }

    int get_xdp_options(int fd, struct xdp_options* options, std::uint32_t* length) override {
        ++get_xdp_options_calls_;
        last_xdp_options_fd_ = fd;
        if (xdp_options_rc_ != 0)
            return xdp_options_rc_;
        if (options == nullptr || length == nullptr)
            return -1;
        options->flags = xdp_options_flags_;
        *length = xdp_options_length_;
        return 0;
    }

    int notify_kernel_tx(int fd) override {
        (void)fd;
        ++notify_kernel_calls_;
        return 0;
    }

    int update_xskmap(struct xsk_socket* xsk, int xsks_map_fd) override {
        (void)xsk;
        last_xsks_map_fd_ = xsks_map_fd;
        ++update_xskmap_calls_;
        return 0;
    }

    int close_fd(int fd) override {
        (void)fd;
        ++close_fd_calls_;
        return 0;
    }

    // -----------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------

    /// Pre-load the RX ring buffer with `descs` and advance the kernel-side
    /// producer pointer so the next `xsk_ring_cons__peek` returns them.
    void preload_rx(std::vector<xdp_desc> descs) {
        if (!rx_ring_)
            return;
        const std::uint32_t n =
            std::min<std::uint32_t>(static_cast<std::uint32_t>(descs.size()), rx_ring_->size);
        if (n == 0)
            return;
        std::memcpy(rx_ring_->desc_storage.data(), descs.data(), n * sizeof(xdp_desc));
        rx_ring_->prod_storage[0] = n;
    }

    /// Pre-load the completion ring with `addrs` and advance the
    /// kernel-side producer so the next `xsk_ring_cons__peek(comp)` returns
    /// them.
    void preload_completions(std::vector<std::uint64_t> addrs) {
        if (!comp_ring_)
            return;
        const std::uint32_t n =
            std::min<std::uint32_t>(static_cast<std::uint32_t>(addrs.size()), comp_ring_->size);
        if (n == 0)
            return;
        std::memcpy(comp_ring_->addr_storage.data(), addrs.data(), n * sizeof(std::uint64_t));
        comp_ring_->prod_storage[0] = n;
    }

    std::uint32_t produce_rx_from_fill(std::uint32_t requested, std::uint32_t length = 128) {
        if (!fill_ring_ || !rx_ring_)
            return 0;

        const std::uint32_t fill_available =
            fill_ring_->prod_storage[0] - fill_ring_->cons_storage[0];
        const std::uint32_t rx_available =
            rx_ring_->size - (rx_ring_->prod_storage[0] - rx_ring_->cons_storage[0]);
        const std::uint32_t count = std::min(requested, std::min(fill_available, rx_available));

        const std::uint32_t fill_start = fill_ring_->cons_storage[0];
        const std::uint32_t rx_start = rx_ring_->prod_storage[0];
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint64_t addr =
                fill_ring_->addr_storage[(fill_start + i) & fill_ring_->mask];
            xdp_desc& desc = rx_ring_->desc_storage[(rx_start + i) & rx_ring_->mask];
            desc.addr = addr;
            desc.len = length;
            desc.options = 0;
            consumed_fill_addresses_.push_back(addr);
        }
        fill_ring_->cons_storage[0] += count;
        rx_ring_->prod_storage[0] += count;
        return count;
    }

    /// Toggle the wakeup flag the TX ring will advertise via
    /// `xsk_ring_prod__needs_wakeup`.
    void set_tx_needs_wakeup(bool v) {
        tx_needs_wakeup_ = v;
        if (tx_ring_) {
            if (v)
                tx_ring_->flags_value |= XDP_RING_NEED_WAKEUP;
            else
                tx_ring_->flags_value &= ~XDP_RING_NEED_WAKEUP;
        }
    }

    /// Toggle the wakeup flag the FILL ring will advertise via
    /// `xsk_ring_prod__needs_wakeup`.  Used by tests that need to drive
    /// the RX loop's "no work + wakeup requested" path.
    void set_fill_needs_wakeup(bool v) {
        fill_needs_wakeup_ = v;
        if (fill_ring_) {
            if (v)
                fill_ring_->flags_value |= XDP_RING_NEED_WAKEUP;
            else
                fill_ring_->flags_value &= ~XDP_RING_NEED_WAKEUP;
        }
    }

    void set_xdp_options_result(int rc, std::uint32_t length, std::uint32_t flags) {
        xdp_options_rc_ = rc;
        xdp_options_length_ = length;
        xdp_options_flags_ = flags;
    }

    /// Snapshot the descriptor payloads visible in the tx ring (test
    /// inspection helper).
    const std::vector<xdp_desc>& tx_desc_storage() const {
        static const std::vector<xdp_desc> kEmpty;
        return tx_ring_ ? tx_ring_->desc_storage : kEmpty;
    }

    std::uint32_t tx_producer_index() const { return tx_ring_ ? tx_ring_->prod_storage[0] : 0; }

    std::uint32_t fill_producer_index() const {
        return fill_ring_ ? fill_ring_->prod_storage[0] : 0;
    }

    std::uint32_t fill_consumer_index() const {
        return fill_ring_ ? fill_ring_->cons_storage[0] : 0;
    }

    std::uint32_t completion_consumer_index() const {
        return comp_ring_ ? comp_ring_->cons_storage[0] : 0;
    }

    const std::vector<std::uint64_t>& consumed_fill_addresses() const noexcept {
        return consumed_fill_addresses_;
    }

    // -----------------------------------------------------------------
    // Observers
    // -----------------------------------------------------------------
    int umem_create_calls() const noexcept { return umem_create_calls_; }
    int socket_create_calls() const noexcept { return socket_create_calls_; }
    int notify_kernel_calls() const noexcept { return notify_kernel_calls_; }
    int update_xskmap_calls() const noexcept { return update_xskmap_calls_; }
    int last_xsks_map_fd() const noexcept { return last_xsks_map_fd_; }
    int close_fd_calls() const noexcept { return close_fd_calls_; }
    int get_xdp_options_calls() const noexcept { return get_xdp_options_calls_; }
    int last_xdp_options_fd() const noexcept { return last_xdp_options_fd_; }
    std::uint32_t socket_libxdp_flags() const noexcept { return last_socket_config_.libxdp_flags; }
    const std::vector<std::string>& deletion_order() const noexcept { return deletion_order_; }
    bool has_umem() const noexcept { return umem_storage_ != nullptr; }
    bool has_socket() const noexcept { return socket_storage_ != nullptr; }

  private:
    // Universal ring builder shared by both xsk_ring_prod and xsk_ring_cons.
    template <typename RingT>
    static void install_ring_impl(MockXskRing& mock, RingT* r, std::uint32_t requested_size,
                                  bool producer, bool desc_layout) {
        std::uint32_t pow2 = 1;
        while (pow2 < requested_size && pow2 < 0x8000u)
            pow2 <<= 1;
        const std::uint32_t size = std::max<std::uint32_t>(pow2, 64u);

        mock.size = size;
        mock.mask = size - 1u;
        mock.is_producer = producer;

        if (desc_layout) {
            mock.desc_storage.assign(size, xdp_desc{});
        } else {
            mock.addr_storage.assign(size, std::uint64_t{0});
        }

        // Producer rings start with cached_cons = size so the first
        // reserve returns `size` without a refresh; consumer rings start
        // with cached_cons = 0 (kernel-side starts at 0).
        r->cached_prod = 0;
        r->cached_cons = producer ? size : 0u;
        r->mask = size - 1u;
        r->size = size;
        r->producer = mock.prod_storage.data();
        r->consumer = mock.cons_storage.data();
        r->ring = desc_layout ? static_cast<void*>(mock.desc_storage.data())
                              : static_cast<void*>(mock.addr_storage.data());
        r->flags = &mock.flags_value;
        mock.flags_value = 0;
    }

    static void install_ring(MockXskRing& mock, struct xsk_ring_prod* r, std::uint32_t size,
                             bool producer, bool desc_layout) {
        install_ring_impl(mock, r, size, producer, desc_layout);
    }
    static void install_ring(MockXskRing& mock, struct xsk_ring_cons* r, std::uint32_t size,
                             bool producer, bool desc_layout) {
        install_ring_impl(mock, r, size, producer, desc_layout);
    }

    // Owned state -------------------------------------------------------
    std::unique_ptr<MockUmem> umem_storage_;
    std::unique_ptr<MockSocket> socket_storage_;
    std::unique_ptr<MockXskRing> fill_ring_;
    std::unique_ptr<MockXskRing> comp_ring_;
    std::unique_ptr<MockXskRing> rx_ring_;
    std::unique_ptr<MockXskRing> tx_ring_;

    // Test knobs --------------------------------------------------------
    int umem_create_calls_{0};
    int socket_create_calls_{0};
    int notify_kernel_calls_{0};
    int update_xskmap_calls_{0};
    int last_xsks_map_fd_{-1};
    int close_fd_calls_{0};
    int get_xdp_options_calls_{0};
    int last_xdp_options_fd_{-1};
    int xdp_options_rc_{0};
    std::uint32_t xdp_options_length_{sizeof(struct xdp_options)};
    std::uint32_t xdp_options_flags_{0};
    bool tx_needs_wakeup_{false};
    bool fill_needs_wakeup_{false};
    std::vector<std::string> deletion_order_;
    struct xsk_socket_config last_socket_config_{};
    std::vector<std::uint64_t> consumed_fill_addresses_;
};

} // namespace packet_engine::testing
