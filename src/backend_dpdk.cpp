// SPDX-License-Identifier: MIT

#ifdef HAVE_DPDK

#include "packet-engine/backend_dpdk.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "packet-engine/logger.hpp"

namespace packet_engine {

namespace {

// Maximum number of RX packets we can hold outstanding in
// `pending_rx_mbufs_` before `release_pending()` must drain.  Matches the
// class constant so the bound is enforced regardless of `recv_batch` max.
constexpr std::uint32_t kPendingCap = DpdkBackend::NUM_MBUFS;
rte_mbuf* const kDeletedMbuf = reinterpret_cast<rte_mbuf*>(static_cast<std::uintptr_t>(1));

std::size_t ownership_hash(const rte_mbuf* mbuf, std::size_t slots) noexcept {
    const auto value = static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(mbuf) >> 6u);
    return (value * static_cast<std::size_t>(0x9e3779b97f4a7c15ULL)) & (slots - 1u);
}

} // namespace

// ===========================================================================
// Construction / destruction
// ===========================================================================

DpdkBackend::DpdkBackend(std::uint16_t port_id, std::uint16_t queue_id,
                         std::string_view pool_name) noexcept
    : port_id_(port_id), queue_id_(queue_id), pool_name_(pool_name) {
    pending_rx_mbufs_.reserve(NUM_MBUFS);
    ownership_slots_ = std::make_unique<std::array<OwnershipSlot, kOwnershipSlots>>();
    tx_scratch_.reserve(BATCH_SIZE);
}

DpdkBackend::DpdkBackend(std::string_view port_name, std::uint16_t queue_id,
                         std::string_view pool_name) noexcept
    : queue_id_(queue_id), port_name_(port_name), pool_name_(pool_name),
      select_port_by_name_(true) {
    pending_rx_mbufs_.reserve(NUM_MBUFS);
    ownership_slots_ = std::make_unique<std::array<OwnershipSlot, kOwnershipSlots>>();
    tx_scratch_.reserve(BATCH_SIZE);
}

DpdkBackend::~DpdkBackend() { cleanup(); }

void DpdkBackend::cleanup() noexcept {
    if (!eal_initialised_) {
        return;
    }

    if (port_started_) {
        (void)rte_eth_dev_stop(port_id_);
        port_started_ = false;
    }
    if (port_configured_) {
        (void)rte_eth_dev_close(port_id_);
        port_configured_ = false;
    }
    if (!pending_rx_mbufs_.empty()) {
        rte_pktmbuf_free_bulk(pending_rx_mbufs_.data(),
                              static_cast<unsigned int>(pending_rx_mbufs_.size()));
        pending_rx_mbufs_.clear();
    }
    if (ownership_slots_) {
        ownership_slots_->fill({});
    }
    if (mbuf_pool_ != nullptr) {
        rte_mempool_free(mbuf_pool_);
        mbuf_pool_ = nullptr;
    }
    std::filesystem::path runtime_dir;
    if (const char* path = rte_eal_get_runtime_dir(); path != nullptr) {
        runtime_dir = path;
    }
    (void)rte_eal_cleanup();
    if (!runtime_dir.empty() && runtime_dir.filename() != "." && runtime_dir.filename() != ".." &&
        runtime_dir.parent_path().filename() == "dpdk") {
        std::error_code error;
        std::filesystem::remove_all(runtime_dir, error);
    }
    eal_initialised_ = false;
}

// ===========================================================================
// init
// ===========================================================================

void DpdkBackend::init(int argc, char** argv) {
    if (eal_initialised_) {
        throw std::runtime_error(
            "DpdkBackend: init() called twice without intervening destruction; "
            "backend is single-shot per lifetime");
    }
    if (argc <= 0 || argv == nullptr || argv[0] == nullptr || argv[0][0] == '\0') {
        throw std::runtime_error("DpdkBackend: EAL argv must start with a non-empty program name");
    }
    if (queue_id_ != 0) {
        throw std::runtime_error("DpdkBackend: v1 supports only queue 0, requested queue " +
                                 std::to_string(queue_id_));
    }
    if (pool_name_.empty()) {
        throw std::runtime_error("DpdkBackend: mempool name must not be empty");
    }
    if (select_port_by_name_ && port_name_.empty()) {
        throw std::runtime_error("DpdkBackend: port name must not be empty");
    }

    try {
        const int eal_rc = rte_eal_init(argc, argv);
        if (eal_rc < 0) {
            const std::string reason = (rte_errno != 0)
                                           ? std::string("rte_errno=") + std::to_string(rte_errno)
                                           : std::string("rc=") + std::to_string(eal_rc);
            throw std::runtime_error("DpdkBackend: rte_eal_init failed: " + reason);
        }
        eal_initialised_ = true;
        LOG_INFO("DpdkBackend: rte_eal_init consumed " + std::to_string(eal_rc) + " argv entries");

        if (select_port_by_name_) {
            std::uint16_t resolved_port = RTE_MAX_ETHPORTS;
            if (rte_eth_dev_get_port_by_name(port_name_.c_str(), &resolved_port) != 0) {
                throw std::runtime_error("DpdkBackend: DPDK port not found by name: " + port_name_);
            }
            port_id_ = resolved_port;
        }
        if (port_id_ >= RTE_MAX_ETHPORTS || !rte_eth_dev_is_valid_port(port_id_)) {
            throw std::runtime_error("DpdkBackend: invalid DPDK port id " +
                                     std::to_string(port_id_));
        }

        int socket_id = rte_eth_dev_socket_id(port_id_);
        if (socket_id < 0) {
            socket_id = static_cast<int>(rte_socket_id());
        }

        mbuf_pool_ = rte_pktmbuf_pool_create(pool_name_.c_str(), static_cast<unsigned>(NUM_MBUFS),
                                             static_cast<unsigned>(MBUF_CACHE_SIZE), 0,
                                             static_cast<std::uint16_t>(MBUF_DATA_ROOM), socket_id);
        if (mbuf_pool_ == nullptr) {
            throw std::runtime_error("DpdkBackend: rte_pktmbuf_pool_create failed for \"" +
                                     pool_name_ + "\" (rte_errno=" + std::to_string(rte_errno) +
                                     ")");
        }

        rte_eth_dev_info dev_info{};
        const int info_rc = rte_eth_dev_info_get(port_id_, &dev_info);
        if (info_rc != 0) {
            throw std::runtime_error("DpdkBackend: rte_eth_dev_info_get failed for port " +
                                     std::to_string(port_id_) + " (rc=" + std::to_string(info_rc) +
                                     ")");
        }

        rte_eth_conf port_conf{};
        constexpr std::uint16_t queue_count = 1;
        const int configure_rc =
            rte_eth_dev_configure(port_id_, queue_count, queue_count, &port_conf);
        if (configure_rc != 0) {
            throw std::runtime_error("DpdkBackend: rte_eth_dev_configure failed for port " +
                                     std::to_string(port_id_) +
                                     " (rc=" + std::to_string(configure_rc) + ")");
        }
        port_configured_ = true;

        std::uint16_t rx_descriptors = 1024;
        std::uint16_t tx_descriptors = 1024;
        const int adjust_rc =
            rte_eth_dev_adjust_nb_rx_tx_desc(port_id_, &rx_descriptors, &tx_descriptors);
        if (adjust_rc != 0) {
            throw std::runtime_error("DpdkBackend: descriptor adjustment failed for port " +
                                     std::to_string(port_id_) +
                                     " (rc=" + std::to_string(adjust_rc) + ")");
        }

        rte_eth_rxconf rx_conf = dev_info.default_rxconf;
        rte_eth_txconf tx_conf = dev_info.default_txconf;
        rx_conf.offloads = 0;
        tx_conf.offloads = 0;

        const int rx_rc = rte_eth_rx_queue_setup(port_id_, queue_id_, rx_descriptors, socket_id,
                                                 &rx_conf, mbuf_pool_);
        if (rx_rc != 0) {
            throw std::runtime_error("DpdkBackend: RX queue setup failed for port " +
                                     std::to_string(port_id_) + " (rc=" + std::to_string(rx_rc) +
                                     ")");
        }

        const int tx_rc =
            rte_eth_tx_queue_setup(port_id_, queue_id_, tx_descriptors, socket_id, &tx_conf);
        if (tx_rc != 0) {
            throw std::runtime_error("DpdkBackend: TX queue setup failed for port " +
                                     std::to_string(port_id_) + " (rc=" + std::to_string(tx_rc) +
                                     ")");
        }

        const int start_rc = rte_eth_dev_start(port_id_);
        if (start_rc != 0) {
            throw std::runtime_error("DpdkBackend: rte_eth_dev_start failed for port " +
                                     std::to_string(port_id_) + " (rc=" + std::to_string(start_rc) +
                                     ")");
        }
        port_started_ = true;

        rte_eth_link link_status{};
        if (rte_eth_link_get(port_id_, &link_status) == 0) {
            LOG_INFO("DpdkBackend: port " + std::to_string(port_id_) +
                     " link status: " + std::to_string(link_status.link_status));
        }
        LOG_INFO("DpdkBackend: initialised port=" + std::to_string(port_id_) +
                 " q=" + std::to_string(queue_id_) + " pool=\"" + pool_name_ +
                 "\" mbufs=" + std::to_string(NUM_MBUFS));
    } catch (...) {
        cleanup();
        throw;
    }
}

// ===========================================================================
// Hot path
// ===========================================================================

std::uint32_t DpdkBackend::recv_batch(PacketDescriptor* out, std::uint32_t max) {
    if (!port_started_ || out == nullptr || max == 0)
        return 0;

    // Cap the burst at our internal scratch + outstanding ring budget so
    // we never overflow the tracked-mbufs vector.
    if (max > BATCH_SIZE)
        max = BATCH_SIZE;
    if (pending_rx_mbufs_.size() + max > kPendingCap) {
        // The worker failed to keep up with `release_pending`.  Drop the
        // request rather than leak mbufs past kPendingCap.
        return 0;
    }

    rte_mbuf* rx_pkts[BATCH_SIZE];
    const uint16_t nb_rx =
        rte_eth_rx_burst(port_id_, queue_id_, rx_pkts, static_cast<uint16_t>(max));
    if (nb_rx == 0)
        return 0;

    const auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();

    std::uint16_t published = 0;
    for (uint16_t i = 0; i < nb_rx; ++i) {
        rte_mbuf* m = rx_pkts[i];
        const auto pending_index = static_cast<std::uint32_t>(pending_rx_mbufs_.size());
        if (!track_mbuf(m, pending_index)) {
            rte_pktmbuf_free(m);
            continue;
        }
        pending_rx_mbufs_.push_back(m);
        out[published].offset = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(m));
        out[published].length = static_cast<std::uint32_t>(m->data_len);
        out[published].rx_queue_id = queue_id_;
        out[published].timestamp_ns = static_cast<std::uint64_t>(now_ns);
        ++published;
    }
    return static_cast<std::uint32_t>(published);
}

std::uint32_t DpdkBackend::release_pending(std::uint32_t n) {
    if (!eal_initialised_ || n == 0 || pending_rx_mbufs_.empty())
        return 0;
    if (n > pending_rx_mbufs_.size())
        n = static_cast<std::uint32_t>(pending_rx_mbufs_.size());

    for (std::uint32_t i = 0; i < n; ++i) {
        untrack_mbuf(pending_rx_mbufs_[i]);
    }
    rte_pktmbuf_free_bulk(pending_rx_mbufs_.data(), n);
    pending_rx_mbufs_.erase(pending_rx_mbufs_.begin(), pending_rx_mbufs_.begin() + n);
    for (std::uint32_t i = 0; i < pending_rx_mbufs_.size(); ++i) {
        update_tracked_index(pending_rx_mbufs_[i], i);
    }
    return n;
}

bool DpdkBackend::owns_mbuf(const rte_mbuf* mbuf) const noexcept {
    std::uint32_t ignored = 0;
    return tracked_index(mbuf, ignored);
}

bool DpdkBackend::track_mbuf(rte_mbuf* mbuf, std::uint32_t index) noexcept {
    if (mbuf == nullptr || !ownership_slots_)
        return false;
    std::size_t slot = ownership_hash(mbuf, kOwnershipSlots);
    std::size_t deleted = kOwnershipSlots;
    for (std::size_t probe = 0; probe < kOwnershipSlots; ++probe) {
        auto& entry = (*ownership_slots_)[slot];
        if (entry.mbuf == mbuf)
            return false;
        if (entry.mbuf == kDeletedMbuf && deleted == kOwnershipSlots)
            deleted = slot;
        if (entry.mbuf == nullptr) {
            auto& destination = (*ownership_slots_)[deleted == kOwnershipSlots ? slot : deleted];
            destination = {mbuf, index};
            return true;
        }
        slot = (slot + 1u) & (kOwnershipSlots - 1u);
    }
    // The table can fill with tombstones after enough RX/TX churn.  There
    // is no empty slot left to terminate a probe run, but a tombstone is
    // safe to reuse: lookups skip tombstones and the duplicate scan above
    // already covered every slot.
    if (deleted != kOwnershipSlots) {
        (*ownership_slots_)[deleted] = {mbuf, index};
        return true;
    }
    return false;
}

bool DpdkBackend::tracked_index(const rte_mbuf* mbuf, std::uint32_t& index) const noexcept {
    if (mbuf == nullptr || !ownership_slots_)
        return false;
    std::size_t slot = ownership_hash(mbuf, kOwnershipSlots);
    for (std::size_t probe = 0; probe < kOwnershipSlots; ++probe) {
        const auto& entry = (*ownership_slots_)[slot];
        if (entry.mbuf == nullptr)
            return false;
        if (entry.mbuf == mbuf) {
            index = entry.pending_index;
            return true;
        }
        slot = (slot + 1u) & (kOwnershipSlots - 1u);
    }
    return false;
}

void DpdkBackend::untrack_mbuf(const rte_mbuf* mbuf) noexcept {
    if (mbuf == nullptr || !ownership_slots_)
        return;
    std::size_t slot = ownership_hash(mbuf, kOwnershipSlots);
    for (std::size_t probe = 0; probe < kOwnershipSlots; ++probe) {
        auto& entry = (*ownership_slots_)[slot];
        if (entry.mbuf == nullptr)
            return;
        if (entry.mbuf == mbuf) {
            entry = {kDeletedMbuf, 0};
            return;
        }
        slot = (slot + 1u) & (kOwnershipSlots - 1u);
    }
}

void DpdkBackend::update_tracked_index(const rte_mbuf* mbuf, std::uint32_t index) noexcept {
    if (mbuf == nullptr || !ownership_slots_)
        return;
    std::size_t slot = ownership_hash(mbuf, kOwnershipSlots);
    for (std::size_t probe = 0; probe < kOwnershipSlots; ++probe) {
        auto& entry = (*ownership_slots_)[slot];
        if (entry.mbuf == nullptr)
            return;
        if (entry.mbuf == mbuf) {
            entry.pending_index = index;
            return;
        }
        slot = (slot + 1u) & (kOwnershipSlots - 1u);
    }
}

void DpdkBackend::compact_pending() noexcept {
    std::size_t write = 0;
    for (rte_mbuf* mbuf : pending_rx_mbufs_) {
        if (mbuf == nullptr)
            continue;
        pending_rx_mbufs_[write] = mbuf;
        update_tracked_index(mbuf, static_cast<std::uint32_t>(write));
        ++write;
    }
    pending_rx_mbufs_.resize(write);
}

std::span<std::byte> DpdkBackend::packet_span(const PacketDescriptor& packet) noexcept {
    auto* mbuf = reinterpret_cast<rte_mbuf*>(static_cast<std::uintptr_t>(packet.offset));
    if (!owns_mbuf(mbuf) || mbuf->nb_segs != 1 || mbuf->next != nullptr ||
        mbuf->pkt_len > mbuf->data_len) {
        return {};
    }
    return {rte_pktmbuf_mtod(mbuf, std::byte*), mbuf->pkt_len};
}

std::span<const std::byte> DpdkBackend::packet_span(const PacketDescriptor& packet) const noexcept {
    const auto* mbuf =
        reinterpret_cast<const rte_mbuf*>(static_cast<std::uintptr_t>(packet.offset));
    if (!owns_mbuf(mbuf) || mbuf->nb_segs != 1 || mbuf->next != nullptr ||
        mbuf->pkt_len > mbuf->data_len) {
        return {};
    }
    return {rte_pktmbuf_mtod(mbuf, const std::byte*), mbuf->pkt_len};
}

std::uint32_t DpdkBackend::send_batch(const PacketDescriptor* pkts, std::uint32_t n) {
    if (!port_started_ || pkts == nullptr || n == 0)
        return 0;
    if (n > BATCH_SIZE)
        n = BATCH_SIZE;

    if (tx_scratch_.size() < n)
        tx_scratch_.resize(n);

    std::array<rte_mbuf*, BATCH_SIZE * 2u> seen{};
    std::array<std::uint32_t, BATCH_SIZE> pending_indices{};
    std::uint32_t prepared = 0;
    for (; prepared < n; ++prepared) {
        rte_mbuf* m =
            reinterpret_cast<rte_mbuf*>(static_cast<std::uintptr_t>(pkts[prepared].offset));
        if (m == nullptr)
            break;
        std::uint32_t pending_index = 0;
        if (!tracked_index(m, pending_index)) {
            break;
        }
        std::size_t slot = ownership_hash(m, seen.size());
        while (seen[slot] != nullptr && seen[slot] != m) {
            slot = (slot + 1u) & (seen.size() - 1u);
        }
        if (seen[slot] == m)
            break;
        seen[slot] = m;
        pending_indices[prepared] = pending_index;
        tx_scratch_[prepared] = m;
    }

    if (prepared == 0)
        return 0;

    const uint16_t nb_tx =
        rte_eth_tx_burst(port_id_, queue_id_, tx_scratch_.data(), static_cast<uint16_t>(prepared));
    for (std::uint16_t i = 0; i < nb_tx; ++i) {
        untrack_mbuf(tx_scratch_[i]);
        pending_rx_mbufs_[pending_indices[i]] = nullptr;
    }
    compact_pending();
    return static_cast<std::uint32_t>(nb_tx);
}

} // namespace packet_engine

#else // HAVE_DPDK

// ---------------------------------------------------------------------------
// Stub build (DPDK disabled).  Public-facing methods still exist so callers
// that compiled unconditionally via the header do not break, but every
// nontrivial operation throws so the misuse is loud.
// ---------------------------------------------------------------------------

#include "packet-engine/backend_dpdk.hpp"

#include <stdexcept>
#include <string>

namespace packet_engine {

DpdkBackend::DpdkBackend(std::uint16_t port_id, std::uint16_t queue_id,
                         std::string_view pool_name) noexcept
    : port_id_(port_id), queue_id_(queue_id), pool_name_(pool_name) {}

DpdkBackend::DpdkBackend(std::string_view port_name, std::uint16_t queue_id,
                         std::string_view pool_name) noexcept
    : queue_id_(queue_id), port_name_(port_name), pool_name_(pool_name),
      select_port_by_name_(true) {}

DpdkBackend::~DpdkBackend() = default;

void DpdkBackend::cleanup() noexcept {}

void DpdkBackend::init(int /*argc*/, char** /*argv*/) {
    throw std::runtime_error("DpdkBackend::init called but the binary was built with "
                             "-DENABLE_DPDK=OFF; rebuild with -DENABLE_DPDK=ON to enable DPDK");
}

std::uint32_t DpdkBackend::recv_batch(PacketDescriptor* /*out*/, std::uint32_t /*max*/) {
    return 0;
}

std::uint32_t DpdkBackend::release_pending(std::uint32_t /*n*/) { return 0; }

std::span<std::byte> DpdkBackend::packet_span(const PacketDescriptor& packet) noexcept {
    (void)packet;
    return {};
}

std::span<const std::byte> DpdkBackend::packet_span(const PacketDescriptor& packet) const noexcept {
    (void)packet;
    return {};
}

std::uint32_t DpdkBackend::send_batch(const PacketDescriptor* /*pkts*/, std::uint32_t /*n*/) {
    return 0;
}

} // namespace packet_engine

#endif // HAVE_DPDK
