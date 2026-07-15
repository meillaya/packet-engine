// SPDX-License-Identifier: MIT
//
// ketama.cpp -- Ketama consistent-hash ring implementation.
//
// Algorithm: see the header documentation in `ketama.hpp`.  The file is
// organised as:
//
//   * Helpers (cold path)
//       - ketama_points_for_backend  -- 160 continuum points per backend.
//       - five_tuple_hash32          -- MD5-based hash for `pick()`.
//
//   * `ContinuumSnapshot` private builders used by `KetamaRing`.
//   * `KetamaRing` -- ctor / pick / add / remove / snapshot / rebuild.
//
// Threading model
// ===============
//
//   * `add_backend` / `remove_backend` take an internal mutex while they
//     rebuild the snapshot, then atomic-store the new shared pointer.
//   * `pick` acquire-loads the snapshot and performs an allocation-free
//     `lower_bound`; atomic-shared-ptr synchronization is implementation-defined.
//   * `snapshot()` does an acquire-load of the snapshot.
//
#include "packet-engine/ketama.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "packet-engine/md5.hpp"

namespace packet_engine {

namespace {

// ---------------------------------------------------------------------------
// Cold-path helpers
// ---------------------------------------------------------------------------

/// Serialise a FiveTuple into a stable byte string that we then MD5-hash.
/// `src_ip|dst_ip|src_port|dst_port|proto` separated by a non-digit byte so
/// that ("10.0.0.1", "0.0.0.2", 0, 2, TCP) never collides with a different
/// decomposition.  Protocol is appended as its 1-byte IANA number.
///
/// Returns the bytestring via an out parameter to keep the function
/// allocation-free for callers that pre-size a buffer.  Used only on the
/// hot-path pick(); the test code uses helpers.
struct FiveTupleSerial {
    std::array<char, 64> buf{};
    std::size_t len{0};
};

FiveTupleSerial serialise_five_tuple(const FiveTuple& t) noexcept {
    FiveTupleSerial out{};

    // Build a printable decomposition of the four IPs.
    const auto print_ip = [](std::uint32_t ip, char* dst) noexcept -> std::size_t {
        const std::uint8_t a = static_cast<std::uint8_t>(ip >> 24);
        const std::uint8_t b = static_cast<std::uint8_t>(ip >> 16);
        const std::uint8_t c = static_cast<std::uint8_t>(ip >> 8);
        const std::uint8_t d = static_cast<std::uint8_t>(ip);
        // Safe because the buffer has 16 bytes; "%u.%u.%u.%u" max is 16.
        std::snprintf(dst, 16, "%u.%u.%u.%u", static_cast<unsigned>(a), static_cast<unsigned>(b),
                      static_cast<unsigned>(c), static_cast<unsigned>(d));
        return std::strlen(dst);
    };

    auto* p = out.buf.data();
    auto* const end = p + out.buf.size();

    auto append = [&](const char* s, std::size_t n) noexcept -> bool {
        if (static_cast<std::size_t>(end - p) < n)
            return false;
        std::memcpy(p, s, n);
        p += n;
        return true;
    };

    char tmp[16];

    const std::size_t src_n = print_ip(t.src_ip.value, tmp);
    if (!append(tmp, src_n))
        return FiveTupleSerial{};
    if (!append("|", 1))
        return FiveTupleSerial{};

    const std::size_t dst_n = print_ip(t.dst_ip.value, tmp);
    if (!append(tmp, dst_n))
        return FiveTupleSerial{};
    if (!append("|", 1))
        return FiveTupleSerial{};

    // Ports as decimal via snprintf -- up to 5 chars each.
    const int sp_n = std::snprintf(tmp, sizeof(tmp), "%u", static_cast<unsigned>(t.src_port));
    if (sp_n <= 0 || !append(tmp, static_cast<std::size_t>(sp_n))) {
        return FiveTupleSerial{};
    }
    if (!append("|", 1))
        return FiveTupleSerial{};
    const int dp_n = std::snprintf(tmp, sizeof(tmp), "%u", static_cast<unsigned>(t.dst_port));
    if (dp_n <= 0 || !append(tmp, static_cast<std::size_t>(dp_n))) {
        return FiveTupleSerial{};
    }
    if (!append("|", 1))
        return FiveTupleSerial{};

    const int pr_n = std::snprintf(tmp, sizeof(tmp), "%u", static_cast<unsigned>(t.proto));
    if (pr_n <= 0 || !append(tmp, static_cast<std::size_t>(pr_n))) {
        return FiveTupleSerial{};
    }

    out.len = static_cast<std::size_t>(p - out.buf.data());
    return out;
}

} // namespace

namespace detail {

std::vector<ContinuumPoint> ketama_points_for_backend(KetamaBackendId id,
                                                      std::string_view address) noexcept {
    std::vector<ContinuumPoint> out;
    out.reserve(KetamaRing::kPointsPerBackend);

    // Build points via the libketama recipe: 40 replicas, each contributing
    // 4 32-bit continuum points extracted from the MD5 of "<addr>-<i>".
    for (std::uint32_t rep = 0; rep < KetamaRing::kReplicasPerBackend; ++rep) {
        // Compose "<addr>-<rep>" into a stack buffer.  libketama writes
        // up to 32 bytes for the address; we over-allocate to handle
        // pathological addresses without heap allocation.
        char key[96];
        int n = std::snprintf(key, sizeof(key), "%.*s-%u", static_cast<int>(address.size()),
                              address.data(), rep);
        if (n <= 0 || static_cast<std::size_t>(n) >= sizeof(key)) {
            // Pathological address length; skip this replica.
            continue;
        }

        const auto digest = compute_md5(key, static_cast<std::size_t>(n));

        // Extract 4 little-endian u32s from the 16-byte digest.
        // libketama uses (digest[3]<<24)|(digest[2]<<16)|(digest[1]<<8)|digest[0],
        // which is the 32-bit load of `digest[i..i+4]` on a little-endian
        // host.  memcpy is the cleanest, endianness-safe way to express it.
        for (std::uint32_t j = 0; j < KetamaRing::kPointsPerReplica; ++j) {
            ContinuumPoint pt{};
            pt.backend_id = id;
            std::memcpy(&pt.point_hash, digest.bytes.data() + (j * 4), sizeof(pt.point_hash));
            out.push_back(pt);
        }
    }
    return out;
}

} // namespace detail

// ---------------------------------------------------------------------------
// `KetamaRing`
// ---------------------------------------------------------------------------

KetamaRing::KetamaRing(std::vector<KetamaBackend> backends) {
    std::lock_guard<std::mutex> lk(mutate_mu_);

    // Seed the cold-path backend state.
    for (const auto& b : backends) {
        if (b.address.empty())
            continue;
        auto [_, addr_inserted] = backends_by_addr_.emplace(b.address, b.id);
        if (addr_inserted) {
            backends_by_id_.emplace(b.id, b.address);
        }
    }

    auto snap = build_(std::move(backends));
    if (!snap)
        snap = std::make_shared<const ContinuumSnapshot>();
    active_.store(snap, std::memory_order_release);
}

ContinuumSnapshotPtr KetamaRing::snapshot() const noexcept {
    return active_.load(std::memory_order_acquire);
}

std::size_t KetamaRing::size() const noexcept {
    auto snap = active_.load(std::memory_order_acquire);
    return snap ? snap->size() : 0u;
}

std::size_t KetamaRing::backend_count() const noexcept {
    auto snap = active_.load(std::memory_order_acquire);
    return snap ? snap->backend_count() : 0u;
}

bool KetamaRing::add_backend(const KetamaBackend& b) {
    if (b.address.empty())
        return false;

    std::lock_guard<std::mutex> lk(mutate_mu_);

    // Reject duplicates by either id or address; the libketama contract
    // expects address uniqueness, but we also guard against id collisions.
    if (backends_by_id_.find(b.id) != backends_by_id_.end())
        return false;
    if (backends_by_addr_.find(b.address) != backends_by_addr_.end())
        return false;

    // Snapshot the current backend set, append, rebuild.
    std::vector<KetamaBackend> next;
    next.reserve(backends_by_id_.size() + 1);
    for (const auto& [id, addr] : backends_by_id_) {
        next.push_back(KetamaBackend{id, addr});
    }
    next.push_back(b);

    auto snap = build_(std::move(next));
    if (!snap)
        return false;

    backends_by_id_.emplace(b.id, b.address);
    backends_by_addr_.emplace(b.address, b.id);

    active_.store(snap, std::memory_order_release);
    return true;
}

bool KetamaRing::remove_backend(KetamaBackendId id) {
    std::lock_guard<std::mutex> lk(mutate_mu_);

    auto it = backends_by_id_.find(id);
    if (it == backends_by_id_.end())
        return false;

    std::vector<KetamaBackend> next;
    next.reserve(backends_by_id_.size() - 1);
    for (const auto& [bid, addr] : backends_by_id_) {
        if (bid == id)
            continue;
        next.push_back(KetamaBackend{bid, addr});
    }

    auto snap = build_(std::move(next));
    if (!snap)
        return false;

    backends_by_addr_.erase(it->second);
    backends_by_id_.erase(it);

    active_.store(snap, std::memory_order_release);
    return true;
}

bool KetamaRing::replace_backends(std::vector<KetamaBackend> backends) {
    std::unordered_map<KetamaBackendId, std::string> by_id;
    std::unordered_map<std::string, KetamaBackendId> by_address;
    by_id.reserve(backends.size());
    by_address.reserve(backends.size());

    for (const auto& backend : backends) {
        if (backend.id == INVALID_KETAMA_BACKEND_ID || backend.address.empty())
            return false;
        if (!by_id.emplace(backend.id, backend.address).second)
            return false;
        if (!by_address.emplace(backend.address, backend.id).second)
            return false;
    }

    auto snapshot = build_(std::move(backends));
    if (!snapshot)
        return false;

    std::lock_guard<std::mutex> lock{mutate_mu_};
    backends_by_id_.swap(by_id);
    backends_by_addr_.swap(by_address);
    active_.store(std::move(snapshot), std::memory_order_release);
    return true;
}

ContinuumSnapshotPtr KetamaRing::rebuild_() const {
    std::vector<KetamaBackend> current;
    current.reserve(backends_by_id_.size());
    for (const auto& [id, addr] : backends_by_id_) {
        current.push_back(KetamaBackend{id, addr});
    }
    return build_(std::move(current));
}

ContinuumSnapshotPtr KetamaRing::build_(std::vector<KetamaBackend> backends) const {
    auto snap = std::make_shared<ContinuumSnapshot>();
    if (backends.empty())
        return snap;

    snap->ring_.reserve(backends.size() * kPointsPerBackend);
    snap->id_map_.reserve(backends.size());

    for (const auto& b : backends) {
        if (b.address.empty())
            continue;
        snap->id_map_.emplace(b.address, b.id);
        auto pts = detail::ketama_points_for_backend(b.id, b.address);
        for (auto& pt : pts)
            snap->ring_.push_back(pt);
    }

    // Sort by point_hash so the lookup is a binary search.  Stable sort
    // preserves insertion order for equal hashes -- libketama treats equal
    // hashes as routing to the first point, so we follow the same rule.
    std::stable_sort(snap->ring_.begin(), snap->ring_.end(),
                     [](const ContinuumPoint& a, const ContinuumPoint& b) noexcept {
                         return a.point_hash < b.point_hash;
                     });
    return snap;
}

KetamaBackendId KetamaRing::pick(const FiveTuple& key) const noexcept {
    const auto serial = serialise_five_tuple(key);
    if (serial.len == 0)
        return INVALID_KETAMA_BACKEND_ID;
    const std::uint32_t h = md5_hash32(serial.buf.data(), serial.len);
    return pick_hash(h);
}

KetamaBackendId KetamaRing::pick_hash(std::uint32_t h) const noexcept {
    auto snap = active_.load(std::memory_order_acquire);
    if (!snap || snap->ring_.empty())
        return INVALID_KETAMA_BACKEND_ID;

    const auto& ring = snap->ring_;
    // std::lower_bound semantics: first point with point_hash >= h
    // (i.e. the canonical Ketama "walk clockwise to next point" rule,
    // including the exact-match case).  Wrap to 0 when we run off the
    // end -- the ring is circular.
    auto it = std::lower_bound(ring.begin(), ring.end(), h,
                               [](const ContinuumPoint& pt, std::uint32_t value) noexcept {
                                   return pt.point_hash < value;
                               });

    if (it == ring.end()) {
        // Off the end -- wrap to the first point.
        return ring.front().backend_id;
    }
    return it->backend_id;
}

} // namespace packet_engine
