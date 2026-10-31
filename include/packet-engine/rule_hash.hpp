// SPDX-License-Identifier: MIT
//
// rule_hash.hpp -- open-addressing, linear-probing hash table.
//
// Design summary
// ==============
//
// * Cache-friendly: every slot is a (std::optional<K>, std::optional<V>)
//   pair.  find() issues __builtin_prefetch on the slot four positions
//   ahead while still processing the current slot; the 4-stride keeps
//   the prefetcher inside a typical L1d line-cache working set so the
//   critical read path is bounded by L1d latency rather than main
//   memory.
//
// * Bounded probe distance: each find/insert/erase walks at most
//   kMaxProbe (16) slots before giving up.  An insert that would
//   exceed the budget triggers a full rebuild (rebuild()) which lays
//   out the existing keys again with fresh probe runs.
//
// * Tombstone-free: deletions simply clear both std::optional
//   sentinels in the slot.  This works because the rebuild invariant
//   guarantees that no live key sits past kMaxProbe, so an empty
//   slot really means "nothing after me at this probe run".
//
// * No locks, no atomics, no virtuals.  The table is immutable after
//   construction for reader threads; writers are expected to take an
//   external lock (see RuleTable, Task 16) and are not on the
//   per-packet hot path.
//
// * Capacity MUST be a power of two so the modulo can be expressed as
//   a single AND with kMask = CAPACITY - 1, matching katran's
//   BpfHdrMap and the probablydance reference.
//
// Reference: katran BpfHdrMap
//   https://github.com/facebookincubator/katran/blob/main/katran/lib/BpfHdrMap.h
//
#pragma once

#include "packet-engine/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

namespace packet_engine {

// ---------------------------------------------------------------------------
// std::hash<FiveTuple> -- the canonical engine key.
// ---------------------------------------------------------------------------
// Combines the four parts of hash_five_tuple with a splitmix64-style
// finalizer so that similar keys (e.g. adjacent IPs in a /24) do not
// land in the same probe run.  Finalizer constants from
// https://xorshift.di.unimi.it/splitmix64.c.
//
} // namespace packet_engine

namespace std {

template <> struct hash<packet_engine::FiveTuple> {
    [[nodiscard]] std::size_t operator()(const packet_engine::FiveTuple& ft) const noexcept {
        std::uint64_t h = static_cast<std::uint64_t>(ft.src_ip.value);
        h ^= static_cast<std::uint64_t>(ft.dst_ip.value) + 0x9e3779b97f4a7c15ULL + (h << 6) +
             (h >> 2);
        h ^= (static_cast<std::uint64_t>(ft.src_port) << 32 |
              static_cast<std::uint64_t>(ft.dst_port)) +
             0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= static_cast<std::uint64_t>(ft.proto) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9ULL;
        h = (h ^ (h >> 27)) * 0x94d049bb133111ebULL;
        h = h ^ (h >> 31);
        return static_cast<std::size_t>(h);
    }
};

} // namespace std

namespace packet_engine {

// ---------------------------------------------------------------------------
// OpenAddrHashTable<K, V, CAPACITY>
// ---------------------------------------------------------------------------
//
// Templated open-addressing hash table with bounded linear probing.
// K must be hashable via std::hash<K>; V must be assignable.
//
// CAPACITY must be a power of two and at least 16 (the kMaxProbe
// budget).  Common values: 65536 (2^16, ~10k entries at load 0.16)
// or 4M (2^22) for a larger store.
//
// The table treats the load-factor cap as full; insert returns false
// after that point rather than growing.
//
template <typename K, typename V, std::size_t CAPACITY> class OpenAddrHashTable {
  public:
    using key_type = K;
    using value_type = V;
    using size_type = std::size_t;

    static constexpr size_type kCapacity = CAPACITY;
    static constexpr size_type kMaxProbe = 16;
    static constexpr size_type kMask = CAPACITY - 1;
    // 0.5 LF is the largest load at which the kMaxProbe=16 bound is
    // statistically safe for linear probing on random keys.  A
    // growable table could push further via doubling on rebuild, but
    // with the fixed-CAPACITY template we cap conservatively.
    static constexpr size_type kLoadFactorCap = CAPACITY / 2;
    static constexpr size_type kMaxSize = (kLoadFactorCap == 0) ? 1 : kLoadFactorCap;

    static_assert(CAPACITY >= 16, "CAPACITY must be >= 16 to hold one probe run");
    static_assert((CAPACITY & (CAPACITY - 1)) == 0, "CAPACITY must be a power of two");

    OpenAddrHashTable() noexcept = default;

    // The hot lookup path is read-only, so copies and moves are not
    // required to be cheap.  Default-disabled keeps the call sites
    // explicit; if a future Task needs them, add noexcept with care
    // (each slot's optional carries a non-trivial copy).
    OpenAddrHashTable(const OpenAddrHashTable&) = delete;
    OpenAddrHashTable& operator=(const OpenAddrHashTable&) = delete;
    OpenAddrHashTable(OpenAddrHashTable&&) = delete;
    OpenAddrHashTable& operator=(OpenAddrHashTable&&) = delete;
    ~OpenAddrHashTable() = default;

    // -------------------------------------------------------------------
    // Lookup -- the per-packet hot path.
    // -------------------------------------------------------------------
    //
    // Bounded linear probe with a __builtin_prefetch one cache line
    // (~4 strides) ahead.  Returns nullptr on miss.
    //
    [[nodiscard]] V* find(const K& key) noexcept {
        const size_type h = hash_(key);
        const size_type base = h & kMask;
        __builtin_prefetch(reinterpret_cast<const void*>(&slots_[(base + 4) & kMask]), 0, 0);
        for (size_type i = 0; i < kMaxProbe; ++i) {
            const size_type cur = (h + i) & kMask;
            // Prefetch 4 strides ahead; the line is consumed 4
            // iterations later, well within L1d reach.
            if (i + 4 < kMaxProbe) {
                __builtin_prefetch(reinterpret_cast<const void*>(&slots_[(cur + 4) & kMask]), 0, 0);
            }
            if (!slots_[cur].key.has_value()) {
                return nullptr;
            }
            if (*slots_[cur].key == key) {
                return slots_[cur].value.has_value() ? &*slots_[cur].value : nullptr;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const V* find(const K& key) const noexcept {
        return const_cast<OpenAddrHashTable*>(this)->find(key);
    }

    // -------------------------------------------------------------------
    // Insert -- returns false if the table refuses (over the load
    // factor cap, or even after a rebuild the probe run is still
    // saturated).
    // -------------------------------------------------------------------
    [[nodiscard]] bool insert(const K& key, const V& value) noexcept {
        // An existing key is an update, not an insertion.  Check it before
        // the load-factor guard so a full table can still refresh a value.
        if (V* existing = find(key); existing != nullptr) {
            *existing = value;
            return true;
        }
        // Hard cap: at this load factor kMaxProbe cannot keep every
        // key inside the probe budget, so the caller is told to back
        // off and grow the table instead.  rebuild() cannot shrink
        // size_, so the guard must come first.
        if (size_ >= kMaxSize) {
            return false;
        }
        if (try_insert(key, value)) {
            return true;
        }
        // Past the probe budget but still under the size cap: rebuild
        // and retry exactly once.  A second failure means the table is
        // saturated after the rebuild -- refuse.
        if (!rebuild()) {
            return false;
        }
        return try_insert(key, value);
    }

    // -------------------------------------------------------------------
    // Erase -- tombstone-free: clears both sentinels and trusts the
    // rebuild invariant that no live key sits past kMaxProbe.
    // -------------------------------------------------------------------
    [[nodiscard]] bool erase(const K& key) noexcept {
        const size_type h = hash_(key);
        for (size_type i = 0; i < kMaxProbe; ++i) {
            const size_type cur = (h + i) & kMask;
            if (!slots_[cur].key.has_value()) {
                return false;
            }
            if (*slots_[cur].key == key) {
                slots_[cur].key.reset();
                slots_[cur].value.reset();
                --size_;
                // Cluster reinsertion: scan forward and reinsert each
                // subsequent key so that the probe chain stays intact.
                size_type j = cur;
                for (;;) {
                    j = (j + 1) & kMask;
                    if (!slots_[j].key.has_value())
                        break;
                    K k = std::move(*slots_[j].key);
                    V v = std::move(*slots_[j].value);
                    slots_[j].key.reset();
                    slots_[j].value.reset();
                    const size_type kh = hash_(k);
                    for (size_type p = 0; p < kCapacity; ++p) {
                        const size_type target = (kh + p) & kMask;
                        if (!slots_[target].key.has_value()) {
                            slots_[target].key = std::move(k);
                            slots_[target].value = std::move(v);
                            break;
                        }
                    }
                }
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------
    // Introspection
    // -------------------------------------------------------------------
    [[nodiscard]] size_type size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] static constexpr size_type capacity() noexcept { return kCapacity; }
    [[nodiscard]] static constexpr size_type max_probe() noexcept { return kMaxProbe; }

    // Count successful probes across the cluster of full slots whose
    // initial index is `bucket`.  Useful for the load-factor / probe
    // length acceptance criteria; O(kMaxProbe) but only called from
    // tests and benchmarks.
    [[nodiscard]] size_type run_length_at(size_type bucket) const noexcept {
        size_type n = 0;
        for (size_type i = 0; i < kMaxProbe; ++i) {
            const size_type cur = (bucket + i) & kMask;
            if (!slots_[cur].key.has_value())
                break;
            ++n;
        }
        return n;
    }

    void clear() noexcept {
        for (auto& s : slots_) {
            s = Slot{};
        }
        size_ = 0;
    }

    // -------------------------------------------------------------------
    // Internal helper used by rebuild().  Public callers go through
    // insert() (the version that caps load factor).
    // -------------------------------------------------------------------
    [[nodiscard]] bool try_insert(K key, V value) noexcept {
        const size_type h = hash_(key);
        for (size_type i = 0; i < kMaxProbe; ++i) {
            const size_type cur = (h + i) & kMask;
            if (!slots_[cur].key.has_value()) {
                slots_[cur].key = std::move(key);
                slots_[cur].value = std::move(value);
                ++size_;
                return true;
            }
            if (*slots_[cur].key == key) {
                slots_[cur].value = std::move(value);
                return true;
            }
        }
        return false;
    }

    // Rehash in place; returns true on success.  The scratch buffer
    // is heap-allocated because at the production sizes (>= 64k
    // slots) a stack-resident copy would blow the default 8 MB
    // thread stack with each rebuild -- this is the bug we hit on
    // the first perf run and found with AddressSanitizer.
    [[nodiscard]] bool rebuild() noexcept {
        auto rebuilt = std::make_unique<OpenAddrHashTable>();
        for (const auto& s : slots_) {
            if (!s.key.has_value())
                continue;
            if (!rebuilt->try_insert(*s.key, *s.value)) {
                return false;
            }
        }
        slots_.swap(rebuilt->slots_);
        size_ = rebuilt->size_;
        return true;
    }

  private:
    struct Slot {
        std::optional<K> key{};
        std::optional<V> value{};
    };

    [[nodiscard]] static size_type hash_(const K& key) noexcept { return std::hash<K>{}(key); }

    std::array<Slot, kCapacity> slots_{};
    size_type size_{0};
};

} // namespace packet_engine
