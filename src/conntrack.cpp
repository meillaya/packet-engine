// SPDX-License-Identifier: MIT
//
// conntrack.cpp -- flow cache implementation + explicit OpenAddrHashTable
// instantiations for the canonical conntrack instantiation.
//
// Single-writer contract: lookup_or_create, peek and evict_idle are invoked
// from the same packet-worker thread.
//
#include "packet-engine/conntrack.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

namespace packet_engine {

// ---------------------------------------------------------------------------
// TCP state machine.  See header for the transition table.
// ---------------------------------------------------------------------------
void ConntrackFlowCache::transition_tcp_state(TcpState& s, std::uint8_t flags) noexcept {
    // RST is terminal from any state.
    if (flags & TcpFlags::RST) {
        s = TcpState::CLOSED;
        return;
    }

    switch (s) {
    case TcpState::NEW:
        if (flags & TcpFlags::SYN) {
            s = TcpState::SYN_SENT;
        }
        // ACK alone (e.g. stray ACK of an unrelated conn) leaves NEW alone.
        break;

    case TcpState::SYN_SENT:
        // SYN+ACK is the canonical 3WHS server response; ACK alone also
        // represents a return ACK in some implementations.
        if ((flags & TcpFlags::SYN) && (flags & TcpFlags::ACK)) {
            s = TcpState::ESTABLISHED;
        } else if ((flags & TcpFlags::ACK) && !(flags & TcpFlags::SYN)) {
            // Pure ACK while still in SYN_SENT -> peer moved us to
            // ESTABLISHED (this happens for split-handshake stacks and
            // also when the SYN-ACK is fragmented / retransmitted).
            s = TcpState::ESTABLISHED;
        }
        break;

    case TcpState::ESTABLISHED:
        if (flags & TcpFlags::FIN) {
            s = TcpState::FIN_WAIT;
        }
        // ACK keeps ESTABLISHED -> no-op.
        break;

    case TcpState::FIN_WAIT:
        // Closing: ACK after the local FIN half-close completes the
        // graceful close.  Re-transmitted FIN keeps us in FIN_WAIT.
        if ((flags & TcpFlags::ACK) && !(flags & TcpFlags::FIN)) {
            s = TcpState::CLOSED;
        }
        break;

    case TcpState::CLOSED:
        // Terminal -- nothing further to do.  The caller will evict
        // this entry on the next idle sweep.
        break;
    }
}

// ---------------------------------------------------------------------------
// peeking helpers -- thin wrappers around OpenAddrHashTable::find.
// ---------------------------------------------------------------------------
FlowEntry* ConntrackFlowCache::peek(const FiveTuple& key) noexcept { return table_.find(key); }

const FlowEntry* ConntrackFlowCache::peek(const FiveTuple& key) const noexcept {
    return table_.find(key);
}

FlowEntry* ConntrackFlowCache::touch(const FiveTuple& key, std::uint64_t now_ns,
                                     std::uint8_t tcp_flags) noexcept {
    FlowEntry* entry = table_.find(key);
    if (entry != nullptr) {
        entry->last_seen_ns = now_ns;
        transition_tcp_state(entry->tcp_state, tcp_flags);
    }
    return entry;
}

FlowEntry* ConntrackFlowCache::peek_translation(const FiveTuple& translated_key) noexcept {
    const FiveTuple* original_key = translations_.find(translated_key);
    return original_key == nullptr ? nullptr : table_.find(*original_key);
}

const FlowEntry*
ConntrackFlowCache::peek_translation(const FiveTuple& translated_key) const noexcept {
    const FiveTuple* original_key = translations_.find(translated_key);
    return original_key == nullptr ? nullptr : table_.find(*original_key);
}

FlowEntry* ConntrackFlowCache::touch_translation(const FiveTuple& translated_key,
                                                 std::uint64_t now_ns,
                                                 std::uint8_t tcp_flags) noexcept {
    FlowEntry* entry = peek_translation(translated_key);
    if (entry != nullptr) {
        entry->last_seen_ns = now_ns;
        transition_tcp_state(entry->tcp_state, tcp_flags);
    }
    return entry;
}

bool ConntrackFlowCache::bind_translation(const FiveTuple& translated_key,
                                          const FiveTuple& original_key) noexcept {
    if (table_.find(original_key) == nullptr) {
        return false;
    }
    return translations_.insert(translated_key, original_key);
}

// ---------------------------------------------------------------------------
// lookup_or_create: the per-packet hot path.
// ---------------------------------------------------------------------------
FlowEntry& ConntrackFlowCache::lookup_or_create(const FiveTuple& key,
                                                const ConntrackLookupArgs& args) noexcept {
    FlowEntry* entry = try_lookup_or_create(key, args);
    if (entry == nullptr) {
        std::abort();
    }
    return *entry;
}

FlowEntry* ConntrackFlowCache::try_lookup_or_create(const FiveTuple& key,
                                                    const ConntrackLookupArgs& args) noexcept {
    if (auto* hit = table_.find(key)) {
        hit->last_seen_ns = args.now_ns;
        transition_tcp_state(hit->tcp_state, args.tcp_flags);
        return hit;
    }

    // Miss -- insert a fresh NEW entry, then drive the state machine
    // against the incoming TCP flags so the very first SYN lands in
    // SYN_SENT, the SYN+ACK sequence lands in ESTABLISHED, etc.
    // Initialising to NEW unconditionally would mean a SYN that creates
    // the flow silently stays in NEW until the next packet.
    FlowEntry fresh{};
    fresh.backend = args.backend;
    fresh.client_ip = args.client_ip;
    fresh.client_port = args.client_port;
    fresh.backend_ip = args.backend_ip;
    fresh.backend_port = args.backend_port;
    fresh.engine_sport = args.engine_sport;
    fresh.service_port = args.service_port;
    fresh.client_mac = args.client_mac;
    fresh.engine_mac = args.engine_mac;
    fresh.backend_mac = args.backend_mac;
    fresh.tcp_state = TcpState::NEW;
    fresh.last_seen_ns = args.now_ns;
    transition_tcp_state(fresh.tcp_state, args.tcp_flags);

    if (table_.insert(key, fresh)) {
        eviction_keys_.push_back(key);
        return table_.find(key);
    }
    return nullptr;
}

void ConntrackFlowCache::set_eviction_handler(void* context, EvictionHandler handler) noexcept {
    eviction_context_ = context;
    eviction_handler_ = handler;
}

void ConntrackFlowCache::clear_eviction_handler(void* context) noexcept {
    if (eviction_context_ == context) {
        eviction_context_ = nullptr;
        eviction_handler_ = nullptr;
    }
}

void ConntrackFlowCache::notify_eviction(const FlowEntry& entry) noexcept {
    if (eviction_handler_ != nullptr) {
        eviction_handler_(eviction_context_, entry);
    }
}

void ConntrackFlowCache::erase_translation(const FiveTuple& original_key,
                                           const FlowEntry& entry) noexcept {
    const FiveTuple translated_key{original_key.dst_ip,
                                   IPv4Addr{static_cast<std::uint32_t>(entry.backend_ip)},
                                   entry.engine_sport, entry.backend_port, original_key.proto};
    (void)translations_.erase(translated_key);
}

bool ConntrackFlowCache::erase(const FiveTuple& original_key) noexcept {
    FlowEntry* entry = table_.find(original_key);
    if (entry == nullptr) {
        return false;
    }
    const FlowEntry snapshot = *entry;
    if (!table_.erase(original_key)) {
        return false;
    }
    erase_translation(original_key, snapshot);
    const auto index = std::find(eviction_keys_.begin(), eviction_keys_.end(), original_key);
    if (index != eviction_keys_.end()) {
        *index = eviction_keys_.back();
        eviction_keys_.pop_back();
        evict_cursor_ = 0;
    }
    notify_eviction(snapshot);
    return true;
}

// ---------------------------------------------------------------------------
// Idle eviction (incremental sweep over the auxiliary index).
// ---------------------------------------------------------------------------
std::size_t ConntrackFlowCache::evict_idle(std::uint64_t now_ns, std::uint64_t idle_timeout_ns,
                                           std::size_t slice) noexcept {
    if (eviction_keys_.empty()) {
        return 0;
    }
    if (slice == 0) {
        slice = 1; // never zero -- at least make forward progress.
    }

    // Normalise the cursor: if a previous call's swap-remove landed it
    // past the end (the rare case where the tail element was just
    // evicted), wrap it back so the unsigned-subtract budget below does
    // not underflow.
    if (evict_cursor_ >= eviction_keys_.size()) {
        evict_cursor_ = 0;
    }

    const std::size_t budget = std::min(slice, eviction_keys_.size() - evict_cursor_);
    std::size_t evicted = 0;

    for (std::size_t step = 0; step < budget; ++step) {
        FiveTuple key = eviction_keys_[evict_cursor_];
        if (auto* entry = table_.find(key)) {
            if (now_ns > entry->last_seen_ns && (now_ns - entry->last_seen_ns) > idle_timeout_ns) {
                const FlowEntry snapshot = *entry;
                erase_translation(key, snapshot);
                notify_eviction(snapshot);
                (void)table_.erase(key);
                ++evicted;
                // Swap-remove from the auxiliary index: move the last
                // element into this slot and shrink.  Compaction keeps
                // the cursor's amortised progress linear and avoids
                // holes.  When the cursor sits on the tail, the swap is
                // a self-assignment, which is well-defined for the
                // trivially-copyable FiveTuple.
                const FiveTuple back = eviction_keys_.back();
                eviction_keys_[evict_cursor_] = back;
                eviction_keys_.pop_back();
                // Re-normalise after the pop: if we just removed the
                // tail, the cursor now sits one past the end.  Wrapping
                // is cheaper than recomputing the budget, and the loop
                // exit condition above (`budget`) is tight against the
                // pre-erase size.
                if (evict_cursor_ >= eviction_keys_.size()) {
                    evict_cursor_ = 0;
                }
                // Do NOT advance the cursor -- the swapped-in element
                // now sits at `evict_cursor_` and must be inspected
                // (or evicted) before moving on.
                continue;
            }
        } else {
            // The entry was already erased by some external path --
            // unlikely under our single-writer contract, but be
            // defensive.  Swap-remove and continue at this slot.
            const FiveTuple back = eviction_keys_.back();
            eviction_keys_[evict_cursor_] = back;
            eviction_keys_.pop_back();
            if (evict_cursor_ >= eviction_keys_.size()) {
                evict_cursor_ = 0;
            }
            continue;
        }

        // Advance cursor; wrap at end-of-vector.
        ++evict_cursor_;
        if (evict_cursor_ >= eviction_keys_.size()) {
            evict_cursor_ = 0;
        }
    }

    return evicted;
}

std::size_t ConntrackFlowCache::remaining_capacity() const noexcept {
    const std::size_t cap = OpenAddrHashTable<FiveTuple, FlowEntry, kCapacity>::kMaxSize;
    return table_.size() >= cap ? 0 : (cap - table_.size());
}

void ConntrackFlowCache::clear() noexcept {
    for (const FiveTuple& key : eviction_keys_) {
        if (const FlowEntry* entry = table_.find(key)) {
            notify_eviction(*entry);
        }
    }
    table_.clear();
    translations_.clear();
    eviction_keys_.clear();
    evict_cursor_ = 0;
}

// ---------------------------------------------------------------------------
// Explicit template instantiations for OpenAddrHashTable with FlowEntry.
//
// Production cache: 65536 (matches the plan).
// Perf test only:   2^18 = 262144 -> 131072 LF cap, fits 100k flows.
// ---------------------------------------------------------------------------
template class OpenAddrHashTable<FiveTuple, FlowEntry, 65536>;
template class OpenAddrHashTable<FiveTuple, FlowEntry, 1ULL << 18>;
template class OpenAddrHashTable<FiveTuple, FlowEntry, 64>;
template class OpenAddrHashTable<FiveTuple, FlowEntry, 128>;

} // namespace packet_engine
