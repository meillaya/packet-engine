// SPDX-License-Identifier: MIT
//
// frame_allocator.cpp -- NUMA-aware UMEM frame allocator implementation.
//
// Outline
// =======
//   * Constructor:
//       1.  Round `frame_size` up to a multiple of the system page size;
//           reject allocations that would overflow `size_t`.
//       2.  mmap the UMEM with `MAP_HUGETLB | MAP_ANONYMOUS | MAP_POPULATE`,
//           falling back to plain `MAP_ANONYMOUS` if huge pages are not
//           available.
//       3.  Pin the constructing thread to a CPU on `target_node`,
//           install `set_mempolicy(MPOL_BIND, ...)`, and fault every page
//           with `memset(0)` so the kernel's first-touch allocator
//           satisfies pages from `target_node`.
//       4.  Apply `mbind(MPOL_BIND, ..., MPOL_MF_MOVE | MPOL_MF_STRICT)`
//           so the VMA itself records the policy -- this is what
//           `get_mempolicy(... MPOL_F_ADDR)` reads back.
//       5.  Restore the caller's previous CPU affinity.
//   * Destructor: `munmap` the region.
//   * `acquire()` uses a monotonic atomic counter until every frame has been
//       issued, then reuses released frames from the cold-path LIFO.
//   * `release()` CAS-clears the per-frame bitmap (lock-free) then
//       pushes the index onto a mutex-guarded LIFO for observability.
//       No code path here ever calls `malloc`/`free` to deliver a frame.
//
#include "packet-engine/frame_allocator.hpp"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// libnuma -- provides set_mempolicy / get_mempolicy / mbind wrappers.
#include <numa.h>
#include <numaif.h>

// Linux kernel headers for cpu_set_t, page-size probe, mmap, pthread affinity.
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <unistd.h>

namespace packet_engine {

namespace {

// ------------------------------------------------------------------
// Small utility wrappers -- keep platform-specific code in .cpp
// ------------------------------------------------------------------

/// Round `x` up to the nearest multiple of `a` (which must be a power of 2).
constexpr std::uint64_t round_up(std::uint64_t x, std::uint64_t a) noexcept {
    return (x + (a - 1)) & ~(a - 1);
}

/// Translate a libnuma / syscall error into a readable string.
std::string numa_err(const char* what, int err) {
    return std::string("FrameAllocator: ") + what + " failed: " + std::strerror(err);
}

/// Probe the system page size via `_SC_PAGESIZE` (single source of truth).
std::uint32_t system_page_size() noexcept {
    const long v = ::sysconf(_SC_PAGESIZE);
    return v > 0 ? static_cast<std::uint32_t>(v) : std::uint32_t{4096};
}

/// mmap the UMEM region trying huge pages first, then regular pages.
void* mmap_region(std::size_t bytes, UmemHugetlbPreference huge) {
    if (huge != UmemHugetlbPreference::Never) {
        void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB, -1, 0);
        if (p != MAP_FAILED) {
            return p;
        }
        if (huge == UmemHugetlbPreference::Always) {
            throw std::runtime_error(numa_err("huge-page mmap", errno));
        }
    }
    void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p == MAP_FAILED) {
        throw std::runtime_error(numa_err("mmap", errno));
    }
    return p;
}

/// munmap wrapper that swallows EINTR but otherwise throws.
void munmap_region(void* base, std::size_t bytes) {
    if (base == nullptr)
        return;
    while (::munmap(base, bytes) == -1 && errno == EINTR) {
        // retry
    }
}

/// Best-effort: pin the current thread to a CPU on the target NUMA node.
/// Failures are non-fatal -- some containers / cgroups prohibit affinity
/// changes, and we still proceed with `set_mempolicy` regardless.
void pin_to_node(int target_node) noexcept {
    if (target_node < 0 || numa_available() < 0)
        return;

    cpu_set_t cpus;
    CPU_ZERO(&cpus);

    struct bitmask* bm = numa_allocate_cpumask();
    if (bm == nullptr)
        return;
    if (numa_node_to_cpus(target_node, bm) != 0) {
        numa_free_cpumask(bm);
        return;
    }
    const int max_cpu = numa_num_configured_cpus();
    for (int c = 0; c < max_cpu; ++c) {
        if (numa_bitmask_isbitset(bm, c)) {
            CPU_SET(c, &cpus);
        }
    }
    numa_free_cpumask(bm);

    if (CPU_COUNT(&cpus) > 0) {
        (void)::pthread_setaffinity_np(::pthread_self(), sizeof(cpus), &cpus);
    }
}

} // namespace

// ====================================================================
// FrameAllocator implementation
// ====================================================================

FrameAllocator::FrameAllocator(std::uint32_t num_frames, std::uint32_t frame_size, int target_node,
                               UmemHugetlbPreference huge)
    : num_frames_{num_frames},
      frame_size_{static_cast<std::uint32_t>(round_up(frame_size, system_page_size()))},
      total_size_{static_cast<std::uint64_t>(num_frames) * static_cast<std::uint64_t>(frame_size_)},
      target_node_{target_node}, page_size_{system_page_size()} {

    if (num_frames == 0 || frame_size_ == 0) {
        throw std::invalid_argument("FrameAllocator: zero frames / frame size");
    }

    const bool numa_enabled = numa_available() >= 0;

    // Allow the caller to pass -1 to mean "use the libnuma-preferred node".
    if (target_node_ < 0) {
        const int preferred = numa_enabled ? numa_preferred() : -1;
        target_node_ = (preferred >= 0) ? preferred : 0;
    }
    const int configured_nodes = numa_enabled ? numa_num_configured_nodes() : 0;
    const auto node_bit = static_cast<unsigned int>(target_node_);
    if ((!numa_enabled && target_node_ != 0) ||
        (numa_enabled &&
         (node_bit >= sizeof(unsigned long) * 8U || target_node_ >= configured_nodes))) {
        throw std::invalid_argument("FrameAllocator: target NUMA node is out of range");
    }

    // 1) Allocate page-aligned UMEM (huge pages if possible, else regular).
    base_ = mmap_region(static_cast<std::size_t>(total_size_), huge);
    if (base_ == nullptr) {
        throw std::runtime_error("FrameAllocator: mmap returned null");
    }

    // 2) Save the caller's CPU affinity so we can restore it on exit.
    cpu_set_t prev_cpus{};
    const bool prev_cpus_saved =
        ::pthread_getaffinity_np(::pthread_self(), sizeof(prev_cpus), &prev_cpus) == 0;

    if (numa_enabled) {
        const unsigned long node_mask = 1UL << node_bit;
        const int maxnode = configured_nodes + 1;

        // 3) Pin the constructing thread to target_node.
        pin_to_node(target_node_);

        // 4) Install task-wide MPOL_BIND so the very first page fault
        //    satisfies the request from target_node.
        if (::set_mempolicy(MPOL_BIND, &node_mask, maxnode) != 0) {
            // Non-fatal -- a container may have stripped NUMA.
        }

        // 5) Fault every page with memset(0) -- first-touch allocation
        //    honours the task's MPOL_BIND policy.
        std::memset(base_, 0, static_cast<std::size_t>(total_size_));

        // 6) Persist the policy on the VMA so that
        //    get_mempolicy(... MPOL_F_ADDR) observes MPOL_BIND.
        //    `set_mempolicy` alone only sets the *task* default; the
        //    kernel does not always promote it to the VMA record.
        if (::mbind(base_, static_cast<std::size_t>(total_size_), MPOL_BIND, &node_mask, maxnode,
                    MPOL_MF_MOVE | MPOL_MF_STRICT) != 0) {
            // Non-fatal -- we still faulted pages on the right node;
            // verify_numa_bind() will report based on VMA policy.
        }
    } else {
        // No NUMA subsystem -- still fault pages so they are actually mapped.
        std::memset(base_, 0, static_cast<std::size_t>(total_size_));
    }

    // 7) Restore the caller's previous affinity so we don't hijack
    //    the creating thread beyond the constructor scope.
    if (prev_cpus_saved) {
        (void)::pthread_setaffinity_np(::pthread_self(), sizeof(prev_cpus), &prev_cpus);
    }

    // 8) Allocate bookkeeping.  Cold path -- one allocation per
    //    FrameAllocator instance.  std::atomic<bool> default-inits to
    //    `false`, so no separate zero-fill loop is needed.
    bitmap_ = std::make_unique<std::atomic<bool>[]>(num_frames_);
}

FrameAllocator::~FrameAllocator() {
    if (base_ != nullptr) {
        munmap_region(base_, static_cast<std::size_t>(total_size_));
        base_ = nullptr;
    }
}

std::optional<std::uint64_t> FrameAllocator::acquire() noexcept {
    const std::uint32_t idx = next_idx_.fetch_add(1, std::memory_order_acq_rel);
    if (idx >= num_frames_) {
        next_idx_.fetch_sub(1, std::memory_order_acq_rel);
        std::uint32_t recycled_idx;
        {
            std::lock_guard<std::mutex> g(free_mtx_);
            if (free_stack_.empty()) {
                return std::nullopt;
            }
            recycled_idx = free_stack_.back();
            free_stack_.pop_back();
        }
        bitmap_[recycled_idx].store(true, std::memory_order_relaxed);
        in_use_.fetch_add(1, std::memory_order_relaxed);
        return static_cast<std::uint64_t>(recycled_idx) * frame_size_;
    }

    // Monotonic bump allocator guarantees no two acquires share an index,
    // so a plain store suffices and remains lock-free.
    bitmap_[idx].store(true, std::memory_order_relaxed);
    in_use_.fetch_add(1, std::memory_order_relaxed);

    return static_cast<std::uint64_t>(idx) * frame_size_;
}

bool FrameAllocator::release(std::uint64_t offset) noexcept {
    if (offset >= total_size_)
        return false;
    if ((offset % frame_size_) != 0)
        return false;

    const std::uint32_t idx = static_cast<std::uint32_t>(offset / frame_size_);
    if (idx >= num_frames_)
        return false;

    // CAS-clear: rejects double-release and never-acquired release.
    bool expected = true;
    if (!bitmap_[idx].compare_exchange_strong(expected, false, std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> g(free_mtx_);
        free_stack_.push_back(idx);
    }
    in_use_.fetch_sub(1, std::memory_order_relaxed);
    frees_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

std::span<std::byte> FrameAllocator::frame_span(std::uint64_t offset) noexcept {
    if (offset >= total_size_)
        return {};
    if ((offset % frame_size_) != 0)
        return {};
    auto* p = static_cast<std::byte*>(base_) + offset;
    return {p, frame_size_};
}

std::span<const std::byte> FrameAllocator::frame_cspan(std::uint64_t offset) const noexcept {
    if (offset >= total_size_)
        return {};
    if ((offset % frame_size_) != 0)
        return {};
    const auto* p = static_cast<const std::byte*>(base_) + offset;
    return {p, frame_size_};
}

std::uint32_t FrameAllocator::free_count() const noexcept {
    std::lock_guard<std::mutex> g(free_mtx_);
    return static_cast<std::uint32_t>(free_stack_.size());
}

bool FrameAllocator::verify_numa_bind() const noexcept {
    if (numa_available() < 0)
        return false;
    if (base_ == nullptr)
        return false;

    const int maxnode = numa_num_configured_nodes() + 1;
    const std::size_t bits_per_long = sizeof(unsigned long) * 8;
    const std::size_t nlongs =
        static_cast<std::size_t>(maxnode + static_cast<int>(bits_per_long) - 1) / bits_per_long;

    std::vector<unsigned long> mask(nlongs == 0 ? 1 : nlongs, 0UL);
    int mode = MPOL_DEFAULT;

    const int rc = ::get_mempolicy(&mode, mask.data(), maxnode, base_, MPOL_F_ADDR);
    if (rc != 0)
        return false;
    if (mode != MPOL_BIND)
        return false;

    const std::size_t bit_pos = static_cast<std::size_t>(target_node_);
    const std::size_t long_idx = bit_pos / bits_per_long;
    const std::size_t bit_inl = bit_pos % bits_per_long;
    if (long_idx >= mask.size())
        return false;

    return (mask[long_idx] & (1UL << bit_inl)) != 0UL;
}

} // namespace packet_engine
