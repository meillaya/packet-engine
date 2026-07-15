// SPDX-License-Identifier: MIT
//
// frame_allocator.hpp -- NUMA-aware UMEM frame allocator.
//
// Design
// ======
//
// A packet engine over AF_XDP / DPDK pins a single contiguous, page-aligned
// region of memory (the *UMEM*).  NICs write DMA descriptors into this
// region directly; userspace never copies packet bytes out of it.  A
// *frame* is a fixed-size slot inside that region whose byte offset is
// what the kernel returns in RX descriptors.
//
// `FrameAllocator` is the structure that:
//   * owns the UMEM (mmap'd on construction, munmap'd on destruction);
//   * binds its physical pages to a target NUMA node using libnuma's
//     `set_mempolicy(MPOL_BIND, ...)` + first-touch `memset`, with an
//     explicit `mbind` afterwards so that the kernel records the policy
//     in the VMA itself -- the only way a `get_mempolicy(... MPOL_F_ADDR)`
//     downstream probe (rule engine, test harness) can observe the bind;
//   * hands out never-issued frame offsets through a monotonic atomic counter;
//   * reclaims released frames through a mutex-guarded cold-path LIFO stack.
//
// Initial acquisition is a single `fetch_add`; only acquisition from the
// recycled-frame LIFO takes its mutex.  No path spins or allocates.
//
// Thread safety
// -------------
//   `acquire()` and `release()` may be called concurrently. Construction and
//   destruction are single-threaded.
//
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace packet_engine {

/// Tag type selecting the page-size variant the caller would prefer.
/// The allocator tries huge pages first and gracefully falls back to
/// regular 4 KiB pages when huge pages are unavailable.
enum class UmemHugetlbPreference {
    Auto,   ///< Try huge pages; fall back to regular.
    Always, ///< Require huge pages; throw on failure.
    Never,  ///< Use regular pages only.
};

/// NUMA-aware UMEM frame allocator.  See file-level docs.
class alignas(128) FrameAllocator {
  public:
    /// Default values match a typical 16 MiB AF_XDP UMEM region
    /// (4096 frames of 4096 bytes each).
    static constexpr std::uint32_t DEFAULT_NUM_FRAMES = 4096;
    static constexpr std::uint32_t DEFAULT_FRAME_SIZE = 4096;

    /// Construct an allocator that owns `num_frames * frame_size` bytes of
    /// page-aligned, NUMA-bound memory.
    ///
    /// @param num_frames     Number of frames inside the UMEM.
    /// @param frame_size     Size of one frame in bytes; rounded up to a
    ///                       multiple of the system page size.
    /// @param target_node    NUMA node the UMEM will be bound to.  -1 means
    ///                       "local" (inherit the calling thread's node).
    /// @param huge           Huge-page strategy; see `UmemHugetlbPreference`.
    ///
    /// Throws `std::runtime_error` when allocation or NUMA binding fails.
    FrameAllocator(std::uint32_t num_frames, std::uint32_t frame_size, int target_node = 0,
                   UmemHugetlbPreference huge = UmemHugetlbPreference::Auto);

    ~FrameAllocator();

    FrameAllocator(const FrameAllocator&) = delete;
    FrameAllocator& operator=(const FrameAllocator&) = delete;

    // Moving a FrameAllocator would require pointer/atomic fixups; not worth it.
    FrameAllocator(FrameAllocator&&) = delete;
    FrameAllocator& operator=(FrameAllocator&&) = delete;

    /// Hand out the next free frame offset.
    ///
    /// Returns a byte offset in `[0, num_frames * frame_size)` that is a
    /// multiple of `frame_size()`, or `std::nullopt` if the pool is
    /// exhausted.  Never-issued frames use an atomic bump counter; acquiring
    /// a recycled frame briefly locks the reclaimed-frame stack.
    [[nodiscard]] std::optional<std::uint64_t> acquire() noexcept;

    /// Return a frame to the pool.
    ///
    /// @return `true` if `offset` was a valid in-flight frame and has now
    ///         been recycled; `false` if the offset is misaligned, out of
    ///         range, or has already been released.
    [[nodiscard]] bool release(std::uint64_t offset) noexcept;

    /// Borrow a writable span over the bytes of a specific frame.
    ///
    /// The caller is responsible for ensuring that `offset` was obtained
    /// from `acquire()` and that the same offset is not used concurrently
    /// from two threads.
    ///
    /// @return Empty span if the offset is misaligned or out of range.
    [[nodiscard]] std::span<std::byte> frame_span(std::uint64_t offset) noexcept;

    /// Read-only counterpart of `frame_span()`.
    [[nodiscard]] std::span<const std::byte> frame_cspan(std::uint64_t offset) const noexcept;

    // ---------------------------------------------------------------------
    // Observers
    // ---------------------------------------------------------------------

    [[nodiscard]] std::uint32_t num_frames() const noexcept { return num_frames_; }
    [[nodiscard]] std::uint32_t frame_size() const noexcept { return frame_size_; }
    [[nodiscard]] std::uint64_t total_size() const noexcept { return total_size_; }
    [[nodiscard]] int target_node() const noexcept { return target_node_; }

    [[nodiscard]] std::uint32_t in_use() const noexcept {
        return in_use_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::uint32_t free_count() const noexcept;

    /// Base address of the UMEM region.  Always page-aligned and non-null
    /// for a successfully-constructed allocator.  Exposed for the OS-level
    /// policy probes (`get_mempolicy(...MPOL_F_ADDR)`) used by the test
    /// harness and the rule engine.
    [[nodiscard]] void* base() noexcept { return base_; }
    [[nodiscard]] const void* cbase() const noexcept { return base_; }

    /// Best-effort probe that asks the kernel for the NUMA policy applied
    /// to the UMEM VMA.  Returns `true` if the kernel reports
    /// `MPOL_BIND` with `target_node` bit set.
    [[nodiscard]] bool verify_numa_bind() const noexcept;

  private:
    // Region parameters.  `num_frames_`, `frame_size_`, `total_size_`
    // are baked at construction; `target_node_` is fixed once we resolve
    // the -1 ("inherit") default in the constructor body.
    const std::uint32_t num_frames_;
    const std::uint32_t frame_size_;
    const std::uint64_t total_size_;
    int target_node_;
    const std::uint32_t page_size_;

    // UMEM base pointer.  Always page-aligned on construction.
    void* base_{nullptr};

    // Monotonic bump counter: slot index of the next *never-issued* frame.
    // When `next_idx_ == num_frames_` the pool is exhausted.
    alignas(64) std::atomic<std::uint32_t> next_idx_{0};

    // Counters for observability (lock-free reads, lock-free increments).
    alignas(64) std::atomic<std::uint32_t> in_use_{0};
    alignas(64) std::atomic<std::uint32_t> frees_{0};

    // Cold-path LIFO of recycled frames.
    mutable std::mutex free_mtx_;
    std::vector<std::uint32_t> free_stack_;

    // Per-frame occupancy bitmap.  `acquire()` does an uncontended
    // `store(true)` and `release()` does a CAS-clear -- both fully
    // lock-free, no external mutex required.
    std::unique_ptr<std::atomic<bool>[]> bitmap_;
};

} // namespace packet_engine
