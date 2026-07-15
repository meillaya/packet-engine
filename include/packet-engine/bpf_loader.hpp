// SPDX-License-Identifier: MIT
//
// bpf_loader.hpp -- BPF program loader + XDP attachment for the packet engine.
//
// Architecture
// ============
//
// `BpfLoader` owns the lifecycle of one `bpf_object` (the ELF produced by
// `bpf/af_xdp_kern.bpf.c`) and one `bpf_link` (the XDP attachment to a
// network interface).  The loader is the only owner of these opaque libbpf
// handles -- the rest of the engine interacts with them exclusively via
// `link_fd()` / `is_attached()` / `detach()`.
//
// All libbpf calls are funnelled through the `IBpfOps` abstract interface.
// In production the `LibBpfOps` implementation forwards to the symbols in
// `libbpf.so` (libbpf >= 1.4, we test against 1.7).  In unit tests a
// GoogleMock-friendly fake (`tests/mocks/mock_bpf.h`) substitutes so the
// entire attach/detach lifecycle can be exercised without root, without a
// real NIC, and without `LIBXDP_OBJECT_PATH` set.
//
// Lifetimes
// =========
//
// * Constructor: takes a reference to the `AfXdpBackend` (used to pull the
//   `xsk_socket*` and `xsk_fd` so the XSKMAP can be updated after the BPF
//   object has been loaded), plus optional `IXskOps*` and `IBpfOps*`
//   dependency injection points.  When null, `LibXdpOps` / `LibBpfOps`
//   are constructed internally.
// * `load_and_attach(ifname)`:
//     1. Open the BPF object file (`bpf_object__open_file`).
//     2. Load it into the kernel (`bpf_object__load`).
//     3. Find the `xsks_map` and pull its fd.
//     4. Resolve the ifname via `if_nametoindex` and the
//        `xsk_redirect_prog` program via `bpf_object__find_program_by_name`.
//     5. Update the XSKMAP via `xsk_socket__update_xskmap` so the running
//        XDP program can redirect packets into the AF_XDP socket.
//     6. Attach via `bpf_program__attach_xdp(prog, ifindex)`.  libbpf 1.7
//        picks the native driver mode by default (with automatic fallback
//        to SKB mode if the NIC has no native XDP support); the engine
//        therefore uses the veth harness path without `XDP_FLAGS_SKB_MODE`.
//     7. Stash the resulting `bpf_link*` for later detach.
// * `detach()`: `bpf_link__destroy` (idempotent) then `bpf_object__close`.
// * Destructor: calls `detach()`.
//
// Idempotency
// ===========
//
// `detach()` is safe to call multiple times.  The second and subsequent
// calls are silent no-ops, matching the engine-wide idempotency contract
// for shutdown paths.  `load_and_attach()` is single-shot: calling it on
// an already-attached loader throws `std::runtime_error`.
//
#pragma once

#include <memory>
#include <string_view>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#include "packet-engine/backend_af_xdp.hpp"

namespace packet_engine {

// Opaque libbpf types (`bpf_object`, `bpf_map`, `bpf_program`, `bpf_link`)
// are declared by `<bpf/libbpf.h>` above; the loader only handles pointers.

// ---------------------------------------------------------------------------
// Abstract libbpf operations interface.
//
// Every libbpf / xsk call site that `BpfLoader` uses is exposed as a pure
// virtual method.  The production implementation (`LibBpfOps`) forwards
// to the symbols in `libbpf.so`; tests substitute their own mock so the
// entire loader can be exercised without root.
// ---------------------------------------------------------------------------
class IBpfOps {
  public:
    virtual ~IBpfOps() = default;

    // ---- BPF object lifecycle ------------------------------------------
    virtual struct bpf_object* open_file(const char* path) = 0;
    virtual int load(struct bpf_object* obj) = 0;
    virtual void close(struct bpf_object* obj) = 0;

    // ---- Lookup helpers -----------------------------------------------
    virtual struct bpf_map* find_map_by_name(struct bpf_object* obj, const char* name) = 0;
    virtual struct bpf_program* find_program_by_name(struct bpf_object* obj, const char* name) = 0;
    virtual int map_fd(const struct bpf_map* map) = 0;

    // ---- XDP attach / detach ------------------------------------------
    virtual struct bpf_link* attach_xdp(struct bpf_program* prog, int ifindex) = 0;
    virtual int destroy_link(struct bpf_link* link) = 0;

    // ---- Interface index resolution -----------------------------------
    virtual unsigned int if_nametoindex(const char* ifname) = 0;
};

// Concrete libbpf-backed implementation of `IBpfOps`.  Pure forwarder; all
// the heavy lifting lives in `libbpf.so` / `libxdp.so`.
class LibBpfOps final : public IBpfOps {
  public:
    struct bpf_object* open_file(const char* path) override;
    int load(struct bpf_object* obj) override;
    void close(struct bpf_object* obj) override;

    struct bpf_map* find_map_by_name(struct bpf_object* obj, const char* name) override;
    struct bpf_program* find_program_by_name(struct bpf_object* obj, const char* name) override;
    int map_fd(const struct bpf_map* map) override;

    struct bpf_link* attach_xdp(struct bpf_program* prog, int ifindex) override;
    int destroy_link(struct bpf_link* link) override;

    unsigned int if_nametoindex(const char* ifname) override;
};

// ---------------------------------------------------------------------------
// BpfLoader
// ---------------------------------------------------------------------------
class BpfLoader {
  public:
    /// Absolute path to the BPF object produced by this build.
    static const char* const kDefaultBpfObjectPath;

    /// Name of the XSKMAP BPF map inside the object.  Must match the
    /// `xsks_map` declaration in `bpf/af_xdp_kern.bpf.c`.
    static constexpr const char* kXsksMapName = "xsks_map";

    /// Name of the XDP program inside the object.  Must match the SEC name
    /// `xdp` / function `xsk_redirect_prog` in `bpf/af_xdp_kern.bpf.c`.
    static constexpr const char* kProgramName = "xsk_redirect_prog";

    /// Construct the loader without loading anything.
    ///
    /// @param backend   Already-initialised `AfXdpBackend` whose XSK fd /
    ///                  socket pointer is wired into the XSKMAP during
    ///                  `load_and_attach()`.  Must outlive the loader.
    /// @param xsk_ops   DI for the `xsk_socket__update_xskmap` call.  When
    ///                  nullptr, a `LibXdpOps` instance is constructed.
    /// @param bpf_ops   DI for the libbpf calls.  When nullptr, a
    ///                  `LibBpfOps` instance is constructed.
    explicit BpfLoader(AfXdpBackend& backend, IXskOps* xsk_ops = nullptr,
                       IBpfOps* bpf_ops = nullptr);

    ~BpfLoader();

    BpfLoader(const BpfLoader&) = delete;
    BpfLoader& operator=(const BpfLoader&) = delete;
    BpfLoader(BpfLoader&&) = delete;
    BpfLoader& operator=(BpfLoader&&) = delete;

    /// Open the BPF object, load it into the kernel, find the program /
    /// map, update the XSKMAP, and attach the XDP program to `ifname`.
    ///
    /// Throws `std::runtime_error` on any libbpf/libxdp failure; on
    /// failure the loader is left in the same state as before the call
    /// (no half-attached resources).
    void load_and_attach(std::string_view ifname);

    /// Idempotent detach.  Safe to call multiple times and from the
    /// destructor.  Tears down the XDP link first, then closes the BPF
    /// object.  After `detach()` returns, `is_attached()` is false and
    /// `load_and_attach()` may be called again with a fresh BPF object.
    void detach();

    // ---- Observers -----------------------------------------------------
    [[nodiscard]] bool is_attached() const noexcept { return link_ != nullptr; }
    [[nodiscard]] struct bpf_link* link() const noexcept { return link_; }
    [[nodiscard]] struct bpf_object* object() const noexcept { return obj_; }

    /// File descriptor of the attached `bpf_link`.  Returns -1 when not
    /// attached.  Surfaced so integration tests can correlate with
    /// `bpftool link show`.
    [[nodiscard]] int link_fd() const noexcept;

    /// Whether `load_and_attach()` has succeeded at least once.
    [[nodiscard]] bool is_loaded() const noexcept { return obj_ != nullptr; }

  private:
    AfXdpBackend& backend_;
    std::unique_ptr<IXskOps> owned_xsk_ops_;
    IXskOps* xsk_ops_;
    std::unique_ptr<IBpfOps> owned_bpf_ops_;
    IBpfOps* bpf_ops_;

    struct bpf_object* obj_{nullptr};
    struct bpf_link* link_{nullptr};
};

} // namespace packet_engine
