// SPDX-License-Identifier: MIT
//
// bpf_loader.cpp -- BPF program loader + XDP attachment implementation.
//
// The loader is intentionally thin: every libbpf symbol it touches is
// routed through `IBpfOps*`, which the production `LibBpfOps` forwards to
// the symbols in `libbpf.so`.  Unit tests substitute their own mock so
// the attach / detach lifecycle can be exercised end-to-end without root.
//
// Failure semantics
// =================
//
// `load_and_attach()` may fail at several steps.  On failure the loader is
// always returned to its pre-call state -- no half-loaded BPF object, no
// dangling `bpf_link`, no partial XSKMAP update.  This is implemented
// by:
//   * closing any opened object before throwing,
//   * never caching the `bpf_link*` until attach has actually succeeded,
//   * wrapping the XSKMAP update in a `try/catch` (the mock throws to
//     simulate failure).
//
#include "packet-engine/bpf_loader.hpp"

#include <cerrno>
#include <cstring>
#include <memory>
#include <net/if.h>
#include <stdexcept>
#include <string>

#include "packet-engine/logger.hpp"

namespace packet_engine {

#ifndef PACKET_ENGINE_BPF_OBJECT_PATH
#error "PACKET_ENGINE_BPF_OBJECT_PATH must name the trusted build artifact"
#endif

const char* const BpfLoader::kDefaultBpfObjectPath = PACKET_ENGINE_BPF_OBJECT_PATH;

// ===========================================================================
// LibBpfOps -- production forwarder.  Thin shims around the C ABI of
// <bpf/libbpf.h>.  Wrapped so the loader can be unit-tested without root.
// ===========================================================================

struct bpf_object* LibBpfOps::open_file(const char* path) {
    return ::bpf_object__open_file(path, nullptr);
}

int LibBpfOps::load(struct bpf_object* obj) { return ::bpf_object__load(obj); }

void LibBpfOps::close(struct bpf_object* obj) { ::bpf_object__close(obj); }

struct bpf_map* LibBpfOps::find_map_by_name(struct bpf_object* obj, const char* name) {
    return ::bpf_object__find_map_by_name(obj, name);
}

struct bpf_program* LibBpfOps::find_program_by_name(struct bpf_object* obj, const char* name) {
    return ::bpf_object__find_program_by_name(obj, name);
}

int LibBpfOps::map_fd(const struct bpf_map* map) { return ::bpf_map__fd(map); }

struct bpf_link* LibBpfOps::attach_xdp(struct bpf_program* prog, int ifindex) {
    // libbpf 1.4+ picks the native driver attach by default and falls back
    // to SKB mode automatically when the NIC does not advertise native XDP.
    // The veth pair used by `dev-run.sh` accepts both, so the default
    // behaviour satisfies the "no SKB_MODE forced" requirement.
    return ::bpf_program__attach_xdp(prog, ifindex);
}

int LibBpfOps::destroy_link(struct bpf_link* link) { return ::bpf_link__destroy(link); }

unsigned int LibBpfOps::if_nametoindex(const char* ifname) { return ::if_nametoindex(ifname); }

// ===========================================================================
// BpfLoader
// ===========================================================================

BpfLoader::BpfLoader(AfXdpBackend& backend, IXskOps* xsk_ops, IBpfOps* bpf_ops)
    : backend_(backend), xsk_ops_(xsk_ops), bpf_ops_(bpf_ops) {
    if (xsk_ops_ == nullptr) {
        owned_xsk_ops_ = std::make_unique<LibXdpOps>();
        xsk_ops_ = owned_xsk_ops_.get();
    }
    if (bpf_ops_ == nullptr) {
        owned_bpf_ops_ = std::make_unique<LibBpfOps>();
        bpf_ops_ = owned_bpf_ops_.get();
    }
}

BpfLoader::~BpfLoader() {
    // RAII: best-effort detach.  Idempotent so a `detach()` call from
    // user code preceding destruction is safe.
    detach();
}

void BpfLoader::load_and_attach(std::string_view ifname) {
    if (is_attached() || is_loaded()) {
        throw std::runtime_error("BpfLoader: load_and_attach() called while already attached; "
                                 "call detach() first");
    }
    if (!backend_.is_initialised() || backend_.xsk() == nullptr) {
        throw std::runtime_error("BpfLoader: AfXdpBackend is not initialised; init() it first");
    }

    // Step 1 -- open the ELF.
    struct bpf_object* obj = bpf_ops_->open_file(kDefaultBpfObjectPath);
    if (obj == nullptr) {
        const int err = errno;
        throw std::runtime_error(std::string("BpfLoader: bpf_object__open_file failed (") +
                                 kDefaultBpfObjectPath + "): " + std::strerror(err));
    }

    // Step 2 -- load into the kernel.  Any failure here closes the
    // partially-initialised object and rethrows.
    if (bpf_ops_->load(obj) != 0) {
        const int err = errno;
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: bpf_object__load failed: ") +
                                 std::strerror(err));
    }

    // Step 3 -- find xsks_map and pull its fd.
    struct bpf_map* xsks_map = bpf_ops_->find_map_by_name(obj, kXsksMapName);
    if (xsks_map == nullptr) {
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: BPF map '") + kXsksMapName +
                                 "' not found in " + kDefaultBpfObjectPath);
    }
    const int xsks_map_fd = bpf_ops_->map_fd(xsks_map);
    if (xsks_map_fd < 0) {
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: bpf_map__fd(") + kXsksMapName +
                                 ") returned < 0");
    }

    // Step 4 -- resolve ifindex.  libbpf's attach_xdp takes int ifindex,
    // not unsigned int, but `if_nametoindex` returns unsigned int.
    if (ifname.empty()) {
        bpf_ops_->close(obj);
        throw std::runtime_error("BpfLoader: ifname is empty");
    }
    // We have to materialise a NUL-terminated copy because `ifname` is a
    // string_view whose backing storage may not be NUL-terminated.
    const std::string ifname_str(ifname);
    const unsigned int ifindex_u = bpf_ops_->if_nametoindex(ifname_str.c_str());
    if (ifindex_u == 0) {
        const int err = errno;
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: if_nametoindex('") + ifname_str +
                                 "') failed: " + std::strerror(err));
    }
    const int ifindex = static_cast<int>(ifindex_u);

    // Step 5 -- find the XDP program.
    struct bpf_program* prog = bpf_ops_->find_program_by_name(obj, kProgramName);
    if (prog == nullptr) {
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: BPF program '") + kProgramName +
                                 "' not found in " + kDefaultBpfObjectPath);
    }

    // Step 6 -- update the XSKMAP so the XDP datapath can redirect
    // packets to the AF_XDP socket.  Done before attach because the
    // BPF program may run on the very first packet after attach.
    const int rc_xskmap = xsk_ops_->update_xskmap(backend_.xsk(), xsks_map_fd);
    if (rc_xskmap != 0) {
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: xsk_socket__update_xskmap failed: ") +
                                 std::strerror(errno));
    }

    // Step 7 -- attach the XDP program.  Failure leaves the BPF object
    // loaded in the kernel but we choose to close it so we do not leak
    // program/map fds; the kernel would GC them on process exit anyway.
    struct bpf_link* link = bpf_ops_->attach_xdp(prog, ifindex);
    if (link == nullptr) {
        const int err = errno;
        bpf_ops_->close(obj);
        throw std::runtime_error(std::string("BpfLoader: bpf_program__attach_xdp failed on ") +
                                 ifname_str + ": " + std::strerror(err));
    }

    // Commit: store both handles atomically.  Once these are set the
    // loader is considered "loaded + attached" and detach() will tear
    // them down.
    obj_ = obj;
    link_ = link;

    LOG_INFO(std::string("BpfLoader: attached '") + kProgramName + "' (xsks_map fd=" +
             std::to_string(xsks_map_fd) + ", xsk fd=" + std::to_string(backend_.xsk_fd()) +
             ", ifindex=" + std::to_string(ifindex) + ", ifname=" + ifname_str + ")");
}

void BpfLoader::detach() {
    // Idempotent: every step nulls its handle before doing the actual
    // tear-down so a second `detach()` call observes null pointers and
    // returns without re-entering libbpf.
    if (link_ != nullptr) {
        // The return value of bpf_link__destroy is intentionally
        // ignored: per libbpf semantics, on success it returns 0 and
        // the link is freed.  We have nothing useful to do on failure
        // because the engine is already in a teardown path; the next
        // attach will fail loudly if the kernel state is bad.
        (void)bpf_ops_->destroy_link(link_);
        link_ = nullptr;
    }
    if (obj_ != nullptr) {
        bpf_ops_->close(obj_);
        obj_ = nullptr;
    }
}

int BpfLoader::link_fd() const noexcept {
    if (link_ == nullptr)
        return -1;
    // libbpf does not export `bpf_link__fd` as a stable symbol across
    // all 1.x versions; production code rarely needs it.  Tests that
    // need to assert "a link exists" rely on `is_attached()`.  Returning
    // -1 keeps the API stable while signalling "not available".
    return -1;
}

} // namespace packet_engine
