// SPDX-License-Identifier: MIT
//
// mock_bpf.h -- libbpf abstraction mock for unit-testing BpfLoader.
//
// Why an `IBpfOps` mock
// =====================
//
// `libbpf` requires root, a real BPF filesystem, and a real ELF object.
// We cannot satisfy any of those in CI, so `BpfLoader` calls libbpf
// through the `IBpfOps` interface (see `bpf_loader.hpp`).  This header
// supplies `MockBpfOps` -- an `IBpfOps` implementation that allocates
// fake `bpf_object*` / `bpf_link*` handles in process-local memory and
// records every call so the unit test can assert ordering and argument
// propagation.
//
// What the mock owns
// ------------------
//
// * `MockObject` / `MockMap` / `MockProgram` / `MockLink` -- lightweight
//   POD wrappers around an integer id so the production code can hold
//   non-null pointers and the tests can identify each handle.
// * Call counters (`open_file_calls_`, `attach_xdp_calls_`, ...) and
//   argument mirrors (`last_attached_ifindex_`, `last_xsks_map_fd_`, ...)
//   so assertions are straightforward.
// * Failure-injection knobs: `fail_open_file_`, `fail_load_`,
//   `fail_attach_xdp_` -- each one returns NULL (or a non-zero value)
//   for the corresponding call.  Default behaviour is "everything
//   succeeds".
//
// Header-only
// -----------
// The whole mock is inline; no `.cpp` to wire into the build.  This keeps
// the parallel Wave-2 glob at `tests/CMakeLists.txt` simple.
//
#pragma once

#include <memory>
#include <string>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "packet-engine/bpf_loader.hpp"

namespace packet_engine::testing {

// ---------------------------------------------------------------------------
// Mock handles
//
// The production loader only ever compares pointers for nullity and passes
// them along to libbpf; it never dereferences them.  We therefore use
// minimal stand-ins whose only purpose is to be non-null and uniquely
// identifiable in test assertions.
// ---------------------------------------------------------------------------
struct MockObject {
    int id = 1001;
};
struct MockMap {
    int id = 2001;
};
struct MockProgram {
    int id = 3001;
};
struct MockLink {
    int id = 4001;
};

// ---------------------------------------------------------------------------
// MockBpfOps
// ---------------------------------------------------------------------------
class MockBpfOps final : public IBpfOps {
  public:
    MockBpfOps() = default;
    ~MockBpfOps() override = default;

    // ---- Failure injection knobs --------------------------------------
    //
    // Tests flip any of these to true before invoking the code under
    // test.  The corresponding method then returns nullptr / non-zero,
    // exactly like a real libbpf call would.
    bool fail_open_file_{false};
    bool fail_load_{false};
    bool fail_attach_xdp_{false};
    bool fail_destroy_link_{false};

    // ---- IBpfOps ------------------------------------------------------
    struct bpf_object* open_file(const char* path) override {
        last_open_path_ = path ? std::string(path) : std::string{};
        ++open_file_calls_;
        if (fail_open_file_) {
            return nullptr;
        }
        object_storage_ = std::make_unique<MockObject>();
        return reinterpret_cast<struct bpf_object*>(object_storage_.get());
    }

    int load(struct bpf_object* obj) override {
        ++load_calls_;
        if (obj == nullptr)
            return -EINVAL;
        if (fail_load_)
            return -EIO;
        return 0;
    }

    void close(struct bpf_object* obj) override {
        ++close_calls_;
        if (obj != nullptr) {
            object_storage_.reset();
        }
    }

    struct bpf_map* find_map_by_name(struct bpf_object* obj, const char* name) override {
        (void)obj;
        last_find_map_name_ = name ? std::string(name) : std::string{};
        ++find_map_calls_;
        map_storage_ = std::make_unique<MockMap>();
        return reinterpret_cast<struct bpf_map*>(map_storage_.get());
    }

    struct bpf_program* find_program_by_name(struct bpf_object* obj, const char* name) override {
        (void)obj;
        last_find_program_name_ = name ? std::string(name) : std::string{};
        ++find_program_calls_;
        program_storage_ = std::make_unique<MockProgram>();
        return reinterpret_cast<struct bpf_program*>(program_storage_.get());
    }

    int map_fd(const struct bpf_map* map) override {
        (void)map;
        ++map_fd_calls_;
        return kXsksMapFd;
    }

    struct bpf_link* attach_xdp(struct bpf_program* prog, int ifindex) override {
        ++attach_xdp_calls_;
        last_attached_prog_ = prog;
        last_attached_ifindex_ = ifindex;
        if (fail_attach_xdp_) {
            return nullptr;
        }
        link_storage_ = std::make_unique<MockLink>();
        return reinterpret_cast<struct bpf_link*>(link_storage_.get());
    }

    int destroy_link(struct bpf_link* link) override {
        ++destroy_link_calls_;
        if (fail_destroy_link_)
            return -EIO;
        if (link != nullptr) {
            link_storage_.reset();
        }
        return 0;
    }

    unsigned int if_nametoindex(const char* ifname) override {
        last_nametoindex_name_ = ifname ? std::string(ifname) : std::string{};
        ++if_nametoindex_calls_;
        if (last_nametoindex_name_.empty())
            return 0;
        return kMockIfindex;
    }

    // ---- Test knobs / observers ---------------------------------------
    static constexpr int kMockIfindex = 7;
    static constexpr int kXsksMapFd = 17;

    int open_file_calls() const noexcept { return open_file_calls_; }
    int load_calls() const noexcept { return load_calls_; }
    int close_calls() const noexcept { return close_calls_; }
    int find_map_calls() const noexcept { return find_map_calls_; }
    int find_program_calls() const noexcept { return find_program_calls_; }
    int map_fd_calls() const noexcept { return map_fd_calls_; }
    int attach_xdp_calls() const noexcept { return attach_xdp_calls_; }
    int destroy_link_calls() const noexcept { return destroy_link_calls_; }
    int if_nametoindex_calls() const noexcept { return if_nametoindex_calls_; }

    const std::string& last_open_path() const noexcept { return last_open_path_; }
    const std::string& last_find_map_name() const noexcept { return last_find_map_name_; }
    const std::string& last_find_program_name() const noexcept { return last_find_program_name_; }
    int last_attached_ifindex() const noexcept { return last_attached_ifindex_; }
    struct bpf_program* last_attached_prog() const noexcept { return last_attached_prog_; }
    const std::string& last_nametoindex_name() const noexcept { return last_nametoindex_name_; }

    bool has_object() const noexcept { return object_storage_ != nullptr; }
    bool has_map() const noexcept { return map_storage_ != nullptr; }
    bool has_program() const noexcept { return program_storage_ != nullptr; }
    bool has_link() const noexcept { return link_storage_ != nullptr; }

  private:
    // Owned state -------------------------------------------------------
    std::unique_ptr<MockObject> object_storage_;
    std::unique_ptr<MockMap> map_storage_;
    std::unique_ptr<MockProgram> program_storage_;
    std::unique_ptr<MockLink> link_storage_;

    // Call counters -----------------------------------------------------
    int open_file_calls_{0};
    int load_calls_{0};
    int close_calls_{0};
    int find_map_calls_{0};
    int find_program_calls_{0};
    int map_fd_calls_{0};
    int attach_xdp_calls_{0};
    int destroy_link_calls_{0};
    int if_nametoindex_calls_{0};

    // Argument mirrors --------------------------------------------------
    std::string last_open_path_;
    std::string last_find_map_name_;
    std::string last_find_program_name_;
    int last_attached_ifindex_{-1};
    struct bpf_program* last_attached_prog_{nullptr};
    std::string last_nametoindex_name_;
};

} // namespace packet_engine::testing