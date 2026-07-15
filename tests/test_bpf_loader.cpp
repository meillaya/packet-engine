// SPDX-License-Identifier: MIT
//
// test_bpf_loader.cpp -- GoogleTest cases for BpfLoader.
//
// All tests run through MockBpfOps + MockXskOps so the entire attach /
// detach lifecycle can be exercised without root, without a real NIC,
// and without `LIBXDP_OBJECT_PATH` set.
//
// Coverage
// ========
//
// * Happy path:
//     - load_and_attach("lo") opens, loads, finds, updates xsks_map,
//       attaches
//     - link state reflects the attach
//     - detach() tears down link + object
// * Idempotency:
//     - detach() twice does not crash, does not re-call libbpf
//     - destructor after detach() does not re-call libbpf
//     - destructor without explicit detach() still cleans up
// * Argument propagation:
//     - the right map / program names are queried
//     - the right fd is passed to xsk_socket__update_xskmap
//     - the right ifindex is passed to bpf_program__attach_xdp
// * Failure paths:
//     - open_file failure -> no leak, loader remains detached
//     - load failure -> object closed, loader remains detached
//     - attach_xdp failure -> object closed, loader remains detached
//
#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>

#include "packet-engine/backend_af_xdp.hpp"
#include "packet-engine/bpf_loader.hpp"
#include "packet-engine/frame_allocator.hpp"

#include "mocks/mock_bpf.h"
#include "mocks/mock_xsk.h"

using packet_engine::AfXdpBackend;
using packet_engine::BpfLoader;
using packet_engine::FrameAllocator;
using packet_engine::testing::MockBpfOps;
using packet_engine::testing::MockXskOps;

namespace {

// RAII helper: spin up a `FrameAllocator` + `AfXdpBackend` initialised
// against a `MockXskOps`.  Used by every test fixture so the test bodies
// can stay focused on the loader behaviour.
struct BackendFixture {
    FrameAllocator allocator;
    MockXskOps xsk_ops;
    std::unique_ptr<AfXdpBackend> backend;

    explicit BackendFixture(std::uint32_t queue_id = 0)
        : allocator(FrameAllocator::DEFAULT_NUM_FRAMES, FrameAllocator::DEFAULT_FRAME_SIZE, 0) {
        backend = std::make_unique<AfXdpBackend>(allocator, "lo", queue_id, &xsk_ops);
        backend->init();
    }
};

// Helper: build a loader pointed at a fresh backend + mocks.
struct LoaderFixture {
    BackendFixture backend_fix;
    MockBpfOps bpf_ops;
    std::unique_ptr<BpfLoader> loader;

    explicit LoaderFixture(std::uint32_t queue_id = 0) : backend_fix(queue_id) {
        loader = std::make_unique<BpfLoader>(*backend_fix.backend, &backend_fix.xsk_ops, &bpf_ops);
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Construction & observer sanity
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, ConstructedDetached) {
    LoaderFixture f;
    EXPECT_FALSE(f.loader->is_attached());
    EXPECT_FALSE(f.loader->is_loaded());
    EXPECT_EQ(f.loader->link_fd(), -1);
}

TEST(BpfLoaderTest, DefaultOpsCreatedWhenNullptr) {
    BackendFixture bf;
    // Construct without DI: the loader must build its own LibXdpOps /
    // LibBpfOps.  We cannot call load_and_attach (no real BPF object),
    // but we can confirm construction does not throw.
    EXPECT_NO_THROW({
        BpfLoader loader(*bf.backend, nullptr, nullptr);
        EXPECT_FALSE(loader.is_attached());
    });
}

// ---------------------------------------------------------------------------
// Happy path: load_and_attach
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, LoadAndAttachHappyPath) {
    LoaderFixture f;
    EXPECT_NO_THROW(f.loader->load_and_attach("lo"));

    EXPECT_TRUE(f.loader->is_attached());
    EXPECT_TRUE(f.loader->is_loaded());

    // Each libbpf entry point should have been hit exactly once.
    EXPECT_EQ(f.bpf_ops.open_file_calls(), 1);
    EXPECT_EQ(f.bpf_ops.load_calls(), 1);
    EXPECT_EQ(f.bpf_ops.find_map_calls(), 1);
    EXPECT_EQ(f.bpf_ops.find_program_calls(), 1);
    EXPECT_EQ(f.bpf_ops.map_fd_calls(), 1);
    EXPECT_EQ(f.bpf_ops.if_nametoindex_calls(), 1);
    EXPECT_EQ(f.bpf_ops.attach_xdp_calls(), 1);

    // Object / link handles survived.
    EXPECT_NE(f.loader->object(), nullptr);
    EXPECT_NE(f.loader->link(), nullptr);

    // XSKMAP update went through the IXskOps seam.
    EXPECT_EQ(f.backend_fix.xsk_ops.update_xskmap_calls(), 1);
    EXPECT_EQ(f.backend_fix.xsk_ops.last_xsks_map_fd(), MockBpfOps::kXsksMapFd);

    // Object has not been closed yet.
    EXPECT_EQ(f.bpf_ops.close_calls(), 0);
}

TEST(BpfLoaderTest, ArgumentPropagation) {
    LoaderFixture f;
    f.loader->load_and_attach("veth0");

    // The expected names from bpf/af_xdp_kern.bpf.c must be queried.
    EXPECT_EQ(f.bpf_ops.last_open_path(), BpfLoader::kDefaultBpfObjectPath);
    EXPECT_EQ(f.bpf_ops.last_find_map_name(), BpfLoader::kXsksMapName);
    EXPECT_EQ(f.bpf_ops.last_find_program_name(), BpfLoader::kProgramName);

    // if_nametoindex was given the right ifname.
    EXPECT_EQ(f.bpf_ops.last_nametoindex_name(), "veth0");

    // attach_xdp saw the right ifindex.
    EXPECT_EQ(f.bpf_ops.last_attached_ifindex(), MockBpfOps::kMockIfindex);
    EXPECT_NE(f.bpf_ops.last_attached_prog(), nullptr);
}

TEST(BpfLoaderTest, DefaultObjectPathIsBoundToBuildArtifact) {
    // Given: the loader's compiled-in default object location.
    const std::filesystem::path object_path{BpfLoader::kDefaultBpfObjectPath};

    // When/Then: it names the build-produced object without consulting process CWD.
    EXPECT_TRUE(object_path.is_absolute());
    EXPECT_EQ(object_path.filename(), "af_xdp_kern.o");
    EXPECT_EQ(object_path.parent_path().filename(), "bpf");
}

// ---------------------------------------------------------------------------
// Detach lifecycle
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, DetachTearsDownLinkAndObject) {
    LoaderFixture f;
    f.loader->load_and_attach("lo");

    f.loader->detach();

    EXPECT_FALSE(f.loader->is_attached());
    EXPECT_FALSE(f.loader->is_loaded());
    EXPECT_EQ(f.loader->link(), nullptr);
    EXPECT_EQ(f.loader->object(), nullptr);

    // Exactly one close, exactly one destroy.
    EXPECT_EQ(f.bpf_ops.destroy_link_calls(), 1);
    EXPECT_EQ(f.bpf_ops.close_calls(), 1);
}

TEST(BpfLoaderTest, DetachIsIdempotent) {
    LoaderFixture f;
    f.loader->load_and_attach("lo");

    f.loader->detach();
    // Second call: must not crash, must not re-invoke libbpf.
    EXPECT_NO_THROW(f.loader->detach());
    EXPECT_NO_THROW(f.loader->detach());

    EXPECT_EQ(f.bpf_ops.destroy_link_calls(), 1);
    EXPECT_EQ(f.bpf_ops.close_calls(), 1);
}

TEST(BpfLoaderTest, DestructorDetachesAfterExplicitDetach) {
    BackendFixture bf;
    MockBpfOps bpf_ops;
    {
        BpfLoader loader(*bf.backend, &bf.xsk_ops, &bpf_ops);
        loader.load_and_attach("lo");
        loader.detach();
        EXPECT_EQ(bpf_ops.destroy_link_calls(), 1);
        EXPECT_EQ(bpf_ops.close_calls(), 1);
    }
    // Destructor must not call libbpf again.
    EXPECT_EQ(bpf_ops.destroy_link_calls(), 1);
    EXPECT_EQ(bpf_ops.close_calls(), 1);
}

TEST(BpfLoaderTest, DestructorDetachesWhenExplicitDetachOmitted) {
    BackendFixture bf;
    MockBpfOps bpf_ops;
    {
        BpfLoader loader(*bf.backend, &bf.xsk_ops, &bpf_ops);
        loader.load_and_attach("lo");
    }
    // RAII: the destructor must have torn down link + object.
    EXPECT_EQ(bpf_ops.destroy_link_calls(), 1);
    EXPECT_EQ(bpf_ops.close_calls(), 1);
}

TEST(BpfLoaderTest, DestructorIsNoOpWhenNeverAttached) {
    BackendFixture bf;
    MockBpfOps bpf_ops;
    {
        BpfLoader loader(*bf.backend, &bf.xsk_ops, &bpf_ops);
    }
    EXPECT_EQ(bpf_ops.destroy_link_calls(), 0);
    EXPECT_EQ(bpf_ops.close_calls(), 0);
}

// ---------------------------------------------------------------------------
// Double-attach protection
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, LoadAndAttachTwiceThrows) {
    LoaderFixture f;
    f.loader->load_and_attach("lo");

    EXPECT_THROW(f.loader->load_and_attach("lo"), std::runtime_error);
    // First attach's handles must still be intact.
    EXPECT_TRUE(f.loader->is_attached());
    EXPECT_EQ(f.bpf_ops.attach_xdp_calls(), 1);
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, OpenFileFailureLeavesLoaderDetached) {
    LoaderFixture f;
    f.bpf_ops.fail_open_file_ = true;

    EXPECT_THROW(f.loader->load_and_attach("lo"), std::runtime_error);
    EXPECT_FALSE(f.loader->is_attached());
    EXPECT_FALSE(f.loader->is_loaded());
    // The failure happened before any other call.
    EXPECT_EQ(f.bpf_ops.load_calls(), 0);
    EXPECT_EQ(f.bpf_ops.attach_xdp_calls(), 0);
    // Object was never opened, so close() is not called.
    EXPECT_EQ(f.bpf_ops.close_calls(), 0);
}

TEST(BpfLoaderTest, LoadFailureClosesObjectAndDetaches) {
    LoaderFixture f;
    f.bpf_ops.fail_load_ = true;

    EXPECT_THROW(f.loader->load_and_attach("lo"), std::runtime_error);
    EXPECT_FALSE(f.loader->is_attached());
    EXPECT_FALSE(f.loader->is_loaded());
    EXPECT_EQ(f.bpf_ops.open_file_calls(), 1);
    EXPECT_EQ(f.bpf_ops.load_calls(), 1);
    // Object must be closed so we don't leak the partial state.
    EXPECT_EQ(f.bpf_ops.close_calls(), 1);
    // attach never ran.
    EXPECT_EQ(f.bpf_ops.attach_xdp_calls(), 0);
    // XSKMAP never updated.
    EXPECT_EQ(f.backend_fix.xsk_ops.update_xskmap_calls(), 0);
}

TEST(BpfLoaderTest, AttachFailureClosesObjectAndDetaches) {
    LoaderFixture f;
    f.bpf_ops.fail_attach_xdp_ = true;

    EXPECT_THROW(f.loader->load_and_attach("lo"), std::runtime_error);
    EXPECT_FALSE(f.loader->is_attached());
    EXPECT_FALSE(f.loader->is_loaded());
    EXPECT_EQ(f.bpf_ops.open_file_calls(), 1);
    EXPECT_EQ(f.bpf_ops.load_calls(), 1);
    EXPECT_EQ(f.bpf_ops.attach_xdp_calls(), 1);
    // Object must be closed so the kernel-side maps get GC'd by us.
    EXPECT_EQ(f.bpf_ops.close_calls(), 1);
    // XSKMAP was updated (it precedes attach); the mock will not roll back.
    EXPECT_EQ(f.backend_fix.xsk_ops.update_xskmap_calls(), 1);
}

// ---------------------------------------------------------------------------
// Backend preconditions
// ---------------------------------------------------------------------------

TEST(BpfLoaderTest, LoadAndAttachRequiresInitialisedBackend) {
    // Build an AfXdpBackend that has NOT been init()'d.
    FrameAllocator allocator(FrameAllocator::DEFAULT_NUM_FRAMES, FrameAllocator::DEFAULT_FRAME_SIZE,
                             0);
    AfXdpBackend backend(allocator, "lo", 0);
    MockXskOps xsk_ops;
    MockBpfOps bpf_ops;
    BpfLoader loader(backend, &xsk_ops, &bpf_ops);

    EXPECT_THROW(loader.load_and_attach("lo"), std::runtime_error);
    EXPECT_FALSE(loader.is_attached());
    // open_file is the very first libbpf call; we should not reach it.
    EXPECT_EQ(bpf_ops.open_file_calls(), 0);
}
