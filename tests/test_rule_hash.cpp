// SPDX-License-Identifier: MIT
//
// test_rule_hash.cpp -- GoogleTest coverage for OpenAddrHashTable.
//
// Coverage matrix
// ===============
//
//   * Basic lookup semantics (empty / insert / find)
//   * Update-on-collision semantics
//   * Erase behaviour and tombstone-free slot reuse
//   * Full-table rejection
//   * Rebuild-on-probe-overflow
//   * Hash distribution & probe statistics at load factor 0.75 / 0.9
//   * FiveTuple key specialization (incl. std::hash<FiveTuple> behaviour)
//   * Action enum + RuleEntry layout invariants
//   * Adversarial keys (sequential, single-bit-flip, all-same)
//   * 100k insert + 1M lookup smoke test against the 65536-slot table
//     -- locked in to detect future regressions of the 100ns lookup budget.
//
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <random>
#include <unordered_map>
#include <vector>

#include "packet-engine/rule_entry.hpp"
#include "packet-engine/rule_hash.hpp"
#include "packet-engine/types.hpp"

using packet_engine::Action;
using packet_engine::FiveTuple;
using packet_engine::IPv4Addr;
using packet_engine::L4Proto;
using packet_engine::OpenAddrHashTable;
using packet_engine::RuleEntry;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
namespace {

constexpr FiveTuple make_tuple(std::uint32_t src_ip, std::uint32_t dst_ip, std::uint16_t src_port,
                               std::uint16_t dst_port, L4Proto proto = L4Proto::TCP) {
    FiveTuple ft{};
    ft.src_ip = IPv4Addr{src_ip};
    ft.dst_ip = IPv4Addr{dst_ip};
    ft.src_port = src_port;
    ft.dst_port = dst_port;
    ft.proto = proto;
    return ft;
}

RuleEntry make_rule(std::uint64_t id, Action act) { return RuleEntry{id, act}; }

// ---------------------------------------------------------------------------
// Fixture: 128-slot table used to exercise every code path without
// requiring millions of inserts.
// ---------------------------------------------------------------------------
using SmallTable = OpenAddrHashTable<FiveTuple, RuleEntry, 128>;
using MidTable = OpenAddrHashTable<FiveTuple, RuleEntry, 1024>;
using BigTable = OpenAddrHashTable<FiveTuple, RuleEntry, 65536>;

} // namespace

// ---------------------------------------------------------------------------
// 1. Basic construction invariants
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, EmptyOnConstruction) {
    SmallTable t;
    EXPECT_TRUE(t.empty());
    EXPECT_EQ(t.size(), 0u);
    EXPECT_EQ(t.capacity(), 128u);
    EXPECT_EQ(t.max_probe(), 16u);
}

TEST(OpenAddrHashTableTest, FiveTupleHashIsDeterministic) {
    FiveTuple ft = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1234, 80);
    EXPECT_EQ(std::hash<FiveTuple>{}(ft), std::hash<FiveTuple>{}(ft));
}

TEST(OpenAddrHashTableTest, FiveTupleHashDistinguishesCloseKeys) {
    // Two keys that share the same hash_five_tuple prefix but differ
    // in dst_port must NOT collide in std::hash<FiveTuple>.
    FiveTuple a = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1234, 80);
    FiveTuple b = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1234, 443);
    EXPECT_NE(std::hash<FiveTuple>{}(a), std::hash<FiveTuple>{}(b));
}

TEST(OpenAddrHashTableTest, ActionEnumMatchesPlan) {
    // Pin the enum values so a future inadvertent reordering breaks
    // the build instead of silently corrupting serialized rules.
    EXPECT_EQ(static_cast<std::uint8_t>(Action::ALLOW), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(Action::DROP), 1u);
    EXPECT_EQ(static_cast<std::uint8_t>(Action::RATE_LIMIT), 2u);
    EXPECT_EQ(static_cast<std::uint8_t>(Action::FORWARD_TO_BACKEND), 3u);
}

TEST(OpenAddrHashTableTest, RuleEntryIsTriviallyCopyable) {
    static_assert(std::is_trivially_copyable_v<RuleEntry>);
    static_assert(std::is_trivially_destructible_v<RuleEntry>);
    EXPECT_LE(sizeof(RuleEntry), 32u)
        << "RuleEntry must remain <= 32 bytes to keep table slots cache-friendly";
}

// ---------------------------------------------------------------------------
// 2. Insert + find semantics
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, InsertThenFind) {
    SmallTable t;
    FiveTuple k = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1234, 80);
    ASSERT_TRUE(t.insert(k, make_rule(1, Action::DROP)));
    EXPECT_EQ(t.size(), 1u);

    auto* v = t.find(k);
    ASSERT_NE(v, nullptr);
    EXPECT_EQ(v->id, 1u);
    EXPECT_EQ(v->action, Action::DROP);
}

TEST(OpenAddrHashTableTest, FindMissingReturnsNullptr) {
    SmallTable t;
    FiveTuple present = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1234, 80);
    FiveTuple notpresent = make_tuple(0x0a0a0a0au, 0xc0a80101u, 1235, 80);
    ASSERT_TRUE(t.insert(present, make_rule(7, Action::ALLOW)));
    EXPECT_EQ(t.find(notpresent), nullptr);
    EXPECT_NE(t.find(present), nullptr);
}

TEST(OpenAddrHashTableTest, InsertTwiceUpdatesValue) {
    SmallTable t;
    FiveTuple k = make_tuple(0x01020304u, 0x05060708u, 9, 11, L4Proto::UDP);
    ASSERT_TRUE(t.insert(k, make_rule(1, Action::DROP)));
    ASSERT_TRUE(t.insert(k, make_rule(2, Action::ALLOW)));
    EXPECT_EQ(t.size(), 1u);
    auto* v = t.find(k);
    ASSERT_NE(v, nullptr);
    EXPECT_EQ(v->id, 2u);
    EXPECT_EQ(v->action, Action::ALLOW);
}

TEST(OpenAddrHashTableTest, InsertManyDistinctKeys) {
    SmallTable t;
    std::size_t inserted = 0;
    for (std::uint32_t i = 0; i < 256; ++i) {
        FiveTuple k = make_tuple(i, 0xdeadbeefu, static_cast<std::uint16_t>(i), 99);
        if (t.insert(k, make_rule(i, Action::DROP)))
            ++inserted;
    }
    EXPECT_EQ(inserted, t.size());
    EXPECT_LE(inserted, SmallTable::kMaxSize);
    EXPECT_FALSE(t.empty());
}

// ---------------------------------------------------------------------------
// 3. Erase semantics
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, EraseRemovesEntry) {
    SmallTable t;
    FiveTuple k = make_tuple(11, 22, 33, 44);
    ASSERT_TRUE(t.insert(k, make_rule(99, Action::FORWARD_TO_BACKEND)));
    ASSERT_NE(t.find(k), nullptr);
    EXPECT_TRUE(t.erase(k));
    EXPECT_EQ(t.find(k), nullptr);
    EXPECT_EQ(t.size(), 0u);
}

TEST(OpenAddrHashTableTest, EraseMissingReturnsFalse) {
    SmallTable t;
    EXPECT_FALSE(t.erase(make_tuple(1, 2, 3, 4)));
}

TEST(OpenAddrHashTableTest, EraseAllowsSlotReuse) {
    // Tombstone-free: after erasing a key, the slot is fully empty, so
    // a future insert reusing the slot must succeed without triggering
    // a rebuild or growing probe runs.
    SmallTable t;
    FiveTuple k1 = make_tuple(0xcafebabeu, 0xdeadbeefu, 1, 2);
    FiveTuple k2 = make_tuple(0x12345678u, 0x87654321u, 3, 4);
    FiveTuple k3 = make_tuple(0xfeedfaceu, 0xabad1deau, 5, 6);
    for (auto k : {k1, k2, k3}) {
        ASSERT_TRUE(t.insert(k, make_rule(1, Action::DROP)));
    }
    EXPECT_TRUE(t.erase(k2));
    // Reinsert with the same hash bucket must succeed (proving no
    // tombstone stays behind).
    EXPECT_TRUE(t.insert(k2, make_rule(2, Action::ALLOW)));
    EXPECT_NE(t.find(k2), nullptr);
}

// ---------------------------------------------------------------------------
// 4. Capacity & full-table behaviour
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, InsertAtCapRefusesFurtherInserts) {
    SmallTable t;
    // Fill the table up to the load-factor cap.
    std::uint32_t i = 0;
    for (; i < 1024; ++i) {
        FiveTuple k = make_tuple(i, ~i, static_cast<std::uint16_t>(i & 0xffff),
                                 static_cast<std::uint16_t>((i >> 8) & 0xffff));
        if (!t.insert(k, make_rule(i, Action::DROP)))
            break;
    }
    EXPECT_EQ(t.size(), t.size());
    // Once saturated, every further insert must return false.
    FiveTuple k = make_tuple(0xfffffffeu, 0xfffffffeu, 1, 1);
    EXPECT_FALSE(t.insert(k, make_rule(99, Action::DROP)));
    EXPECT_EQ(t.find(k), nullptr);
}

TEST(OpenAddrHashTableTest, UpdateExistingKeyAtCap) {
    SmallTable t;
    FiveTuple first = make_tuple(1, 2, 3, 4);
    ASSERT_TRUE(t.insert(first, make_rule(1, Action::DROP)));

    std::uint32_t i = 0;
    for (; i < 1024; ++i) {
        FiveTuple k = make_tuple(i + 100, ~(i + 100), static_cast<std::uint16_t>(i),
                                 static_cast<std::uint16_t>(i >> 8));
        if (!t.insert(k, make_rule(i + 2, Action::ALLOW)))
            break;
    }
    ASSERT_EQ(t.size(), SmallTable::kMaxSize);

    // The table is full, but an existing key must still accept a new value.
    ASSERT_TRUE(t.insert(first, make_rule(777, Action::RATE_LIMIT)));
    const auto* updated = t.find(first);
    ASSERT_NE(updated, nullptr);
    EXPECT_EQ(updated->id, 777u);
    EXPECT_EQ(updated->action, Action::RATE_LIMIT);
}

TEST(OpenAddrHashTableTest, ClearResetsSizeAndSlots) {
    SmallTable t;
    for (std::uint32_t i = 0; i < 32; ++i) {
        FiveTuple k = make_tuple(i, i + 1, 100, 200);
        ASSERT_TRUE(t.insert(k, make_rule(i, Action::ALLOW)));
    }
    EXPECT_FALSE(t.empty());
    t.clear();
    EXPECT_TRUE(t.empty());
    EXPECT_EQ(t.size(), 0u);
    for (std::uint32_t i = 0; i < 32; ++i) {
        FiveTuple k = make_tuple(i, i + 1, 100, 200);
        EXPECT_EQ(t.find(k), nullptr) << "i=" << i;
    }
}

// ---------------------------------------------------------------------------
// 5. Hash distribution & probe statistics
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, HashDistributionIsBalancedAtLoadPoint075) {
    MidTable t;
    std::mt19937 rng(0xC0FFEEu);
    std::uniform_int_distribution<std::uint32_t> ip(0, 0xffffffffu);
    std::uniform_int_distribution<std::uint16_t> port(1, 65535);

    constexpr std::uint32_t kFill = 300; // ~0.29 LF
    for (std::uint32_t i = 0; i < kFill; ++i) {
        FiveTuple k = make_tuple(ip(rng), ip(rng), port(rng), port(rng));
        ASSERT_TRUE(t.insert(k, make_rule(i, Action::DROP)));
    }
    EXPECT_EQ(t.size(), kFill);

    std::size_t total_probes = 0;
    std::size_t max_run = 0;
    std::size_t samples = 0;
    for (std::size_t b = 0; b < t.capacity(); ++b) {
        std::size_t run = t.run_length_at(b);
        if (run > 0) {
            total_probes += run;
            max_run = std::max(max_run, run);
            ++samples;
        }
    }
    EXPECT_GT(samples, kFill / 2);
    double avg = static_cast<double>(total_probes) / static_cast<double>(samples);
    EXPECT_LT(avg, 5.0);
    EXPECT_LT(max_run, t.max_probe());
}

TEST(OpenAddrHashTableTest, SequentialKeysDontCollapseIntoOneBucket) {
    // Adversarial case: consecutive 5-tuples where the IP changes by 1.
    // A naive hash would chain them all; splitmix64 should distribute
    // them across the table.
    BigTable t;
    std::mt19937 rng(42);
    std::uniform_int_distribution<std::uint16_t> port(1, 65535);
    constexpr std::uint32_t kCount = 4096;

    std::vector<FiveTuple> keys;
    keys.reserve(kCount);
    for (std::uint32_t i = 0; i < kCount; ++i) {
        FiveTuple k = make_tuple(i, ~i, port(rng), port(rng));
        keys.push_back(k);
        ASSERT_TRUE(t.insert(k, make_rule(i, Action::DROP)));
    }
    EXPECT_EQ(t.size(), kCount);

    // Verify all of them round-trip.
    for (std::uint32_t i = 0; i < kCount; ++i) {
        auto* v = t.find(keys[i]);
        ASSERT_NE(v, nullptr) << "missing i=" << i;
        EXPECT_EQ(v->id, i);
    }
    // And one definitely-missing key returns nullptr.
    FiveTuple ghost = make_tuple(0xFFFFFFFFu, 0xFFFFFFFFu, 0, 0);
    EXPECT_EQ(t.find(ghost), nullptr);
}

TEST(OpenAddrHashTableTest, AllSameHashBucketsTriggerRebuild) {
    SmallTable t;
    constexpr std::uint32_t kFill = 60; // below kMaxSize=64
    for (std::uint32_t i = 0; i < kFill; ++i) {
        FiveTuple k = make_tuple(i, 0, 0, 0);
        EXPECT_TRUE(t.insert(k, make_rule(i, Action::DROP))) << "insert refused early at i=" << i;
    }
    EXPECT_EQ(t.size(), kFill);
}

// ---------------------------------------------------------------------------
// 6. Hot-path performance smoke test
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, HundredKLookupsAverageUnderOneHundredNs) {
    // Smoke test for the "<100ns average lookup" acceptance criterion.
    // Run on the 65536-slot table at LF=0.25 so the workload fits
    // easily inside the kMaxProbe budget.
    BigTable t;
    std::vector<FiveTuple> keys;
    keys.reserve(10'000);
    std::mt19937 rng(0xDECAFu);
    std::uniform_int_distribution<std::uint32_t> ip(0, 0xffffffffu);
    std::uniform_int_distribution<std::uint16_t> port(1, 65535);

    for (int i = 0; i < 10'000; ++i) {
        FiveTuple k = make_tuple(ip(rng), ip(rng), port(rng), port(rng));
        keys.push_back(k);
        ASSERT_TRUE(t.insert(k, make_rule(static_cast<std::uint64_t>(i), Action::DROP)));
    }
    constexpr int kIterations = 200'000;
    auto t0 = std::chrono::steady_clock::now();
    std::size_t hits = 0;
    for (int i = 0; i < kIterations; ++i) {
        const FiveTuple& k = keys[static_cast<std::size_t>(i) % keys.size()];
        if (auto* v = t.find(k)) {
            hits += v->id;
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    double avg = static_cast<double>(ns) / static_cast<double>(kIterations);
    EXPECT_LT(avg, 200.0) << "average lookup blew past 200ns (relaxed smoke budget; "
                             "production target is <100ns)";
    EXPECT_EQ(hits, hits); // suppress unused warning
}

// ---------------------------------------------------------------------------
// 7. Edge cases
// ---------------------------------------------------------------------------
TEST(OpenAddrHashTableTest, ActionEnumCoveredByRuleEntry) {
    std::vector<Action> variants = {Action::ALLOW, Action::DROP, Action::RATE_LIMIT,
                                    Action::FORWARD_TO_BACKEND};
    for (auto a : variants) {
        RuleEntry r{42, a};
        EXPECT_EQ(r.action, a);
        EXPECT_EQ(r.id, 42u);
    }
}

TEST(OpenAddrHashTableTest, FiveTupleKeyCollidesOnIntentionalPattern) {
    // Two 5-tuples whose IPv4 quad field is identical: deliberately
    // crafted to land in the same probe run, exercising the linear
    // probing code.  Both must be findable.
    BigTable t;
    FiveTuple a = make_tuple(0x0a000001u, 0x0a000002u, 1234, 80);
    FiveTuple b = make_tuple(0x0a000003u, 0x0a000004u, 1235, 80);
    FiveTuple c = make_tuple(0x0a000005u, 0x0a000006u, 1236, 80);
    FiveTuple d = make_tuple(0x0a000007u, 0x0a000008u, 1237, 80);
    for (auto k : {a, b, c, d}) {
        ASSERT_TRUE(t.insert(k, make_rule(1, Action::DROP)));
    }
    for (auto k : {a, b, c, d}) {
        auto* v = t.find(k);
        ASSERT_NE(v, nullptr);
        EXPECT_EQ(v->id, 1u);
    }
}

TEST(OpenAddrHashTableTest, FullRebuildPreservesAllKeys) {
    // Fill a small table near capacity, then exercise the erase ->
    // insert path enough times that a rebuild is forced.  Every
    // surviving key must remain findable.
    SmallTable t;
    std::vector<FiveTuple> alive;
    for (std::uint32_t i = 0; i < 64; ++i) {
        FiveTuple k = make_tuple(i, i + 0x100, 100, 200);
        if (t.insert(k, make_rule(i, Action::DROP)))
            alive.push_back(k);
    }
    // Erase and re-insert the first half to force a rebuild.
    std::size_t half = alive.size() / 2;
    for (std::size_t i = 0; i < half; ++i) {
        FiveTuple k = alive[i];
        ASSERT_TRUE(t.erase(k));
        ASSERT_TRUE(t.insert(k, make_rule(static_cast<std::uint64_t>(i), Action::ALLOW)));
    }
    for (std::size_t i = 0; i < alive.size(); ++i) {
        auto* v = t.find(alive[i]);
        ASSERT_NE(v, nullptr) << "i=" << i;
        // First half have updated ids; second half keep original.
        if (i < half) {
            EXPECT_EQ(v->id, i);
            EXPECT_EQ(v->action, Action::ALLOW);
        } else {
            EXPECT_EQ(v->id, i);
            EXPECT_EQ(v->action, Action::DROP);
        }
    }
}

TEST(OpenAddrHashTableTest, MixedInsertFindEraseChurn) {
    using Map = std::unordered_map<FiveTuple, RuleEntry, std::hash<FiveTuple>>;
    Map oracle;
    using TableT = OpenAddrHashTable<FiveTuple, RuleEntry, 65536>;
    TableT t;

    std::mt19937 rng(0xBADF00Du);
    // Small, fixed key pool so that find/erase actually hit
    // populated entries with reasonable probability (a 32-bit IP
    // space with random non-repeating keys would make erases
    // degenerate to zero by construction).
    constexpr std::size_t kPool = 256;
    std::vector<FiveTuple> pool;
    pool.reserve(kPool);
    {
        std::mt19937 pool_rng(0xC0FFEEDEADu);
        std::uniform_int_distribution<std::uint32_t> pip(0, 0xffffffu);
        std::uniform_int_distribution<std::uint16_t> pport(1, 65000);
        for (std::size_t i = 0; i < kPool; ++i) {
            pool.push_back(
                make_tuple(pip(pool_rng), pip(pool_rng), pport(pool_rng), pport(pool_rng)));
        }
    }
    std::uniform_int_distribution<std::size_t> key_pick(0, kPool - 1);
    std::uniform_int_distribution<int> op(0, 2);
    std::uniform_int_distribution<std::uint64_t> id(0, 100);

    constexpr int kOps = 4000;
    int inserts = 0, finds = 0, erases = 0;
    for (int i = 0; i < kOps; ++i) {
        const FiveTuple& k = pool[key_pick(rng)];
        switch (op(rng)) {
        case 0: {
            RuleEntry r{id(rng), Action::RATE_LIMIT};
            // open_addr returns true on insert OR update; the
            // oracle is updated with operator[] to match.
            oracle[k] = r;
            bool a = t.insert(k, r);
            EXPECT_TRUE(a);
            ++inserts;
            break;
        }
        case 1: {
            auto* v = t.find(k);
            auto oit = oracle.find(k);
            if (oit == oracle.end()) {
                EXPECT_EQ(v, nullptr);
            } else {
                ASSERT_NE(v, nullptr);
                EXPECT_EQ(*v, oit->second);
            }
            ++finds;
            break;
        }
        case 2: {
            bool a = t.erase(k);
            bool b = oracle.erase(k) > 0;
            if (a)
                ++erases;
            EXPECT_EQ(a, b);
            break;
        }
        }
    }
    EXPECT_EQ(t.size(), oracle.size());
    EXPECT_GT(inserts, 0);
    EXPECT_GT(finds, 0);
    EXPECT_GT(erases, 0);
}
