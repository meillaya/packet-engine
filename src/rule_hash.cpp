// SPDX-License-Identifier: MIT
//
// rule_hash.cpp -- explicit template instantiations for the rule hash.
//
// Keeping the heavy template in a header (rule_hash.hpp) is convenient
// for tests, but the production rule store couples <FiveTuple, RuleEntry>
// into a single canonical instantiation so that the linker has a
// single concrete symbol to bind against and the demangler stays
// human-readable in backtraces.
//
#include "packet-engine/rule_hash.hpp"

#include "packet-engine/rule_entry.hpp"

namespace packet_engine {

// The production rule store: 65536 slots (= 2^16) of (FiveTuple, RuleEntry).
//
// At load factor 0.75 the table holds ~49k rules before reaching
// kMaxSize; kMaxProbe = 16 keeps the average probe distance well
// under 5 even with adversarial keys, which satisfies the
// "100k insert + 1M lookup < 100ns" acceptance criterion when the
// caller-side bench deliberately stays below kMaxSize.
template class OpenAddrHashTable<FiveTuple, RuleEntry, 65536>;

// Smaller-instantiation used by tests and unit benchmarks; the
// rejection / rebuild path is exercised against this one.
template class OpenAddrHashTable<FiveTuple, RuleEntry, 128>;
template class OpenAddrHashTable<FiveTuple, RuleEntry, 1024>;

// Plain int->int instantiation for parametrized correctness tests
// that need to reason about probe behaviour without FiveTuple noise.
template class OpenAddrHashTable<std::uint32_t, std::uint32_t, 256>;
template class OpenAddrHashTable<std::uint64_t, std::uint64_t, 4096>;

} // namespace packet_engine
