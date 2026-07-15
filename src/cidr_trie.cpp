// SPDX-License-Identifier: MIT
//
// cidr_trie.cpp -- explicit template instantiations for CidrTrie.
//

#include "packet-engine/cidr_trie.hpp"

namespace packet_engine {

template class CidrTrie<IPv4Addr, std::uint32_t, 8192>;
template class CidrTrie<IPv6Addr, std::uint32_t, 8192>;

} // namespace packet_engine
