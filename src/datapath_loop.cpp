// SPDX-License-Identifier: MIT
//
// datapath_loop.cpp -- non-template bits of the RX/TX loops.
//
// The hot path (`run_rx_iteration`, `run_tx_iteration`, `run_rx_loop`,
// `run_tx_loop`) is templated on the SPSC ring capacity and lives in the
// header so each translation unit instantiates only the capacities it
// uses.  This file holds the only piece that is not a template:
// `hash_five_tuple`, which is small enough to be inlinable but is also
// non-trivial enough that putting it in a header would be a cost we
// pay in every TU that includes datapath_loop.hpp.

#include "packet-engine/datapath_loop.hpp"

#include <cstdint>

namespace packet_engine {

std::uint32_t hash_five_tuple(const FiveTuple& ft) noexcept {
    // Promote every field to uint64_t so the upper bits actually carry
    // signal.  The plan's spec is a literal XOR; we keep it as such and
    // let the compiler's strength-reduction pass turn the constants
    // into immediates.
    const std::uint64_t src_ip = static_cast<std::uint64_t>(ft.src_ip.value);
    const std::uint64_t dst_ip = static_cast<std::uint64_t>(ft.dst_ip.value);
    const std::uint64_t ports =
        (static_cast<std::uint64_t>(ft.src_port) << 32) | static_cast<std::uint64_t>(ft.dst_port);
    const std::uint64_t proto = static_cast<std::uint64_t>(static_cast<std::uint8_t>(ft.proto));

    const std::uint64_t mixed = src_ip ^ dst_ip ^ ports ^ proto;
    // Fold the high bits down so a 32-bit modulus does not discard the
    // upper half of the entropy.
    const std::uint32_t h32 =
        static_cast<std::uint32_t>(mixed) ^ static_cast<std::uint32_t>(mixed >> 32);
    return h32;
}

} // namespace packet_engine
