// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>

#ifdef HAVE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <unistd.h>

#include "packet-engine/backend_dpdk.hpp"

namespace {

using packet_engine::DpdkBackend;
using packet_engine::PacketDescriptor;

constexpr std::array<std::uint8_t, 60> kFrame{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0xb5, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
    0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
};

void write_u16_le(std::ofstream& stream, std::uint16_t value) {
    const std::array<char, 2> bytes{
        static_cast<char>(value & 0xffU),
        static_cast<char>((value >> 8U) & 0xffU),
    };
    stream.write(bytes.data(), bytes.size());
}

void write_u32_le(std::ofstream& stream, std::uint32_t value) {
    const std::array<char, 4> bytes{
        static_cast<char>(value & 0xffU),
        static_cast<char>((value >> 8U) & 0xffU),
        static_cast<char>((value >> 16U) & 0xffU),
        static_cast<char>((value >> 24U) & 0xffU),
    };
    stream.write(bytes.data(), bytes.size());
}

void write_one_packet_pcap(const std::filesystem::path& path) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(stream.is_open());

    write_u32_le(stream, 0xa1b2c3d4U);
    write_u16_le(stream, 2);
    write_u16_le(stream, 4);
    write_u32_le(stream, 0);
    write_u32_le(stream, 0);
    write_u32_le(stream, 65'535);
    constexpr std::uint32_t link_type_ethernet = 1;
    write_u32_le(stream, link_type_ethernet);
    write_u32_le(stream, 1'700'000'000U);
    write_u32_le(stream, 123'456U);
    write_u32_le(stream, kFrame.size());
    write_u32_le(stream, kFrame.size());
    stream.write(reinterpret_cast<const char*>(kFrame.data()), kFrame.size());
    ASSERT_TRUE(stream.good());
}

class MutableArgv {
  public:
    explicit MutableArgv(std::vector<std::string> args) : args_(std::move(args)) {
        argv_.reserve(args_.size() + 1);
        for (auto& arg : args_) {
            argv_.push_back(arg.data());
        }
        argv_.push_back(nullptr);
    }

    [[nodiscard]] int argc() const { return static_cast<int>(args_.size()); }
    [[nodiscard]] char** argv() { return argv_.data(); }

  private:
    std::vector<std::string> args_;
    std::vector<char*> argv_;
};

TEST(DpdkContractRedTest, BackendAcceptsAStablePortName) {
    EXPECT_TRUE(
        (std::is_constructible_v<DpdkBackend, std::string_view, std::uint16_t, std::string_view>))
        << "DPDK ports must be selected by stable ethdev name, not discovery "
           "order or an assumed numeric port 0";
}

TEST(DpdkContractRedTest, AcceptedTxLeavesApplicationOwnershipAndCleanupIsComplete) {
    const std::string unique = std::to_string(static_cast<long long>(::getpid()));
    const std::string port_name = "net_pcap_pe_contract";
    const std::string pool_name = "pe_contract_pool_" + unique;
    const auto temp_dir =
        std::filesystem::temp_directory_path() / ("packet-engine-dpdk-contract-" + unique);
    const auto input = temp_dir / "input.pcap";
    const auto output = temp_dir / "output.pcap";
    std::filesystem::create_directories(temp_dir);
    write_one_packet_pcap(input);

    MutableArgv eal_args({
        "test_dpdk_contract",
        "-l",
        "0",
        "-n",
        "1",
        "--no-huge",
        "--no-pci",
        "--file-prefix=pe-contract-" + unique,
        "--vdev=" + port_name + ",rx_pcap=" + input.string() + ",tx_pcap=" + output.string(),
    });

    {
        constexpr std::uint16_t queue_zero = 0;
        DpdkBackend backend(port_name, queue_zero, pool_name);
        ASSERT_NO_THROW(backend.init(eal_args.argc(), eal_args.argv()));

        std::uint16_t resolved_port = RTE_MAX_ETHPORTS;
        ASSERT_EQ(rte_eth_dev_get_port_by_name(port_name.c_str(), &resolved_port), 0);
        EXPECT_EQ(backend.port_id(), resolved_port);

        PacketDescriptor descriptor{};
        std::uint32_t received = 0;
        for (int attempt = 0; attempt < 100 && received == 0; ++attempt) {
            received = backend.recv_batch(&descriptor, 1);
            if (received == 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        ASSERT_EQ(received, 1U);
        ASSERT_EQ(backend.pending_count(), 1U);

        auto packet_bytes = backend.packet_span(descriptor);
        ASSERT_EQ(packet_bytes.size(), kFrame.size());
        for (std::size_t index = 0; index < kFrame.size(); ++index) {
            EXPECT_EQ(std::to_integer<std::uint8_t>(packet_bytes[index]), kFrame[index]);
        }
        const std::byte original_byte = packet_bytes.front();
        packet_bytes.front() = std::byte{0x7f};
        const DpdkBackend& const_backend = backend;
        EXPECT_EQ(const_backend.packet_span(descriptor).front(), std::byte{0x7f});
        packet_bytes.front() = original_byte;

        auto* mbuf = reinterpret_cast<rte_mbuf*>(static_cast<std::uintptr_t>(descriptor.offset));
        const std::uint16_t original_segment_count = mbuf->nb_segs;
        mbuf->nb_segs = 2;
        EXPECT_TRUE(backend.packet_span(descriptor).empty());
        EXPECT_TRUE(const_backend.packet_span(descriptor).empty());
        mbuf->nb_segs = original_segment_count;

        ASSERT_EQ(backend.send_batch(&descriptor, 1), 1U);
        EXPECT_EQ(backend.pending_count(), 0U)
            << "an accepted TX prefix belongs to the PMD and must be removed "
               "from the application's outstanding ledger";
        EXPECT_TRUE(backend.packet_span(descriptor).empty());
        EXPECT_TRUE(const_backend.packet_span(descriptor).empty());
    }

    EXPECT_LT(rte_eal_cleanup(), 0) << "backend teardown must call rte_eal_cleanup exactly once";
    std::filesystem::remove_all(temp_dir);
}

} // namespace

#endif
