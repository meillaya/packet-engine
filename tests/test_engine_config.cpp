#include "packet-engine/engine_config.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <variant>
#include <vector>

namespace packet_engine {
namespace {

ConfigResult parse(std::initializer_list<const char*> args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const auto* arg : args) {
        argv.push_back(const_cast<char*>(arg));
    }
    return parse_engine_config(static_cast<int>(argv.size()), argv.data());
}

TEST(EngineConfigTest, GivenHelpFlagWhenParsedThenHelpIsReachable) {
    const auto result = parse({"packet-engine", "--help"});

    ASSERT_TRUE(std::holds_alternative<EngineConfig>(result));
    EXPECT_TRUE(std::get<EngineConfig>(result).show_help);
}

TEST(EngineConfigTest, GivenAllDpdkOptionsWhenParsedThenTypedValuesAndEalBoundaryArePreserved) {
    const auto result =
        parse({"/opt/packet-engine", "--backend=dpdk", "--interface", "ens5", "--queue=0",
               "--dpdk-port", "net_pcap0", "--max-packets=42", "--max-idle-ms", "250",
               "--control-socket=/tmp/pe-test.sock", "--metrics-port", "9191", "--vip=10.99.0.1",
               "--default-action=allow", "--", "-l", "0", "--no-pci"});

    ASSERT_TRUE(std::holds_alternative<EngineConfig>(result));
    const auto& config = std::get<EngineConfig>(result);
    EXPECT_EQ(config.backend, BackendKind::Dpdk);
    EXPECT_EQ(config.interface_name, "ens5");
    EXPECT_EQ(config.queue_id, 0U);
    EXPECT_EQ(config.dpdk_port, "net_pcap0");
    EXPECT_EQ(config.max_packets, 42U);
    EXPECT_EQ(config.max_idle, std::chrono::milliseconds{250});
    EXPECT_EQ(config.control_socket, "/tmp/pe-test.sock");
    EXPECT_EQ(config.metrics_port, 9191U);
    ASSERT_TRUE(config.vip.has_value());
    EXPECT_EQ(*config.vip, IPv4Addr(10, 99, 0, 1));
    EXPECT_TRUE(config.default_allow);
    EXPECT_EQ(config.eal_argv,
              (std::vector<std::string>{"/opt/packet-engine", "-l", "0", "--no-pci"}));
}

TEST(EngineConfigTest, GivenNoVipWhenParsedThenNatRemainsDisabled) {
    const auto result = parse({"packet-engine", "--backend=af_xdp"});

    ASSERT_TRUE(std::holds_alternative<EngineConfig>(result));
    EXPECT_FALSE(std::get<EngineConfig>(result).vip.has_value());
    EXPECT_FALSE(std::get<EngineConfig>(result).default_allow);
}

TEST(EngineConfigTest, GivenInvalidDefaultActionWhenParsedThenItIsRejected) {
    const auto result = parse({"packet-engine", "--default-action=reject"});

    ASSERT_TRUE(std::holds_alternative<ConfigError>(result));
    EXPECT_NE(std::get<ConfigError>(result).message.find("--default-action"), std::string::npos);
}

TEST(EngineConfigTest, GivenMalformedVipWhenParsedThenItIsRejected) {
    for (const auto& option :
         {"--vip=10.99.0", "--vip=10.99.0.256", "--vip=10.99.0.1.extra", "--vip=-1.2.3.4"}) {
        const auto result = parse({"packet-engine", option});
        ASSERT_TRUE(std::holds_alternative<ConfigError>(result)) << option;
        EXPECT_NE(std::get<ConfigError>(result).message.find("--vip"), std::string::npos);
    }
}

TEST(EngineConfigTest, GivenAnUnknownOptionWhenParsedThenItIsRejected) {
    const auto result = parse({"packet-engine", "--mystery=1"});

    ASSERT_TRUE(std::holds_alternative<ConfigError>(result));
    EXPECT_NE(std::get<ConfigError>(result).message.find("--mystery"), std::string::npos);
}

TEST(EngineConfigTest, GivenInvalidTypedValuesWhenParsedThenTheyAreRejected) {
    for (const auto& option :
         {"--queue=-1", "--max-packets=0", "--max-idle-ms=0", "--metrics-port=65536"}) {
        const auto result = parse({"packet-engine", option});
        ASSERT_TRUE(std::holds_alternative<ConfigError>(result)) << option;
    }
}

TEST(EngineConfigTest, GivenDpdkWithoutNamedPortWhenParsedThenItIsRejected) {
    const auto result = parse({"packet-engine", "--backend=dpdk", "--", "-l", "0"});

    ASSERT_TRUE(std::holds_alternative<ConfigError>(result));
    EXPECT_NE(std::get<ConfigError>(result).message.find("--dpdk-port"), std::string::npos);
}

TEST(EngineConfigTest, GivenAfXdpWithEalArgumentsWhenParsedThenItIsRejected) {
    const auto result = parse({"packet-engine", "--backend=af_xdp", "--", "--no-pci"});

    ASSERT_TRUE(std::holds_alternative<ConfigError>(result));
    EXPECT_NE(std::get<ConfigError>(result).message.find("EAL"), std::string::npos);
}

} // namespace
} // namespace packet_engine
