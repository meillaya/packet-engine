#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "packet-engine/types.hpp"

namespace packet_engine {

enum class BackendKind : std::uint8_t {
    AfXdp,
    Dpdk,
};

struct EngineConfig {
    BackendKind backend{BackendKind::AfXdp};
    std::string interface_name{"veth0"};
    std::uint32_t queue_id{0};
    std::string dpdk_port;
    std::optional<std::uint64_t> max_packets;
    std::optional<std::chrono::milliseconds> max_idle;
    std::string control_socket{"/tmp/packet-engine.sock"};
    std::uint16_t metrics_port{9090};
    std::optional<IPv4Addr> vip;
    bool default_allow{false};
    std::vector<std::string> eal_argv;
    bool show_help{false};
};

struct ConfigError {
    std::string message;
};

using ConfigResult = std::variant<EngineConfig, ConfigError>;

[[nodiscard]] ConfigResult parse_engine_config(int argc, char* const argv[]);
[[nodiscard]] std::string engine_usage(const std::string& program_name);

} // namespace packet_engine
