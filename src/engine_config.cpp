#include "packet-engine/engine_config.hpp"

#include <charconv>
#include <limits>
#include <string_view>
#include <system_error>

namespace packet_engine {
namespace {

template <typename T> bool parse_unsigned(std::string_view text, T& value) {
    T parsed{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return false;
    }
    value = parsed;
    return true;
}

ConfigError invalid_value(std::string_view option, std::string_view value) {
    return {"invalid value '" + std::string{value} + "' for " + std::string{option}};
}

std::optional<IPv4Addr> parse_ipv4(std::string_view text) {
    std::uint8_t octets[4]{};
    std::size_t start = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        const auto dot = text.find('.', start);
        if ((index < 3 && dot == std::string_view::npos) ||
            (index == 3 && dot != std::string_view::npos)) {
            return std::nullopt;
        }
        const auto end = dot == std::string_view::npos ? text.size() : dot;
        std::uint16_t octet{};
        if (!parse_unsigned(text.substr(start, end - start), octet) || octet > 255) {
            return std::nullopt;
        }
        octets[index] = static_cast<std::uint8_t>(octet);
        start = end + 1;
    }
    return IPv4Addr{octets[0], octets[1], octets[2], octets[3]};
}

} // namespace

ConfigResult parse_engine_config(int argc, char* const argv[]) {
    EngineConfig config;
    const std::string program_name = argc > 0 && argv[0] != nullptr ? argv[0] : "packet-engine";
    config.eal_argv.push_back(program_name);

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument == "--") {
            for (++index; index < argc; ++index) {
                config.eal_argv.emplace_back(argv[index]);
            }
            break;
        }
        if (argument == "-h" || argument == "--help") {
            config.show_help = true;
            continue;
        }

        const auto equals = argument.find('=');
        const auto option = argument.substr(0, equals);
        std::string_view value;
        if (equals != std::string_view::npos) {
            value = argument.substr(equals + 1);
        } else if (index + 1 < argc && std::string_view{argv[index + 1]} != "--") {
            value = argv[++index];
        } else {
            return ConfigError{"missing value for " + std::string{option}};
        }
        if (value.empty()) {
            return invalid_value(option, value);
        }

        if (option == "--backend") {
            if (value == "af_xdp") {
                config.backend = BackendKind::AfXdp;
            } else if (value == "dpdk") {
                config.backend = BackendKind::Dpdk;
            } else {
                return invalid_value(option, value);
            }
        } else if (option == "--interface") {
            config.interface_name = value;
        } else if (option == "--queue") {
            if (!parse_unsigned(value, config.queue_id)) {
                return invalid_value(option, value);
            }
        } else if (option == "--dpdk-port") {
            config.dpdk_port = value;
        } else if (option == "--max-packets") {
            std::uint64_t parsed{};
            if (!parse_unsigned(value, parsed) || parsed == 0) {
                return invalid_value(option, value);
            }
            config.max_packets = parsed;
        } else if (option == "--max-idle-ms") {
            std::uint64_t parsed{};
            constexpr auto max_duration = static_cast<std::uint64_t>(
                std::numeric_limits<std::chrono::milliseconds::rep>::max());
            if (!parse_unsigned(value, parsed) || parsed == 0 || parsed > max_duration) {
                return invalid_value(option, value);
            }
            config.max_idle = std::chrono::milliseconds{parsed};
        } else if (option == "--control-socket") {
            config.control_socket = value;
        } else if (option == "--metrics-port") {
            if (!parse_unsigned(value, config.metrics_port) || config.metrics_port == 0) {
                return invalid_value(option, value);
            }
        } else if (option == "--vip") {
            config.vip = parse_ipv4(value);
            if (!config.vip) {
                return invalid_value(option, value);
            }
        } else if (option == "--default-action") {
            if (value == "allow") {
                config.default_allow = true;
            } else if (value == "drop") {
                config.default_allow = false;
            } else {
                return invalid_value(option, value);
            }
        } else {
            return ConfigError{"unknown option '" + std::string{option} + "'"};
        }
    }

    if (config.show_help) {
        return config;
    }
    if (config.backend == BackendKind::Dpdk) {
        if (config.dpdk_port.empty()) {
            return ConfigError{"--dpdk-port is required for backend=dpdk"};
        }
        if (config.queue_id != 0) {
            return ConfigError{"backend=dpdk currently supports only --queue=0"};
        }
    } else if (config.eal_argv.size() != 1) {
        return ConfigError{"EAL arguments after -- require backend=dpdk"};
    }
    return config;
}

std::string engine_usage(const std::string& program_name) {
    return "Usage: " + program_name +
           " [engine options] [-- EAL args]\n"
           "  --backend=af_xdp|dpdk    datapath backend (default: af_xdp)\n"
           "  --interface=NAME         AF_XDP interface (default: veth0)\n"
           "  --queue=N                queue id (default: 0)\n"
           "  --dpdk-port=NAME         DPDK port or vdev name\n"
           "  --max-packets=N          stop after N received packets\n"
           "  --max-idle-ms=N          stop after N idle milliseconds\n"
           "  --control-socket=PATH    control socket path\n"
           "  --metrics-port=PORT      Prometheus listen port\n"
           "  --vip=IPv4               enable L4 NAT for this virtual IP\n"
           "  --default-action=ACTION  unmatched policy: drop|allow (default: drop)\n"
           "  -h, --help               show this help\n";
}

} // namespace packet_engine
