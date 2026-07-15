#include "packet-engine/backend_af_xdp.hpp"
#include "packet-engine/bpf_loader.hpp"
#include "packet-engine/engine_config.hpp"
#include "packet-engine/frame_allocator.hpp"
#include "packet-engine/metrics_aggregator.hpp"
#include "packet-engine/packet_processor.hpp"
#include "packet-engine/signal_handler.hpp"
#include "packet-engine/transmit_batch.hpp"
#include "packet-engine/types.hpp"

#include "runtime_context.hpp"

#ifdef HAVE_DPDK
#include "packet-engine/backend_dpdk.hpp"
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace packet_engine {
namespace {

constexpr std::uint32_t kBatchSize = 64;

bool should_transmit(Action action) noexcept {
    switch (action) {
    case Action::ALLOW:
    case Action::RATE_LIMIT:
    case Action::TX_TO_BACKEND_INTERFACE:
    case Action::TX_TO_CLIENT_INTERFACE:
        return true;
    case Action::DROP:
    case Action::FORWARD_TO_BACKEND:
        return false;
    }
    return false;
}

std::uint32_t receive_capacity(const EngineConfig& config, std::uint64_t received) {
    if (!config.max_packets) {
        return kBatchSize;
    }
    const auto remaining = *config.max_packets - received;
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(remaining, kBatchSize));
}

bool idle_limit_reached(const EngineConfig& config,
                        std::chrono::steady_clock::time_point last_packet) {
    return config.max_idle && std::chrono::steady_clock::now() - last_packet >= *config.max_idle;
}

#ifdef HAVE_DPDK
int run_dpdk(const EngineConfig& config) {
    std::vector<char*> eal_argv;
    eal_argv.reserve(config.eal_argv.size());
    for (const auto& argument : config.eal_argv) {
        eal_argv.push_back(const_cast<char*>(argument.data()));
    }

    DpdkBackend backend{config.dpdk_port, static_cast<std::uint16_t>(config.queue_id)};
    backend.init(static_cast<int>(eal_argv.size()), eal_argv.data());
    RuntimeContext runtime{config};
    runtime.start();
    std::cout << "capability backend=dpdk port=" << backend.port_name()
              << " queue=" << backend.queue_id() << " mode=copy-backed zero-copy=false\n";

    std::array<PacketDescriptor, kBatchSize> packets{};
    std::uint64_t received_total = 0;
    std::uint64_t transmitted_total = 0;
    std::uint64_t dropped_total = 0;
    auto last_packet = std::chrono::steady_clock::now();

    while (!stop_flag().load(std::memory_order_acquire) &&
           (!config.max_packets || received_total < *config.max_packets)) {
        runtime.maintenance();
        const auto received =
            backend.recv_batch(packets.data(), receive_capacity(config, received_total));
        if (received == 0) {
            if (idle_limit_reached(config, last_packet)) {
                break;
            }
            continue;
        }
        const auto batch_started = std::chrono::steady_clock::now();
        const auto batch_now_ns = packets[0].timestamp_ns;
        last_packet = batch_started;
        TransmitBatch transmit_batch{packets.data()};
        const auto rule_snapshot = runtime.processor().rules_snapshot();
        for (std::uint32_t index = 0; index < received; ++index) {
            auto bytes = backend.packet_span(packets[index]);
            const auto result =
                bytes.empty() || !rule_snapshot
                    ? PacketProcessResult{}
                    : runtime.processor().process(bytes, *rule_snapshot, batch_now_ns);
            if (should_transmit(result.action)) {
                transmit_batch.forward(packets[index]);
            } else {
                transmit_batch.drop(packets[index]);
            }
        }
        const auto accepted = backend.send_batch(transmit_batch.transmit_descriptors(),
                                                 transmit_batch.transmit_count());
        const auto outcome = transmit_batch.complete(accepted);
        if (backend.release_pending(outcome.dropped) != outcome.dropped) {
            throw std::runtime_error{"DPDK pending ownership ledger mismatch"};
        }
        received_total += received;
        transmitted_total += outcome.transmitted;
        dropped_total += outcome.dropped;
        runtime.metrics().record_rx(0, received);
        runtime.metrics().record_tx(0, outcome.transmitted);
        runtime.metrics().record_drop(0, outcome.dropped);
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - batch_started);
        runtime.metrics().record_latency_us(0, static_cast<std::uint64_t>(elapsed.count()));
    }
    std::cout << "runtime received=" << received_total << " transmitted=" << transmitted_total
              << " dropped=" << dropped_total << '\n';
    return EXIT_SUCCESS;
}
#endif

int run_af_xdp(const EngineConfig& config) {
    FrameAllocator allocator{FrameAllocator::DEFAULT_NUM_FRAMES,
                             FrameAllocator::DEFAULT_FRAME_SIZE};
    AfXdpBackend backend{allocator, config.interface_name, config.queue_id};
    backend.init();
    BpfLoader loader{backend};
    loader.load_and_attach(config.interface_name);
    RuntimeContext runtime{config};
    runtime.start();
    std::cout << "capability backend=af_xdp interface=" << config.interface_name
              << " queue=" << config.queue_id << " mode=" << backend.actual_mode_name() << '\n';

    std::array<PacketDescriptor, kBatchSize> packets{};
    std::uint64_t received_total = 0;
    auto last_packet = std::chrono::steady_clock::now();
    while (!stop_flag().load(std::memory_order_acquire) &&
           (!config.max_packets || received_total < *config.max_packets)) {
        runtime.maintenance();
        const auto received =
            backend.recv_batch(packets.data(), receive_capacity(config, received_total));
        if (received == 0) {
            static_cast<void>(backend.recycle_completions(kBatchSize));
            static_cast<void>(backend.service_fill_ring());
            if (idle_limit_reached(config, last_packet)) {
                break;
            }
            if (backend.needs_wakeup_fill() && backend.xsk_fd() >= 0) {
                pollfd descriptor{.fd = backend.xsk_fd(), .events = POLLIN, .revents = 0};
                static_cast<void>(::poll(&descriptor, 1, 1));
            }
            continue;
        }
        const auto batch_started = std::chrono::steady_clock::now();
        const auto batch_now_ns = packets[0].timestamp_ns;
        last_packet = batch_started;
        TransmitBatch transmit_batch{packets.data()};
        const auto rule_snapshot = runtime.processor().rules_snapshot();
        for (std::uint32_t index = 0; index < received; ++index) {
            auto frame = allocator.frame_span(packets[index].offset);
            const auto length = packets[index].length;
            const auto result =
                length <= frame.size() && rule_snapshot
                    ? runtime.processor().process(frame.first(length), *rule_snapshot, batch_now_ns)
                    : PacketProcessResult{};
            if (should_transmit(result.action)) {
                transmit_batch.forward(packets[index]);
            } else {
                transmit_batch.drop(packets[index]);
            }
        }
        const auto accepted = backend.send_batch(transmit_batch.transmit_descriptors(),
                                                 transmit_batch.transmit_count());
        const auto outcome = transmit_batch.complete(accepted);
        backend.recycle_rx_addresses(transmit_batch.recycle_addresses(),
                                     transmit_batch.recycle_count());
        received_total += received;
        runtime.metrics().record_rx(0, received);
        runtime.metrics().record_tx(0, outcome.transmitted);
        runtime.metrics().record_drop(0, outcome.dropped);
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - batch_started);
        runtime.metrics().record_latency_us(0, static_cast<std::uint64_t>(elapsed.count()));
        static_cast<void>(backend.recycle_completions(kBatchSize));
        static_cast<void>(backend.service_fill_ring());
    }
    return EXIT_SUCCESS;
}

} // namespace
} // namespace packet_engine

auto main(int argc, char** argv) -> int {
    const auto parsed = packet_engine::parse_engine_config(argc, argv);
    if (const auto* error = std::get_if<packet_engine::ConfigError>(&parsed)) {
        std::cerr << "packet-engine: " << error->message << '\n'
                  << packet_engine::engine_usage(argc > 0 ? argv[0] : "packet-engine");
        return EXIT_FAILURE;
    }
    const auto& config = std::get<packet_engine::EngineConfig>(parsed);
    if (config.show_help) {
        std::cout << packet_engine::engine_usage(config.eal_argv.front());
        return EXIT_SUCCESS;
    }
    packet_engine::stop_flag().store(false, std::memory_order_release);
    if (!packet_engine::install_signal_handlers()) {
        std::cerr << "packet-engine: could not install SIGINT/SIGTERM handlers\n";
        return EXIT_FAILURE;
    }
    try {
        if (config.backend == packet_engine::BackendKind::AfXdp) {
            return packet_engine::run_af_xdp(config);
        }
#ifdef HAVE_DPDK
        return packet_engine::run_dpdk(config);
#else
        std::cerr << "packet-engine: backend=dpdk requires a build with -DENABLE_DPDK=ON\n";
        return EXIT_FAILURE;
#endif
    } catch (const std::exception& error) {
        std::cerr << "packet-engine: " << error.what();
        if (config.backend == packet_engine::BackendKind::AfXdp) {
            std::cerr << "; verify interface existence, CAP_NET_ADMIN/CAP_BPF, and RLIMIT_MEMLOCK";
        }
        std::cerr << '\n';
        return EXIT_FAILURE;
    }
}
