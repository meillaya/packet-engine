#include "runtime_context.hpp"

#include "packet-engine/backend_registry.hpp"
#include "packet-engine/conntrack.hpp"
#include "packet-engine/control_api.hpp"
#include "packet-engine/ketama.hpp"
#include "packet-engine/health_prober.hpp"
#include "packet-engine/metrics_aggregator.hpp"
#include "packet-engine/metrics_endpoint.hpp"
#include "packet-engine/nat.hpp"
#include "packet-engine/packet_processor.hpp"
#include "packet-engine/prometheus_client.hpp"
#include "packet-engine/rule_table.hpp"

#include <memory>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace packet_engine {
namespace {

class KetamaRegistryAdapter final : public IKetamaRebuildCallback {
  public:
    explicit KetamaRegistryAdapter(KetamaRing& ring) noexcept : ring_{ring} {}

    void rebuild(const std::vector<Backend>& backends) override {
        std::vector<KetamaBackend> replacement;
        replacement.reserve(backends.size());
        for (const auto& backend : backends) {
            replacement.push_back(
                KetamaBackend{static_cast<KetamaBackendId>(backend.id), backend.authority});
        }
        static_cast<void>(ring_.replace_backends(std::move(replacement)));
    }

  private:
    KetamaRing& ring_;
};

std::unique_ptr<NatEngine> make_nat(const EngineConfig& config, ConntrackFlowCache& flows,
                                    BackendRegistry& backends, KetamaRing& ketama) {
    if (!config.vip) {
        return nullptr;
    }
    return std::make_unique<NatEngine>(flows, backends, ketama, *config.vip);
}

} // namespace

class RuntimeContext::Impl {
  public:
    explicit Impl(const EngineConfig& config)
        : adapter_{ketama_}, backends_{&adapter_}, health_prober_{backends_},
          nat_{make_nat(config, flows_, backends_, ketama_)}, rules_{std::make_shared<RuleTable>()},
          metrics_{1, &registry_}, metrics_publisher_{metrics_, std::chrono::milliseconds{100}},
          processor_{rules_, nat_.get(),
                     config.default_allow ? DefaultPacketAction::ALLOW : DefaultPacketAction::DROP},
          control_{rules_, backends_, ketama_, config.control_socket},
          endpoint_{registry_, config.metrics_port} {}

    ~Impl() {
        health_prober_.stop();
        metrics_publisher_.stop();
        endpoint_.stop();
        control_.stop();
    }

    void start() {
        if (!control_.start()) {
            throw std::runtime_error{"could not start control socket"};
        }
        metrics_publisher_.start();
        if (!endpoint_.start()) {
            metrics_publisher_.stop();
            control_.stop();
            throw std::runtime_error{"could not start metrics endpoint"};
        }
        health_prober_.start();
    }

    void maintenance() noexcept {
        constexpr std::uint32_t kClockSampleMask = 4095;
        if ((maintenance_poll_count_++ & kClockSampleMask) != 0) {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now < next_maintenance_) {
            return;
        }
        next_maintenance_ = now + std::chrono::milliseconds{100};
        const auto now_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        static_cast<void>(flows_.evict_idle(static_cast<std::uint64_t>(now_ns)));
    }

    KetamaRing ketama_;
    KetamaRegistryAdapter adapter_;
    BackendRegistry backends_;
    HealthProber health_prober_;
    ConntrackFlowCache flows_;
    std::unique_ptr<NatEngine> nat_;
    RuleTableRegistry rules_;
    pe::MetricsRegistry registry_;
    pe::MetricsAggregator metrics_;
    pe::PeriodicMetricsPublisher metrics_publisher_;
    PacketProcessor processor_;
    ControlApi control_;
    pe::MetricsEndpoint endpoint_;
    std::chrono::steady_clock::time_point next_maintenance_{};
    std::uint32_t maintenance_poll_count_{0};
};

RuntimeContext::RuntimeContext(const EngineConfig& config)
    : impl_{std::make_unique<Impl>(config)} {}

RuntimeContext::~RuntimeContext() = default;

void RuntimeContext::start() { impl_->start(); }

void RuntimeContext::maintenance() noexcept { impl_->maintenance(); }

PacketProcessor& RuntimeContext::processor() noexcept { return impl_->processor_; }

pe::MetricsAggregator& RuntimeContext::metrics() noexcept { return impl_->metrics_; }

} // namespace packet_engine
