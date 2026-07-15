#pragma once

#include <memory>

#include "packet-engine/engine_config.hpp"
#include "packet-engine/metrics_aggregator.hpp"

namespace packet_engine {

class PacketProcessor;

class RuntimeContext {
  public:
    explicit RuntimeContext(const EngineConfig& config);
    ~RuntimeContext();

    RuntimeContext(const RuntimeContext&) = delete;
    RuntimeContext& operator=(const RuntimeContext&) = delete;

    void start();
    void maintenance() noexcept;
    [[nodiscard]] PacketProcessor& processor() noexcept;
    [[nodiscard]] pe::MetricsAggregator& metrics() noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace packet_engine
