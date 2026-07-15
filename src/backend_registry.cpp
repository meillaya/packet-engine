// SPDX-License-Identifier: MIT
//
// backend_registry.cpp -- implementation of BackendRegistry.
//

#include "packet-engine/backend_registry.hpp"

#include <algorithm>
#include <mutex>
#include <utility>

namespace packet_engine {

BackendRegistry::BackendRegistry(IKetamaRebuildCallback* ketama_callback,
                                 std::size_t failure_threshold, std::chrono::seconds failure_window)
    : ketama_callback_{ketama_callback}, failure_threshold_{failure_threshold},
      failure_window_{failure_window} {}

void BackendRegistry::register_backend(Backend backend) {
    const auto id = backend.id;
    std::unique_lock lock{mutex_};
    backend.state = BackendState::HEALTHY;
    backends_[id] = std::move(backend);
    failures_.erase(id);
    rebuild_ketama_locked();
}

void BackendRegistry::unregister_backend(BackendId id) {
    std::unique_lock lock{mutex_};
    backends_.erase(id);
    failures_.erase(id);
    rebuild_ketama_locked();
}

bool BackendRegistry::replace_all(std::vector<Backend> backends) {
    std::unordered_map<BackendId, Backend> replacement;
    replacement.reserve(backends.size());
    for (auto& backend : backends) {
        if (backend.authority.empty())
            return false;
        backend.state = BackendState::HEALTHY;
        if (!replacement.emplace(backend.id, std::move(backend)).second)
            return false;
    }

    std::unique_lock lock{mutex_};
    backends_.swap(replacement);
    failures_.clear();
    rebuild_ketama_locked();
    return true;
}

void BackendRegistry::report_failure(BackendId id) {
    std::unique_lock lock{mutex_};
    auto it = backends_.find(id);
    if (it == backends_.end()) {
        return;
    }

    const auto now = Clock::now();
    auto fit = failures_.find(id);
    if (fit == failures_.end()) {
        fit = failures_.emplace(id, FailureRecord{}).first;
    }
    fit->second.times.push_back(now);
    prune_failures_locked(id, now);

    // Re-fetch the record in case pruning erased it.
    fit = failures_.find(id);
    const std::size_t failure_count = (fit == failures_.end()) ? 0 : fit->second.times.size();
    if (failure_count > failure_threshold_ && it->second.state != BackendState::DEGRADED) {
        it->second.state = BackendState::DEGRADED;
        rebuild_ketama_locked();
    }
}

void BackendRegistry::report_success(BackendId id) {
    std::unique_lock lock{mutex_};
    auto it = backends_.find(id);
    if (it == backends_.end()) {
        return;
    }

    const bool had_failures = failures_.erase(id) > 0;
    if (it->second.state != BackendState::HEALTHY) {
        it->second.state = BackendState::HEALTHY;
        rebuild_ketama_locked();
    } else if (had_failures) {
        rebuild_ketama_locked();
    }
}

std::optional<Backend> BackendRegistry::find(BackendId id) const {
    std::shared_lock lock{mutex_};
    auto it = backends_.find(id);
    if (it == backends_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<Backend> BackendRegistry::snapshot() const {
    std::shared_lock lock{mutex_};
    std::vector<Backend> result;
    result.reserve(backends_.size());
    for (const auto& [id, backend] : backends_) {
        (void)id;
        result.push_back(backend);
    }
    return result;
}

std::vector<Backend> BackendRegistry::healthy_snapshot() const {
    std::shared_lock lock{mutex_};
    std::vector<Backend> result;
    result.reserve(backends_.size());
    for (const auto& [id, backend] : backends_) {
        (void)id;
        if (backend.state != BackendState::DOWN) {
            result.push_back(backend);
        }
    }
    return result;
}

std::size_t BackendRegistry::size() const {
    std::shared_lock lock{mutex_};
    return backends_.size();
}

void BackendRegistry::rebuild_ketama_locked() {
    if (ketama_callback_ == nullptr) {
        return;
    }

    std::vector<Backend> eligible;
    eligible.reserve(backends_.size());
    for (const auto& [id, backend] : backends_) {
        (void)id;
        if (backend.state == BackendState::HEALTHY) {
            eligible.push_back(backend);
        }
    }
    ketama_callback_->rebuild(std::move(eligible));
}

void BackendRegistry::prune_failures_locked(BackendId id, TimePoint now) {
    auto it = failures_.find(id);
    if (it == failures_.end()) {
        return;
    }

    const auto cutoff = now - failure_window_;
    auto& times = it->second.times;
    times.erase(std::remove_if(times.begin(), times.end(),
                               [cutoff](const TimePoint& tp) { return tp < cutoff; }),
                times.end());

    if (times.empty()) {
        failures_.erase(it);
    }
}

void BackendRegistry::set_state_locked(BackendId id, BackendState new_state) {
    auto it = backends_.find(id);
    if (it != backends_.end() && it->second.state != new_state) {
        it->second.state = new_state;
        rebuild_ketama_locked();
    }
}

} // namespace packet_engine
