// SPDX-License-Identifier: MIT
//
// control_api.cpp -- Unix-socket REST/JSON control API for the packet engine.
//

#include "packet-engine/control_api.hpp"

#include "packet-engine/rule_entry.hpp"
#include "packet-engine/rule_schema.hpp"

#include <nlohmann/json.hpp>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace packet_engine {

namespace {

constexpr std::size_t kRecvBufSize = 8192;
constexpr std::size_t kMaxRequestSize = 65536;
constexpr suseconds_t kClientIoTimeoutUs = 500'000;

struct ContentLength {
    bool valid = true;
    std::size_t value = 0;
};

bool ascii_equal_ignore_case(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size())
        return false;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        char left = lhs[i];
        char right = rhs[i];
        if (left >= 'A' && left <= 'Z')
            left = static_cast<char>(left - 'A' + 'a');
        if (right >= 'A' && right <= 'Z')
            right = static_cast<char>(right - 'A' + 'a');
        if (left != right)
            return false;
    }
    return true;
}

ContentLength parse_content_length(std::string_view headers) noexcept {
    ContentLength result;
    bool found = false;
    std::size_t line_start = headers.find("\r\n");
    if (line_start == std::string_view::npos)
        return ContentLength{false, 0};
    line_start += 2;

    while (line_start < headers.size()) {
        std::size_t line_end = headers.find("\r\n", line_start);
        if (line_end == std::string_view::npos)
            line_end = headers.size();
        const std::string_view line = headers.substr(line_start, line_end - line_start);
        const std::size_t colon = line.find(':');
        if (colon != std::string_view::npos &&
            ascii_equal_ignore_case(line.substr(0, colon), "Content-Length")) {
            if (found)
                return ContentLength{false, 0};
            found = true;
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                value.remove_prefix(1);
            }
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
                value.remove_suffix(1);
            }
            const char* begin = value.data();
            const char* end = value.data() + value.size();
            const auto [ptr, error] = std::from_chars(begin, end, result.value);
            if (value.empty() || error != std::errc{} || ptr != end) {
                return ContentLength{false, 0};
            }
        }
        if (line_end == headers.size())
            break;
        line_start = line_end + 2;
    }
    return result;
}

std::optional<std::uint64_t> parse_u64(std::string_view value) noexcept {
    std::uint64_t parsed = 0;
    const char* begin = value.data();
    const char* end = value.data() + value.size();
    const auto [ptr, error] = std::from_chars(begin, end, parsed);
    if (value.empty() || error != std::errc{} || ptr != end)
        return std::nullopt;
    return parsed;
}

bool send_all(int fd, std::string_view response) noexcept {
    std::size_t sent = 0;
    while (sent < response.size()) {
        const ssize_t count =
            ::send(fd, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        return false;
    }
    return true;
}

using Json = nlohmann::json;

struct BackendUpdate {
    std::vector<Backend> backends;
    std::string error;

    [[nodiscard]] explicit operator bool() const noexcept { return error.empty(); }
};

std::optional<std::uint64_t> parse_json_u64(const Json& value) {
    if (value.is_number_unsigned()) {
        return value.get<Json::number_unsigned_t>();
    }
    if (value.is_number_integer()) {
        const auto parsed = value.get<Json::number_integer_t>();
        if (parsed >= 0)
            return static_cast<std::uint64_t>(parsed);
    }
    return std::nullopt;
}

std::optional<MacAddr> parse_mac(const Json& value) {
    if (!value.is_string())
        return std::nullopt;
    const std::string text = value.get<std::string>();
    if (text.size() != 17u)
        return std::nullopt;
    MacAddr mac{};
    for (std::size_t index = 0; index < mac.bytes.size(); ++index) {
        const std::size_t offset = index * 3u;
        unsigned parsed = 0;
        const auto [end, error] =
            std::from_chars(text.data() + offset, text.data() + offset + 2u, parsed, 16);
        if (error != std::errc{} || end != text.data() + offset + 2u || parsed > 0xffu ||
            (index + 1u < mac.bytes.size() && text[offset + 2u] != ':')) {
            return std::nullopt;
        }
        mac.bytes[index] = static_cast<std::uint8_t>(parsed);
    }
    return mac;
}

bool is_zero_mac(const MacAddr& mac) noexcept {
    return std::all_of(mac.bytes.begin(), mac.bytes.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

std::string format_mac(const MacAddr& mac) {
    constexpr char digits[] = "0123456789abcdef";
    std::string text(17u, ':');
    for (std::size_t index = 0; index < mac.bytes.size(); ++index) {
        const std::size_t offset = index * 3u;
        text[offset] = digits[mac.bytes[index] >> 4u];
        text[offset + 1u] = digits[mac.bytes[index] & 0x0fu];
    }
    return text;
}

BackendUpdate parse_backend_update(std::string_view body) {
    const auto document = Json::parse(body, nullptr, false);
    if (document.is_discarded() || !document.is_array()) {
        return {{}, "backends must be a JSON array"};
    }

    BackendUpdate update;
    update.backends.reserve(document.size());
    std::set<BackendId> ids;
    std::set<std::string> authorities;
    for (const auto& item : document) {
        const bool has_mac = item.is_object() && item.contains("mac");
        if (!item.is_object() || item.size() != (has_mac ? 4u : 3u) || !item.contains("id") ||
            !item.contains("authority") || !item.contains("health_port")) {
            return {{}, "each backend must contain id, authority, health_port, and optional mac"};
        }

        const auto id = parse_json_u64(item.at("id"));
        if (!id || *id >= INVALID_KETAMA_BACKEND_ID) {
            return {{}, "backend id must be an unsigned 32-bit integer"};
        }
        if (!item.at("authority").is_string()) {
            return {{}, "backend authority must be a string"};
        }
        const auto authority = item.at("authority").get<std::string>();
        if (authority.empty())
            return {{}, "backend authority must not be empty"};
        if (authority.find('\0') != std::string::npos)
            return {{}, "backend authority must not contain a NUL byte"};

        const auto health_port = parse_json_u64(item.at("health_port"));
        if (!health_port || *health_port > std::numeric_limits<std::uint16_t>::max()) {
            return {{}, "backend health_port must be an unsigned 16-bit integer"};
        }
        if (!ids.insert(*id).second)
            return {{}, "backend ids must be unique"};
        if (!authorities.insert(authority).second) {
            return {{}, "backend authorities must be unique"};
        }
        MacAddr mac{};
        if (has_mac) {
            const auto parsed_mac = parse_mac(item.at("mac"));
            if (!parsed_mac || is_zero_mac(*parsed_mac))
                return {{}, "backend mac must be a non-zero xx:xx:xx:xx:xx:xx address"};
            mac = *parsed_mac;
        }
        update.backends.push_back(
            Backend{*id, authority, *health_port, BackendState::HEALTHY, mac});
    }
    return update;
}

std::string serialize_backends(std::vector<Backend> backends) {
    std::sort(backends.begin(), backends.end(),
              [](const Backend& lhs, const Backend& rhs) { return lhs.id < rhs.id; });
    Json document = Json::array();
    for (const auto& backend : backends) {
        Json item{{"id", backend.id},
                  {"authority", backend.authority},
                  {"health_port", backend.health_port}};
        if (!is_zero_mac(backend.next_hop_mac))
            item["mac"] = format_mac(backend.next_hop_mac);
        document.push_back(std::move(item));
    }
    return document.dump();
}

} // namespace

ControlApi::ControlApi(RuleTableRegistry& rules, BackendRegistry& backends, KetamaRing& ketama,
                       std::string socket_path)
    : rules_{rules}, backends_{backends}, socket_path_{std::move(socket_path)} {
    static_cast<void>(ketama);
}

ControlApi::~ControlApi() { stop(); }

bool ControlApi::start() {
    if (running_.load(std::memory_order_acquire)) {
        return true;
    }

    stop();

    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) {
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        if (errno != EADDRINUSE) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        const int probe_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (probe_fd < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        const int probe_result =
            ::connect(probe_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        const int probe_error = errno;
        ::close(probe_fd);
        if (probe_result == 0 || probe_error != ECONNREFUSED) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        struct stat stale{};
        if (::lstat(socket_path_.c_str(), &stale) < 0 || !S_ISSOCK(stale.st_mode)) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
        struct stat unchanged{};
        if (::lstat(socket_path_.c_str(), &unchanged) < 0 || stale.st_dev != unchanged.st_dev ||
            stale.st_ino != unchanged.st_ino || ::unlink(socket_path_.c_str()) < 0 ||
            ::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }
    }

    struct stat owned{};
    if (::lstat(socket_path_.c_str(), &owned) < 0 || !S_ISSOCK(owned.st_mode)) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    owns_socket_path_ = true;
    socket_device_ = static_cast<std::uint64_t>(owned.st_dev);
    socket_inode_ = static_cast<std::uint64_t>(owned.st_ino);

    if (::chmod(socket_path_.c_str(), S_IRUSR | S_IWUSR) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        unlink_owned_socket_();
        return false;
    }
    struct stat secured{};
    if (::lstat(socket_path_.c_str(), &secured) < 0 ||
        static_cast<std::uint64_t>(secured.st_dev) != socket_device_ ||
        static_cast<std::uint64_t>(secured.st_ino) != socket_inode_ ||
        (secured.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        unlink_owned_socket_();
        return false;
    }

    if (::listen(listen_fd_, 8) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        unlink_owned_socket_();
        return false;
    }

    running_.store(true, std::memory_order_release);
    thread_ = std::jthread([this](std::stop_token st) { accept_loop(st); });
    return true;
}

void ControlApi::stop() noexcept {
    running_.store(false, std::memory_order_release);

    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
    }

    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }

    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }

    unlink_owned_socket_();
}

void ControlApi::accept_loop(std::stop_token st) {
    while (running_.load(std::memory_order_acquire) && !st.stop_requested()) {
        int client_fd = ::accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        try {
            handle_connection(client_fd);
        } catch (const std::exception&) {
            const auto response =
                build_http_response(400, "application/json", R"({"error":"bad request"})");
            static_cast<void>(send_all(client_fd, response));
        }
        ::close(client_fd);
    }
}

void ControlApi::handle_connection(int client_fd) {
    const timeval timeout{0, kClientIoTimeoutUs};
    if (::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        ::setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return;
    }

    std::string request;
    std::array<char, kRecvBufSize> buf{};
    std::size_t expected_size = 0;
    bool complete = false;
    bool malformed = false;

    while (request.size() < kMaxRequestSize) {
        const ssize_t n = ::recv(client_fd, buf.data(), buf.size(), 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            break;
        }
        const auto received = static_cast<std::size_t>(n);
        if (received > kMaxRequestSize - request.size()) {
            malformed = true;
            break;
        }
        request.append(buf.data(), received);

        const std::size_t header_end = request.find("\r\n\r\n");
        if (header_end != std::string::npos) {
            const ContentLength content_length =
                parse_content_length(std::string_view(request).substr(0, header_end));
            constexpr std::size_t separator_size = 4;
            if (header_end > kMaxRequestSize - separator_size) {
                malformed = true;
                break;
            }
            const std::size_t header_size = header_end + separator_size;
            if (!content_length.valid || content_length.value > kMaxRequestSize - header_size) {
                malformed = true;
                break;
            }
            expected_size = header_size + content_length.value;
            if (request.size() >= expected_size) {
                complete = true;
                break;
            }
        }
    }

    if (request.empty()) {
        return;
    }
    if (!complete || malformed) {
        const auto response =
            build_http_response(400, "application/json", R"({"error":"bad request"})");
        static_cast<void>(send_all(client_fd, response));
        return;
    }

    std::string_view method;
    std::string_view path;
    std::string_view body;

    auto first_line_end = request.find("\r\n");
    if (first_line_end == std::string::npos) {
        auto resp = build_http_response(400, "text/plain", "Bad request");
        static_cast<void>(send_all(client_fd, resp));
        return;
    }

    auto first_line = std::string_view(request).substr(0, first_line_end);
    auto method_end = first_line.find(' ');
    if (method_end == std::string_view::npos) {
        auto resp = build_http_response(400, "text/plain", "Bad request");
        static_cast<void>(send_all(client_fd, resp));
        return;
    }
    method = first_line.substr(0, method_end);

    auto path_start = method_end + 1;
    auto path_end = first_line.find(' ', path_start);
    if (path_end == std::string_view::npos) {
        path_end = first_line.size();
    }
    path = first_line.substr(path_start, path_end - path_start);

    auto header_end = request.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        body = std::string_view(request).substr(header_end + 4, expected_size - header_end - 4);
    }

    auto response = handle_request(method, path, body);
    static_cast<void>(send_all(client_fd, response));
}

std::string ControlApi::handle_request(std::string_view method, std::string_view path,
                                       std::string_view body) {
    if (method == "GET" && path == "/health") {
        return build_http_response(200, "application/json", R"({"status":"ok"})");
    }

    if (method == "GET" && path == "/rules") {
        auto rules = active_rules_.load(std::memory_order_acquire);
        if (!rules) {
            return build_http_response(200, "application/json", "[]");
        }
        return build_http_response(200, "application/json", serialize_rules_json(*rules));
    }

    if (method == "PUT" && path == "/rules") {
        auto parsed = parse_rules_json(std::string(body));
        if (!parsed) {
            // Error messages can contain quotes from the JSON parser; let
            // nlohmann escape them instead of splicing raw text.
            return build_http_response(400, "application/json",
                                       Json{{"error", parsed.error().message}}.dump());
        }

        auto table = std::make_shared<RuleTable>();
        auto rule_list = std::make_shared<std::vector<Rule>>(std::move(*parsed));
        const auto previous_table = rules_.active();
        std::set<std::uint64_t> rule_ids;
        std::unordered_set<FiveTuple> exact_matchers;
        std::unordered_set<std::uint64_t> cidr_matchers;

        for (const auto& rule : *rule_list) {
            RuleEntry entry;
            const auto rule_id = parse_u64(rule.id);
            if (!rule_id) {
                return build_http_response(400, "application/json",
                                           R"({"error":"rule id must be an unsigned integer"})");
            }
            if (!rule_ids.insert(*rule_id).second) {
                return build_http_response(400, "application/json",
                                           R"({"error":"rule ids must be unique"})");
            }
            entry.id = *rule_id;
            switch (rule.action) {
            case SchemaAction::ALLOW:
                entry.action = RuleEntryAction::ALLOW;
                break;
            case SchemaAction::DROP:
                entry.action = RuleEntryAction::DROP;
                break;
            case SchemaAction::FORWARD:
                entry.action = RuleEntryAction::FORWARD_TO_BACKEND;
                if (rule.backend_id) {
                    const auto backend_id = parse_u64(*rule.backend_id);
                    if (!backend_id || *backend_id > std::numeric_limits<std::uint32_t>::max()) {
                        return build_http_response(
                            400, "application/json",
                            R"({"error":"backend id must be an unsigned 32-bit integer"})");
                    }
                    entry.backend_id = static_cast<std::uint32_t>(*backend_id);
                    entry.has_backend_id = true;
                }
                break;
            case SchemaAction::RATE_LIMIT:
                entry.action = RuleEntryAction::RATE_LIMIT;
                if (rule.rate_bps) {
                    if (*rule.rate_bps > std::numeric_limits<std::uint32_t>::max()) {
                        return build_http_response(
                            400, "application/json",
                            R"({"error":"rate_bps exceeds the supported range"})");
                    }
                    entry.rate_limit_bps = static_cast<std::uint32_t>(*rule.rate_bps);
                }
                break;
            }

            bool inserted = false;
            if (rule.tuple) {
                const auto& t = *rule.tuple;
                const FiveTuple matcher{t.src_ip, t.dst_ip, t.src_port, t.dst_port, t.proto};
                if (!exact_matchers.insert(matcher).second) {
                    return build_http_response(400, "application/json",
                                               R"({"error":"exact matchers must be unique"})");
                }
                inserted = table->add_exact(matcher, entry);
            } else if (rule.cidr) {
                const auto mask =
                    rule.cidr->prefix_len == 0 ? 0u : ~0u << (32u - rule.cidr->prefix_len);
                const auto network = rule.cidr->addr.value & mask;
                const auto matcher =
                    (static_cast<std::uint64_t>(network) << 8u) | rule.cidr->prefix_len;
                if (!cidr_matchers.insert(matcher).second) {
                    return build_http_response(400, "application/json",
                                               R"({"error":"CIDR matchers must be unique"})");
                }
                inserted = table->add_cidr_v4(IPv4Addr{network}, rule.cidr->prefix_len, entry);
            }
            if (!inserted) {
                return build_http_response(
                    400, "application/json",
                    R"({"error":"rule could not be inserted into the active table"})");
            }
            if (rule.action == SchemaAction::RATE_LIMIT) {
                if (!rule.rate_bps || !rule.burst_bytes) {
                    return build_http_response(
                        400, "application/json",
                        R"({"error":"RATE_LIMIT requires rate_bps and burst_bytes"})");
                }
                auto state = previous_table ? previous_table->matching_rate_limit_state(
                                                  entry.id, *rule.rate_bps, *rule.burst_bytes)
                                            : nullptr;
                if (state) {
                    table->add_rate_limit_state(entry.id, std::move(state));
                } else {
                    table->add_rate_limit_state(
                        entry.id,
                        TokenBucket{*rule.rate_bps, *rule.burst_bytes, detail::steady_now_ns()});
                }
            }
        }

        publish_rule_table_(std::move(table), std::move(rule_list));
        return build_http_response(200, "application/json", R"({"ok":true})");
    }

    if (method == "GET" && path == "/backends") {
        return build_http_response(200, "application/json",
                                   serialize_backends(backends_.snapshot()));
    }

    if (method == "PUT" && path == "/backends") {
        auto update = parse_backend_update(body);
        if (!update) {
            return build_http_response(400, "application/json",
                                       Json{{"error", update.error}}.dump());
        }
        if (!backends_.replace_all(std::move(update.backends))) {
            return build_http_response(400, "application/json",
                                       R"({"error":"backend set could not be replaced"})");
        }
        return build_http_response(200, "application/json", R"({"ok":true})");
    }

    return build_http_response(404, "application/json", R"({"error":"not found"})");
}

void ControlApi::publish_rule_table_(std::shared_ptr<const RuleTable> table, RuleListPtr rules) {
    rules_.swap(std::move(table));
    active_rules_.store(std::move(rules), std::memory_order_release);
}

void ControlApi::unlink_owned_socket_() noexcept {
    if (!owns_socket_path_)
        return;

    struct stat current{};
    if (::lstat(socket_path_.c_str(), &current) == 0 &&
        static_cast<std::uint64_t>(current.st_dev) == socket_device_ &&
        static_cast<std::uint64_t>(current.st_ino) == socket_inode_) {
        static_cast<void>(::unlink(socket_path_.c_str()));
    }
    owns_socket_path_ = false;
    socket_device_ = 0;
    socket_inode_ = 0;
}

std::string ControlApi::build_http_response(int code, const char* content_type,
                                            std::string_view body) {
    const char* status_text = "OK";
    if (code == 400)
        status_text = "Bad Request";
    else if (code == 404)
        status_text = "Not Found";

    std::string response;
    response.reserve(256 + body.size());
    response += "HTTP/1.1 ";
    response += std::to_string(code);
    response += ' ';
    response += status_text;
    response += "\r\nContent-Type: ";
    response += content_type;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nConnection: close\r\n\r\n";
    response += body;
    return response;
}

} // namespace packet_engine
