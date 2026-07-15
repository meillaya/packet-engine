#include "packet-engine/metrics_endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <string_view>

namespace pe {

namespace {

constexpr std::string_view kStatusOk = R"({"status":"ok"})";
constexpr std::string_view kNotFound = "Not Found\n";
constexpr suseconds_t kClientIoTimeoutUs = 100'000;

bool send_all(int fd, std::string_view response) noexcept {
    std::size_t sent = 0;
    while (sent < response.size()) {
        const ssize_t rc = send(fd, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
        if (rc < 0 && errno == EINTR) {
            continue;
        }
        if (rc <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(rc);
    }
    return true;
}

// Minimal HTTP request-line parse: "METHOD /path HTTP/1.x".
// Returns true and fills method/path on success.
bool parse_request_line(std::string_view request, std::string_view& method,
                        std::string_view& path) {
    const size_t first_line_end = request.find("\r\n");
    if (first_line_end == std::string_view::npos) {
        return false;
    }
    std::string_view line = request.substr(0, first_line_end);

    const size_t first_space = line.find(' ');
    if (first_space == std::string_view::npos) {
        return false;
    }
    method = line.substr(0, first_space);

    const size_t second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos) {
        return false;
    }
    path = line.substr(first_space + 1, second_space - first_space - 1);
    return true;
}

std::string reason_phrase(int code) {
    switch (code) {
    case 200:
        return "OK";
    case 404:
        return "Not Found";
    default:
        return "Unknown";
    }
}

} // namespace

MetricsEndpoint::MetricsEndpoint(MetricsRegistry& registry, int port)
    : registry_(registry), port_(port) {}

MetricsEndpoint::~MetricsEndpoint() { stop(); }

bool MetricsEndpoint::start() {
    if (running_.load(std::memory_order_acquire)) {
        return true;
    }

    stop();

    listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) {
        return false;
    }

    int opt = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port_));

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (listen(listen_fd_, 16) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    // Update port_ with the actual bound port in case 0 was requested.
    socklen_t addr_len = sizeof(addr);
    if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
        port_ = ntohs(addr.sin_port);
    }

    running_.store(true, std::memory_order_release);
    thread_ = std::jthread([this](std::stop_token st) { accept_loop(st); });
    return true;
}

void MetricsEndpoint::stop() noexcept {
    running_.store(false, std::memory_order_release);
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
    }
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }
    if (listen_fd_ >= 0) {
        close(listen_fd_);
        listen_fd_ = -1;
    }
}

void MetricsEndpoint::accept_loop(std::stop_token st) {
    while (running_.load(std::memory_order_acquire) && !st.stop_requested()) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept4(listen_fd_, reinterpret_cast<sockaddr*>(&client_addr), &client_len,
                                SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            // Listening socket was closed or another error: exit loop.
            break;
        }
        handle_connection(client_fd);
    }
}

void MetricsEndpoint::handle_connection(int client_fd) {
    const timeval timeout{0, kClientIoTimeoutUs};
    if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(client_fd);
        return;
    }

    std::array<char, 4096> buffer{};
    ssize_t n = recv(client_fd, buffer.data(), buffer.size() - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buffer[static_cast<size_t>(n)] = '\0';

    std::string_view request(buffer.data(), static_cast<size_t>(n));
    std::string_view method;
    std::string_view path;

    std::string response;
    if (!parse_request_line(request, method, path) || method != "GET") {
        response = build_http_response(404, "text/plain; charset=utf-8", kNotFound);
    } else if (path == "/metrics") {
        std::string body = registry_.expose_text();
        response = build_http_response(200, "text/plain; version=0.0.4; charset=utf-8", body);
    } else if (path == "/health") {
        response = build_http_response(200, "application/json; charset=utf-8", kStatusOk);
    } else {
        response = build_http_response(404, "text/plain; charset=utf-8", kNotFound);
    }

    static_cast<void>(send_all(client_fd, response));
    close(client_fd);
}

std::string MetricsEndpoint::build_http_response(int code, const char* content_type,
                                                 std::string_view body) {
    std::string response;
    response.reserve(128 + body.size());
    response += "HTTP/1.1 ";
    response += std::to_string(code);
    response += ' ';
    response += reason_phrase(code);
    response += "\r\nContent-Type: ";
    response += content_type;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nConnection: close\r\n\r\n";
    response += body;
    return response;
}

} // namespace pe
