#include "kvmlib/input.hpp"
#include "kvmlib/privilege.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <filesystem>
#include <fcntl.h>
#include <linux/input.h>
#include <string_view>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) {
        return kvmlib::Error::permission_denied;
    }
    if (errno == ENOENT) {
        return kvmlib::Error::not_found;
    }
    return kvmlib::Error::io_error;
}

std::expected<kvmlib::EvdevInput, kvmlib::Error> open_kind(const std::string_view kind,
                                                           const bool host_only) {
    const std::filesystem::path directory{"/dev/input/by-id"};
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(kvmlib::Error::not_found);
    }

    std::vector<std::filesystem::path> candidates;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        const auto name = entry.path().filename().string();
        if (host_only && name.starts_with("baykus-")) {
            continue;
        }

        if (name.contains(kind) && name.contains("event")) {
            candidates.push_back(entry.path());
        }
    }

    std::ranges::sort(candidates, [](const auto& left, const auto& right) {
        return left.filename().string().starts_with("baykus-")
            > right.filename().string().starts_with("baykus-");
    });

    for (const auto& candidate : candidates) {
        if (auto input = kvmlib::EvdevInput::open(candidate.string())) {
            return input;
        }
    }

    return std::unexpected(kvmlib::Error::not_found);
}

} // namespace

namespace kvmlib {

EvdevInput::EvdevInput(const int descriptor) noexcept : descriptor_(descriptor) {}

EvdevInput::~EvdevInput() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

EvdevInput::EvdevInput(EvdevInput&& other) noexcept : descriptor_(other.descriptor_) {
    other.descriptor_ = -1;
}

EvdevInput& EvdevInput::operator=(EvdevInput&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
    }
    return *this;
}

std::expected<EvdevInput, Error> EvdevInput::open(std::string path) {
    if (const auto privileged = require_root(); !privileged) {
        return std::unexpected(privileged.error());
    }

    const int descriptor = ::open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }

    return EvdevInput{descriptor};
}

std::expected<EvdevInput, Error> EvdevInput::open_mouse() {
    return open_kind("mouse", false);
}

std::expected<EvdevInput, Error> EvdevInput::open_keyboard() {
    auto input = open_kind("kbd", false);
    if (input) {
        return input;
    }

    return open_kind("keyboard", false);
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_mouse() {
    return open("/dev/input/by-id/baykus-vmouse-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_keyboard() {
    return open("/dev/input/by-id/baykus-vkbd-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_host_keyboard() {
    auto input = open_kind("kbd", true);
    if (input) {
        return input;
    }

    return open_kind("keyboard", true);
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_keyboards() {
    const std::filesystem::path directory{"/dev/input/by-id"};
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(Error::not_found);
    }

    std::vector<std::filesystem::path> candidates;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        const auto name = entry.path().filename().string();
        if (name.starts_with("baykus-") || !name.contains("event")
            || (!name.contains("kbd") && !name.contains("keyboard"))) {
            continue;
        }
        candidates.push_back(entry.path());
    }

    std::ranges::sort(candidates);
    std::vector<EvdevInput> inputs;

    for (const auto& candidate : candidates) {
        if (auto input = open(candidate.string())) {
            inputs.push_back(std::move(*input));
        }
    }

    if (inputs.empty()) {
        return std::unexpected(Error::not_found);
    }

    return inputs;
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_mice() {
    const std::filesystem::path directory{"/dev/input/by-id"};
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(Error::not_found);
    }

    std::vector<std::filesystem::path> candidates;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        const auto name = entry.path().filename().string();
        if (name.starts_with("baykus-") || !name.contains("event") || !name.contains("mouse")) {
            continue;
        }
        candidates.push_back(entry.path());
    }

    std::ranges::sort(candidates);
    std::vector<EvdevInput> inputs;

    for (const auto& candidate : candidates) {
        if (auto input = open(candidate.string())) {
            inputs.push_back(std::move(*input));
        }
    }

    if (inputs.empty()) {
        return std::unexpected(Error::not_found);
    }

    return inputs;
}

bool EvdevInput::is_open() const noexcept {
    return descriptor_ >= 0;
}

std::expected<bool, Error> EvdevInput::key_down(const std::uint16_t key_code) const {
    if (!is_open() || key_code > KEY_MAX) {
        return std::unexpected(Error::invalid_argument);
    }

    std::array<std::uint8_t, KEY_MAX / 8 + 1> bits{};
    if (::ioctl(descriptor_, EVIOCGKEY(bits.size()), bits.data()) < 0) {
        return std::unexpected(errno_error());
    }

    return (bits[key_code / 8] & (1U << (key_code % 8))) != 0;
}

std::expected<bool, Error> EvdevInput::mouse_button_down(const std::uint16_t button_code) const {
    return key_down(button_code);
}

std::expected<std::vector<InputEvent>, Error> EvdevInput::poll() {
    if (!is_open()) {
        return std::unexpected(Error::invalid_argument);
    }

    std::array<input_event, 128> native_events{};
    const auto bytes = ::read(descriptor_, native_events.data(), sizeof(native_events));
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::vector<InputEvent>{};
        }

        return std::unexpected(errno_error());
    }

    if (bytes % static_cast<ssize_t>(sizeof(input_event)) != 0) {
        return std::unexpected(Error::io_error);
    }

    std::vector<InputEvent> result;
    result.reserve(static_cast<std::size_t>(bytes) / sizeof(input_event));

    for (std::size_t index = 0; index < static_cast<std::size_t>(bytes) / sizeof(input_event);
         ++index) {
        const auto& event = native_events[index];
        result.push_back({event.type, event.code, event.value});
    }

    return result;
}

std::expected<void, Error> EvdevInput::send(const InputEvent& event) const {
    if (!is_open()) {
        return std::unexpected(Error::invalid_argument);
    }
    input_event native_event{};
    native_event.type = event.type;
    native_event.code = event.code;
    native_event.value = event.value;

    if (::write(descriptor_, &native_event, sizeof(native_event)) != sizeof(native_event)) {
        return std::unexpected(errno_error());
    }
    return {};
}

std::expected<void, Error> EvdevInput::synchronize() const {
    return send({EV_SYN, SYN_REPORT, 0});
}

std::expected<void, Error> EvdevInput::send_key(const std::uint16_t key_code,
                                                const bool pressed) const {
    if (key_code > KEY_MAX) {
        return std::unexpected(Error::invalid_argument);
    }
    auto sent = send({EV_KEY, key_code, pressed ? 1 : 0});
    if (!sent) {
        return sent;
    }

    return synchronize();
}

std::expected<void, Error> EvdevInput::send_mouse_button(const std::uint16_t button_code,
                                                         const bool pressed) const {
    return send_key(button_code, pressed);
}

std::expected<void, Error> EvdevInput::click_mouse_button(const std::uint16_t button_code) const {
    auto pressed = send_mouse_button(button_code, true);
    if (!pressed) {
        return pressed;
    }

    return send_mouse_button(button_code, false);
}

std::expected<void, Error> EvdevInput::move_relative(const std::int32_t x,
                                                     const std::int32_t y) const {
    if (x == 0 && y == 0) {
        return {};
    }

    if (x != 0) {
        auto sent = send({EV_REL, REL_X, x});
        if (!sent) {
            return sent;
        }
    }

    if (y != 0) {
        auto sent = send({EV_REL, REL_Y, y});
        if (!sent) {
            return sent;
        }
    }

    return synchronize();
}

} // namespace kvmlib
