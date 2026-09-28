#include "kvmlib/cr3_trace.hpp"
#include "kvmlib/privilege.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

struct NativeCr3Event {
    std::uint64_t timestamp_ns;
    std::uint32_t virtual_cpu;
    std::uint32_t padding;
    std::uint64_t previous;
    std::uint64_t current;
};

static_assert(sizeof(NativeCr3Event) == 32);

constexpr unsigned long ioctl_command(const unsigned type, const unsigned number) {
    return (type << 8) | number;
}

constexpr unsigned long arm_command = ioctl_command(0xC3, 1);
constexpr unsigned long disarm_command = ioctl_command(0xC3, 2);
constexpr unsigned long flush_command = ioctl_command(0xC3, 3);

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) {
        return kvmlib::Error::permission_denied;
    }
    if (errno == ENOENT) {
        return kvmlib::Error::not_found;
    }
    return kvmlib::Error::io_error;
}

} // namespace

namespace kvmlib {

Cr3Trace::Cr3Trace(const int descriptor) noexcept : descriptor_(descriptor) {}

Cr3Trace::~Cr3Trace() {
    static_cast<void>(stop());

    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

Cr3Trace::Cr3Trace(Cr3Trace&& other) noexcept
    : descriptor_(other.descriptor_), enabled_(other.enabled_) {
    other.descriptor_ = -1;
    other.enabled_ = false;
}

Cr3Trace& Cr3Trace::operator=(Cr3Trace&& other) noexcept {
    if (this != &other) {
        static_cast<void>(stop());

        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }

        descriptor_ = other.descriptor_;
        enabled_ = other.enabled_;
        other.descriptor_ = -1;
        other.enabled_ = false;
    }

    return *this;
}

std::expected<Cr3Trace, Error> Cr3Trace::open(std::string device) {
    if (const auto privileged = require_root(); !privileged) {
        return std::unexpected(privileged.error());
    }

    const int descriptor = ::open(device.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }

    return Cr3Trace{descriptor};
}

bool Cr3Trace::enabled() const noexcept {
    return enabled_;
}

std::expected<void, Error> Cr3Trace::start() {
    if (descriptor_ < 0 || enabled_) {
        return std::unexpected(Error::invalid_argument);
    }
    if (::ioctl(descriptor_, flush_command) < 0 || ::ioctl(descriptor_, arm_command) < 0) {
        return std::unexpected(errno_error());
    }

    enabled_ = true;
    return {};
}

std::expected<void, Error> Cr3Trace::stop() {
    if (!enabled_) {
        return {};
    }

    enabled_ = false;
    if (descriptor_ >= 0 && ::ioctl(descriptor_, disarm_command) < 0) {
        return std::unexpected(errno_error());
    }
    return {};
}

std::expected<std::vector<Cr3Event>, Error> Cr3Trace::poll() {
    if (descriptor_ < 0 || !enabled_) {
        return std::unexpected(Error::invalid_argument);
    }

    std::array<NativeCr3Event, 128> events{};
    const auto bytes = ::read(descriptor_, events.data(), sizeof(events));
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::vector<Cr3Event>{};
        }

        return std::unexpected(errno_error());
    }

    if (bytes % static_cast<ssize_t>(sizeof(NativeCr3Event)) != 0) {
        return std::unexpected(Error::io_error);
    }

    std::vector<Cr3Event> result;
    result.reserve(static_cast<std::size_t>(bytes) / sizeof(NativeCr3Event));

    for (std::size_t index = 0; index < static_cast<std::size_t>(bytes) / sizeof(NativeCr3Event);
         ++index) {
        const auto& event = events[index];
        result.push_back({event.timestamp_ns, event.virtual_cpu, event.previous, event.current});
    }

    return result;
}

} // namespace kvmlib
