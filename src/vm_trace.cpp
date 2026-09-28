#include "kvmlib/vm_trace.hpp"
#include "kvmlib/privilege.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

struct NativeVmTraceConfig {
    std::uint64_t cr3;
    std::uint64_t stop_rip;
    std::uint64_t max_events;
};

struct NativeVmTraceEvent {
    std::uint64_t sequence;
    std::uint64_t timestamp_ns;
    std::uint64_t cr3;
    std::uint64_t rip;
    std::uint64_t rflags;
    std::uint64_t rax;
    std::uint64_t rbx;
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t rsi;
    std::uint64_t rdi;
    std::uint64_t rbp;
    std::uint64_t rsp;
    std::uint64_t r8;
    std::uint64_t r9;
    std::uint64_t r10;
    std::uint64_t r11;
    std::uint64_t r12;
    std::uint64_t r13;
    std::uint64_t r14;
    std::uint64_t r15;
    std::uint32_t virtual_cpu;
    std::uint32_t flags;
};

static_assert(sizeof(NativeVmTraceEvent) == 176);

constexpr unsigned long ioctl_none(const unsigned type, const unsigned number) {
    return (type << 8) | number;
}

constexpr unsigned long
ioctl_write(const unsigned type, const unsigned number, const std::size_t size) {
    return (1UL << 30) | (size << 16) | (type << 8) | number;
}

constexpr unsigned long configure_command = ioctl_write(0xd6, 1, sizeof(NativeVmTraceConfig));
constexpr unsigned long arm_command = ioctl_none(0xd6, 2);
constexpr unsigned long disarm_command = ioctl_none(0xd6, 3);
constexpr unsigned long flush_command = ioctl_none(0xd6, 4);

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) {
        return kvmlib::Error::permission_denied;
    }
    if (errno == ENOENT) {
        return kvmlib::Error::not_found;
    }
    if (errno == EINVAL || errno == EBUSY) {
        return kvmlib::Error::invalid_argument;
    }
    return kvmlib::Error::io_error;
}

kvmlib::VmTraceEvent convert(const NativeVmTraceEvent& event) {
    return {
        event.sequence,
        event.timestamp_ns,
        event.cr3,
        event.rip,
        {
            event.rflags,
            event.rax,
            event.rbx,
            event.rcx,
            event.rdx,
            event.rsi,
            event.rdi,
            event.rbp,
            event.rsp,
            event.r8,
            event.r9,
            event.r10,
            event.r11,
            event.r12,
            event.r13,
            event.r14,
            event.r15,
        },
        event.virtual_cpu,
        event.flags,
    };
}

} // namespace

namespace kvmlib {

VmTrace::VmTrace(const int descriptor) noexcept : descriptor_(descriptor) {}

VmTrace::~VmTrace() {
    static_cast<void>(stop());

    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

VmTrace::VmTrace(VmTrace&& other) noexcept
    : descriptor_(other.descriptor_), configured_(other.configured_), enabled_(other.enabled_) {
    other.descriptor_ = -1;
    other.configured_ = false;
    other.enabled_ = false;
}

VmTrace& VmTrace::operator=(VmTrace&& other) noexcept {
    if (this == &other) {
        return *this;
    }

    static_cast<void>(stop());
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
    descriptor_ = other.descriptor_;
    configured_ = other.configured_;
    enabled_ = other.enabled_;
    other.descriptor_ = -1;
    other.configured_ = false;
    other.enabled_ = false;

    return *this;
}

std::expected<VmTrace, Error> VmTrace::open(std::string device) {
    if (const auto privileged = require_root(); !privileged) {
        return std::unexpected(privileged.error());
    }

    const int descriptor = ::open(device.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }

    return VmTrace{descriptor};
}

bool VmTrace::enabled() const noexcept {
    return enabled_;
}

std::expected<void, Error> VmTrace::configure(const VmTraceConfig& config) {
    if (descriptor_ < 0 || enabled_ || config.cr3 == 0 || config.stop_rip == 0
        || config.max_events == 0) {
        return std::unexpected(Error::invalid_argument);
    }

    const NativeVmTraceConfig native{config.cr3, config.stop_rip, config.max_events};
    if (::ioctl(descriptor_, configure_command, &native) < 0) {
        return std::unexpected(errno_error());
    }

    configured_ = true;
    return {};
}

std::expected<void, Error> VmTrace::start() {
    if (descriptor_ < 0 || enabled_ || !configured_) {
        return std::unexpected(Error::invalid_argument);
    }
    if (::ioctl(descriptor_, flush_command) < 0 || ::ioctl(descriptor_, arm_command) < 0) {
        return std::unexpected(errno_error());
    }

    enabled_ = true;
    return {};
}

std::expected<void, Error> VmTrace::stop() {
    if (!enabled_) {
        return {};
    }

    enabled_ = false;
    if (descriptor_ >= 0 && ::ioctl(descriptor_, disarm_command) < 0) {
        return std::unexpected(errno_error());
    }
    return {};
}

std::expected<std::vector<VmTraceEvent>, Error> VmTrace::poll() {
    if (descriptor_ < 0 || !configured_) {
        return std::unexpected(Error::invalid_argument);
    }

    std::array<NativeVmTraceEvent, 256> events{};
    const auto bytes = ::read(descriptor_, events.data(), sizeof(events));
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::vector<VmTraceEvent>{};
        }

        return std::unexpected(errno_error());
    }

    if (bytes % static_cast<ssize_t>(sizeof(NativeVmTraceEvent)) != 0) {
        return std::unexpected(Error::io_error);
    }

    std::vector<VmTraceEvent> result;
    result.reserve(static_cast<std::size_t>(bytes) / sizeof(NativeVmTraceEvent));

    for (std::size_t index{}; index < static_cast<std::size_t>(bytes) / sizeof(NativeVmTraceEvent);
         ++index) {
        result.push_back(convert(events[index]));
    }

    return result;
}

} // namespace kvmlib
