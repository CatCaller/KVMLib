#include "kvmlib/branch_trace.hpp"
#include "kvmlib/privilege.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <utility>

namespace {

struct NativeConfig {
    std::uint64_t cr3;
    std::uint64_t start;
    std::uint64_t stop;
    std::uint64_t range_begin;
    std::uint64_t range_end;
    std::uint64_t max_records;
    std::uint64_t timeout_ns;
    std::uint32_t qemu_process_id;
    std::uint32_t reserved;
};

struct NativeEventV1 {
    std::uint64_t from;
    std::uint64_t to;
    std::uint64_t rip;
    std::uint64_t rsp;
    std::uint64_t rax;
    std::uint64_t rcx;
    std::uint64_t rdx;
    std::uint64_t rflags;
};

struct NativeEventV2 {
    std::uint64_t from;
    std::uint64_t to;
    std::uint64_t rip;
    std::uint64_t rflags;
    std::array<std::uint64_t, 16> registers;
};

struct NativeContext {
    std::array<std::uint64_t, 16> registers;
    std::uint64_t rip;
    std::uint64_t rsp;
    std::uint64_t rflags;
    std::uint64_t cr3;
    std::uint64_t stop;
};

struct NativeStatus {
    std::uint32_t state;
    std::uint32_t reason;
    std::uint32_t virtual_cpu;
    std::uint32_t reserved;
    std::uint64_t records;
    NativeContext context;
};

static_assert(sizeof(NativeConfig) == 64);
static_assert(sizeof(NativeEventV1) == 64);
static_assert(sizeof(NativeEventV2) == 160);
static_assert(sizeof(NativeContext) == 168);
static_assert(sizeof(NativeStatus) == 192);

constexpr unsigned long ioctl_none(const unsigned type, const unsigned number) {
    return (type << 8) | number;
}

constexpr unsigned long
ioctl_read(const unsigned type, const unsigned number, const std::size_t size) {
    return (2UL << 30) | (size << 16) | (type << 8) | number;
}

constexpr unsigned long
ioctl_write(const unsigned type, const unsigned number, const std::size_t size) {
    return (1UL << 30) | (size << 16) | (type << 8) | number;
}

constexpr unsigned long configure_command = ioctl_write(0xb6, 1, sizeof(NativeConfig));
constexpr unsigned long arm_command = ioctl_none(0xb6, 2);
constexpr unsigned long disarm_command = ioctl_none(0xb6, 3);
constexpr unsigned long status_command = ioctl_read(0xb6, 4, sizeof(NativeStatus));

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

kvmlib::BranchTraceStatus convert(const NativeStatus& status) {
    return {
        static_cast<kvmlib::BranchTraceState>(status.state),
        static_cast<kvmlib::BranchTraceReason>(status.reason),
        status.virtual_cpu,
        status.reserved,
        status.records,
        {
            {status.context.registers.begin(), status.context.registers.end()},
            status.context.rip,
            status.context.rsp,
            status.context.rflags,
            status.context.cr3,
            status.context.stop,
        },
    };
}

std::uint64_t canonical_lbr_address(std::uint64_t value) {
    constexpr std::uint64_t mask = (std::uint64_t{1} << 57) - 1;
    value &= mask;
    if ((value & (std::uint64_t{1} << 56)) != 0) {
        value |= ~mask;
    }
    return value;
}

template <typename Event>
std::expected<std::vector<Event>, kvmlib::Error> read_events(const int descriptor,
                                                             const std::uint64_t count) {
    if (count > std::numeric_limits<std::size_t>::max() / sizeof(Event)) {
        return std::unexpected(kvmlib::Error::invalid_argument);
    }
    std::vector<Event> events(count);
    auto* destination = reinterpret_cast<std::byte*>(events.data());
    std::size_t remaining = events.size() * sizeof(Event);

    while (remaining) {
        const auto received = ::read(descriptor, destination, remaining);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }

            return std::unexpected(errno_error());
        }

        if (received == 0) {
            return std::unexpected(kvmlib::Error::io_error);
        }

        destination += received;
        remaining -= static_cast<std::size_t>(received);
    }

    return events;
}

} // namespace

namespace kvmlib {

BranchTrace::BranchTrace(const int descriptor) noexcept : descriptor_(descriptor) {}

BranchTrace::~BranchTrace() {
    static_cast<void>(stop());

    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

BranchTrace::BranchTrace(BranchTrace&& other) noexcept
    : descriptor_(other.descriptor_), configured_(other.configured_), enabled_(other.enabled_) {
    other.descriptor_ = -1;
    other.configured_ = false;
    other.enabled_ = false;
}

BranchTrace& BranchTrace::operator=(BranchTrace&& other) noexcept {
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

std::expected<BranchTrace, Error> BranchTrace::open(std::string device) {
    if (const auto privileged = require_root(); !privileged) {
        return std::unexpected(privileged.error());
    }

    const int descriptor = ::open(device.c_str(), O_RDWR | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }

    return BranchTrace{descriptor};
}

std::expected<void, Error> BranchTrace::configure(const BranchTraceConfig& config) {
    if (descriptor_ < 0 || enabled_ || config.cr3 == 0 || config.start == 0
        || config.range_begin >= config.range_end || config.start < config.range_begin
        || config.start >= config.range_end || config.max_records == 0
        || config.timeout.count() <= 0 || config.qemu_process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    const NativeConfig native{
        config.cr3,
        config.start,
        config.stop,
        config.range_begin,
        config.range_end,
        config.max_records,
        static_cast<std::uint64_t>(config.timeout.count()),
        config.qemu_process_id,
        0,
    };

    if (::ioctl(descriptor_, configure_command, &native) < 0) {
        return std::unexpected(errno_error());
    }

    configured_ = true;
    return {};
}

std::expected<void, Error> BranchTrace::start() {
    if (descriptor_ < 0 || enabled_ || !configured_) {
        return std::unexpected(Error::invalid_argument);
    }
    if (::ioctl(descriptor_, arm_command) < 0) {
        return std::unexpected(errno_error());
    }

    enabled_ = true;
    return {};
}

std::expected<void, Error> BranchTrace::stop() {
    if (!enabled_) {
        return {};
    }

    enabled_ = false;
    if (descriptor_ >= 0 && ::ioctl(descriptor_, disarm_command) < 0) {
        return std::unexpected(errno_error());
    }
    return {};
}

std::expected<BranchTraceStatus, Error> BranchTrace::status() const {
    if (descriptor_ < 0 || !configured_) {
        return std::unexpected(Error::invalid_argument);
    }

    NativeStatus native{};
    if (::ioctl(descriptor_, status_command, &native) < 0) {
        return std::unexpected(errno_error());
    }
    return convert(native);
}

std::expected<BranchTraceStatus, Error>
BranchTrace::wait(const std::chrono::milliseconds timeout) const {
    if (descriptor_ < 0 || !enabled_ || timeout.count() <= 0) {
        return std::unexpected(Error::invalid_argument);
    }

    if (timeout.count() > std::numeric_limits<int>::max()) {
        return std::unexpected(Error::invalid_argument);
    }

    pollfd descriptor{descriptor_, POLLIN, 0};
    const auto result = ::poll(&descriptor, 1, static_cast<int>(timeout.count()));
    if (result < 0) {
        return std::unexpected(errno_error());
    }
    if (result == 0) {
        return std::unexpected(Error::timed_out);
    }

    return status();
}

std::expected<std::vector<BranchTraceEvent>, Error> BranchTrace::read(const std::uint64_t count) {
    if (descriptor_ < 0 || !configured_) {
        return std::unexpected(Error::invalid_argument);
    }

    const auto current = status();
    if (!current) {
        return std::unexpected(current.error());
    }

    std::vector<BranchTraceEvent> events;
    events.reserve(count);

    if (current->abi_version >= 2) {
        const auto native = read_events<NativeEventV2>(descriptor_, count);
        if (!native) {
            return std::unexpected(native.error());
        }

        for (const auto& event : *native) {
            events.push_back({
                canonical_lbr_address(event.from),
                canonical_lbr_address(event.to),
                event.rip,
                event.registers[4],
                event.registers[0],
                event.registers[1],
                event.registers[2],
                event.rflags,
                event.registers,
            });
        }
    } else {
        const auto native = read_events<NativeEventV1>(descriptor_, count);
        if (!native) {
            return std::unexpected(native.error());
        }

        for (const auto& event : *native) {
            std::array<std::uint64_t, 16> registers{};
            registers[0] = event.rax;
            registers[1] = event.rcx;
            registers[2] = event.rdx;
            registers[4] = event.rsp;

            events.push_back({
                canonical_lbr_address(event.from),
                canonical_lbr_address(event.to),
                event.rip,
                event.rsp,
                event.rax,
                event.rcx,
                event.rdx,
                event.rflags,
                registers,
            });
        }
    }

    return events;
}

} // namespace kvmlib
