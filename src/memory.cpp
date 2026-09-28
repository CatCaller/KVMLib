#include "kvmlib/memory.hpp"

#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <fstream>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>

namespace {

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) {
        return kvmlib::Error::permission_denied;
    }
    if (errno == ENOENT || errno == ESRCH) {
        return kvmlib::Error::not_found;
    }
    return kvmlib::Error::io_error;
}

std::expected<std::uintptr_t, kvmlib::Error> parse_address(const std::string_view text) {
    std::uintptr_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);

    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    return value;
}

} // namespace

namespace kvmlib {

ProcessMemory::ProcessMemory(const std::int32_t process_id, const int descriptor) noexcept
    : process_id_(process_id), descriptor_(descriptor) {}

ProcessMemory::~ProcessMemory() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

ProcessMemory::ProcessMemory(ProcessMemory&& other) noexcept
    : process_id_(other.process_id_), descriptor_(other.descriptor_) {
    other.process_id_ = 0;
    other.descriptor_ = -1;
}

ProcessMemory& ProcessMemory::operator=(ProcessMemory&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
        process_id_ = other.process_id_;
        descriptor_ = other.descriptor_;
        other.process_id_ = 0;
        other.descriptor_ = -1;
    }
    return *this;
}

std::expected<ProcessMemory, Error> ProcessMemory::open(const std::int32_t process_id) {
    if (process_id <= 0) {
        return std::unexpected(Error::invalid_argument);
    }

    const auto path = "/proc/" + std::to_string(process_id) + "/mem";
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }

    return ProcessMemory{process_id, descriptor};
}

std::int32_t ProcessMemory::process_id() const noexcept {
    return process_id_;
}

bool ProcessMemory::is_open() const noexcept {
    return descriptor_ >= 0;
}

std::expected<std::size_t, Error>
ProcessMemory::read(const std::uintptr_t address, const std::span<std::byte> destination) const {
    if (!is_open() || (!destination.empty() && address == 0)) {
        return std::unexpected(Error::invalid_argument);
    }

    std::size_t total{};

    while (total < destination.size()) {
        const auto count = ::pread(descriptor_,
                                   destination.data() + total,
                                   destination.size() - total,
                                   static_cast<off_t>(address + total));
        if (count < 0) {
            if (total) {
                return total;
            }

            return std::unexpected(errno_error());
        }

        if (count == 0) {
            break;
        }

        total += static_cast<std::size_t>(count);
    }

    return total;
}

std::expected<std::string, Error> ProcessMemory::read_string(const std::uintptr_t address,
                                                             const std::size_t maximum_size) const {
    if (maximum_size == 0) {
        return std::string{};
    }

    std::string value(maximum_size, '\0');
    auto read_result = read(address, std::as_writable_bytes(std::span{value.data(), value.size()}));
    if (!read_result) {
        return std::unexpected(read_result.error());
    }

    value.resize(*read_result);
    const auto terminator = value.find('\0');
    if (terminator != std::string::npos) {
        value.resize(terminator);
    }

    return value;
}

std::expected<std::vector<MemoryRegion>, Error> ProcessMemory::regions() const {
    if (!is_open()) {
        return std::unexpected(Error::invalid_argument);
    }

    std::ifstream input("/proc/" + std::to_string(process_id_) + "/maps");
    if (!input) {
        return std::unexpected(errno_error());
    }

    std::vector<MemoryRegion> result;
    std::string line;

    while (std::getline(input, line)) {
        const auto first_space = line.find(' ');
        if (first_space == std::string::npos || line.size() < first_space + 5) {
            return std::unexpected(Error::parse_error);
        }
        const auto dash = line.find('-');
        if (dash == std::string::npos) {
            return std::unexpected(Error::parse_error);
        }

        const auto begin = parse_address(std::string_view{line}.substr(0, dash));
        const auto end =
            parse_address(std::string_view{line}.substr(dash + 1, first_space - dash - 1));
        if (!begin || !end || *end <= *begin) {
            return std::unexpected(Error::parse_error);
        }

        const auto path_start = line.find('/', first_space + 1);
        result.push_back(
            {*begin,
             *end,
             line[first_space + 1] == 'r',
             line[first_space + 2] == 'w',
             line[first_space + 3] == 'x',
             line[first_space + 4] == 'p',
             path_start == std::string::npos ? std::string{} : line.substr(path_start)});
    }

    return result;
}

std::expected<MemoryInfo, Error> memory_info() {
    std::ifstream input("/proc/meminfo");
    if (!input) {
        return std::unexpected(errno_error());
    }

    MemoryInfo result;
    std::string key;
    std::uint64_t value{};
    std::string unit;

    while (input >> key >> value >> unit) {
        const auto bytes = value * 1024;
        if (key == "MemTotal:") {
            result.total_bytes = bytes;
        }
        if (key == "MemFree:") {
            result.free_bytes = bytes;
        }
        if (key == "MemAvailable:") {
            result.available_bytes = bytes;
        }
        if (key == "Buffers:") {
            result.buffers_bytes = bytes;
        }
        if (key == "Cached:") {
            result.cached_bytes = bytes;
        }
        if (key == "SwapTotal:") {
            result.swap_total_bytes = bytes;
        }
        if (key == "SwapFree:") {
            result.swap_free_bytes = bytes;
        }
    }

    return result.total_bytes ? std::expected<MemoryInfo, Error>{result}
                              : std::unexpected(Error::parse_error);
}

} // namespace kvmlib
