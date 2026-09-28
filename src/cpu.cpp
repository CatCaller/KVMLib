#include "kvmlib/cpu.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>

namespace {

std::expected<std::uint32_t, kvmlib::Error> read_number(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::uint32_t value{};

    if (!(input >> value)) {
        return std::unexpected(std::filesystem::exists(path) ? kvmlib::Error::parse_error
                                                             : kvmlib::Error::not_found);
    }
    return value;
}

std::vector<std::uint32_t> parse_cpu_list(const std::string& value) {
    std::vector<std::uint32_t> result;
    std::size_t position{};

    while (position < value.size()) {
        const auto separator = value.find(',', position);
        const auto segment = value.substr(position, separator - position);
        const auto dash = segment.find('-');
        try {
            const auto first = static_cast<std::uint32_t>(std::stoul(segment));
            const auto last = dash == std::string::npos
                ? first
                : static_cast<std::uint32_t>(std::stoul(segment.substr(dash + 1)));
            for (std::uint32_t current = first; current <= last; ++current) {
                result.push_back(current);
            }
        } catch (...) {
            return {};
        }

        if (separator == std::string::npos) {
            break;
        }

        position = separator + 1;
    }

    return result;
}

bool has_virtualization_flag() {
    std::ifstream input("/proc/cpuinfo");
    std::string line;

    while (std::getline(input, line)) {
        if ((line.starts_with("flags") || line.starts_with("Features"))
            && (line.contains(" vmx") || line.contains(" svm"))) {
            return true;
        }
    }
    return false;
}

} // namespace

namespace kvmlib {

std::uint32_t CpuTopology::physical_core_count() const {
    std::set<std::pair<std::uint32_t, std::uint32_t>> cores;
    for (const auto& thread : threads) {
        cores.emplace(thread.package_id, thread.core_id);
    }

    return static_cast<std::uint32_t>(cores.size());
}

bool CpuTopology::smt_enabled() const {
    return std::any_of(threads.begin(), threads.end(), [](const CpuThread& thread) {
        return thread.siblings.size() > 1;
    });
}

const CpuThread* CpuTopology::find(const std::uint32_t logical_id) const {
    const auto found = std::ranges::find(threads, logical_id, &CpuThread::logical_id);
    return found == threads.end() ? nullptr : &*found;
}

std::expected<CpuTopology, Error> cpu_topology() {
    const std::filesystem::path root{"/sys/devices/system/cpu"};
    if (!std::filesystem::exists(root)) {
        return std::unexpected(Error::unsupported);
    }

    CpuTopology topology;

    for (const auto& entry : std::filesystem::directory_iterator(root)) {
        const auto name = entry.path().filename().string();
        if (!entry.is_directory() || !name.starts_with("cpu") || name.size() == 3
            || !std::all_of(name.begin() + 3, name.end(), ::isdigit)) {
            continue;
        }
        const auto id = read_number(entry.path() / "topology/core_id");
        const auto package = read_number(entry.path() / "topology/physical_package_id");
        std::ifstream siblings_input(entry.path() / "topology/thread_siblings_list");
        std::string siblings_text;

        if (!id || !package || !std::getline(siblings_input, siblings_text)) {
            continue;
        }

        auto siblings = parse_cpu_list(siblings_text);
        if (siblings.empty()) {
            continue;
        }
        topology.threads.push_back({static_cast<std::uint32_t>(std::stoul(name.substr(3))),
                                    *package,
                                    *id,
                                    std::move(siblings)});
    }

    std::ranges::sort(topology.threads, {}, &CpuThread::logical_id);
    if (topology.threads.empty()) {
        return std::unexpected(Error::not_found);
    }
    return topology;
}

std::expected<KvmStatus, Error> kvm_status() {
    const std::filesystem::path device{"/dev/kvm"};
    std::error_code error;
    const bool present = std::filesystem::exists(device, error);

    if (error) {
        return std::unexpected(Error::io_error);
    }

    const bool accessible = present && ::access(device.c_str(), R_OK | W_OK) == 0;
    return KvmStatus{present, accessible, has_virtualization_flag()};
}

} // namespace kvmlib
