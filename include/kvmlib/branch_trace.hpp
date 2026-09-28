#pragma once

#include "kvmlib/error.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace kvmlib {

enum class BranchTraceState : std::uint32_t {
    idle,
    armed,
    triggered,
    running,
    paused,
    complete,
    error
};

enum class BranchTraceReason : std::uint32_t {
    none,
    stop,
    budget,
    range_exit,
    disarmed,
    virtual_cpu_freed,
    debug_conflict,
    memory_read,
    cr3_changed,
    timed_out
};

struct BranchTraceConfig {
    std::uint64_t cr3{};
    std::uint64_t start{};
    std::uint64_t stop{};
    std::uint64_t range_begin{};
    std::uint64_t range_end{};
    std::uint64_t max_records{};
    std::chrono::nanoseconds timeout{};
    std::uint32_t qemu_process_id{};
};

struct BranchTraceEvent {
    std::uint64_t from{};
    std::uint64_t to{};
    std::uint64_t rip{};
    std::uint64_t rsp{};
    std::uint64_t rax{};
    std::uint64_t rcx{};
    std::uint64_t rdx{};
    std::uint64_t rflags{};
    std::array<std::uint64_t, 16> registers{};
};

struct BranchTraceContext {
    std::vector<std::uint64_t> registers;
    std::uint64_t rip{};
    std::uint64_t rsp{};
    std::uint64_t rflags{};
    std::uint64_t cr3{};
    std::uint64_t stop{};
};

struct BranchTraceStatus {
    BranchTraceState state{};
    BranchTraceReason reason{};
    std::uint32_t virtual_cpu{};
    std::uint32_t abi_version{};
    std::uint64_t records{};
    BranchTraceContext context;
};

class BranchTrace {
  public:
    BranchTrace() = default;
    ~BranchTrace();

    BranchTrace(const BranchTrace&) = delete;
    BranchTrace& operator=(const BranchTrace&) = delete;
    BranchTrace(BranchTrace&& other) noexcept;
    BranchTrace& operator=(BranchTrace&& other) noexcept;

    [[nodiscard]] static std::expected<BranchTrace, Error>
    open(std::string device = "/dev/kvm_brtrace");
    [[nodiscard]] std::expected<void, Error> configure(const BranchTraceConfig& config);
    [[nodiscard]] std::expected<void, Error> start();
    [[nodiscard]] std::expected<void, Error> stop();
    [[nodiscard]] std::expected<BranchTraceStatus, Error> status() const;
    [[nodiscard]] std::expected<BranchTraceStatus, Error>
    wait(std::chrono::milliseconds timeout) const;
    [[nodiscard]] std::expected<std::vector<BranchTraceEvent>, Error> read(std::uint64_t count);

  private:
    explicit BranchTrace(int descriptor) noexcept;

    int descriptor_{-1};
    bool configured_{};
    bool enabled_{};
};

} // namespace kvmlib
