#pragma once

#include "kvmlib/error.hpp"

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace kvmlib {

struct VmTraceConfig {
    std::uint64_t cr3{};
    std::uint64_t stop_rip{};
    std::uint64_t max_events{};
};

struct VmTraceRegisters {
    std::uint64_t rflags{};
    std::uint64_t rax{};
    std::uint64_t rbx{};
    std::uint64_t rcx{};
    std::uint64_t rdx{};
    std::uint64_t rsi{};
    std::uint64_t rdi{};
    std::uint64_t rbp{};
    std::uint64_t rsp{};
    std::uint64_t r8{};
    std::uint64_t r9{};
    std::uint64_t r10{};
    std::uint64_t r11{};
    std::uint64_t r12{};
    std::uint64_t r13{};
    std::uint64_t r14{};
    std::uint64_t r15{};
};

struct VmTraceEvent {
    std::uint64_t sequence{};
    std::uint64_t timestamp_ns{};
    std::uint64_t cr3{};
    std::uint64_t rip{};
    VmTraceRegisters registers;
    std::uint32_t virtual_cpu{};
    std::uint32_t flags{};
};

class VmTrace {
  public:
    VmTrace() = default;
    ~VmTrace();

    VmTrace(const VmTrace&) = delete;
    VmTrace& operator=(const VmTrace&) = delete;
    VmTrace(VmTrace&& other) noexcept;
    VmTrace& operator=(VmTrace&& other) noexcept;

    [[nodiscard]] static std::expected<VmTrace, Error>
    open(std::string device = "/dev/kvm_vmtrace");
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] std::expected<void, Error> configure(const VmTraceConfig& config);
    [[nodiscard]] std::expected<void, Error> start();
    [[nodiscard]] std::expected<void, Error> stop();
    [[nodiscard]] std::expected<std::vector<VmTraceEvent>, Error> poll();

  private:
    explicit VmTrace(int descriptor) noexcept;

    int descriptor_{-1};
    bool configured_{};
    bool enabled_{};
};

} // namespace kvmlib
