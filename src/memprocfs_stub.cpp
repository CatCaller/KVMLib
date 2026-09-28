#include "kvmlib/memprocfs.hpp"

#include <utility>

namespace kvmlib {

MemProcFs::MemProcFs(void* handle) noexcept : handle_(handle) {}

MemProcFs::~MemProcFs() = default;

MemProcFs::MemProcFs(MemProcFs&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

MemProcFs& MemProcFs::operator=(MemProcFs&& other) noexcept {
    if (this != &other) {
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

std::expected<MemProcFs, Error> MemProcFs::open(const MemProcFsOptions&) {
    return std::unexpected(Error::unsupported);
}

std::expected<std::uint32_t, Error> MemProcFs::qemu_process_id(std::string_view) {
    return std::unexpected(Error::unsupported);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(std::string_view, RefreshMode) {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::refresh() const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::refresh_tlb_partial() const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ProcessInfo>, Error> MemProcFs::processes() const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::uint32_t, Error> MemProcFs::process_id(std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::force_process_dtb(std::uint32_t, std::uint64_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<ProcessInfo, Error> MemProcFs::process_info(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ThreadInfo>, Error> MemProcFs::threads(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ThreadFrame>, Error> MemProcFs::thread_callstack(std::uint32_t,
                                                                           std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ModuleInfo>, Error> MemProcFs::modules(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ExportInfo>, Error> MemProcFs::exports(std::uint32_t,
                                                                 std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ImportInfo>, Error> MemProcFs::imports(std::uint32_t,
                                                                 std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<HeapInfo>, Error> MemProcFs::heaps(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<HeapAllocation>, Error> MemProcFs::heap_allocations(std::uint32_t,
                                                                              std::uint64_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<MemoryRange>, Error> MemProcFs::memory_ranges(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::uint64_t, Error> MemProcFs::module_base(std::uint32_t, std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error>
MemProcFs::read(std::uint32_t, std::uint64_t, std::span<std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error>
MemProcFs::write(std::uint32_t, std::uint64_t, std::span<const std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error> MemProcFs::read_physical(std::uint64_t,
                                                           std::span<std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::scatter_read(std::uint32_t, std::span<MemoryTransfer>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::scatter_write(std::uint32_t,
                                                    std::span<MemoryTransfer>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::dump_process(std::uint32_t,
                                                   std::uint64_t,
                                                   std::uint64_t,
                                                   const std::filesystem::path&) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error>
MemProcFs::dump_physical(std::uint64_t, std::uint64_t, const std::filesystem::path&) const {
    return std::unexpected(Error::unsupported);
}

} // namespace kvmlib
