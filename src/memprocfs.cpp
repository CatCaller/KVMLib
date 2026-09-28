#include "kvmlib/memprocfs.hpp"
#include "kvmlib/privilege.hpp"

extern "C" {
#include "vmmdll.h"
}

#include <algorithm>
#include <fstream>
#include <filesystem>
#include <limits>
#include <cctype>
#include <cstdlib>

namespace {

constexpr DWORD no_cache = 0x0001;
constexpr DWORD physical_memory = static_cast<DWORD>(-1);

kvmlib::Error failure() {
    return kvmlib::Error::io_error;
}

std::expected<std::uint32_t, kvmlib::Error> find_qemu_process(const std::string_view guest_name) {
    const std::string needle = "guest=" + std::string(guest_name);
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        const auto name = entry.path().filename().string();
        if (name.empty() || !std::ranges::all_of(name, ::isdigit)) {
            continue;
        }

        std::ifstream comm(entry.path() / "comm");
        std::string executable;
        std::getline(comm, executable);
        if (!executable.starts_with("qemu-system")) {
            continue;
        }

        std::ifstream command_line(entry.path() / "cmdline", std::ios::binary);
        const std::string arguments(std::istreambuf_iterator<char>(command_line), {});
        if (!arguments.contains(needle)) {
            continue;
        }

        return static_cast<std::uint32_t>(std::stoul(name));
    }
    return std::unexpected(kvmlib::Error::not_found);
}

} // namespace

namespace kvmlib {

MemProcFs::MemProcFs(void* handle) noexcept : handle_(handle) {}

MemProcFs::~MemProcFs() {
    if (handle_) {
        VMMDLL_Close(static_cast<VMM_HANDLE>(handle_));
    }
}

MemProcFs::MemProcFs(MemProcFs&& other) noexcept : handle_(other.handle_) {
    other.handle_ = nullptr;
}

MemProcFs& MemProcFs::operator=(MemProcFs&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            VMMDLL_Close(static_cast<VMM_HANDLE>(handle_));
        }
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

std::expected<MemProcFs, Error> MemProcFs::open(const MemProcFsOptions& options) {
    if (const auto privileged = require_root(); !privileged) {
        return std::unexpected(privileged.error());
    }
    if (options.device.empty()) {
        return std::unexpected(Error::invalid_argument);
    }

    std::vector<std::string> arguments{"", "-device", options.device};
    if (options.disable_python) {
        arguments.emplace_back("-disable-python");
    }
    if (options.wait_initialize) {
        arguments.emplace_back("-waitinitialize");
    }
    if (options.refresh_mode == RefreshMode::manual) {
        arguments.emplace_back("-norefresh");
    }
    if (!options.log_file.empty()) {
        arguments.emplace_back("-logfile");
        arguments.push_back(options.log_file);
    }
    if (!options.log_level.empty()) {
        arguments.emplace_back("-loglevel");
        arguments.push_back(options.log_level);
    }

    std::vector<const char*> values;
    values.reserve(arguments.size());
    for (const auto& argument : arguments) {
        values.push_back(argument.c_str());
    }

    const auto handle = VMMDLL_Initialize(static_cast<DWORD>(values.size()), values.data());
    if (!handle) {
        return std::unexpected(failure());
    }

    return MemProcFs{handle};
}

std::expected<std::uint32_t, Error> MemProcFs::qemu_process_id(const std::string_view guest_name) {
    if (guest_name.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    return find_qemu_process(guest_name);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(const std::string_view guest_name,
                                                     const RefreshMode refresh_mode) {
    if (guest_name.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto process = find_qemu_process(guest_name);
    if (!process) {
        return std::unexpected(process.error());
    }

    const auto log_file = std::getenv("KVMLIB_MEMPROCFS_LOG_FILE");
    const auto log_level = std::getenv("KVMLIB_MEMPROCFS_LOG_LEVEL");
    return open({
        .device = "qemu://hugepage-pid=" + std::to_string(*process) + ",qmp=/tmp/qmp-"
            + std::string(guest_name) + ".sock",
        .refresh_mode = refresh_mode,
        .log_file = log_file == nullptr ? "" : log_file,
        .log_level = log_level == nullptr ? "" : log_level,
    });
}

std::expected<void, Error> MemProcFs::refresh() const {
    if (!handle_) {
        return std::unexpected(Error::invalid_argument);
    }
    if (!VMMDLL_ConfigSet(static_cast<VMM_HANDLE>(handle_), VMMDLL_OPT_REFRESH_ALL, 1)) {
        return std::unexpected(failure());
    }
    return {};
}

std::expected<void, Error> MemProcFs::refresh_tlb_partial() const {
    if (!handle_) {
        return std::unexpected(Error::invalid_argument);
    }
    if (!VMMDLL_ConfigSet(
            static_cast<VMM_HANDLE>(handle_), VMMDLL_OPT_REFRESH_FREQ_TLB_PARTIAL, 1)) {
        return std::unexpected(failure());
    }
    return {};
}

std::expected<std::vector<ProcessInfo>, Error> MemProcFs::processes() const {
    if (!handle_) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_PROCESS_INFORMATION native{};
    DWORD count{};
    if (!VMMDLL_ProcessGetInformationAll(static_cast<VMM_HANDLE>(handle_), &native, &count)
        || !native) {
        return std::unexpected(failure());
    }

    std::vector<ProcessInfo> result;
    result.reserve(count);

    for (DWORD index{}; index < count; ++index) {
        const auto& process = native[index];
        result.push_back({process.dwPID,
                          process.paDTB,
                          process.paDTB_UserOpt,
                          process.win.vaEPROCESS,
                          process.szNameLong[0] ? process.szNameLong : process.szName});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::uint32_t, Error> MemProcFs::process_id(const std::string_view name) const {
    if (!handle_ || name.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string value(name);
    DWORD pid{};
    if (VMMDLL_PidGetFromName(static_cast<VMM_HANDLE>(handle_), value.c_str(), &pid)) {
        return pid;
    }

    static_cast<void>(refresh());
    if (VMMDLL_PidGetFromName(static_cast<VMM_HANDLE>(handle_), value.c_str(), &pid)) {
        return pid;
    }

    auto expected = value;
    std::ranges::transform(expected, expected.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    const auto list = processes();
    if (!list) {
        return std::unexpected(list.error());
    }

    for (const auto& process : *list) {
        auto candidate = process.name;
        std::ranges::transform(candidate, candidate.begin(), [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
        if (candidate.empty()) {
            continue;
        }

        if (expected.contains(candidate) || candidate.contains(expected)
            || candidate.contains("fortniteclient")) {
            return process.process_id;
        }
    }

    return std::unexpected(Error::not_found);
}

std::expected<void, Error> MemProcFs::force_process_dtb(const std::uint32_t process_id,
                                                        const std::uint64_t dtb) const {
    if (!handle_ || !process_id || !dtb) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto option = VMMDLL_OPT_PROCESS_DTB | process_id;
    if (!VMMDLL_ConfigSet(static_cast<VMM_HANDLE>(handle_), option, dtb & ~std::uint64_t{0xFFF})) {
        return std::unexpected(failure());
    }
    return {};
}

std::expected<ProcessInfo, Error> MemProcFs::process_info(const std::uint32_t process_id) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    VMMDLL_PROCESS_INFORMATION native{};
    native.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    native.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    SIZE_T size = sizeof(native);
    if (!VMMDLL_ProcessGetInformation(
            static_cast<VMM_HANDLE>(handle_), process_id, &native, &size)) {
        return std::unexpected(Error::not_found);
    }

    return ProcessInfo{native.dwPID,
                       native.paDTB,
                       native.paDTB_UserOpt,
                       native.win.vaEPROCESS,
                       native.szNameLong[0] ? native.szNameLong : native.szName};
}

std::expected<std::vector<ThreadInfo>, Error>
MemProcFs::threads(const std::uint32_t process_id) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_THREAD native{};
    if (!VMMDLL_Map_GetThread(static_cast<VMM_HANDLE>(handle_), process_id, &native) || !native) {
        return std::unexpected(failure());
    }

    std::vector<ThreadInfo> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& thread = native->pMap[index];
        result.push_back({
            thread.dwTID,
            thread.vaTeb,
            thread.vaStartAddress,
            thread.vaWin32StartAddress,
            thread.vaRIP,
            thread.vaRSP,
            thread.vaStackBaseUser,
            thread.vaStackLimitUser,
            thread.ftCreateTime,
            thread.bState,
            thread.bRunning != 0,
        });
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<ThreadFrame>, Error>
MemProcFs::thread_callstack(const std::uint32_t process_id, const std::uint32_t thread_id) const {
    if (!handle_ || !process_id || !thread_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_THREAD_CALLSTACK native{};
    if (!VMMDLL_Map_GetThread_CallstackU(
            static_cast<VMM_HANDLE>(handle_), process_id, thread_id, 0, &native)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_THREAD_CALLSTACK_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<ThreadFrame> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& frame = native->pMap[index];
        result.push_back({
            frame.i,
            frame.fRegPresent != 0,
            frame.vaRetAddr,
            frame.vaRSP,
            frame.vaBaseSP,
            frame.cbDisplacement,
            frame.uszModule ? frame.uszModule : "",
            frame.uszFunction ? frame.uszFunction : "",
        });
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<ModuleInfo>, Error>
MemProcFs::modules(const std::uint32_t process_id) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_MODULE native{};
    if (!VMMDLL_Map_GetModuleU(static_cast<VMM_HANDLE>(handle_), process_id, &native, 0)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_MODULE_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<ModuleInfo> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& module = native->pMap[index];
        result.push_back({module.vaBase,
                          module.vaEntry,
                          module.cbImageSize,
                          module.cbFileSizeRaw,
                          module.fWoW64 != 0,
                          module.uszText ? module.uszText : "",
                          module.uszFullName ? module.uszFullName : ""});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<ExportInfo>, Error>
MemProcFs::exports(const std::uint32_t process_id, const std::string_view module) const {
    if (!handle_ || !process_id || module.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string value(module);
    PVMMDLL_MAP_EAT native{};
    if (!VMMDLL_Map_GetEATU(static_cast<VMM_HANDLE>(handle_), process_id, value.c_str(), &native)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_EAT_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<ExportInfo> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& entry = native->pMap[index];
        result.push_back({entry.vaFunction,
                          entry.dwOrdinal,
                          entry.uszFunction ? entry.uszFunction : "",
                          entry.uszForwardedFunction ? entry.uszForwardedFunction : ""});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<ImportInfo>, Error>
MemProcFs::imports(const std::uint32_t process_id, const std::string_view module) const {
    if (!handle_ || !process_id || module.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string value(module);
    PVMMDLL_MAP_IAT native{};
    if (!VMMDLL_Map_GetIATU(static_cast<VMM_HANDLE>(handle_), process_id, value.c_str(), &native)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_IAT_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<ImportInfo> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& entry = native->pMap[index];
        result.push_back({entry.vaFunction,
                          entry.Thunk.rvaFirstThunk,
                          entry.Thunk.rvaOriginalFirstThunk,
                          entry.Thunk.wHint,
                          entry.Thunk.f32 != 0,
                          entry.uszModule ? entry.uszModule : "",
                          entry.uszFunction ? entry.uszFunction : ""});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<HeapInfo>, Error> MemProcFs::heaps(const std::uint32_t process_id) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_HEAP native{};
    if (!VMMDLL_Map_GetHeap(static_cast<VMM_HANDLE>(handle_), process_id, &native) || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_HEAP_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<HeapInfo> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& heap = native->pMap[index];
        result.push_back({heap.va,
                          static_cast<std::uint32_t>(heap.tp),
                          heap.iHeap,
                          heap.dwHeapNum,
                          heap.f32 != 0});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<HeapAllocation>, Error>
MemProcFs::heap_allocations(const std::uint32_t process_id,
                            const std::uint64_t heap_number_or_address) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_HEAPALLOC native{};
    if (!VMMDLL_Map_GetHeapAlloc(
            static_cast<VMM_HANDLE>(handle_), process_id, heap_number_or_address, &native)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_HEAPALLOC_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<HeapAllocation> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& allocation = native->pMap[index];
        result.push_back({allocation.va, allocation.cb, static_cast<std::uint32_t>(allocation.tp)});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::vector<MemoryRange>, Error>
MemProcFs::memory_ranges(const std::uint32_t process_id) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_VAD native{};
    if (!VMMDLL_Map_GetVadU(static_cast<VMM_HANDLE>(handle_), process_id, false, &native)
        || !native) {
        return std::unexpected(failure());
    }
    if (native->dwVersion != VMMDLL_MAP_VAD_VERSION) {
        VMMDLL_MemFree(native);
        return std::unexpected(failure());
    }

    std::vector<MemoryRange> result;
    result.reserve(native->cMap);

    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& range = native->pMap[index];
        result.push_back({range.vaStart,
                          range.vaEnd,
                          range.Protection,
                          range.HeapNum,
                          range.CommitCharge,
                          range.MemCommit != 0,
                          range.fPrivateMemory != 0,
                          range.fHeap != 0,
                          range.fStack != 0,
                          range.uszText ? range.uszText : ""});
    }

    VMMDLL_MemFree(native);
    return result;
}

std::expected<std::uint64_t, Error> MemProcFs::module_base(const std::uint32_t process_id,
                                                           const std::string_view module) const {
    if (!handle_ || !process_id || module.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string value(module);
    const auto base =
        VMMDLL_ProcessGetModuleBaseU(static_cast<VMM_HANDLE>(handle_), process_id, value.c_str());
    if (!base) {
        return std::unexpected(Error::not_found);
    }

    return base;
}

std::expected<std::size_t, Error> MemProcFs::read(const std::uint32_t process_id,
                                                  const std::uint64_t address,
                                                  const std::span<std::byte> bytes) const {
    if (!handle_ || !process_id || bytes.size() > std::numeric_limits<DWORD>::max()) {
        return std::unexpected(Error::invalid_argument);
    }

    DWORD count{};
    const auto ok = VMMDLL_MemReadEx(static_cast<VMM_HANDLE>(handle_),
                                     process_id,
                                     address,
                                     reinterpret_cast<PBYTE>(bytes.data()),
                                     static_cast<DWORD>(bytes.size()),
                                     &count,
                                     no_cache);
    if (!ok && !count) {
        return std::unexpected(failure());
    }

    return count;
}

std::expected<std::size_t, Error> MemProcFs::write(const std::uint32_t process_id,
                                                   const std::uint64_t address,
                                                   const std::span<const std::byte> bytes) const {
    if (!handle_ || !process_id || bytes.size() > std::numeric_limits<DWORD>::max()) {
        return std::unexpected(Error::invalid_argument);
    }

    if (!VMMDLL_MemWrite(static_cast<VMM_HANDLE>(handle_),
                         process_id,
                         address,
                         reinterpret_cast<PBYTE>(const_cast<std::byte*>(bytes.data())),
                         static_cast<DWORD>(bytes.size()))) {
        return std::unexpected(failure());
    }

    return bytes.size();
}

std::expected<std::size_t, Error> MemProcFs::read_physical(const std::uint64_t address,
                                                           const std::span<std::byte> bytes) const {
    if (!handle_ || bytes.size() > std::numeric_limits<DWORD>::max()) {
        return std::unexpected(Error::invalid_argument);
    }

    DWORD count{};
    const auto ok = VMMDLL_MemReadEx(static_cast<VMM_HANDLE>(handle_),
                                     physical_memory,
                                     address,
                                     reinterpret_cast<PBYTE>(bytes.data()),
                                     static_cast<DWORD>(bytes.size()),
                                     &count,
                                     no_cache);
    if (!ok && !count) {
        return std::unexpected(failure());
    }

    return count;
}

std::expected<void, Error>
MemProcFs::scatter_read(const std::uint32_t process_id,
                        const std::span<MemoryTransfer> transfers) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto scatter =
        VMMDLL_Scatter_Initialize(static_cast<VMM_HANDLE>(handle_), process_id, no_cache);
    if (!scatter) {
        return std::unexpected(failure());
    }

    std::vector<DWORD> counts(transfers.size());
    bool prepared = true;

    for (std::size_t index = 0; index < transfers.size(); ++index) {
        const auto& transfer = transfers[index];
        prepared = prepared && transfer.bytes.size() <= std::numeric_limits<DWORD>::max()
            && VMMDLL_Scatter_PrepareEx(scatter,
                                        transfer.address,
                                        static_cast<DWORD>(transfer.bytes.size()),
                                        reinterpret_cast<PBYTE>(transfer.bytes.data()),
                                        &counts[index]);
    }

    const bool executed = prepared && VMMDLL_Scatter_ExecuteRead(scatter);
    auto complete = executed;

    for (std::size_t index{}; index < transfers.size(); ++index) {
        transfers[index].bytes_read = counts[index];
        complete = complete && counts[index] == transfers[index].bytes.size();
    }

    VMMDLL_Scatter_CloseHandle(scatter);
    return complete ? std::expected<void, Error>{} : std::unexpected(failure());
}

std::expected<void, Error>
MemProcFs::scatter_write(const std::uint32_t process_id,
                         const std::span<MemoryTransfer> transfers) const {
    if (!handle_ || !process_id) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto scatter =
        VMMDLL_Scatter_Initialize(static_cast<VMM_HANDLE>(handle_), process_id, no_cache);
    if (!scatter) {
        return std::unexpected(failure());
    }

    bool prepared = true;

    for (const auto& transfer : transfers) {
        prepared = prepared && transfer.bytes.size() <= std::numeric_limits<DWORD>::max()
            && VMMDLL_Scatter_PrepareWrite(scatter,
                                           transfer.address,
                                           reinterpret_cast<PBYTE>(transfer.bytes.data()),
                                           static_cast<DWORD>(transfer.bytes.size()));
    }

    const bool executed = prepared && VMMDLL_Scatter_Execute(scatter);
    VMMDLL_Scatter_CloseHandle(scatter);
    return executed ? std::expected<void, Error>{} : std::unexpected(failure());
}

std::expected<void, Error> MemProcFs::dump_process(const std::uint32_t process_id,
                                                   const std::uint64_t address,
                                                   const std::uint64_t size,
                                                   const std::filesystem::path& output) const {
    if (!handle_ || !process_id || output.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    std::ofstream file(output, std::ios::binary | std::ios::trunc);
    std::vector<std::byte> buffer(1 << 20);

    for (std::uint64_t offset{}; offset < size;) {
        const auto count =
            static_cast<std::size_t>((std::min)(std::uint64_t{buffer.size()}, size - offset));
        auto result = read(process_id, address + offset, std::span{buffer}.first(count));
        if (!result || *result != count) {
            return std::unexpected(result ? Error::io_error : result.error());
        }

        file.write(reinterpret_cast<const char*>(buffer.data()), count);
        if (!file) {
            return std::unexpected(Error::io_error);
        }
        offset += count;
    }

    return {};
}

std::expected<void, Error> MemProcFs::dump_physical(const std::uint64_t address,
                                                    const std::uint64_t size,
                                                    const std::filesystem::path& output) const {
    if (!handle_ || output.empty()) {
        return std::unexpected(Error::invalid_argument);
    }
    std::ofstream file(output, std::ios::binary | std::ios::trunc);
    std::vector<std::byte> buffer(1 << 20);

    for (std::uint64_t offset{}; offset < size;) {
        const auto count =
            static_cast<std::size_t>((std::min)(std::uint64_t{buffer.size()}, size - offset));
        auto result = read_physical(address + offset, std::span{buffer}.first(count));
        if (!result || *result != count) {
            return std::unexpected(result ? Error::io_error : result.error());
        }

        file.write(reinterpret_cast<const char*>(buffer.data()), count);
        if (!file) {
            return std::unexpected(Error::io_error);
        }
        offset += count;
    }

    return {};
}

} // namespace kvmlib
