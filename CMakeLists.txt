cmake_minimum_required(VERSION 3.25)

project(KVMLib VERSION 0.1.0 LANGUAGES CXX)

add_library(kvmlib
    src/branch_trace.cpp
    src/cr3_trace.cpp
    src/cpu.cpp
    src/input.cpp
    src/memory.cpp
    src/privilege.cpp
    src/vm_trace.cpp
)

add_library(kvmlib::kvmlib ALIAS kvmlib)

target_compile_features(kvmlib PUBLIC cxx_std_23)

target_include_directories(kvmlib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_options(kvmlib PRIVATE -Wall -Wextra -Wpedantic)

option(KVMLIB_ENABLE_MEMPROCFS "Build the MemProcFS backend" OFF)
set(MEMPROCFS_ROOT "" CACHE PATH "MemProcFS checkout root")
set(MEMPROCFS_LIBRARY_DIR "" CACHE PATH "Directory containing vmm.so")

if(KVMLIB_ENABLE_MEMPROCFS)
    if(NOT EXISTS "${MEMPROCFS_ROOT}/includes/vmmdll.h")
        message(FATAL_ERROR "MEMPROCFS_ROOT must contain includes/vmmdll.h")
    endif()
    if(NOT EXISTS "${MEMPROCFS_LIBRARY_DIR}/vmm.so")
        message(FATAL_ERROR "MEMPROCFS_LIBRARY_DIR must contain vmm.so")
    endif()
    target_sources(kvmlib PRIVATE src/memprocfs.cpp)
    target_include_directories(kvmlib PRIVATE "${MEMPROCFS_ROOT}/includes")
    target_compile_definitions(kvmlib PRIVATE LINUX)
    add_library(kvmlib_memprocfs SHARED IMPORTED GLOBAL)
    set_target_properties(kvmlib_memprocfs PROPERTIES IMPORTED_LOCATION "${MEMPROCFS_LIBRARY_DIR}/vmm.so")
    target_link_libraries(kvmlib PUBLIC kvmlib_memprocfs)
    set_target_properties(kvmlib PROPERTIES BUILD_RPATH "${MEMPROCFS_LIBRARY_DIR}")
else()
    target_sources(kvmlib PRIVATE src/memprocfs_stub.cpp)
endif()

include(GNUInstallDirs)
install(TARGETS kvmlib EXPORT KVMLibTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT KVMLibTargets
    FILE KVMLibTargets.cmake
    NAMESPACE kvmlib::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KVMLib
)
