# KVMLib

C++23 library for KVM memory reads, tracing, CPU info, and input.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

MemProcFS support is off by default. To enable it, pass `-DKVMLIB_ENABLE_MEMPROCFS=ON`, `-DMEMPROCFS_ROOT=/path/to/MemProcFS`, and `-DMEMPROCFS_LIBRARY_DIR=/path/to/MemProcFS/files` to CMake.

Fork: [Kryptos-s/kvmlib](https://github.com/Kryptos-s/kvmlib).
