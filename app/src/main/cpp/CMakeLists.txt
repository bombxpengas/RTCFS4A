cmake_minimum_required(VERSION 3.22.1)
project(rtmemhelper C)

add_executable(rtmemhelper rtmem_helper.c)

# This is a real standalone executable, not a shared library — but Android's
# Gradle plugin only auto-packages build outputs matching lib*.so from the
# native build output directory into the APK's lib/<abi>/ folder (where they
# get installed with correct executable permissions automatically). Naming
# it this way is a well-known trick for shipping a helper binary without a
# separate manual asset-copy + chmod step at runtime.
set_target_properties(rtmemhelper PROPERTIES
    OUTPUT_NAME "rtmemhelper"
    SUFFIX ".so"
    PREFIX "lib"
)
