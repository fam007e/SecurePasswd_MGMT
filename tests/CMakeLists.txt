cmake_minimum_required(VERSION 3.10)

# Find cmocka
if(WIN32)
    find_package(cmocka CONFIG REQUIRED)
    set(CMOCKA_LIBRARIES cmocka::cmocka)
    set(CMOCKA_INCLUDE_DIRS "")  # Handled by target
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(CMOCKA REQUIRED cmocka)
endif()

# Core tests
add_executable(core_tests test_core.c)
target_include_directories(core_tests PRIVATE ../)
target_link_libraries(core_tests PRIVATE core_lib)

# Add library directories before creating executables (for non-Windows)
if(NOT WIN32 AND CMOCKA_LIBRARY_DIRS)
    link_directories(${CMOCKA_LIBRARY_DIRS})
endif()

# CMocka tests
add_executable(cmocka_tests test_cmocka.c)
target_include_directories(cmocka_tests PRIVATE ../)

if(NOT WIN32)
    target_include_directories(cmocka_tests PRIVATE ${CMOCKA_INCLUDE_DIRS})
endif()

target_link_libraries(cmocka_tests PRIVATE
    core_lib
    ${CMOCKA_LIBRARIES}
)

# Sync protocol v2 tests
add_executable(sync_protocol_tests test_sync_protocol.c)
target_include_directories(sync_protocol_tests PRIVATE ../)

if(NOT WIN32)
    target_include_directories(sync_protocol_tests PRIVATE ${CMOCKA_INCLUDE_DIRS})
endif()

target_link_libraries(sync_protocol_tests PRIVATE
    core_lib
    ${CMOCKA_LIBRARIES}
)

# Enable testing
enable_testing()
add_test(NAME CoreTests COMMAND core_tests)
add_test(NAME CMockaTests COMMAND cmocka_tests)
add_test(NAME SyncProtocolTests COMMAND sync_protocol_tests)

# libFuzzer targets for the sync protocol parsers (untrusted input surface).
# Build with clang and global sanitizer flags, e.g.:
#   cmake -B build-fuzz -DCMAKE_C_COMPILER=clang -DENABLE_FUZZING=ON \
#     -DCMAKE_C_FLAGS="-fsanitize=address,undefined,fuzzer-no-link -fno-omit-frame-pointer" \
#     -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
option(ENABLE_FUZZING "Build libFuzzer fuzz targets for the sync protocol (requires clang)" OFF)
if(ENABLE_FUZZING)
    foreach(fuzz_target fuzz_snapshot fuzz_frames fuzz_totp fuzz_pwgen)
        add_executable(${fuzz_target} fuzz/${fuzz_target}.c)
        target_include_directories(${fuzz_target} PRIVATE ../)
        target_link_libraries(${fuzz_target} PRIVATE core_lib)
        target_compile_options(${fuzz_target} PRIVATE -fsanitize=fuzzer)
        target_link_options(${fuzz_target} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()
