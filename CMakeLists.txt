cmake_minimum_required(VERSION 3.10)
project(SecurePassManager C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Define the core library
add_library(securepasscore SHARED
    src/csv_handler.c
    src/csv_parser.c
    src/data_path.c
    src/encryption.c
    src/password_generator.c
    src/totp.c
    src/utils.c
    src/securepass_core.c
    lib/libcsv/libcsv.c
)

# Include directories
target_include_directories(securepasscore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/libcsv
)

# Link against OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(securepasscore PUBLIC OpenSSL::Crypto)

# Link against Argon2
find_path(ARGON2_INCLUDE_DIR argon2.h PATHS /usr/include /usr/include/argon2)
find_library(ARGON2_LIBRARY argon2)

if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
    target_include_directories(securepasscore PUBLIC ${ARGON2_INCLUDE_DIR})
    target_link_libraries(securepasscore PUBLIC ${ARGON2_LIBRARY})
else()
    message(FATAL_ERROR "Could not find argon2.h or libargon2. Please install libargon2-dev or argon2-devel.")
endif()

# Manually find and link libsodium
find_path(LIBSODIUM_INCLUDE_DIR sodium.h PATHS /usr/include /usr/local/include)
find_library(LIBSODIUM_LIBRARY sodium)

if(LIBSODIUM_INCLUDE_DIR AND LIBSODIUM_LIBRARY)
    target_include_directories(securepasscore PUBLIC ${LIBSODIUM_INCLUDE_DIR})
    target_link_libraries(securepasscore PUBLIC ${LIBSODIUM_LIBRARY})
else()
    message(FATAL_ERROR "Could not find sodium.h or libsodium. Please install libsodium-dev or libsodium.")
endif()

# Manually find and link liboath for TOTP
find_path(OATH_INCLUDE_DIR oath.h PATHS /usr/include /usr/include/liboath)
find_library(OATH_LIBRARY oath)

if(OATH_INCLUDE_DIR AND OATH_LIBRARY)
    target_include_directories(securepasscore PUBLIC ${OATH_INCLUDE_DIR})
    target_link_libraries(securepasscore PUBLIC /usr/lib/liboath.so m)
else()
    message(FATAL_ERROR "Could not find oath.h or liboath. Please install oath-toolkit-dev or liboath-dev.")
endif()

# Define the CLI executable
add_executable(securepass src/main.c)
target_link_libraries(securepass PRIVATE securepasscore)

# Set output directories for easier access
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Security-focused compilation flags (from original Makefile)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(securepasscore PRIVATE
        -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
        -Wformat -Werror=format-security -fPIC
        -fstack-clash-protection -fcf-protection
        -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    )
    target_compile_options(securepass PRIVATE
        -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong
        -Wformat -Werror=format-security -pie -fPIE
        -fstack-clash-protection -fcf-protection
        -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    )
endif()

# Enable testing
# enable_testing()
# add_subdirectory(tests)
