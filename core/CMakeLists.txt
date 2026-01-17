add_library(core_lib STATIC
    key_derivation.c
    database.c
    totp.c
    pwned_check.c
    platform_paths.c
    password_generator.c
)

# Include directories
target_include_directories(core_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Include directories for dependencies
target_include_directories(core_lib PUBLIC
    ${LIBSODIUM_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIRS}
    ${SQLCIPHER_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(core_lib PUBLIC
    ${LIBSODIUM_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# SQLCipher handling - Check for header location
include(CheckIncludeFile)
set(CMAKE_REQUIRED_INCLUDES ${SQLCIPHER_INCLUDE_DIRS})
check_include_file("sqlcipher/sqlite3.h" HAVE_SQLCIPHER_SUBDIR)
check_include_file("sqlcipher.h" HAVE_SQLCIPHER_HEADER)

if(HAVE_SQLCIPHER_SUBDIR)
    target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_SUBDIR)
elseif(HAVE_SQLCIPHER_HEADER)
    target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_HEADER)
endif()

# Explicitly link SQLCipher
if(TARGET sqlcipher::sqlcipher)
    target_link_libraries(core_lib PUBLIC sqlcipher::sqlcipher)
elseif(SQLCIPHER_LIBRARIES)
    target_link_libraries(core_lib PUBLIC ${SQLCIPHER_LIBRARIES})
else()
    # Fallback for manual linking if neither target nor variable is set correctly
    find_library(SQLCIPHER_LIBRARY NAMES sqlcipher)
    if(SQLCIPHER_LIBRARY)
        target_link_libraries(core_lib PUBLIC ${SQLCIPHER_LIBRARY})
    else()
        message(FATAL_ERROR "Could not find sqlcipher library")
    endif()
endif()

# Platform-specific link directories (mostly for Linux/macOS)
if(NOT WIN32)
    target_link_directories(core_lib PUBLIC
        ${LIBSODIUM_LIBRARY_DIRS}
        ${ARGON2_LIBRARY_DIRS}
    )
endif()

target_compile_definitions(core_lib PRIVATE SQLITE_HAS_CODEC)


