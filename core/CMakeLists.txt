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

# Platform-specific includes (only for non-target based libraries)
if(NOT WIN32)
    message(STATUS "SQLCIPHER_INCLUDE_DIRS: ${SQLCIPHER_INCLUDE_DIRS}")
    message(STATUS "SQLCIPHER_LIBRARIES: ${SQLCIPHER_LIBRARIES}")
    message(STATUS "SQLCIPHER_LIBRARY_DIRS: ${SQLCIPHER_LIBRARY_DIRS}")

    target_include_directories(core_lib PUBLIC
        ${LIBSODIUM_INCLUDE_DIRS}
        ${ARGON2_INCLUDE_DIRS}
        ${SQLCIPHER_INCLUDE_DIRS}
    )

    # Check where sqlcipher headers are located
    include(CheckIncludeFile)

    # Save current includes
    set(CMAKE_REQUIRED_INCLUDES ${SQLCIPHER_INCLUDE_DIRS})

    check_include_file("sqlcipher/sqlite3.h" HAVE_SQLCIPHER_SUBDIR)
    check_include_file("sqlcipher.h" HAVE_SQLCIPHER_HEADER)

    if(HAVE_SQLCIPHER_SUBDIR)
        target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_SUBDIR)
    elseif(HAVE_SQLCIPHER_HEADER)
        target_compile_definitions(core_lib PRIVATE HAVE_SQLCIPHER_HEADER)
    endif()
endif()

# Always include these (they use traditional find_package)
target_include_directories(core_lib PUBLIC
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(core_lib PUBLIC
    ${LIBSODIUM_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SQLCIPHER_LIBRARIES}
)

# Platform-specific link directories
if(NOT WIN32)
    target_link_directories(core_lib PUBLIC
        ${LIBSODIUM_LIBRARY_DIRS}
        ${ARGON2_LIBRARY_DIRS}
        ${SQLCIPHER_LIBRARY_DIRS}
    )
endif()

target_compile_definitions(core_lib PRIVATE SQLITE_HAS_CODEC)
