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
)

# Explicitly find and link SQLCipher by absolute path to avoid ambiguity
find_library(SQLCIPHER_LIBRARY NAMES sqlcipher PATHS ${SQLCIPHER_LIBRARY_DIRS} NO_DEFAULT_PATH)
find_library(SQLCIPHER_LIBRARY NAMES sqlcipher) # Fallback to default paths

if(SQLCIPHER_LIBRARY)
    message(STATUS "Found SQLCipher library: ${SQLCIPHER_LIBRARY}")
    target_link_libraries(core_lib PUBLIC ${SQLCIPHER_LIBRARY})
else()
    message(WARNING "Could not find sqlcipher library file, falling back to target")
    target_link_libraries(core_lib PUBLIC PkgConfig::SQLCIPHER)
endif()

# Platform-specific link directories
if(NOT WIN32)
    target_link_directories(core_lib PUBLIC
        ${LIBSODIUM_LIBRARY_DIRS}
        ${ARGON2_LIBRARY_DIRS}
        # SQLCipher handled via PkgConfig::SQLCIPHER
    )
endif()

# Check if sqlite3_key symbol is present in the libraries
include(CheckFunctionExists)
set(OLD_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_LIBRARIES
    ${LIBSODIUM_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)
if(SQLCIPHER_LIBRARY)
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${SQLCIPHER_LIBRARY})
else()
    list(APPEND CMAKE_REQUIRED_LIBRARIES PkgConfig::SQLCIPHER)
endif()

# We need to include math/dl libs on some platforms for the check to pass
if(UNIX AND NOT APPLE)
    list(APPEND CMAKE_REQUIRED_LIBRARIES m dl)
endif()

check_function_exists(sqlite3_key HAVE_SQLITE3_KEY)
set(CMAKE_REQUIRED_LIBRARIES ${OLD_CMAKE_REQUIRED_LIBRARIES})

if(NOT HAVE_SQLITE3_KEY)
    message(STATUS "sqlite3_key not found in libraries - will use PRAGMA key shim")
    target_compile_definitions(core_lib PRIVATE MISSING_SQLITE3_KEY)
endif()

target_compile_definitions(core_lib PRIVATE SQLITE_HAS_CODEC)

