cmake_minimum_required(VERSION 3.10)

# Check if version is provided from command line (for releases)
# Otherwise use default version for local builds
if(NOT DEFINED PROJECT_VERSION)
    set(PROJECT_VERSION "1.0.0")
endif()

project(SecurePasswd_MGMT VERSION ${PROJECT_VERSION} LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)

# Handle vcpkg vs system packages
if(WIN32)
    # vcpkg on Windows uses unofficial- prefix for some packages
    find_package(unofficial-sodium CONFIG REQUIRED)
    find_package(unofficial-argon2 CONFIG REQUIRED)

    # SQLCipher from vcpkg uses sqlcipher (not unofficial-sqlcipher)
    find_package(sqlcipher CONFIG REQUIRED)

    # getopt-win32 doesn't provide CMake config files, use manual search
    find_path(GETOPT_INCLUDE_DIR NAMES getopt.h)
    find_library(GETOPT_LIBRARY NAMES getopt)
    if(GETOPT_INCLUDE_DIR AND GETOPT_LIBRARY)
        message(STATUS "Found getopt-win32: ${GETOPT_LIBRARY}")
        include_directories(${GETOPT_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "getopt-win32 not found")
    endif()

    # libcsv doesn't provide CMake config files in vcpkg, use manual search
    find_path(LIBCSV_INCLUDE_DIRS NAMES csv.h)
    find_library(LIBCSV_LIBRARIES NAMES csv libcsv)

    # Set variables to match pkg-config naming convention for cross-platform compatibility
    set(LIBSODIUM_LIBRARIES unofficial-sodium::sodium)
    set(LIBSODIUM_INCLUDE_DIRS "")  # Handled by target
    set(ARGON2_LIBRARIES unofficial::argon2::libargon2)
    set(ARGON2_INCLUDE_DIRS "")  # Handled by target
    set(SQLCIPHER_LIBRARIES sqlcipher::sqlcipher)
    set(SQLCIPHER_INCLUDE_DIRS "")  # Handled by target
else()
    # Linux/macOS use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSODIUM REQUIRED libsodium)
    pkg_check_modules(ARGON2 REQUIRED libargon2)
    pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

    # Find libcsv
    find_path(LIBCSV_INCLUDE_DIRS NAMES csv.h)
    find_library(LIBCSV_LIBRARIES NAMES csv)
endif()

# Check if libcsv was found
if(LIBCSV_INCLUDE_DIRS AND LIBCSV_LIBRARIES)
    set(LIBCSV_FOUND TRUE)
    message(STATUS "Found libcsv: ${LIBCSV_LIBRARIES}")
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBCSV DEFAULT_MSG LIBCSV_LIBRARIES LIBCSV_INCLUDE_DIRS)
else()
    message(WARNING "libcsv not found - build may fail")
    set(LIBCSV_FOUND FALSE)
endif()

# Find Qt6
find_package(Qt6 COMPONENTS Widgets REQUIRED)

# Find OpenSSL and CURL
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Security flags
if(NOT MSVC)
    add_compile_options(-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_link_options(-Wl,-z,relro,-z,now)
endif()

# Add subdirectories
add_subdirectory(core)
add_subdirectory(cli)
add_subdirectory(gui)
add_subdirectory(tests)

# CPack configuration
set(CPACK_PACKAGE_NAME "SecurePasswd_MGMT")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "SecurePasswd_MGMT-${CPACK_PACKAGE_VERSION}")
set(CPACK_GENERATOR "DEB;RPM;NSIS")
set(CPACK_PACKAGE_CONTACT "fam007e <faisalmoshiur+secpasswdmgmt@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "fam007e")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_RPM_PACKAGE_GROUP "Utilities")
set(CPACK_NSIS_PACKAGE_NAME "${PROJECT_NAME} ${CPACK_PACKAGE_VERSION}")
set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
set(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}/gui/icons/app_icon.ico")
set(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}/gui/icons/app_icon.ico")

# Include CPack AFTER all CPACK_* variables are set
include(CPack)
