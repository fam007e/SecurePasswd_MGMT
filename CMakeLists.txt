cmake_minimum_required(VERSION 3.10)
project(SecurePassManager VERSION 1.0.0 LANGUAGES C CXX)
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(ARGON2 REQUIRED libargon2)
pkg_check_modules(SQLCIPHER REQUIRED sqlcipher)

find_path(LIBCSV_INCLUDE_DIRS NAMES csv.h)
find_library(LIBCSV_LIBRARIES NAMES csv)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBCSV DEFAULT_MSG LIBCSV_LIBRARIES LIBCSV_INCLUDE_DIRS)

find_package(Qt6 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_compile_options(-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2)
add_link_options(-Wl,-z,relro,-z,now)

add_subdirectory(core)
add_subdirectory(cli)
add_subdirectory(gui)
add_subdirectory(tests)

# CPack configuration
include(CPack)
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_GENERATOR "DEB;RPM;NSIS")
set(CPACK_PACKAGE_CONTACT "fam007e <faisalmoshiur+secpasswdmgmt@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "fam007e")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_RPM_PACKAGE_GROUP "Utilities")
set(CPACK_NSIS_PACKAGE_NAME "${PROJECT_NAME} ${CPACK_PACKAGE_VERSION}")
set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
set(CPACK_NSIS_CREATE_ICONS "ON")
set(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}/gui/icons/app_icon.ico")
set(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}/gui/icons/app_icon.ico")
