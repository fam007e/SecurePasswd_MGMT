cmake_minimum_required(VERSION 3.10)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CMOCKA REQUIRED cmocka)

add_executable(core_tests test_core.c)
target_include_directories(core_tests PRIVATE ../)
target_link_libraries(core_tests PRIVATE core_lib)

link_directories(${CMOCKA_LIBRARY_DIRS})
add_executable(cmocka_tests test_cmocka.c)
target_include_directories(cmocka_tests PRIVATE ../ ${CMOCKA_INCLUDE_DIRS})
target_link_libraries(cmocka_tests PRIVATE core_lib password_generator_lib ${CMOCKA_LIBRARIES})

enable_testing()
add_test(NAME CoreTests COMMAND core_tests)
add_test(NAME CMockaTests COMMAND cmocka_tests)