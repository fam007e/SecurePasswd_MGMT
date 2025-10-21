add_library(password_generator_lib STATIC password_generator.c)

# Include directories
if(NOT WIN32)
    target_include_directories(password_generator_lib PUBLIC ${LIBSODIUM_INCLUDE_DIRS})
endif()

target_link_libraries(password_generator_lib PUBLIC ${LIBSODIUM_LIBRARIES})

# CLI executable
add_executable(securepasswd_cli main.c)

target_include_directories(securepasswd_cli PRIVATE
    ${LIBCSV_INCLUDE_DIRS}
)

target_link_libraries(securepasswd_cli PRIVATE
    core_lib
    password_generator_lib
    ${LIBCSV_LIBRARIES}
)

# Windows-specific: link getopt
if(WIN32)
    target_link_libraries(securepasswd_cli PRIVATE getopt-win32::getopt-win32)
endif()
