add_library(password_generator_lib STATIC password_generator.c)

add_executable(securepasswd_cli main.c)

target_include_directories(securepasswd_cli PRIVATE ${LIBCSV_INCLUDE_DIRS})

target_link_libraries(securepasswd_cli PRIVATE core_lib password_generator_lib ${LIBCSV_LIBRARIES})