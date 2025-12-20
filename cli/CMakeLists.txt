add_executable(securepasswd_cli main.c)

target_include_directories(securepasswd_cli PRIVATE
    ${LIBCSV_INCLUDE_DIRS}
)

target_link_libraries(securepasswd_cli PRIVATE
    core_lib
    ${LIBCSV_LIBRARIES}
)

# Windows-specific: link getopt
if(WIN32)
    target_link_libraries(securepasswd_cli PRIVATE ${GETOPT_LIBRARY})
endif()

install(TARGETS securepasswd_cli DESTINATION bin)

if(WIN32)
    deploy_windows_dependencies(securepasswd_cli)
endif()
