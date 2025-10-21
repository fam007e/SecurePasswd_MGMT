set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(ICONS
    icons/add.svg
    icons/app_icon.svg
    icons/copy_username.svg
    icons/copy_passwd.svg
    icons/copy_totp.svg
    icons/delete.svg
    icons/edit.svg
    icons/export.svg
    icons/health-check.svg
    icons/import.svg
    icons/darkmode.svg
    icons/lightmode.svg
)

set(THEMES
    dark.qss
    light.qss
)

qt_add_executable(securepasswd_gui
    main.cpp
    passworddialog.cpp
    mainwindow.cpp
    entrydialog.cpp
    passwordentry.h
    passwordgeneratordialog.h
    passwordgeneratordialog.cpp
    ../cli/password_generator.c
    healthcheckdialog.h
    healthcheckdialog.cpp
    icons.qrc
)

# Include directories
target_include_directories(securepasswd_gui PRIVATE
    ${CMAKE_SOURCE_DIR}/cli
)

# Only add LIBCSV_INCLUDE_DIRS if it's not empty (to avoid warnings)
if(LIBCSV_INCLUDE_DIRS)
    target_include_directories(securepasswd_gui PRIVATE ${LIBCSV_INCLUDE_DIRS})
endif()

# Link libraries
target_link_libraries(securepasswd_gui PRIVATE
    Qt6::Widgets
    core_lib
    ${LIBCSV_LIBRARIES}
)

# Installation rules
install(TARGETS securepasswd_gui
    RUNTIME DESTINATION bin
    BUNDLE DESTINATION .
)

install(FILES ${ICONS} DESTINATION bin/icons)
install(FILES ${THEMES} DESTINATION bin)

# Windows-specific: Copy DLLs to output directory
if(WIN32)
    # This helps with running the executable directly from the build directory
    add_custom_command(TARGET securepasswd_gui POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:Qt6::Widgets>
        $<TARGET_FILE_DIR:securepasswd_gui>
    )
endif()
