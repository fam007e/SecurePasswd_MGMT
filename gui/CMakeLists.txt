cmake_minimum_required(VERSION 3.21)
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
    WIN32  # This prevents console window on Windows
    main.cpp
    passworddialog.cpp
    mainwindow.cpp
    entrydialog.cpp
    passwordentry.h
    passwordgeneratordialog.h
    passwordgeneratordialog.cpp
    healthcheckdialog.h
    healthcheckdialog.cpp
    icons.qrc
)

# Embed Windows icon into executable
if(WIN32)
    target_sources(securepasswd_gui PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/app.rc")
endif()

# Include directories
target_include_directories(securepasswd_gui PRIVATE
    ${CMAKE_SOURCE_DIR}/core
)

# Only add LIBCSV_INCLUDE_DIRS if it's not empty (to avoid warnings)
if(LIBCSV_INCLUDE_DIRS)
    target_include_directories(securepasswd_gui PRIVATE ${LIBCSV_INCLUDE_DIRS})
endif()

# Link libraries
target_link_libraries(securepasswd_gui PRIVATE
    Qt6::Widgets
    Qt6::Svg
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

if(WIN32)
    deploy_windows_dependencies(securepasswd_gui USES_QT)
endif()

if(UNIX AND NOT APPLE)
    # Install desktop file
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/securepasswd_gui.desktop.in"
        "${CMAKE_CURRENT_BINARY_DIR}/securepasswd_gui.desktop"
        @ONLY
    )

    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/securepasswd_gui.desktop"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/applications"
    )

    # Install icon
    install(
        FILES "${CMAKE_CURRENT_SOURCE_DIR}/icons/app_icon.svg"
        RENAME "securepasswd_gui.svg"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps"
    )
endif()
