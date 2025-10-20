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


target_include_directories(securepasswd_gui PRIVATE ${CMAKE_SOURCE_DIR}/cli ${LIBCSV_INCLUDE_DIRS})

target_link_libraries(securepasswd_gui PRIVATE Qt6::Widgets core_lib ${LIBCSV_LIBRARIES})

install(TARGETS securepasswd_gui
    RUNTIME DESTINATION bin
    BUNDLE DESTINATION .
)

install(FILES ${ICONS} DESTINATION bin/icons)
install(FILES ${THEMES} DESTINATION bin)
