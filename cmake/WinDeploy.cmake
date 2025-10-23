
# cmake/WinDeploy.cmake

function(deploy_windows_dependencies target)
    if(NOT WIN32)
        return()
    endif()

    # Find windeployqt executable from the vcpkg installation
    get_filename_component(VCPKG_SCRIPT_DIR "${CMAKE_TOOLCHAIN_FILE}" DIRECTORY)
    get_filename_component(VCPKG_ROOT "${VCPKG_SCRIPT_DIR}/../.." REALPATH)

    find_program(
        WINDEPLOYQT_EXECUTABLE windeployqt
        HINTS "${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/tools/qtbase/bin"
        NO_DEFAULT_PATH
    )

    if(NOT WINDEPLOYQT_EXECUTABLE)
        message(FATAL_ERROR "Failed to find windeployqt.exe. Searched in: ${VCPKG_ROOT}/installed/${VCPKG_TARGET_TRIPLET}/tools/qtbase/bin")
    endif()

    # Use windeployqt to deploy Qt dependencies
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}" --release --dir "$<TARGET_FILE_DIR:${target}>" "$<TARGET_FILE:${target}>"
        COMMENT "Deploying Qt dependencies for ${target}"
    )

    # List of vcpkg dependencies to deploy
    set(VCPKG_DEPS
        unofficial-sodium
        unofficial-argon2
        sqlcipher
        OpenSSL
        CURL
    )

    foreach(dep ${VCPKG_DEPS})
        if(TARGET ${dep}::${dep})
            set(DEP_LIBRARY_PATH "$<TARGET_FILE:${dep}::${dep}>")
        elseif(TARGET ${dep})
            set(DEP_LIBRARY_PATH "$<TARGET_FILE:${dep}>")
        else()
            # Handle unofficial prefixes and other naming variations
            if(TARGET unofficial-${dep}::${dep})
                set(DEP_LIBRARY_PATH "$<TARGET_FILE:unofficial-${dep}::${dep}>")
            elseif(TARGET unofficial::${dep}::lib${dep})
                 set(DEP_LIBRARY_PATH "$<TARGET_FILE:unofficial::${dep}::lib${dep}>")
            else()
                message(WARNING "Could not find target for dependency: ${dep}")
                continue()
            endif()
        endif()

        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DEP_LIBRARY_PATH}"
                "$<TARGET_FILE_DIR:${target}>"
            COMMENT "Deploying ${dep} for ${target}"
        )
    endforeach()

    # Also install the DLLs to the CPack installation directory
    install(DIRECTORY "$<TARGET_FILE_DIR:${target}>/" DESTINATION bin FILES_MATCHING PATTERN "*.dll")
endfunction()
