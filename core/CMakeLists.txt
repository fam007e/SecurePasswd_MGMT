add_library(core_lib STATIC key_derivation.c database.c totp.c pwned_check.c)

target_include_directories(core_lib PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBSODIUM_INCLUDE_DIRS}
    ${ARGON2_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${SQLCIPHER_INCLUDE_DIRS}
)

target_link_libraries(core_lib PUBLIC 
    ${LIBSODIUM_LIBRARIES}
    ${ARGON2_LIBRARIES}
    ${CURL_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${SQLCIPHER_LIBRARIES}
)
target_link_libraries(core_lib PRIVATE sqlcipher)
target_compile_definitions(core_lib PRIVATE SQLITE_HAS_CODEC)