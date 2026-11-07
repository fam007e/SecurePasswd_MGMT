#ifndef PLATFORM_PATHS_H
#define PLATFORM_PATHS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets the platform-specific path to the configuration directory.
 *
 * On Linux, this follows XDG specs (e.g., ~/.config/securepasswd).
 * On Windows, it uses %LOCALAPPDATA%/securepasswd.
 *
 * @param path_buffer The buffer where the absolute path will be stored.
 * @param buffer_size The size of the path buffer (recommended at least 4096).
 */
void get_config_path(char* path_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
