#include "platform_paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void get_config_path(char* path_buffer, size_t buffer_size) {
#ifdef _WIN32
    // Use AppData\Local\securepasswd on Windows
    const char* localappdata = getenv("LOCALAPPDATA");
    if (localappdata) {
        snprintf(path_buffer, buffer_size, "%s\\securepasswd", localappdata);
    } else {
        // Fallback if LOCALAPPDATA is not set
        snprintf(path_buffer, buffer_size, ".");
    }
#else
    // Linux/macOS: use XDG_DATA_HOME or ~/.local/share
    const char* data_home = getenv("XDG_DATA_HOME");
    if (data_home) {
        snprintf(path_buffer, buffer_size, "%s/securepasswd", data_home);
    } else {
        const char* home = getenv("HOME");
        if (home) {
            snprintf(path_buffer, buffer_size, "%s/.local/share/securepasswd", home);
        } else {
            // Fallback if HOME is not set
            snprintf(path_buffer, buffer_size, ".");
        }
    }
#endif
}
