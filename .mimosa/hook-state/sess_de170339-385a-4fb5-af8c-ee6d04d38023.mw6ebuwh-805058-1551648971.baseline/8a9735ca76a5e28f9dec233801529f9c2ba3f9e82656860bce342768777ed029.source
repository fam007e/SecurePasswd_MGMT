#include "platform_paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

void get_config_path(char *path_buffer, size_t buffer_size) {
    if (buffer_size == 0) return;

#ifdef _WIN32
    // Use AppData\Local\securepasswd on Windows
    const char *localappdata = getenv("LOCALAPPDATA"); // flawfinder: ignore
    if (localappdata && strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ localappdata) < buffer_size /* flawfinder: ignore */  - 32) {
        snprintf(path_buffer, buffer_size, "%s\\securepasswd", localappdata);
    } else {
        // Fallback if LOCALAPPDATA is not set or too long
        snprintf(path_buffer, buffer_size, ".");
    }
#else
    // Linux/macOS: use XDG_DATA_HOME or ~/.local/share
    const char *data_home = getenv("XDG_DATA_HOME"); // flawfinder: ignore
    if (data_home && strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ data_home) < buffer_size /* flawfinder: ignore */  - 32) {
        snprintf(path_buffer, buffer_size, "%s/securepasswd", data_home);
    } else {
        const char *home = getenv("HOME"); // flawfinder: ignore
        if (home && strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ home) < buffer_size /* flawfinder: ignore */  - 32) {
            snprintf(path_buffer, buffer_size, "%s/.local/share/securepasswd", home);
        } else {
            // Fallback if HOME is not set or too long
            snprintf(path_buffer, buffer_size, ".");
        }
    }
#endif
    path_buffer[buffer_size - 1] = '\0';
}
