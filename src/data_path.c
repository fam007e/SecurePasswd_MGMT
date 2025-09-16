#include "data_path.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#endif

static char data_dir[256] = "data";

void init_data_dir(void) {
    const char *env_data_dir = getenv("SECPASS_DATA_DIR");
    if (env_data_dir) {
        strncpy(data_dir, env_data_dir, sizeof(data_dir) - 1);
        data_dir[sizeof(data_dir) - 1] = '\0';
    } else {
#ifdef _WIN32
        char path[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path))) {
            snprintf(data_dir, sizeof(data_dir), "%s/securepass", path);
        }
#else
        const char *home_dir = getenv("HOME");
        if (home_dir) {
            snprintf(data_dir, sizeof(data_dir), "%s/.config/securepass", home_dir);
        }
#endif
    }
}

void ensure_data_directory(void) {
    struct stat st = {0};
    if (stat(data_dir, &st) == -1) {
#ifdef _WIN32
        if (CreateDirectory(data_dir, NULL) || ERROR_ALREADY_EXISTS == GetLastError()) {
            // Directory created or already exists
        } else {
            printf("Error: Cannot create data directory: %s\n", data_dir);
            exit(1);
        }
#else
        if (mkdir(data_dir, 0700) != 0) {
            printf("Error: Cannot create data directory: %s\n", data_dir);
            exit(1);
        }
#endif
    }
}

void get_data_path(char *path, size_t path_size, const char *filename) {
    size_t required_size = strlen(data_dir) + 1 + strlen(filename) + 1;
    if (required_size > path_size) {
        fprintf(stderr, "Error: Path buffer is too small for \"%s/%s\".\n", data_dir, filename);
        exit(EXIT_FAILURE);
    }
    snprintf(path, path_size, "%s/%s", data_dir, filename);
}

const char *get_master_key_path(void) {
    static char master_key_path[256];
    get_data_path(master_key_path, sizeof(master_key_path), "master.key");
    return master_key_path;
}

const char *get_passwords_path(void) {
    static char passwords_path[256];
    get_data_path(passwords_path, sizeof(passwords_path), "passwords.csv");
    return passwords_path;
}
