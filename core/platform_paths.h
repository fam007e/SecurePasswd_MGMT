#ifndef PLATFORM_PATHS_H
#define PLATFORM_PATHS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void get_config_path(char* path_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
