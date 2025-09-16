#ifndef DATA_PATH_H
#define DATA_PATH_H

#include <stddef.h> // For size_t

// Initializes the data directory path (respects SECPASS_DATA_DIR)
void init_data_dir(void);

// Ensures the data directory exists, creating it if necessary
void ensure_data_directory(void);

// Constructs the full path for a given filename within the data directory
void get_data_path(char *path, size_t path_size, const char *filename);

// Gets the full path to the master.key file
const char *get_master_key_path(void);

// Gets the full path to the passwords.csv file
const char *get_passwords_path(void);


#endif // DATA_PATH_H