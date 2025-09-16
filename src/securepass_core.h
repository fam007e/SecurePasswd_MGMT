/*
 * securepass_core.h
 * Public API for the SecurePassManager C core library.
 */

#ifndef SECUREPASS_CORE_H
#define SECUREPASS_CORE_H

#include <stddef.h> // For size_t

#define MAX_PASSWORD_LEN 256
#define MAX_USERNAME_LEN 256
#define MAX_ACCOUNT_LEN 256

// Initialization and Validation
void securepass_init_data_dir(void);
void securepass_ensure_data_directory(void);
int securepass_validate_master_password(const char *master_password);

// Password Management
int securepass_add_password(const char *account, const char *username, const char *plaintext_password, const char *master_password);
int securepass_get_password(const char *account, const char *master_password, char *decrypted_username_out, char *decrypted_password_out);
char *securepass_generate_password(int length, int use_uppercase, int use_numbers, int use_special);

// TOTP Management
int securepass_add_totp(const char *account, const char *secret_key, const char *master_password);
int securepass_generate_totp(const char *account, const char *master_password, char *totp_code_out);

// Data Import/Export
int securepass_export_csv(const char *master_password, const char *filepath);
int securepass_import_csv(const char *master_password, const char *filepath);

// --- Migration ---
int securepass_migrate_data(const char *master_password);

// Utility Functions
void securepass_secure_zero(void *ptr, size_t size);
void securepass_clear_screen(void);
int securepass_get_hidden_input(char *buffer, size_t size);
int securepass_get_input_line(char *buffer, size_t size);


#endif // SECUREPASS_CORE_H
