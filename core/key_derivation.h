#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SALT_LEN 16
#define KEY_LEN 32

// Derives a key from a password and salt using Argon2id.
int derive_key(const char *password, const uint8_t *salt, uint8_t *key);

// Loads the salt from the specified path.
// If the file doesn't exist, it generates a new salt and saves it.
int load_or_generate_salt(const char *path, uint8_t *salt);

#ifdef __cplusplus
}
#endif

#endif // KEY_DERIVATION_H