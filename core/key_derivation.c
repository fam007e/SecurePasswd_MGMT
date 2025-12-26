#include "key_derivation.h"

#include <argon2.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#define MEMORY_COST (1 << 16) // 64MB
#define TIME_COST 3
#define PARALLELISM 1

int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    if (sodium_init() < 0)
        return -1;
    return argon2id_hash_raw(TIME_COST, MEMORY_COST, PARALLELISM, password,
                             strlen(password), salt, SALT_LEN, key, KEY_LEN);
}

int load_or_generate_salt(const char *path, uint8_t *salt) {
    FILE *f = fopen(path, "rb");
    if (f) {
        // Salt file exists, read it
        size_t n = fread(salt, 1, SALT_LEN, f);
        fclose(f);
        if (n != SALT_LEN) {
            return -1; // Failed to read salt
        }
        return 0;
    } else {
        // Salt file does not exist, generate a new one
        if (sodium_init() < 0)
            return -1;
        randombytes_buf(salt, SALT_LEN);

        // Save the new salt
        f = fopen(path, "wb");
        if (!f) {
            return -1; // Failed to open salt file for writing
        }
        size_t n = fwrite(salt, 1, SALT_LEN, f);
        fclose(f);
        if (n != SALT_LEN) {
            return -1; // Failed to write salt
        }
        return 0;
    }
}
