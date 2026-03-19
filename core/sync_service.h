#ifndef SYNC_SERVICE_H
#define SYNC_SERVICE_H

#include <stddef.h>

#define SYNC_KEY_LEN 32
#define SYNC_NONCE_LEN 12
#define SYNC_TAG_LEN 16

/**
 * @brief Encrypts the database and salt for sync.
 */
int sync_encrypt_vault(const char *db_path, unsigned char *output_buffer, size_t *output_size, const unsigned char key[SYNC_KEY_LEN]); // flawfinder: ignore

/**
 * @brief Decrypts the received data and restores vault/salt.
 */
int sync_decrypt_vault(const unsigned char *encrypted_data, size_t data_len, const char *db_path, const unsigned char key[SYNC_KEY_LEN]); // flawfinder: ignore

#endif // SYNC_SERVICE_H
