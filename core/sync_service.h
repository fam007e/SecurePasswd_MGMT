#ifndef SYNC_SERVICE_H
#define SYNC_SERVICE_H

#include <stddef.h>

#define SYNC_KEY_LEN 32
#define SYNC_NONCE_LEN 12
#define SYNC_TAG_LEN 16

/**
 * @brief Encrypts the database and salt into a single package for mobile synchronization.
 *
 * This function packs the vault.db and vault.db.salt files together, then encrypts
 * the package using Chacha20-Poly1305 authenticated encryption.
 *
 * @param db_path Path to the database file (the salt path is derived from this).
 * @param output_buffer Buffer where the encrypted package will be stored.
 * @param output_size Pointer to store the size of the generated package.
 * @param key The 32-byte synchronization key.
 * @return 0 on success, -1 on error.
 */
int sync_encrypt_vault(const char *db_path, unsigned char *output_buffer, size_t *output_size, const unsigned char key[SYNC_KEY_LEN]); // flawfinder: ignore

/**
 * @brief Decrypts a received sync package and restores the database and salt files.
 *
 * @param encrypted_data The received encrypted package data.
 * @param data_len The length of the encrypted data.
 * @param db_path Path where the database should be restored (salt path is derived).
 * @param key The 32-byte synchronization key used for encryption.
 * @return 0 on success, -1 on error.
 */
int sync_decrypt_vault(const unsigned char *encrypted_data, size_t data_len, const char *db_path, const unsigned char key[SYNC_KEY_LEN]); // flawfinder: ignore

#endif // SYNC_SERVICE_H
