#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>

#define AES_BLOCK_SIZE 16

/**
 * Encrypt a password using AES-256-CBC with PBKDF2 key derivation
 * @param plaintext The password to encrypt
 * @param master_password The master password for key derivation
 * @param encrypted_output Buffer to store base64-encoded encrypted result (must be large enough)
 * @return 1 on success, 0 on failure
 */
int encrypt_password(const char *plaintext, const char *master_password, char *encrypted_output);

/**
 * Decrypt a password using AES-256-CBC
 * @param encrypted_input Base64-encoded encrypted password
 * @param master_password The master password for key derivation
 * @param decrypted_output Buffer to store decrypted password (must be large enough)
 * @return 1 on success, 0 on failure
 */
int decrypt_password(const char *encrypted_input, const char *master_password, char *decrypted_output);

/**
 * Generate a cryptographically secure random key
 * @param key Buffer to store the generated key
 * @param key_length Length of key to generate in bytes
 * @return 1 on success, 0 on failure
 */
int generate_secure_key(unsigned char *key, int key_length);

/**
 * Hash a password with salt using PBKDF2
 * @param password The password to hash
 * @param salt The salt (hex string)
 * @param hash_output Buffer to store the hash (hex string)
 * @return 1 on success, 0 on failure
 */
int hash_password_with_salt(const char *password, const char *salt, char *hash_output);

/**
 * Cleanup OpenSSL resources
 */
void cleanup_openssl(void);

#endif // ENCRYPTION_H