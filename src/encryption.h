#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/evp.h>
#include <argon2.h>
#include <stdint.h> // For uint32_t

#define MAX_PASSWORD_LEN 256
#define AES_BLOCK_SIZE 16
#define ARGON2_ENCODED_LEN 256 // A sufficiently large buffer for Argon2 encoded hash string

// New structure to store Argon2 parameters
typedef struct {
    uint32_t t_cost;        // Time cost
    uint32_t m_cost;        // Memory cost (in KiB)
    uint32_t parallelism;   // Number of threads
    size_t salt_len;        // Salt length in bytes
    size_t hash_len;        // Hash length in bytes
} Argon2Params;

// Function to get default Argon2 parameters
Argon2Params get_default_argon2_params();

// Function to hash a password using Argon2
// The hash_output buffer should be large enough to hold the encoded hash string (ARGON2_MAX_ENCODED_LEN)
int argon2_hash_password(const char *password, const Argon2Params *params, char *hash_output);

// Function to verify a password against an Argon2 encoded hash
int argon2_verify_password(const char *password, const char *encoded_hash);

/**
 * Encrypt a password using AES-256-CBC with Argon2 key derivation
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
 * Setup the master password for the first time using Argon2.
 * @param password The master password to set.
 * @param params Argon2 parameters to use for hashing.
 * @return 1 on success, 0 on failure.
 */
int setup_master_password_argon2(const char *password, const Argon2Params *params);

/**
 * Validate the entered master password against the stored Argon2 hash.
 * @param input_password The master password entered by the user.
 * @return 1 on success (password matches), 0 on failure.
 */
int validate_master_password_argon2(const char *input_password);

/**
 * Cleanup OpenSSL resources
 */
void cleanup_openssl(void);

#endif // ENCRYPTION_H