#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h> // For libsodium
#include <openssl/evp.h> // For Base64
#include <openssl/bio.h> // For Base64
#include <openssl/buffer.h> // For Base64
#include <argon2.h>
#include "encryption.h"
#include "securepass_core.h"
#include "utils.h"
#include "data_path.h"

#define SALT_SIZE 16
#define KEY_SIZE crypto_secretbox_KEYBYTES // 32 bytes, from libsodium

// The encrypted blob will be: [Argon2 salt (16 bytes)][XChaCha20 nonce (24 bytes)][ciphertext + Poly1305 tag]
#define NONCE_SIZE crypto_secretbox_NONCEBYTES // 24 bytes, from libsodium

// Internal function to read Argon2 parameters from the master key file
static int get_argon2_params_from_master_key(Argon2Params *params_out) {
    const char *master_key_file_path = get_master_key_path();
    FILE *file = fopen(master_key_file_path, "r");
    if (!file) {
        return 0; // File not found
    }

    char params_line[256];
    if (fgets(params_line, sizeof(params_line), file) == NULL) {
        fclose(file);
        return 0; // Empty or corrupted file
    }
    fclose(file);

    if (sscanf(params_line, "t=%u,m=%u,p=%u", &params_out->t_cost, &params_out->m_cost, &params_out->parallelism) != 3) {
        return 0;
    }

    params_out->salt_len = SALT_SIZE;
    params_out->hash_len = KEY_SIZE;

    return 1; // Success
}

// Base64 encoding function (using OpenSSL)
static char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    (void)BIO_flush(bio); // Cast to void to ignore return value
    
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char *result = malloc(buffer_ptr->length + 1);
    if (result) {
        memcpy(result, buffer_ptr->data, buffer_ptr->length);
        result[buffer_ptr->length] = '\0'; // Correct null terminator
    }
    
    BIO_free_all(bio);
    return result;
}

// Base64 decoding function (using OpenSSL)
static unsigned char *base64_decode(const char *input, int *output_length) {
    BIO *bio, *b64;
    size_t decode_len = strlen(input); // Use size_t for strlen
    unsigned char *buffer = malloc(decode_len);
    
    if (!buffer) return NULL;
    
    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *output_length = BIO_read(bio, buffer, (int)decode_len); // Cast to int for BIO_read
    
    BIO_free_all(bio);
    
    if (*output_length <= 0) {
        free(buffer);
        return NULL;
    }
    
    return buffer;
}

Argon2Params get_default_argon2_params() {
    Argon2Params params;
    params.t_cost = 3;
    params.m_cost = (1 << 12); // 4096 KiB
    params.parallelism = 1;
    params.salt_len = SALT_SIZE;
    params.hash_len = KEY_SIZE;
    return params;
}

// NEW: encrypt_password using libsodium
int encrypt_password(const char *plaintext, const char *master_password, char *encrypted_output) {
    if (!plaintext || !master_password || !encrypted_output) return 0;

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    unsigned char key[KEY_SIZE];

    // 1. Generate random salt for Argon2 and nonce for XChaCha20
    randombytes_buf(salt, SALT_SIZE);
    randombytes_buf(nonce, NONCE_SIZE);

    // 2. Get Argon2 parameters and derive key from master password
    Argon2Params params;
    if (!get_argon2_params_from_master_key(&params)) return 0;

    if (argon2i_hash_raw(params.t_cost, params.m_cost, params.parallelism, master_password, strlen(master_password), salt, SALT_SIZE, key, KEY_SIZE) != ARGON2_OK) {
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // 3. Encrypt with libsodium's crypto_secretbox (XChaCha20-Poly1305)
    size_t plaintext_len = strlen(plaintext);
    size_t ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    if (crypto_secretbox_easy(ciphertext, (const unsigned char *)plaintext, plaintext_len, nonce, key) != 0) {
        free(ciphertext);
        securepass_secure_zero(key, sizeof(key));
        return 0; // Encryption failed
    }
    securepass_secure_zero(key, sizeof(key)); // Key is no longer needed

    // 4. Combine [salt][nonce][ciphertext] into a single blob
    size_t total_len = SALT_SIZE + NONCE_SIZE + ciphertext_len;
    unsigned char *combined = malloc(total_len);
    if (!combined) {
        free(ciphertext);
        return 0;
    }

    memcpy(combined, salt, SALT_SIZE);
    memcpy(combined + SALT_SIZE, nonce, NONCE_SIZE);
    memcpy(combined + SALT_SIZE + NONCE_SIZE, ciphertext, ciphertext_len);
    free(ciphertext);

    // 5. Base64 encode the final blob
    char *base64_result = base64_encode(combined, total_len);
    free(combined);
    if (!base64_result) {
        return 0;
    }

    strcpy(encrypted_output, base64_result);
    free(base64_result);

    return 1;
}

// NEW: decrypt_password using libsodium
int decrypt_password(const char *encrypted_input, const char *master_password, char *decrypted_output) {
    if (!encrypted_input || !master_password || !decrypted_output) return 0;

    // 1. Base64 decode the input
    int decoded_len;
    unsigned char *decoded = base64_decode(encrypted_input, &decoded_len);
    if (!decoded || decoded_len < SALT_SIZE + NONCE_SIZE + crypto_secretbox_MACBYTES) {
        if (decoded) free(decoded);
        return 0;
    }

    // 2. Extract [salt][nonce][ciphertext] from the blob
    unsigned char *salt = decoded;
    unsigned char *nonce = decoded + SALT_SIZE;
    unsigned char *ciphertext = decoded + SALT_SIZE + NONCE_SIZE;
    size_t ciphertext_len = decoded_len - (SALT_SIZE + NONCE_SIZE);

    // 3. Get Argon2 params and re-derive the key
    Argon2Params params;
    if (!get_argon2_params_from_master_key(&params)) {
        free(decoded);
        return 0;
    }

    unsigned char key[KEY_SIZE];
    if (argon2i_hash_raw(params.t_cost, params.m_cost, params.parallelism, master_password, strlen(master_password), salt, SALT_SIZE, key, KEY_SIZE) != ARGON2_OK) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // 4. Decrypt with libsodium
    size_t decrypted_len = ciphertext_len - crypto_secretbox_MACBYTES;
    // Use malloc for the buffer that will be returned
    unsigned char *decrypted_buf = malloc(decrypted_len + 1);
    if (!decrypted_buf) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    if (crypto_secretbox_open_easy(decrypted_buf, ciphertext, ciphertext_len, nonce, key) != 0) {
        free(decrypted_buf);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0; // Decryption failed (invalid MAC)
    }
    securepass_secure_zero(key, sizeof(key));
    free(decoded);

    // 5. Copy to output
    decrypted_buf[decrypted_len] = '\0'; // Correct null terminator
    strcpy(decrypted_output, (char *)decrypted_buf);
    securepass_secure_zero(decrypted_buf, decrypted_len + 1);
    free(decrypted_buf);

    return 1;
}

// OLD AES-GCM decryption logic for migration.
int decrypt_password_old(const char *encrypted_input, const char *master_password, char *decrypted_output) {
    if (!encrypted_input || !master_password || !decrypted_output) return 0;

    int decoded_len;
    unsigned char *decoded = base64_decode(encrypted_input, &decoded_len);
    if (!decoded || decoded_len < SALT_SIZE + 12 + 16) { // GCM_IV_SIZE=12, GCM_TAG_SIZE=16
        if (decoded) free(decoded);
        return 0;
    }

    unsigned char *salt = decoded;
    unsigned char *iv = decoded + SALT_SIZE;
    unsigned char *tag = decoded + SALT_SIZE + 12;
    unsigned char *ciphertext = decoded + SALT_SIZE + 12 + 16;
    int ciphertext_len = decoded_len - (SALT_SIZE + 12 + 16);

    Argon2Params params;
    if (!get_argon2_params_from_master_key(&params)) {
        free(decoded);
        return 0;
    }

    unsigned char key[KEY_SIZE];
    if (argon2i_hash_raw(params.t_cost, params.m_cost, params.parallelism, master_password, strlen(master_password), salt, SALT_SIZE, key, KEY_SIZE) != ARGON2_OK) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    unsigned char *plaintext = malloc(ciphertext_len + 1);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len += len;

    plaintext[plaintext_len] = '\0'; // Correct null terminator
    strcpy(decrypted_output, (char *)plaintext);

    EVP_CIPHER_CTX_free(ctx);
    securepass_secure_zero(plaintext, plaintext_len);
    free(plaintext);
    free(decoded);
    securepass_secure_zero(key, sizeof(key));

    return 1;
}

// --- Argon2 Functions (unchanged) ---

int argon2_hash_password(const char *password, const Argon2Params *params, char *hash_output) {
    if (!password || !params || !hash_output) return 0;

    unsigned char salt[params->salt_len];
    // Use libsodium's randombytes_buf for consistency
    randombytes_buf(salt, params->salt_len);

    int result = argon2i_hash_encoded(params->t_cost, params->m_cost, params->parallelism, password, strlen(password), salt, params->salt_len, params->hash_len, hash_output, ARGON2_ENCODED_LEN);
    securepass_secure_zero(salt, sizeof(salt));
    return (result == ARGON2_OK);
}

int argon2_verify_password(const char *password, const char *encoded_hash) {
    if (!password || !encoded_hash) return 0;
    return (argon2_verify(encoded_hash, password, strlen(password), Argon2_i) == ARGON2_OK);
}

int setup_master_password_argon2(const char *password, const Argon2Params *params) {
    char encoded_hash[ARGON2_ENCODED_LEN];
    if (!argon2_hash_password(password, params, encoded_hash)) {
        printf("Error: Failed to hash master password with Argon2.\n");
        return 0;
    }

    const char *master_key_file_path = get_master_key_path();
    FILE *file = fopen(master_key_file_path, "w");
    if (!file) {
        printf("Error: Cannot create master password file at %s.\n", master_key_file_path);
        return 0;
    }

    fprintf(file, "t=%u,m=%u,p=%u\n", params->t_cost, params->m_cost, params->parallelism);
    fprintf(file, "%s\n", encoded_hash);
    fclose(file);

    return 1;
}

int validate_master_password_argon2(const char *input_password) {
    const char *master_key_file_path = get_master_key_path();
    FILE *file = fopen(master_key_file_path, "r");
    if (!file) {
        Argon2Params default_params = get_default_argon2_params();
        if (setup_master_password_argon2(input_password, &default_params)) {
            return 1; // Success
        }
        else {
            return 0; // Failure
        }
    }

    char line1[256];
    if (fgets(line1, sizeof(line1), file) == NULL) {
        fclose(file);
        return 0; // Empty file
    }

    if (strncmp(line1, "t=", 2) == 0) {
        char stored_encoded_hash[ARGON2_ENCODED_LEN];
        if (fgets(stored_encoded_hash, sizeof(stored_encoded_hash), file) == NULL) {
            fclose(file);
            return 0; // Corrupted file
        }
        stored_encoded_hash[strcspn(stored_encoded_hash, "\n")] = '\0';
        fclose(file);
        return argon2_verify_password(input_password, stored_encoded_hash);

    } else {
        // This 'else' block handles the old PBKDF2 format and is part of the migration path.
        // It is separate from the AES vs XChaCha20 data encryption format.
        char *stored_encoded_hash = line1;
        stored_encoded_hash[strcspn(stored_encoded_hash, "\n")] = '\0';
        fclose(file);

        printf("Old master key format detected. Migration is required.\n");
        return 2; // Special status for migration needed
    }
}

void cleanup_openssl(void) {
    // This function can be removed if OpenSSL is no longer used for anything else.
    // For now, it's kept as Base64 functions still use it.
    EVP_cleanup();
}