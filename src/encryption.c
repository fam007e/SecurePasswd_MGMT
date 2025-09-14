#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <argon2.h>
#include "encryption.h"
#include "securepass_core.h"
#include "utils.h"
#include "data_path.h"

#define SALT_SIZE 16
#define KEY_SIZE 32
#define XCHACHA_NONCE_SIZE 24 // For XChaCha20
#define POLY1305_TAG_SIZE 16

// Base64 encoding function
static char *base64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    
    BIO_get_mem_ptr(bio, &buffer_ptr);
    
    char *result = malloc(buffer_ptr->length + 1);
    if (result) {
        memcpy(result, buffer_ptr->data, buffer_ptr->length);
        result[buffer_ptr->length] = '\0';
    }
    
    BIO_free_all(bio);
    return result;
}

// Base64 decoding function
static unsigned char *base64_decode(const char *input, int *output_length) {
    BIO *bio, *b64;
    int decode_len = strlen(input);
    unsigned char *buffer = malloc(decode_len);
    
    if (!buffer) return NULL;
    
    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *output_length = BIO_read(bio, buffer, decode_len);
    
    BIO_free_all(bio);
    
    if (*output_length <= 0) {
        free(buffer);
        return NULL;
    }
    
    return buffer;
}



int generate_secure_key(unsigned char *key, int key_length) {
    if (!key || key_length <= 0) {
        return 0;
    }
    
    return RAND_bytes(key, key_length);
}

Argon2Params get_default_argon2_params() {
    Argon2Params params;
    params.t_cost = 3;      // Iterations
    params.m_cost = (1 << 12); // 4096 KiB = 4 MiB
    params.parallelism = 1; // Threads
    params.salt_len = 16;   // 16 bytes
    params.hash_len = 32;   // 32 bytes
    return params;
}

int argon2_hash_password(const char *password, const Argon2Params *params, char *hash_output) {
    if (!password || !params || !hash_output) {
        return 0;
    }

    unsigned char salt[params->salt_len];
    if (RAND_bytes(salt, params->salt_len) != 1) {
        return 0; // Failed to generate random salt
    }

    int result = argon2i_hash_encoded(
        params->t_cost,
        params->m_cost,
        params->parallelism,
        password,
        strlen(password),
        salt,
        params->salt_len,
        params->hash_len,
        hash_output,
        ARGON2_ENCODED_LEN // Max length for encoded hash
    );

    securepass_secure_zero(salt, sizeof(salt)); // Clear sensitive data

    return (result == ARGON2_OK);
}

int argon2_verify_password(const char *password, const char *encoded_hash) {
    if (!password || !encoded_hash) {
        return 0;
    }
    int result = argon2_verify(encoded_hash, password, strlen(password), Argon2_i);
    return (result == ARGON2_OK);
}

int encrypt_password(const char *plaintext, const char *master_password, char *encrypted_output) {
    if (!plaintext || !master_password || !encrypted_output) {
        return 0;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char nonce[XCHACHA_NONCE_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char tag[POLY1305_TAG_SIZE];

    // 1. Generate random salt and nonce
    if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(nonce, XCHACHA_NONCE_SIZE) != 1) {
        return 0;
    }

    // 2. Derive key from master password using Argon2
    int t_cost = 2;
    int m_cost = (1 << 10); // 1 MiB
    int parallelism = 1;
    if (argon2i_hash_raw(t_cost, m_cost, parallelism, master_password, strlen(master_password), salt, SALT_SIZE, key, KEY_SIZE) != ARGON2_OK) {
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // 3. Encrypt with XChaCha20-Poly1305
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    int plaintext_len = strlen(plaintext);
    unsigned char *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    int len = 0;
    int ciphertext_len = 0;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, XCHACHA_NONCE_SIZE, NULL) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    // Set key and nonce
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)plaintext, plaintext_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    ciphertext_len = len;

    // Finalize encryption (not much happens here for AEAD, but good practice)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    ciphertext_len += len;

    // Get the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, POLY1305_TAG_SIZE, tag) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);

    // 4. Combine salt + nonce + tag + ciphertext
    int total_len = SALT_SIZE + XCHACHA_NONCE_SIZE + POLY1305_TAG_SIZE + ciphertext_len;
    unsigned char *combined = malloc(total_len);
    if (!combined) {
        free(ciphertext);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    memcpy(combined, salt, SALT_SIZE);
    memcpy(combined + SALT_SIZE, nonce, XCHACHA_NONCE_SIZE);
    memcpy(combined + SALT_SIZE + XCHACHA_NONCE_SIZE, tag, POLY1305_TAG_SIZE);
    memcpy(combined + SALT_SIZE + XCHACHA_NONCE_SIZE + POLY1305_TAG_SIZE, ciphertext, ciphertext_len);

    // 5. Encode to Base64
    char *base64_result = base64_encode(combined, total_len);
    if (!base64_result) {
        free(combined);
        free(ciphertext);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    strcpy(encrypted_output, base64_result);

    // Clean up
    free(base64_result);
    free(combined);
    securepass_secure_zero(ciphertext, ciphertext_len);
    free(ciphertext);
    securepass_secure_zero(key, sizeof(key));

    return 1;
}

int decrypt_password(const char *encrypted_input, const char *master_password, char *decrypted_output) {
    if (!encrypted_input || !master_password || !decrypted_output) {
        return 0;
    }

    // 1. Decode from Base64
    int decoded_len;
    unsigned char *decoded = base64_decode(encrypted_input, &decoded_len);
    if (!decoded || decoded_len < SALT_SIZE + XCHACHA_NONCE_SIZE + POLY1305_TAG_SIZE) {
        if (decoded) free(decoded);
        return 0;
    }

    // 2. Extract components: salt, nonce, tag, ciphertext
    unsigned char *salt = decoded;
    unsigned char *nonce = decoded + SALT_SIZE;
    unsigned char *tag = decoded + SALT_SIZE + XCHACHA_NONCE_SIZE;
    unsigned char *ciphertext = decoded + SALT_SIZE + XCHACHA_NONCE_SIZE + POLY1305_TAG_SIZE;
    int ciphertext_len = decoded_len - (SALT_SIZE + XCHACHA_NONCE_SIZE + POLY1305_TAG_SIZE);

    // 3. Derive key from master password using Argon2
    unsigned char key[KEY_SIZE];
    int t_cost = 2;
    int m_cost = (1 << 10); // 1 MiB
    int parallelism = 1;
    if (argon2i_hash_raw(t_cost, m_cost, parallelism, master_password, strlen(master_password), salt, SALT_SIZE, key, KEY_SIZE) != ARGON2_OK) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // 4. Decrypt with XChaCha20-Poly1305
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    unsigned char *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    int len = 0;
    int plaintext_len = 0;

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, XCHACHA_NONCE_SIZE, NULL) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    // Set key and nonce
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    // Set the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, POLY1305_TAG_SIZE, tag) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len = len;

    // Finalize decryption (verifies tag)
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        // Authentication failed
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        securepass_secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len += len;

    // Null-terminate and copy result
    plaintext[plaintext_len] = '\0';
    strcpy(decrypted_output, (char *)plaintext);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    securepass_secure_zero(plaintext, plaintext_len);
    free(plaintext);
    free(decoded);
    securepass_secure_zero(key, sizeof(key));

    return 1;
}

int setup_master_password_argon2(const char *password, const Argon2Params *params) {
    printf("Setting up master password for first time with Argon2...\n");

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

    fprintf(file, "%s\n", encoded_hash); // Store the encoded hash directly
    fclose(file);

    printf("Master password set successfully with Argon2!\n");
    return 1;
}

int validate_master_password_argon2(const char *input_password) {
    const char *master_key_file_path = get_master_key_path();
    FILE *file = fopen(master_key_file_path, "r");
    if (!file) {
        // If master.key doesn't exist, it's the first time setup.
        // Use default Argon2 parameters for setup.
        Argon2Params default_params = get_default_argon2_params();
        return setup_master_password_argon2(input_password, &default_params);
    }

    char stored_encoded_hash[ARGON2_ENCODED_LEN];
    if (fgets(stored_encoded_hash, sizeof(stored_encoded_hash), file) == NULL) {
        fclose(file);
        printf("Error: Corrupted master password file or empty at %s.\n", master_key_file_path);
        return 0;
    }
    // Remove trailing newline if present
    stored_encoded_hash[strcspn(stored_encoded_hash, "\n")] = '\0';

    fclose(file);

    return argon2_verify_password(input_password, stored_encoded_hash);
}


void cleanup_openssl(void) {
    EVP_cleanup();
}