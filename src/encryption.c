#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "encryption.h"

#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define PBKDF2_ITERATIONS 10000

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

// Secure memory clearing function
static void secure_zero(void *ptr, size_t size) {
    if (ptr) {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

int generate_secure_key(unsigned char *key, int key_length) {
    if (!key || key_length <= 0) {
        return 0;
    }
    
    return RAND_bytes(key, key_length);
}

int hash_password_with_salt(const char *password, const char *salt_hex, char *hash_output) {
    if (!password || !salt_hex || !hash_output) {
        return 0;
    }
    
    unsigned char salt[SALT_SIZE];
    unsigned char hash[KEY_SIZE];
    
    // Convert hex salt to bytes
    for (int i = 0; i < SALT_SIZE; i++) {
        if (sscanf(salt_hex + (i * 2), "%2hhx", &salt[i]) != 1) {
            return 0;
        }
    }
    
    // Generate hash using PBKDF2
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 
                          PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, hash) != 1) {
        return 0;
    }
    
    // Convert hash to hex string
    for (int i = 0; i < KEY_SIZE; i++) {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[KEY_SIZE * 2] = '\0';
    
    // Clear sensitive data
    secure_zero(salt, sizeof(salt));
    secure_zero(hash, sizeof(hash));
    
    return 1;
}

int encrypt_password(const char *plaintext, const char *master_password, char *encrypted_output) {
    if (!plaintext || !master_password || !encrypted_output) {
        return 0;
    }
    
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char key[KEY_SIZE];
    
    // Generate random salt and IV
    if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, IV_SIZE) != 1) {
        return 0;
    }
    
    // Derive key from master password using PBKDF2
    if (PKCS5_PBKDF2_HMAC(master_password, strlen(master_password), salt, SALT_SIZE,
                          PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key) != 1) {
        return 0;
    }
    
    // Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    int plaintext_len = strlen(plaintext);
    unsigned char *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    int len;
    int ciphertext_len;
    
    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, sizeof(key));
        return 0;
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        secure_zero(key, sizeof(key));
        return 0;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Combine salt + iv + ciphertext
    int total_len = SALT_SIZE + IV_SIZE + ciphertext_len;
    unsigned char *combined = malloc(total_len);
    if (!combined) {
        free(ciphertext);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    memcpy(combined, salt, SALT_SIZE);
    memcpy(combined + SALT_SIZE, iv, IV_SIZE);
    memcpy(combined + SALT_SIZE + IV_SIZE, ciphertext, ciphertext_len);
    
    // Encode to base64
    char *base64_result = base64_encode(combined, total_len);
    if (!base64_result) {
        free(combined);
        free(ciphertext);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    strcpy(encrypted_output, base64_result);
    
    // Clean up
    free(base64_result);
    free(combined);
    secure_zero(ciphertext, ciphertext_len);
    free(ciphertext);
    secure_zero(key, sizeof(key));
    
    return 1;
}

int decrypt_password(const char *encrypted_input, const char *master_password, char *decrypted_output) {
    if (!encrypted_input || !master_password || !decrypted_output) {
        return 0;
    }
    
    // Decode from base64
    int decoded_len;
    unsigned char *decoded = base64_decode(encrypted_input, &decoded_len);
    if (!decoded || decoded_len < SALT_SIZE + IV_SIZE + AES_BLOCK_SIZE) {
        if (decoded) free(decoded);
        return 0;
    }
    
    // Extract salt, IV, and ciphertext
    unsigned char *salt = decoded;
    unsigned char *iv = decoded + SALT_SIZE;
    unsigned char *ciphertext = decoded + SALT_SIZE + IV_SIZE;
    int ciphertext_len = decoded_len - SALT_SIZE - IV_SIZE;
    
    // Derive key from master password
    unsigned char key[KEY_SIZE];
    if (PKCS5_PBKDF2_HMAC(master_password, strlen(master_password), salt, SALT_SIZE,
                          PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key) != 1) {
        free(decoded);
        return 0;
    }
    
    // Create decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(decoded);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    unsigned char *plaintext = malloc(ciphertext_len + AES_BLOCK_SIZE);
    if (!plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        secure_zero(key, sizeof(key));
        return 0;
    }
    
    int len;
    int plaintext_len;
    
    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len = len;
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        free(decoded);
        secure_zero(key, sizeof(key));
        return 0;
    }
    plaintext_len += len;
    
    // Null terminate and copy result
    plaintext[plaintext_len] = '\0';
    strcpy(decrypted_output, (char *)plaintext);
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    secure_zero(plaintext, plaintext_len);
    free(plaintext);
    free(decoded);
    secure_zero(key, sizeof(key));
    
    return 1;
}

void cleanup_openssl(void) {
    EVP_cleanup();
}