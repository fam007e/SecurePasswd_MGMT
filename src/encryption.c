#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdlib.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define SALT_SIZE 16

static unsigned char key[AES_256_KEY_SIZE];
static unsigned char iv[AES_BLOCK_SIZE];

// Base64 encoding function
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}

// Base64 decoding function
unsigned char *base64_decode(const char *input, int *outlen) {
    BIO *b64, *bmem;

    int length = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, -1);
    bmem = BIO_push(b64, bmem);

    *outlen = BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

int init_encryption(const char* master_password) {
    unsigned char salt[SALT_SIZE];
    
    // Generate a random salt
    if (RAND_bytes(salt, SALT_SIZE) != 1) {
        return 0;
    }

    // Derive the key and IV from the master password and salt
    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt,
                        (unsigned char*)master_password, strlen(master_password),
                        1, key, iv)) {
        return 0;
    }

    return 1;
}

char* encrypt_password(const char* password) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char *ciphertext;
    char *encoded;

    // Allocate memory for ciphertext
    ciphertext = malloc(strlen(password) + AES_BLOCK_SIZE);
    if (ciphertext == NULL) return NULL;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;

    // Initialise the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto cleanup;

    // Encrypt the password
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)password, strlen(password))) goto cleanup;
    ciphertext_len = len;

    // Finalise the encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto cleanup;
    ciphertext_len += len;

    // Encode the ciphertext to base64
    encoded = base64_encode(ciphertext, ciphertext_len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    return encoded;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return NULL;
}

char* decrypt_password(const char* encrypted_password) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char *ciphertext;
    int ciphertext_len;
    unsigned char *plaintext;
    char *decrypted;

    // Decode the base64 encrypted password
    ciphertext = base64_decode(encrypted_password, &ciphertext_len);
    if (ciphertext == NULL) return NULL;

    // Allocate memory for plaintext
    plaintext = malloc(ciphertext_len);
    if (plaintext == NULL) {
        free(ciphertext);
        return NULL;
    }

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) goto cleanup;

    // Initialise the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto cleanup;

    // Decrypt the ciphertext
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto cleanup;
    plaintext_len = len;

    // Finalise the decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto cleanup;
    plaintext_len += len;

    // Null-terminate the plaintext
    decrypted = malloc(plaintext_len + 1);
    if (decrypted == NULL) goto cleanup;
    memcpy(decrypted, plaintext, plaintext_len);
    decrypted[plaintext_len] = '\0';

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);

    return decrypted;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);
    return NULL;
}

void cleanup_encryption() {
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(iv, sizeof(iv));
}