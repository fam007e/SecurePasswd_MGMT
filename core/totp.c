#include <openssl/hmac.h>
#include <openssl/evp.h>

#if defined(__linux__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#endif

#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include "totp.h"

// Simple base32 decoder
static int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize) {
    int buffer = 0;
    int bitsLeft = 0;
    int count = 0;
    for (const uint8_t *ptr = encoded; count < bufSize && *ptr; ++ptr) {
        uint8_t ch = *ptr;
        if (ch >= 'A' && ch <= 'Z') ch -= 'A';
        else if (ch >= 'a' && ch <= 'z') ch -= 'a'; // Support lowercase
        else if (ch >= '2' && ch <= '7') ch -= '2' - 26;
        else continue;

        buffer = (buffer << 5) | ch;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            result[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    return count;
}

char* generate_totp_code_at_time(const char *base32_secret, time_t current_time) {
    if (!base32_secret || strlen(base32_secret) == 0) {
        return NULL;
    }

    int decoded_len = (strlen(base32_secret) * 5 + 7) / 8;
    uint8_t *decoded_secret = malloc(decoded_len);
    if (!decoded_secret) return NULL;

    int actual_len = base32_decode((const uint8_t*)base32_secret, decoded_secret, decoded_len);

    uint64_t time_step = htobe64((uint64_t)current_time / 30);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    HMAC(EVP_sha1(), decoded_secret, actual_len, (const uint8_t*)&time_step, sizeof(time_step), hash, &hash_len);

    free(decoded_secret);

    int offset = hash[hash_len - 1] & 0x0F;
    uint32_t truncated_hash = be32toh(*(uint32_t*)(hash + offset)) & 0x7FFFFFFF;

    uint32_t totp = truncated_hash % 1000000;

    char *result = malloc(7);
    if (!result) return NULL;
    snprintf(result, 7, "%06u", totp);

    return result;
}

char* generate_totp_code(const char *base32_secret) {
    return generate_totp_code_at_time(base32_secret, time(NULL));
}
