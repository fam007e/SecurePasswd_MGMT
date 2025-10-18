#include "pwned_check.h"
#include <openssl/sha.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Memory struct for libcurl write callback
struct MemoryStruct {
    char *memory;
    size_t size;
};

// libcurl write callback function
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        // out of memory!
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

int is_password_pwned(const char *password) {
    // 1. Calculate SHA-1 hash of the password
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)password, strlen(password), hash);

    char full_hash[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(full_hash + (i * 2), "%02X", hash[i]);
    }
    full_hash[SHA_DIGEST_LENGTH * 2] = 0;

    // 2. Split hash into prefix (5 chars) and suffix
    char prefix[6];
    strncpy(prefix, full_hash, 5);
    prefix[5] = '\0';
    char *suffix = full_hash + 5;

    // 3. Query the HIBP API
    char url[100];
    snprintf(url, sizeof(url), "https://api.pwnedpasswords.com/range/%s", prefix);

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SecurePasswd-MGMT/1.0");

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(chunk.memory);
        return -1; // Network or other error
    }

    // 4. Check response for the hash suffix
    int pwn_count = 0;
    char *line = strtok(chunk.memory, "\r\n");
    while (line) {
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0'; // Split line into hash and count
            if (strcmp(line, suffix) == 0) {
                pwn_count = atoi(colon + 1);
                break;
            }
        }
        line = strtok(NULL, "\r\n");
    }

    free(chunk.memory);
    return pwn_count;
}
