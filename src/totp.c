#include "totp.h"
#include "encryption.h"
#include "csv_handler.h"
#include <liboath/oath.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TOTP_DIGITS 6
#define TOTP_STEP 30

char* generate_totp(const char* secret) {
    char otp[TOTP_DIGITS + 1];
    time_t now = time(NULL);
    oath_totp_generate(secret, strlen(secret), now, TOTP_STEP, 0, TOTP_DIGITS, otp);
    return strdup(otp);
}

int setup_totp(const char* account, const char* secret) {
    return write_password(account, "", "", secret);
}

char* generate_totp_for_account(const char* account) {
    char** passwords = read_passwords();
    if (!passwords) return NULL;

    char* totp = NULL;
    for (int i = 0; passwords[i] != NULL; i++) {
        char* line = strdup(passwords[i]);
        char* curr_account = strtok(line, ",");
        strtok(NULL, ","); // username
        strtok(NULL, ","); // password
        char* encrypted_secret = strtok(NULL, ",");

        if (strcmp(account, curr_account) == 0 && encrypted_secret) {
            char* decrypted_secret = decrypt_password(encrypted_secret);
            if (decrypted_secret) {
                totp = generate_totp(decrypted_secret);
                free(decrypted_secret);
            }
            free(line);
            break;
        }
        free(line);
    }

    // Free memory
    for (int i = 0; passwords[i] != NULL; i++) {
        free(passwords[i]);
    }
    free(passwords);

    return totp;
}