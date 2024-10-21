#include "csv_handler.h"
#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define CSV_FILENAME "data/passwords.csv"

int write_password(const char* account, const char* username, const char* password, const char* totp_secret) {
    FILE* file = fopen(CSV_FILENAME, "a");
    if (!file) return 0;

    char* encrypted_password = encrypt_password(password);
    char* encrypted_totp = totp_secret ? encrypt_password(totp_secret) : NULL;

    if (!encrypted_password) {
        fclose(file);
        return 0;
    }

    fprintf(file, "%s,%s,%s,%s\n", account, username, encrypted_password, encrypted_totp ? encrypted_totp : "");

    free(encrypted_password);
    if (encrypted_totp) free(encrypted_totp);
    fclose(file);
    return 1;
}

char** read_passwords() {
    FILE* file = fopen(CSV_FILENAME, "r");
    if (!file) return NULL;

    char** passwords = NULL;
    char line[MAX_LINE_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), file)) {
        count++;
        passwords = realloc(passwords, (count + 1) * sizeof(char*));
        if (!passwords) {
            fclose(file);
            return NULL;
        }
        passwords[count-1] = strdup(line);
        passwords[count] = NULL;  // Null-terminate the array
    }

    fclose(file);
    return passwords;
}

int import_passwords(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return 0;

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        char* account = strtok(line, ",");
        char* username = strtok(NULL, ",");
        char* password = strtok(NULL, ",");
        char* totp_secret = strtok(NULL, ",");

        if (account && username && password) {
            write_password(account, username, password, totp_secret);
        }
    }

    fclose(file);
    return 1;
}

int export_passwords(const char* filename) {
    char** passwords = read_passwords();
    if (!passwords) return 0;

    FILE* file = fopen(filename, "w");
    if (!file) {
        // Free memory before returning
        for (int i = 0; passwords[i] != NULL; i++) {
            free(passwords[i]);
        }
        free(passwords);
        return 0;
    }

    for (int i = 0; passwords[i] != NULL; i++) {
        char* line = strdup(passwords[i]);
        char* account = strtok(line, ",");
        char* username = strtok(NULL, ",");
        char* encrypted_password = strtok(NULL, ",");
        char* encrypted_totp = strtok(NULL, ",");

        char* decrypted_password = decrypt_password(encrypted_password);
        char* decrypted_totp = encrypted_totp ? decrypt_password(encrypted_totp) : NULL;

        fprintf(file, "%s,%s,%s,%s\n", account, username, decrypted_password, decrypted_totp ? decrypted_totp : "");

        free(line);
        free(decrypted_password);
        if (decrypted_totp) free(decrypted_totp);
    }

    fclose(file);

    // Free memory
    for (int i = 0; passwords[i] != NULL; i++) {
        free(passwords[i]);
    }
    free(passwords);

    return 1;
}