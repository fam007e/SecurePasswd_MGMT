#include <oath.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include "totp.h"
#include "encryption.h"
#include "csv_parser.h"
#include "../lib/base32.h"

#define TOTP_FILE "data/otp.dat"

uint64_t get_current_timestamp(void) {
    return (uint64_t)time(NULL);
}

int get_totp_remaining_seconds(void) {
    time_t now = time(NULL);
    return TOTP_INTERVAL - (now % TOTP_INTERVAL);
}

int generate_totp_code(const char *secret, uint64_t timestamp, char *code) {
    if (!secret || !code) {
        return 0;
    }

    size_t decoded_secret_len; // Declare here
    char *decoded_secret_buf = NULL;
    size_t decoded_secret_len_val = 0;
    int decoded_len_ret = oath_base32_decode(secret, strlen(secret), &decoded_secret_buf, &decoded_secret_len_val);

    if (decoded_len_ret <= 0 || decoded_secret_buf == NULL) {
        fprintf(stderr, "Error: oath_base32_decode() failed.\n");
        return 0;
    }
    uint8_t *decoded_secret = (uint8_t *)decoded_secret_buf;
    decoded_secret_len = decoded_secret_len_val;

    time_t now = timestamp;
    if (now == 0) {
        now = time(NULL);
    }


    int ret = oath_init();
    if (ret != OATH_OK) {
        fprintf(stderr, "Error: oath_init() failed: %s\n", oath_strerror(ret));
        free(decoded_secret);
        return 0;
    }

    ret = oath_totp_generate((const char *)decoded_secret, decoded_secret_len, now, OATH_TOTP_DEFAULT_TIME_STEP_SIZE, OATH_TOTP_DEFAULT_START_TIME, 6, code);
    if (ret != OATH_OK) {
        fprintf(stderr, "Error: oath_totp_generate() failed: %s\n", oath_strerror(ret));
        free(decoded_secret);
        oath_done();
        return 0;
    }

    free(decoded_secret);
    oath_done();
    return 1;
}

int add_totp_account(const char *account_name, const char *secret, const char *master_password) {
    if (!account_name || !secret || !master_password) {
        return 0;
    }

    CsvData *csv_data = parse_csv(TOTP_FILE);
    if (csv_data) {
        for (int i = 0; i < csv_data->num_rows; i++) {
            if (csv_data->rows[i].num_fields > 0 && strcmp(csv_data->rows[i].fields[0], account_name) == 0) {
                printf("Error: Account '%s' already exists\n", account_name);
                free_csv_data(csv_data);
                return 0;
            }
        }
        free_csv_data(csv_data);
    }

    char encrypted_secret[512];
    if (!encrypt_password(secret, master_password, encrypted_secret)) {
        printf("Error: Failed to encrypt TOTP secret\n");
        return 0;
    }

    const char *row[] = {account_name, encrypted_secret};
    return append_csv_row(TOTP_FILE, row, 2);
}

int generate_totp(const char *account_name, const char *master_password, char *totp_code_out) {
    if (!account_name || !master_password || !totp_code_out) {
        return 0;
    }

    CsvData *csv_data = parse_csv(TOTP_FILE);
    if (!csv_data) {
        return 0;
    }

    int found = 0;
    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields >= 2 && strcmp(csv_data->rows[i].fields[0], account_name) == 0) {
            char decrypted_secret[TOTP_SECRET_MAX_LENGTH];
            if (!decrypt_password(csv_data->rows[i].fields[1], master_password, decrypted_secret)) {
                found = -1; // Indicate decryption failure
                break;
            }

            if (!generate_totp_code(decrypted_secret, 0, totp_code_out)) {
                memset(decrypted_secret, 0, sizeof(decrypted_secret));
                found = -1; // Indicate generation failure
                break;
            }

            memset(decrypted_secret, 0, sizeof(decrypted_secret));
            found = 1;
            break;
        }
    }

    free_csv_data(csv_data);
    return (found == 1);
}

int validate_base32_secret(const char *secret) {
    if (!secret) {
        return 0;
    }
    size_t decoded_len; // Declare here
    char *decoded_secret_buf = NULL;
    size_t decoded_len_val = 0;
    int decoded_len_ret = oath_base32_decode(secret, strlen(secret), &decoded_secret_buf, &decoded_len_val);

    if (decoded_len_ret <= 0 || decoded_secret_buf == NULL) {
        return 0; // Decoding failed, so it's not a valid base32 secret
    }
    uint8_t *decoded_secret = (uint8_t *)decoded_secret_buf;
    decoded_len = decoded_len_val;
    free(decoded_secret);
    return 1; // Decoding successful, so it's a valid base32 secret
}

void list_totp_accounts(void) {
    CsvData *csv_data = parse_csv(TOTP_FILE);
    if (!csv_data || csv_data->num_rows == 0) {
        printf("No TOTP accounts found.\n");
        if (csv_data) {
            free_csv_data(csv_data);
        }
        return;
    }

    printf("\nTOTP Accounts:\n");
    printf("==============\n");

    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields > 0) {
            printf("%d. %s\n", i + 1, csv_data->rows[i].fields[0]);
        }
    }

    free_csv_data(csv_data);
}

int delete_totp_account(const char *account_name) {
    if (!account_name) {
        return 0;
    }

    CsvData *csv_data = parse_csv(TOTP_FILE);
    if (!csv_data) {
        printf("Error: No TOTP accounts found\n");
        return 0;
    }

    int found_index = -1;
    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields > 0 && strcmp(csv_data->rows[i].fields[0], account_name) == 0) {
            found_index = i;
            break;
        }
    }

    if (found_index != -1) {
        // Free the memory for the row being deleted
        for (int j = 0; j < csv_data->rows[found_index].num_fields; j++) {
            free(csv_data->rows[found_index].fields[j]);
        }
        free(csv_data->rows[found_index].fields);

        // Shift subsequent rows up
        for (int i = found_index; i < csv_data->num_rows - 1; i++) {
            csv_data->rows[i] = csv_data->rows[i + 1];
        }
        csv_data->num_rows--;

        if (write_csv_data(TOTP_FILE, csv_data)) {
            printf("TOTP account '%s' deleted successfully\n", account_name);
        } else {
            printf("Error writing to TOTP file\n");
        }
    } else {
        printf("Error: Account '%s' not found\n", account_name);
    }

    free_csv_data(csv_data);
    return (found_index != -1);
}
