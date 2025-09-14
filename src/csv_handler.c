#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csv_handler.h"
#include "csv_parser.h"
#include "encryption.h"

#define PASSWORDS_FILE "data/vault.dat"
#define MAX_FIELD_LENGTH 512

int store_password(const char *account, const char *username, const char *encrypted_password, const char *master_password) {
    if (!account || !username || !encrypted_password || !master_password) {
        return 0;
    }

    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (csv_data) {
        for (int i = 0; i < csv_data->num_rows; i++) {
            if (csv_data->rows[i].num_fields > 0 && strcmp(csv_data->rows[i].fields[0], account) == 0) {
                printf("Error: Account '%s' already exists\n", account);
                free_csv_data(csv_data);
                return 0;
            }
        }
        free_csv_data(csv_data);
    }

    char encrypted_username[MAX_FIELD_LENGTH * 2];
    if (!encrypt_password(username, master_password, encrypted_username)) {
        printf("Error: Failed to encrypt username\n");
        return 0;
    }

    const char *row[] = {account, encrypted_username, encrypted_password};
    return append_csv_row(PASSWORDS_FILE, row, 3);
}

void search_password(const char *account_name, const char *master_password) {
    if (!account_name || !master_password) {
        return;
    }

    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (!csv_data) {
        printf("Error: No passwords found. Add a password first.\n");
        return;
    }

    int found = 0;
    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields >= 3 && strcmp(csv_data->rows[i].fields[0], account_name) == 0) {
            char decrypted_username[MAX_FIELD_LENGTH];
            char decrypted_password[MAX_FIELD_LENGTH];

            if (decrypt_password(csv_data->rows[i].fields[1], master_password, decrypted_username) &&
                decrypt_password(csv_data->rows[i].fields[2], master_password, decrypted_password)) {
                printf("\nAccount: %s\n", csv_data->rows[i].fields[0]);
                printf("Username: %s\n", decrypted_username);
                printf("Password: %s\n", decrypted_password);

                memset(decrypted_username, 0, sizeof(decrypted_username));
                memset(decrypted_password, 0, sizeof(decrypted_password));
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        printf("Error: Account '%s' not found\n", account_name);
    }

    free_csv_data(csv_data);
}

void list_all_accounts(void) {
    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (!csv_data || csv_data->num_rows == 0) {
        printf("No accounts found.\n");
        if (csv_data) {
            free_csv_data(csv_data);
        }
        return;
    }

    printf("\nStored Accounts:\n");
    printf("===============\n");

    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields > 0) {
            printf("%d. %s\n", i + 1, csv_data->rows[i].fields[0]);
        }
    }

    free_csv_data(csv_data);
}

int export_passwords(const char *filename, const char *master_password) {
    if (!filename || !master_password) {
        return 0;
    }

    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (!csv_data) {
        printf("Error: No passwords to export\n");
        return 0;
    }

    FILE *output_file = fopen(filename, "w");
    if (!output_file) {
        free_csv_data(csv_data);
        printf("Error: Cannot create export file\n");
        return 0;
    }

    fprintf(output_file, "Account,Username,Password\n");

    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields >= 3) {
            char decrypted_username[MAX_FIELD_LENGTH];
            char decrypted_password[MAX_FIELD_LENGTH];

            if (decrypt_password(csv_data->rows[i].fields[1], master_password, decrypted_username) &&
                decrypt_password(csv_data->rows[i].fields[2], master_password, decrypted_password)) {
                fprintf(output_file, "%s,%s,%s\n", csv_data->rows[i].fields[0], decrypted_username, decrypted_password);
            }
        }
    }

    fclose(output_file);
    free_csv_data(csv_data);
    return 1;
}

int import_passwords(const char *filename, const char *master_password) {
    if (!filename || !master_password) {
        return 0;
    }

    CsvData *import_data = parse_csv(filename);
    if (!import_data) {
        printf("Error: Cannot open import file\n");
        return 0;
    }

    int imported_count = 0;
    for (int i = 0; i < import_data->num_rows; i++) {
        if (import_data->rows[i].num_fields >= 3) {
            // Skip header
            if (i == 0 && (strcmp(import_data->rows[i].fields[0], "Account") == 0 || strcmp(import_data->rows[i].fields[0], "account") == 0)) {
                continue;
            }

            char encrypted_password[MAX_FIELD_LENGTH * 2];
            if (encrypt_password(import_data->rows[i].fields[2], master_password, encrypted_password)) {
                if (store_password(import_data->rows[i].fields[0], import_data->rows[i].fields[1], encrypted_password, master_password)) {
                    imported_count++;
                }
            }
        }
    }

    free_csv_data(import_data);
    printf("Successfully imported %d passwords\n", imported_count);
    return (imported_count > 0);
}

int delete_password(const char *account_name) {
    if (!account_name) {
        return 0;
    }

    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (!csv_data) {
        printf("Error: No passwords found\n");
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

        if (write_csv_data(PASSWORDS_FILE, csv_data)) {
            printf("Password for '%s' deleted successfully\n", account_name);
        } else {
            printf("Error writing to passwords file\n");
            // In a real app, you might want to restore the old data here
        }
    } else {
        printf("Error: Account '%s' not found\n", account_name);
    }

    free_csv_data(csv_data);
    return (found_index != -1);
}

int find_encrypted_entry(const char *account, char **encrypted_username_out, char **encrypted_password_out) {
    if (!account || !encrypted_username_out || !encrypted_password_out) {
        return 0;
    }

    CsvData *csv_data = parse_csv(PASSWORDS_FILE);
    if (!csv_data) {
        return 0; // File not found or empty
    }

    int found = 0;
    for (int i = 0; i < csv_data->num_rows; i++) {
        if (csv_data->rows[i].num_fields >= 3 && strcmp(csv_data->rows[i].fields[0], account) == 0) {
            *encrypted_username_out = strdup(csv_data->rows[i].fields[1]);
            *encrypted_password_out = strdup(csv_data->rows[i].fields[2]);

            if (!*encrypted_username_out || !*encrypted_password_out) {
                // Allocation failed, free any allocated memory
                free(*encrypted_username_out);
                free(*encrypted_password_out);
                *encrypted_username_out = NULL;
                *encrypted_password_out = NULL;
                found = 0; // Indicate failure
            } else {
                found = 1; // Success
            }
            break; // Stop after finding the first match
        }
    }

    free_csv_data(csv_data);
    return found;
}
