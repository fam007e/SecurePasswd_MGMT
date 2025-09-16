#include "securepass_core.h"
#include "encryption.h"
#include "csv_handler.h"
#include "totp.h"
#include "password_generator.h"
#include "utils.h"
#include "data_path.h"
#include <sodium.h>
#include <stdlib.h>
#include "csv_parser.h"
#include <stdio.h>
#include <string.h>

#define ENCRYPTED_BUFFER_SIZE (MAX_PASSWORD_LEN * 4)

// --- Password Management ---

int securepass_add_password(const char *account, const char *username, const char *plaintext_password, const char *master_password) {
    char *encrypted_password = (char *)malloc(ENCRYPTED_BUFFER_SIZE);
    if (!encrypted_password) return 0;

    if (!encrypt_password(plaintext_password, master_password, encrypted_password)) {
        free(encrypted_password);
        return 0;
    }

    int result = store_password(account, username, encrypted_password, master_password);
    free(encrypted_password);
    return result;
}

int securepass_get_password(const char *account, const char *master_password, char *decrypted_username_out, char *decrypted_password_out) {
    char *encrypted_username = NULL;
    char *encrypted_password = NULL;

    if (!find_encrypted_entry(account, &encrypted_username, &encrypted_password)) {
        return 0;
    }

    int decrypt_user_ok = decrypt_password(encrypted_username, master_password, decrypted_username_out);
    int decrypt_pass_ok = decrypt_password(encrypted_password, master_password, decrypted_password_out);

    free(encrypted_username);
    free(encrypted_password);

    if (!decrypt_user_ok || !decrypt_pass_ok) {
        securepass_secure_zero(decrypted_username_out, MAX_USERNAME_LEN);
        securepass_secure_zero(decrypted_password_out, MAX_PASSWORD_LEN);
        return 0;
    }

    return 1;
}

char *securepass_generate_password(int length, int use_uppercase, int use_numbers, int use_special) {
    return generate_password_to_string(length, use_uppercase, use_numbers, use_special);
}

// --- Initialization and Validation ---

void securepass_init_data_dir(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "CRITICAL: Failed to initialize libsodium!\n");
        exit(EXIT_FAILURE);
    }
    init_data_dir();
}


void securepass_ensure_data_directory(void) {
    ensure_data_directory();
}

int securepass_validate_master_password(const char *master_password) {
    return validate_master_password_argon2(master_password);
}

// --- TOTP Management ---

int securepass_add_totp(const char *account, const char *secret_key, const char *master_password) {
    return add_totp_account(account, secret_key, master_password);
}

int securepass_generate_totp(const char *account, const char *master_password, char *totp_code_out) {
    return generate_totp(account, master_password, totp_code_out);
}

// --- Data Import/Export ---

int securepass_export_csv(const char *master_password, const char *filepath) {
    return export_passwords(filepath, master_password);
}

int securepass_import_csv(const char *master_password, const char *filepath) {
    return import_passwords(filepath, master_password);
}

// --- Migration ---

int securepass_migrate_data(const char *master_password) {
    printf("Starting data migration. This may take a while...\n");

    const char *passwords_file = get_passwords_path();
    char tmp_passwords_file[512];
    snprintf(tmp_passwords_file, sizeof(tmp_passwords_file), "%s.tmp", passwords_file);

    CsvData *old_data = parse_csv(passwords_file);
    if (!old_data) {
        printf("No password data found to migrate. Upgrading master key only.\n");
        Argon2Params params = get_default_argon2_params();
        return setup_master_password_argon2(master_password, &params);
    }

    FILE *tmp_file = fopen(tmp_passwords_file, "w");
    if (!tmp_file) {
        fprintf(stderr, "Error: Could not create temporary migration file.\n");
        free_csv_data(old_data);
        return 0;
    }

    int migration_ok = 1;
    for (int i = 0; i < old_data->num_rows; i++) {
        if (old_data->rows[i].num_fields < 3) continue; // Skip malformed rows

        char *account = old_data->rows[i].fields[0];
        char *old_encrypted_user = old_data->rows[i].fields[1];
        char *old_encrypted_pass = old_data->rows[i].fields[2];

        char plaintext_user[MAX_USERNAME_LEN];
        char plaintext_pass[MAX_PASSWORD_LEN];

        if (!decrypt_password_old(old_encrypted_user, master_password, plaintext_user) || 
            !decrypt_password_old(old_encrypted_pass, master_password, plaintext_pass)) {
            fprintf(stderr, "Error: Failed to decrypt old data for account '%s'. Wrong master password? Aborting.\n", account);
            migration_ok = 0;
            break;
        }

        char new_encrypted_user[ENCRYPTED_BUFFER_SIZE];
        char new_encrypted_pass[ENCRYPTED_BUFFER_SIZE];

        if (!encrypt_password(plaintext_user, master_password, new_encrypted_user) || 
            !encrypt_password(plaintext_pass, master_password, new_encrypted_pass)) {
            fprintf(stderr, "Error: Failed to re-encrypt data for account '%s'. Aborting.\n", account);
            migration_ok = 0;
            break;
        }

        // Write new encrypted data to tmp file
        fprintf(tmp_file, "%s,%s,%s\n", account, new_encrypted_user, new_encrypted_pass);

        securepass_secure_zero(plaintext_user, sizeof(plaintext_user));
        securepass_secure_zero(plaintext_pass, sizeof(plaintext_pass));
    }

    free_csv_data(old_data);
    fclose(tmp_file);

    if (!migration_ok) {
        remove(tmp_passwords_file); // Clean up temp file
        return 0;
    }

    // Now, upgrade the master key file
    printf("Upgrading master key file...\n");
    Argon2Params params = get_default_argon2_params();
    if (!setup_master_password_argon2(master_password, &params)) {
        fprintf(stderr, "CRITICAL: Failed to upgrade master key file after data migration!\n");
        remove(tmp_passwords_file);
        return 0;
    }

    // Finally, replace the old passwords file with the new one
    if (rename(tmp_passwords_file, passwords_file) != 0) {
        fprintf(stderr, "CRITICAL: Failed to replace old password file with migrated data!\n");
        return 0;
    }

    printf("Data migration completed successfully!\n");
    return 1;
}