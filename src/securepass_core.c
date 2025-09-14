#include "securepass_core.h"
#include "encryption.h"
#include "csv_handler.h"
#include "totp.h"
#include "password_generator.h"
#include "utils.h"
#include "data_path.h"
#include <stdlib.h>
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


