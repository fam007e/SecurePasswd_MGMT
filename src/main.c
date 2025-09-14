#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "securepass_core.h"

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// This should be defined in a version header, but defining here for now
#ifndef VERSION
#define VERSION "1.1.0-refactor"
#endif

static char program_name[256];

void print_version(void) {
    printf("%s\n", TOSTRING(VERSION));
}

void print_help(void) {
    printf("SecurePassManager v%s\n", TOSTRING(VERSION));
    printf("A secure command-line password manager with TOTP support\n\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -h, --help             Show this help message\n");
    printf("  -v, --version          Show version information\n");
    printf("  --generate-password    Generate a new password\n");
    printf("  -l, --length <num>     Set password length (default: 12)\n");
    printf("  -c, --case-variance    Include uppercase letters in password\n");
    printf("  -n, --numbers          Include numbers in password\n");
    printf("  -s, --special          Include special characters in password\n\n");
    printf("For more information, visit: https://github.com/fam007e/SecurePasswd_MGMT\n");
}

void interactive_menu(const char *master_password);

int main(int argc, char *argv[]) {
    strncpy(program_name, argv[0], sizeof(program_name) - 1);
    program_name[sizeof(program_name) - 1] = '\0';

    int generate_password_flag = 0;
    int password_length = 12;
    int include_uppercase = 0;
    int include_numbers = 0;
    int include_special = 0;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"generate-password", no_argument, 0, 0},
        {"length", required_argument, 0, 'l'},
        {"case-variance", no_argument, 0, 'c'},
        {"numbers", no_argument, 0, 'n'},
        {"special", no_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    int opt, long_index = 0;
    while ((opt = getopt_long(argc, argv, "hvl:cns", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'h': print_help(); exit(EXIT_SUCCESS);
            case 'v': print_version(); exit(EXIT_SUCCESS);
            case 0: 
                if (strcmp("generate-password", long_options[long_index].name) == 0) {
                    generate_password_flag = 1;
                }
                break;
            case 'l': password_length = atoi(optarg); break;
            case 'c': include_uppercase = 1; break;
            case 'n': include_numbers = 1; break;
            case 's': include_special = 1; break;
            default: print_help(); exit(EXIT_FAILURE);
        }
    }

    if (generate_password_flag) {
        char *generated_password = securepass_generate_password(password_length, include_uppercase, include_numbers, include_special);
        if (generated_password) {
            printf("Generated Password: %s\n", generated_password);
            free(generated_password); // securepass_generate_password allocates memory
        } else {
            fprintf(stderr, "Failed to generate password.\n");
            exit(EXIT_FAILURE);
        }
        exit(EXIT_SUCCESS);
    }

    securepass_init_data_dir();
    securepass_ensure_data_directory();

    char master_password[MAX_PASSWORD_LEN];
    printf("Enter Master Password: ");
    if (!securepass_get_hidden_input(master_password, sizeof(master_password))) {
        fprintf(stderr, "Failed to read master password.\n");
        exit(EXIT_FAILURE);
    }

    if (!securepass_validate_master_password(master_password)) {
        fprintf(stderr, "Master password validation failed. Exiting.\n");
        securepass_secure_zero(master_password, sizeof(master_password));
        exit(EXIT_FAILURE);
    }

    interactive_menu(master_password);

    securepass_secure_zero(master_password, sizeof(master_password));
    exit(EXIT_SUCCESS);
}

void add_password_entry_interactive(const char *master_password);
void search_password_entry_interactive(const char *master_password);
void generate_totp_code_interactive(const char *master_password);
void add_totp_account_interactive(const char *master_password);
void export_passwords_interactive(const char *master_password);
void import_passwords_interactive(const char *master_password);

void interactive_menu(const char *master_password) {
    char choice_str[10];
    int choice;

    while (1) {
        securepass_clear_screen();
        printf("SecurePassManager Menu:\n");
        printf("1. Add new password\n");
        printf("2. Search for password\n");
        printf("3. Generate TOTP code\n");
        printf("4. Add new TOTP account\n");
        printf("5. Export passwords\n");
        printf("6. Import passwords\n");
        printf("7. Exit\n");
        printf("Enter your choice: ");

        if (!securepass_get_input_line(choice_str, sizeof(choice_str))) continue;
        choice = atoi(choice_str);

        switch (choice) {
            case 1: add_password_entry_interactive(master_password); break;
            case 2: search_password_entry_interactive(master_password); break;
            case 3: generate_totp_code_interactive(master_password); break;
            case 4: add_totp_account_interactive(master_password); break;
            case 5: export_passwords_interactive(master_password); break;
            case 6: import_passwords_interactive(master_password); break;
            case 7: printf("Exiting SecurePassManager. Goodbye!\n"); return;
            default: printf("Invalid choice. Please try again.\n"); break;
        }
        printf("\nPress Enter to continue...");
        while (getchar() != '\n');
    }
}

void add_password_entry_interactive(const char *master_password) {
    char account[MAX_ACCOUNT_LEN], username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN];
    printf("--- Add New Password ---\n");
    printf("Enter account name: ");
    if (!securepass_get_input_line(account, sizeof(account))) return;
    printf("Enter username: ");
    if (!securepass_get_input_line(username, sizeof(username))) return;
    printf("Enter password: ");
    if (!securepass_get_hidden_input(password, sizeof(password))) return;

    if (securepass_add_password(account, username, password, master_password)) {
        printf("Password added successfully!\n");
    } else {
        printf("Failed to add password.\n");
    }
    securepass_secure_zero(password, sizeof(password));
}

void search_password_entry_interactive(const char *master_password) {
    char account[MAX_ACCOUNT_LEN], decrypted_username[MAX_USERNAME_LEN], decrypted_password[MAX_PASSWORD_LEN];
    printf("--- Search for Password ---\n");
    printf("Enter account name: ");
    if (!securepass_get_input_line(account, sizeof(account))) return;

    if (securepass_get_password(account, master_password, decrypted_username, decrypted_password)) {
        printf("\n--- Account Found ---\n");
        printf("Account:  %s\n", account);
        printf("Username: %s\n", decrypted_username);
        printf("Password: %s\n", decrypted_password);
    } else {
        printf("\nError: Account not found or decryption failed.\n");
    }
    securepass_secure_zero(decrypted_username, sizeof(decrypted_username));
    securepass_secure_zero(decrypted_password, sizeof(decrypted_password));
}

void generate_totp_code_interactive(const char *master_password) {
    char account[MAX_ACCOUNT_LEN], totp_code[10];
    printf("--- Generate TOTP Code ---\n");
    printf("Enter account name for TOTP: ");
    if (!securepass_get_input_line(account, sizeof(account))) return;

    if (securepass_generate_totp(account, master_password, totp_code)) {
        printf("TOTP Code: %s\n", totp_code);
    } else {
        printf("Failed to generate TOTP code. Is there a secret for this account?\n");
    }
}

void add_totp_account_interactive(const char *master_password) {
    char account[MAX_ACCOUNT_LEN], secret_key[100];
    printf("--- Add New TOTP Account ---\n");
    printf("Enter account name: ");
    if (!securepass_get_input_line(account, sizeof(account))) return;
    printf("Enter TOTP secret key: ");
    if (!securepass_get_input_line(secret_key, sizeof(secret_key))) return;

    if (securepass_add_totp(account, secret_key, master_password)) {
        printf("TOTP secret added successfully!\n");
    } else {
        printf("Failed to add TOTP secret.\n");
    }
}

void export_passwords_interactive(const char *master_password) {
    char filepath[256];
    printf("--- Export Passwords to CSV ---\n");
    printf("Enter full path for export file (e.g., /path/to/export.csv): ");
    if (!securepass_get_input_line(filepath, sizeof(filepath))) return;

    if (securepass_export_csv(master_password, filepath)) {
        printf("Passwords exported successfully to %s\n", filepath);
    } else {
        printf("Failed to export passwords.\n");
    }
}

void import_passwords_interactive(const char *master_password) {
    char filepath[256];
    printf("--- Import Passwords from CSV ---\n");
    printf("Enter full path of CSV file to import: ");
    if (!securepass_get_input_line(filepath, sizeof(filepath))) return;

    if (securepass_import_csv(master_password, filepath)) {
        printf("Passwords imported successfully from %s\n", filepath);
    } else {
        printf("Failed to import passwords.\n");
    }
}


