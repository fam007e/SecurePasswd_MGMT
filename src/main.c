#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encryption.h"
#include "csv_handler.h"
#include "totp.h"
#include "utils.h"
#include "version.h" 

#define MAX_PASSWORD_LENGTH 128
#define MAX_INPUT_LENGTH 256

void print_menu() {
    printf("\nSecurePassManager Menu:\n");
    printf("1. Add new password\n");
    printf("2. Search for password\n");
    printf("3. Generate TOTP code\n");
    printf("4. Add new TOTP account\n");
    printf("5. Export passwords\n");
    printf("6. Import passwords\n");
    printf("7. Exit\n");
    printf("Enter your choice: ");
}

void print_version() {
    printf("SecurePassManager version %s\n", VERSION);
}

void print_help(const char* program_name) {
    printf("Usage: %s [OPTION]\n", program_name);
    printf("Options:\n");
    printf("  --version     Display version information and exit\n");
    printf("  --help        Display this help message and exit\n");
    printf("\nRun without options to start the interactive SecurePassManager.\n");
}

int main(int argc, char *argv[]) {
    // Check for command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[1], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
    }

    char master_password[MAX_PASSWORD_LENGTH];
    int choice;

    printf("Welcome to SecurePassManager\n");

    // Get master password
    printf("Enter master password: ");
    if (!get_secure_input(master_password, MAX_PASSWORD_LENGTH)) {
        fprintf(stderr, "Error reading master password\n");
        return 1;
    }

    // Initialize encryption with master password
    if (!init_encryption(master_password)) {
        fprintf(stderr, "Failed to initialize encryption\n");
        return 1;
    }

    while (1) {
        print_menu();
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Invalid input\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1: // Add new password
                {
                    char account[MAX_INPUT_LENGTH], username[MAX_INPUT_LENGTH], password[MAX_PASSWORD_LENGTH];
                    printf("Enter account name: ");
                    get_secure_input(account, MAX_INPUT_LENGTH);
                    printf("Enter username: ");
                    get_secure_input(username, MAX_INPUT_LENGTH);
                    printf("Enter password: ");
                    get_secure_input(password, MAX_PASSWORD_LENGTH);

                    if (write_password(account, username, password, NULL)) {
                        printf("Password added successfully\n");
                    } else {
                        fprintf(stderr, "Failed to add password\n");
                    }
                }
                break;
            case 2: // Search for password
                {
                    char account[MAX_INPUT_LENGTH];
                    printf("Enter account name to search: ");
                    get_secure_input(account, MAX_INPUT_LENGTH);
                    char **result = read_passwords();
                    if (result) {
                        int found = 0;
                        for (int i = 0; result[i] != NULL; i++) {
                            if (strstr(result[i], account) != NULL) {
                                printf("Found: %s\n", result[i]);
                                found = 1;
                            }
                            free(result[i]);
                        }
                        free(result);
                        if (!found) {
                            printf("Account not found\n");
                        }
                    } else {
                        printf("No passwords found or error occurred\n");
                    }
                }
                break;
            case 3: // Generate TOTP code
                {
                    char account[MAX_INPUT_LENGTH];
                    printf("Enter TOTP account name: ");
                    get_secure_input(account, MAX_INPUT_LENGTH);
                    char *totp = generate_totp_for_account(account);
                    if (totp) {
                        printf("TOTP code: %s\n", totp);
                        free(totp);
                    } else {
                        fprintf(stderr, "Failed to generate TOTP code\n");
                    }
                }
                break;
            case 4: // Add new TOTP account
                {
                    char account[MAX_INPUT_LENGTH], secret[MAX_INPUT_LENGTH];
                    printf("Enter TOTP account name: ");
                    get_secure_input(account, MAX_INPUT_LENGTH);
                    printf("Enter TOTP secret: ");
                    get_secure_input(secret, MAX_INPUT_LENGTH);
                    if (setup_totp(account, secret)) {
                        printf("TOTP account added successfully\n");
                    } else {
                        fprintf(stderr, "Failed to add TOTP account\n");
                    }
                }
                break;
            case 5: // Export passwords
                {
                    char filename[MAX_INPUT_LENGTH];
                    printf("Enter export filename: ");
                    get_secure_input(filename, MAX_INPUT_LENGTH);
                    if (export_passwords(filename)) {
                        printf("Passwords exported successfully\n");
                    } else {
                        fprintf(stderr, "Failed to export passwords\n");
                    }
                }
                break;
            case 6: // Import passwords
                {
                    char filename[MAX_INPUT_LENGTH];
                    printf("Enter import filename: ");
                    get_secure_input(filename, MAX_INPUT_LENGTH);
                    if (import_passwords(filename)) {
                        printf("Passwords imported successfully\n");
                    } else {
                        fprintf(stderr, "Failed to import passwords\n");
                    }
                }
                break;
            case 7: // Exit
                printf("Exiting SecurePassManager. Goodbye!\n");
                cleanup_encryption();
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
