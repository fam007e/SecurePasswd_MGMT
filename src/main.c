#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "encryption.h"
#include "csv_handler.h"
#include "totp.h"
#include "utils.h"
#include "version.h"

static char program_name[256];

void print_version(void) {
    printf("%s\n", VERSION);
}

void print_help(void) {
    printf("SecurePassManager v%s\n", VERSION);
    printf("A secure command-line password manager with TOTP support\n\n");
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --version  Show version information\n");
    printf("  help           Show this help message\n\n");
    printf("Features:\n");
    printf("  • Secure password storage with AES-256 encryption\n");
    printf("  • Two-factor authentication (TOTP) support\n");
    printf("  • Import/Export functionality\n");
    printf("  • Local storage for maximum privacy\n\n");
    printf("For more information, visit: https://github.com/fam007e/SecurePasswd_MGMT\n");
}

void ensure_data_directory(void) {
    struct stat st = {0};
    
    if (stat("data", &st) == -1) {
        if (mkdir("data", 0700) != 0) {
            printf("Error: Cannot create data directory\n");
            exit(1);
        }
    }
}

void generate_salt(char *salt_hex) {
    unsigned char salt[16];
    if (RAND_bytes(salt, 16) != 1) {
        printf("Error: Failed to generate random salt\n");
        exit(1);
    }
    
    // Convert to hex string
    for (int i = 0; i < 16; i++) {
        sprintf(salt_hex + (i * 2), "%02x", salt[i]);
    }
    salt_hex[32] = '\0';
}

void generate_password_hash(const char *password, const char *salt_hex, char *hash_hex) {
    unsigned char salt[16];
    unsigned char hash[32];
    
    // Convert hex salt back to bytes
    for (int i = 0; i < 16; i++) {
        sscanf(salt_hex + (i * 2), "%2hhx", &salt[i]);
    }
    
    // Use PBKDF2 with 10000 iterations
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 16, 10000, EVP_sha256(), 32, hash) != 1) {
        printf("Error: Failed to generate password hash\n");
        exit(1);
    }
    
    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(hash_hex + (i * 2), "%02x", hash[i]);
    }
    hash_hex[64] = '\0';
}

int setup_master_password(const char *password) {
    printf("Setting up master password for first time...\n");
    
    char salt_hex[33];
    char hash_hex[65];
    
    generate_salt(salt_hex);
    generate_password_hash(password, salt_hex, hash_hex);
    
    FILE *file = fopen("data/master.key", "w");
    if (!file) {
        printf("Error: Cannot create master password file\n");
        return 0;
    }
    
    fprintf(file, "%s %s\n", hash_hex, salt_hex);
    fclose(file);
    
    printf("Master password set successfully!\n");
    return 1;
}

int validate_master_password(const char *input_password) {
    FILE *file = fopen("data/master.key", "r");
    if (!file) {
        // First time setup - create master password
        return setup_master_password(input_password);
    }
    
    char stored_hash[65];
    char salt[33];
    
    if (fscanf(file, "%64s %32s", stored_hash, salt) != 2) {
        fclose(file);
        printf("Error: Corrupted master password file\n");
        return 0;
    }
    fclose(file);
    
    // Generate hash from input password with stored salt
    char input_hash[65];
    generate_password_hash(input_password, salt, input_hash);
    
    // Compare hashes
    return (strcmp(stored_hash, input_hash) == 0);
}

void add_password_entry(const char *master_password) {
    char account[256], username[256], password[256];
    
    printf("\n=== Add New Password ===\n");
    
    printf("Enter account name: ");
    fflush(stdout);
    if (!fgets(account, sizeof(account), stdin)) {
        printf("Error reading account name\n");
        return;
    }
    account[strcspn(account, "\n")] = 0;
    
    if (strlen(account) == 0) {
        printf("Account name cannot be empty\n");
        return;
    }
    
    printf("Enter username: ");
    fflush(stdout);
    if (!fgets(username, sizeof(username), stdin)) {
        printf("Error reading username\n");
        return;
    }
    username[strcspn(username, "\n")] = 0;
    
    if (strlen(username) == 0) {
        printf("Username cannot be empty\n");
        return;
    }
    
    printf("Enter password: ");
    fflush(stdout);
    hide_input();
    if (!fgets(password, sizeof(password), stdin)) {
        show_input();
        printf("\nError reading password\n");
        return;
    }
    show_input();
    printf("\n");
    password[strcspn(password, "\n")] = 0;
    
    if (strlen(password) == 0) {
        printf("Password cannot be empty\n");
        return;
    }
    
    // Encrypt and store password
    char encrypted_password[512];
    if (encrypt_password(password, master_password, encrypted_password)) {
        if (store_password(account, username, encrypted_password)) {
            printf("Password added successfully!\n");
        } else {
            printf("Error storing password\n");
        }
    } else {
        printf("Error encrypting password\n");
    }
    
    // Clear sensitive data
    memset(password, 0, sizeof(password));
    memset(encrypted_password, 0, sizeof(encrypted_password));
}

void search_password_menu(const char *master_password) {
    char account[256];
    
    printf("\n=== Search Password ===\n");
    printf("Enter account name to search: ");
    fflush(stdout);
    
    if (!fgets(account, sizeof(account), stdin)) {
        printf("Error reading account name\n");
        return;
    }
    account[strcspn(account, "\n")] = 0;
    
    if (strlen(account) == 0) {
        printf("Account name cannot be empty\n");
        return;
    }
    
    search_password(account, master_password);
}

void generate_totp_menu(void) {
    char account[256];
    
    printf("\n=== Generate TOTP Code ===\n");
    printf("Enter account name: ");
    fflush(stdout);
    
    if (!fgets(account, sizeof(account), stdin)) {
        printf("Error reading account name\n");
        return;
    }
    account[strcspn(account, "\n")] = 0;
    
    if (strlen(account) == 0) {
        printf("Account name cannot be empty\n");
        return;
    }
    
    generate_totp(account);
}

void add_totp_menu(void) {
    char account[256], secret[256];
    
    printf("\n=== Add TOTP Account ===\n");
    printf("Enter account name: ");
    fflush(stdout);
    
    if (!fgets(account, sizeof(account), stdin)) {
        printf("Error reading account name\n");
        return;
    }
    account[strcspn(account, "\n")] = 0;
    
    if (strlen(account) == 0) {
        printf("Account name cannot be empty\n");
        return;
    }
    
    printf("Enter TOTP secret: ");
    fflush(stdout);
    hide_input();
    if (!fgets(secret, sizeof(secret), stdin)) {
        show_input();
        printf("\nError reading secret\n");
        return;
    }
    show_input();
    printf("\n");
    secret[strcspn(secret, "\n")] = 0;
    
    if (strlen(secret) == 0) {
        printf("TOTP secret cannot be empty\n");
        return;
    }
    
    if (add_totp_account(account, secret)) {
        printf("TOTP account added successfully!\n");
    } else {
        printf("Error adding TOTP account\n");
    }
    
    // Clear sensitive data
    memset(secret, 0, sizeof(secret));
}

void export_passwords_menu(const char *master_password) {
    char filename[256];
    
    printf("\n=== Export Passwords ===\n");
    printf("Enter filename to export to: ");
    fflush(stdout);
    
    if (!fgets(filename, sizeof(filename), stdin)) {
        printf("Error reading filename\n");
        return;
    }
    filename[strcspn(filename, "\n")] = 0;
    
    if (strlen(filename) == 0) {
        printf("Filename cannot be empty\n");
        return;
    }
    
    if (export_passwords(filename, master_password)) {
        printf("Passwords exported successfully to %s\n", filename);
    } else {
        printf("Error exporting passwords\n");
    }
}

void import_passwords_menu(const char *master_password) {
    char filename[256];
    
    printf("\n=== Import Passwords ===\n");
    printf("Enter filename to import from: ");
    fflush(stdout);
    
    if (!fgets(filename, sizeof(filename), stdin)) {
        printf("Error reading filename\n");
        return;
    }
    filename[strcspn(filename, "\n")] = 0;
    
    if (strlen(filename) == 0) {
        printf("Filename cannot be empty\n");
        return;
    }
    
    if (import_passwords(filename, master_password)) {
        printf("Passwords imported successfully from %s\n", filename);
    } else {
        printf("Error importing passwords\n");
    }
}

void print_menu(void) {
    printf("\nSecurePassManager Menu:\n");
    printf("1. Add new password\n");
    printf("2. Search for password\n");
    printf("3. Generate TOTP code\n");
    printf("4. Add new TOTP account\n");
    printf("5. Export passwords\n");
    printf("6. Import passwords\n");
    printf("7. Exit\n");
    printf("Enter your choice: ");
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    // Store program name
    strncpy(program_name, argv[0], sizeof(program_name) - 1);
    program_name[sizeof(program_name) - 1] = '\0';
    
    // Handle command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
            print_help();
            return 0;
        } else if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
            print_version();
            return 0;
        }
    }
    
    // Ensure data directory exists
    ensure_data_directory();
    
    printf("Welcome to SecurePassManager\n");
    
    char master_password[256];
    printf("Enter master password: ");
    fflush(stdout);
    
    // Hide password input
    hide_input();
    if (!fgets(master_password, sizeof(master_password), stdin)) {
        show_input();
        printf("\nError reading password\n");
        return 1;
    }
    show_input();
    printf("\n");
    
    // Remove newline
    master_password[strcspn(master_password, "\n")] = 0;
    
    // Validate master password
    if (!validate_master_password(master_password)) {
        printf("Incorrect master password. Access denied.\n");
        // Clear password from memory
        memset(master_password, 0, sizeof(master_password));
        return 1;
    }
    
    printf("Access granted!\n");
    
    int choice;
    char input[10];
    
    while (1) {
        print_menu();
        
        if (!fgets(input, sizeof(input), stdin)) {
            printf("Error reading input\n");
            continue;
        }
        
        choice = atoi(input);
        
        switch (choice) {
            case 1:
                add_password_entry(master_password);
                break;
            case 2:
                search_password_menu(master_password);
                break;
            case 3:
                generate_totp_menu();
                break;
            case 4:
                add_totp_menu();
                break;
            case 5:
                export_passwords_menu(master_password);
                break;
            case 6:
                import_passwords_menu(master_password);
                break;
            case 7:
                printf("Exiting SecurePassManager. Goodbye!\n");
                // Clear master password from memory
                memset(master_password, 0, sizeof(master_password));
                return 0;
            default:
                printf("Invalid choice. Please enter a number between 1 and 7.\n");
                break;
        }
    }
    
    return 0;
}