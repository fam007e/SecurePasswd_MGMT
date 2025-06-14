#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "csv_handler.h"
#include "encryption.h"

#define PASSWORDS_FILE "data/passwords.csv"
#define MAX_LINE_LENGTH 2048
#define MAX_FIELD_LENGTH 512

// Helper function to escape CSV fields
static void escape_csv_field(const char *input, char *output, size_t output_size) {
    size_t i = 0, j = 0;
    int needs_quotes = 0;
    
    // Check if field needs quotes
    if (strchr(input, ',') || strchr(input, '"') || strchr(input, '\n')) {
        needs_quotes = 1;
    }
    
    if (needs_quotes && j < output_size - 1) {
        output[j++] = '"';
    }
    
    while (input[i] && j < output_size - 2) {
        if (input[i] == '"' && needs_quotes) {
            output[j++] = '"'; // Escape quote with double quote
        }
        output[j++] = input[i++];
    }
    
    if (needs_quotes && j < output_size - 1) {
        output[j++] = '"';
    }
    
    output[j] = '\0';
}

// Helper function to unescape CSV field
static void unescape_csv_field(const char *input, char *output, size_t output_size) {
    size_t i = 0, j = 0;
    int in_quotes = 0;
    
    if (input[0] == '"') {
        in_quotes = 1;
        i = 1; // Skip first quote
    }
    
    while (input[i] && j < output_size - 1) {
        if (in_quotes && input[i] == '"') {
            if (input[i + 1] == '"') {
                // Double quote - add single quote to output
                output[j++] = '"';
                i += 2;
            } else {
                // End quote
                break;
            }
        } else {
            output[j++] = input[i++];
        }
    }
    
    output[j] = '\0';
}

int store_password(const char *account, const char *username, const char *encrypted_password) {
    if (!account || !username || !encrypted_password) {
        return 0;
    }
    
    // Check if account already exists
    FILE *file = fopen(PASSWORDS_FILE, "r");
    if (file) {
        char line[MAX_LINE_LENGTH];
        char existing_account[MAX_FIELD_LENGTH];
        
        while (fgets(line, sizeof(line), file)) {
            // Parse account name (first field)
            char *comma = strchr(line, ',');
            if (comma) {
                *comma = '\0';
                unescape_csv_field(line, existing_account, sizeof(existing_account));
                *comma = ',';
                
                if (strcmp(existing_account, account) == 0) {
                    fclose(file);
                    printf("Error: Account '%s' already exists\n", account);
                    return 0;
                }
            }
        }
        fclose(file);
    }
    
    // Add new entry
    file = fopen(PASSWORDS_FILE, "a");
    if (!file) {
        printf("Error: Cannot open passwords file for writing\n");
        return 0;
    }
    
    // Escape fields for CSV
    char escaped_account[MAX_FIELD_LENGTH * 2];
    char escaped_username[MAX_FIELD_LENGTH * 2];
    char escaped_password[MAX_FIELD_LENGTH * 2];
    
    escape_csv_field(account, escaped_account, sizeof(escaped_account));
    escape_csv_field(username, escaped_username, sizeof(escaped_username));
    escape_csv_field(encrypted_password, escaped_password, sizeof(escaped_password));
    
    fprintf(file, "%s,%s,%s\n", escaped_account, escaped_username, escaped_password);
    fclose(file);
    
    return 1;
}

void search_password(const char *account_name, const char *master_password) {
    if (!account_name || !master_password) {
        return;
    }
    
    FILE *file = fopen(PASSWORDS_FILE, "r");
    if (!file) {
        printf("Error: No passwords found. Add a password first.\n");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    char stored_account[MAX_FIELD_LENGTH];
    char stored_username[MAX_FIELD_LENGTH];
    char stored_password[MAX_FIELD_LENGTH];
    int found = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Parse CSV line manually
        char *fields[3];
        char *current = line;
        int field_count = 0;
        
        for (int i = 0; i < 3 && current && field_count < 3; i++) {
            char *next_comma = NULL;
            
            if (current[0] == '"') {
                // Quoted field
                current++; // Skip opening quote
                char *end_quote = current;
                while ((end_quote = strchr(end_quote, '"')) != NULL) {
                    if (end_quote[1] == '"') {
                        // Escaped quote
                        end_quote += 2;
                    } else {
                        // End of field
                        break;
                    }
                }
                
                if (end_quote) {
                    *end_quote = '\0';
                    next_comma = strchr(end_quote + 1, ',');
                }
            } else {
                // Unquoted field
                next_comma = strchr(current, ',');
                if (next_comma) {
                    *next_comma = '\0';
                }
            }
            
            fields[field_count++] = current;
            current = next_comma ? next_comma + 1 : NULL;
        }
        
        if (field_count >= 3) {
            unescape_csv_field(fields[0], stored_account, sizeof(stored_account));
            unescape_csv_field(fields[1], stored_username, sizeof(stored_username));
            unescape_csv_field(fields[2], stored_password, sizeof(stored_password));
            
            if (strcmp(stored_account, account_name) == 0) {
                found = 1;
                break;
            }
        }
    }
    fclose(file);
    
    if (!found) {
        printf("Error: Account '%s' not found\n", account_name);
        return;
    }
    
    // Decrypt password
    char decrypted_password[MAX_FIELD_LENGTH];
    if (decrypt_password(stored_password, master_password, decrypted_password)) {
        printf("\nAccount: %s\n", stored_account);
        printf("Username: %s\n", stored_username);
        printf("Password: %s\n", decrypted_password);
        
        // Clear decrypted password
        memset(decrypted_password, 0, sizeof(decrypted_password));
    } else {
        printf("Error: Failed to decrypt password\n");
    }
}

void list_all_accounts(void) {
    FILE *file = fopen(PASSWORDS_FILE, "r");
    if (!file) {
        printf("No accounts found.\n");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    char account[MAX_FIELD_LENGTH];
    int count = 0;
    
    printf("\nStored Accounts:\n");
    printf("===============\n");
    
    while (fgets(line, sizeof(line), file)) {
        // Parse account name (first field)
        char *comma = strchr(line, ',');
        if (comma) {
            *comma = '\0';
            unescape_csv_field(line, account, sizeof(account));
            printf("%d. %s\n", ++count, account);
        }
    }
    
    if (count == 0) {
        printf("No accounts found.\n");
    }
    
    fclose(file);
}

int export_passwords(const char *filename, const char *master_password) {
    if (!filename || !master_password) {
        return 0;
    }
    
    FILE *input_file = fopen(PASSWORDS_FILE, "r");
    if (!input_file) {
        printf("Error: No passwords to export\n");
        return 0;
    }
    
    FILE *output_file = fopen(filename, "w");
    if (!output_file) {
        fclose(input_file);
        printf("Error: Cannot create export file\n");
        return 0;
    }
    
    // Write CSV header
    fprintf(output_file, "Account,Username,Password\n");
    
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), input_file)) {
        line[strcspn(line, "\n")] = 0;
        
        // Parse encrypted entry
        char *fields[3];
        char *current = line;
        int field_count = 0;
        
        // Simple CSV parsing (same as in search_password)
        for (int i = 0; i < 3 && current && field_count < 3; i++) {
            char *next_comma = strchr(current, ',');
            if (next_comma) {
                *next_comma = '\0';
            }
            fields[field_count++] = current;
            current = next_comma ? next_comma + 1 : NULL;
        }
        
        if (field_count >= 3) {
            char account[MAX_FIELD_LENGTH];
            char username[MAX_FIELD_LENGTH];
            char encrypted_password[MAX_FIELD_LENGTH];
            char decrypted_password[MAX_FIELD_LENGTH];
            
            unescape_csv_field(fields[0], account, sizeof(account));
            unescape_csv_field(fields[1], username, sizeof(username));
            unescape_csv_field(fields[2], encrypted_password, sizeof(encrypted_password));
            
            if (decrypt_password(encrypted_password, master_password, decrypted_password)) {
                char escaped_account[MAX_FIELD_LENGTH * 2];
                char escaped_username[MAX_FIELD_LENGTH * 2];
                char escaped_password[MAX_FIELD_LENGTH * 2];
                
                escape_csv_field(account, escaped_account, sizeof(escaped_account));
                escape_csv_field(username, escaped_username, sizeof(escaped_username));
                escape_csv_field(decrypted_password, escaped_password, sizeof(escaped_password));
                
                fprintf(output_file, "%s,%s,%s\n", escaped_account, escaped_username, escaped_password);
                
                // Clear decrypted password
                memset(decrypted_password, 0, sizeof(decrypted_password));
            }
        }
    }
    
    fclose(input_file);
    fclose(output_file);
    return 1;
}

int import_passwords(const char *filename, const char *master_password) {
    if (!filename || !master_password) {
        return 0;
    }
    
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open import file\n");
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_number = 0;
    int imported_count = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        line[strcspn(line, "\n")] = 0;
        
        // Skip header line
        if (line_number == 1 && (strstr(line, "Account") || strstr(line, "account"))) {
            continue;
        }
        
        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }
        
        // Parse CSV line
        char *fields[3];
        char *current = line;
        int field_count = 0;
        
        for (int i = 0; i < 3 && current && field_count < 3; i++) {
            char *next_comma = strchr(current, ',');
            if (next_comma) {
                *next_comma = '\0';
            }
            fields[field_count++] = current;
            current = next_comma ? next_comma + 1 : NULL;
        }
        
        if (field_count >= 3) {
            char account[MAX_FIELD_LENGTH];
            char username[MAX_FIELD_LENGTH];
            char password[MAX_FIELD_LENGTH];
            
            unescape_csv_field(fields[0], account, sizeof(account));
            unescape_csv_field(fields[1], username, sizeof(username));
            unescape_csv_field(fields[2], password, sizeof(password));
            
            // Encrypt password
            char encrypted_password[MAX_FIELD_LENGTH];
            if (encrypt_password(password, master_password, encrypted_password)) {
                if (store_password(account, username, encrypted_password)) {
                    imported_count++;
                }
            }
            
            // Clear sensitive data
            memset(password, 0, sizeof(password));
            memset(encrypted_password, 0, sizeof(encrypted_password));
        }
    }
    
    fclose(file);
    printf("Successfully imported %d passwords\n", imported_count);
    return (imported_count > 0);
}

int delete_password(const char *account_name) {
    if (!account_name) {
        return 0;
    }
    
    FILE *file = fopen(PASSWORDS_FILE, "r");
    if (!file) {
        printf("Error: No passwords found\n");
        return 0;
    }
    
    // Read all lines
    char lines[1000][MAX_LINE_LENGTH];
    int line_count = 0;
    char line[MAX_LINE_LENGTH];
    
    while (fgets(line, sizeof(line), file) && line_count < 1000) {
        strcpy(lines[line_count], line);
        line_count++;
    }
    fclose(file);
    
    // Find and remove the account
    int found = 0;
    FILE *temp_file = fopen(PASSWORDS_FILE ".tmp", "w");
    if (!temp_file) {
        printf("Error: Cannot create temporary file\n");
        return 0;
    }
    
    for (int i = 0; i < line_count; i++) {
        char account[MAX_FIELD_LENGTH];
        char *comma = strchr(lines[i], ',');
        
        if (comma) {
            *comma = '\0';
            unescape_csv_field(lines[i], account, sizeof(account));
            *comma = ','; // Restore comma
            
            if (strcmp(account, account_name) == 0) {
                found = 1;
                continue; // Skip this line (delete it)
            }
        }
        
        fputs(lines[i], temp_file);
    }
    fclose(temp_file);
    
    if (found) {
        if (rename(PASSWORDS_FILE ".tmp", PASSWORDS_FILE) == 0) {
            printf("Password for '%s' deleted successfully\n", account_name);
            return 1;
        } else {
            printf("Error: Failed to update passwords file\n");
            remove(PASSWORDS_FILE ".tmp");
            return 0;
        }
    } else {
        remove(PASSWORDS_FILE ".tmp");
        printf("Error: Account '%s' not found\n", account_name);
        return 0;
    }
}