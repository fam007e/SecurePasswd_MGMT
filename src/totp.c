#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include "totp.h"

#define TOTP_FILE "data/totp.csv"

// Base32 alphabet
static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int validate_base32_secret(const char *secret) {
    if (!secret || strlen(secret) == 0) {
        return 0;
    }
    
    size_t len = strlen(secret);
    for (size_t i = 0; i < len; i++) {
        char c = toupper(secret[i]);
        if (!strchr(base32_alphabet, c)) {
            return 0;
        }
    }
    
    return 1;
}

int base32_decode(const char *base32_input, unsigned char *binary_output, size_t *output_length) {
    if (!base32_input || !binary_output || !output_length) {
        return 0;
    }
    
    size_t input_len = strlen(base32_input);
    if (input_len == 0) {
        *output_length = 0;
        return 1;
    }
    
    // Remove padding and calculate output length
    while (input_len > 0 && base32_input[input_len - 1] == '=') {
        input_len--;
    }
    
    *output_length = (input_len * 5) / 8;
    
    int bits = 0;
    int value = 0;
    size_t output_pos = 0;
    
    for (size_t i = 0; i < input_len; i++) {
        char c = toupper(base32_input[i]);
        const char *pos = strchr(base32_alphabet, c);
        
        if (!pos) {
            return 0; // Invalid character
        }
        
        value = (value << 5) | (pos - base32_alphabet);
        bits += 5;
        
        if (bits >= 8) {
            binary_output[output_pos++] = (value >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    
    return 1;
}

uint64_t get_current_timestamp(void) {
    return (uint64_t)time(NULL);
}

int get_totp_remaining_seconds(void) {
    time_t now = time(NULL);
    return TOTP_INTERVAL - (now % TOTP_INTERVAL);
}

// Convert uint64_t to big-endian bytes
void uint64_to_bytes(uint64_t value, unsigned char *bytes) {
    for (int i = 7; i >= 0; i--) {
        bytes[i] = value & 0xFF;
        value >>= 8;
    }
}

int generate_totp_code(const char *secret, uint64_t timestamp, char *code) {
    if (!secret || !code) {
        return 0;
    }
    
    // Decode base32 secret
    unsigned char binary_secret[128];
    size_t secret_length;
    
    if (!base32_decode(secret, binary_secret, &secret_length)) {
        return 0;
    }
    
    // Use current time if timestamp is 0
    if (timestamp == 0) {
        timestamp = get_current_timestamp();
    }
    
    // Calculate time counter (30-second intervals)
    uint64_t time_counter = timestamp / TOTP_INTERVAL;
    
    // Convert counter to big-endian bytes
    unsigned char counter_bytes[8];
    uint64_to_bytes(time_counter, counter_bytes);
    
    // Generate HMAC-SHA1
    unsigned char hmac_result[20];
    unsigned int hmac_len;
    
    if (!HMAC(EVP_sha1(), binary_secret, secret_length, counter_bytes, 8, hmac_result, &hmac_len)) {
        return 0;
    }
    
    // Dynamic truncation
    int offset = hmac_result[19] & 0x0F;
    uint32_t binary_code = ((hmac_result[offset] & 0x7F) << 24) |
                          ((hmac_result[offset + 1] & 0xFF) << 16) |
                          ((hmac_result[offset + 2] & 0xFF) << 8) |
                          (hmac_result[offset + 3] & 0xFF);
    
    // Generate 6-digit code
    uint32_t totp_code = binary_code % 1000000;
    
    // Format with leading zeros
    snprintf(code, 7, "%06u", totp_code);
    
    // Clear sensitive data
    memset(binary_secret, 0, sizeof(binary_secret));
    memset(hmac_result, 0, sizeof(hmac_result));
    
    return 1;
}

int add_totp_account(const char *account_name, const char *secret) {
    if (!account_name || !secret) {
        return 0;
    }
    
    // Validate secret
    if (!validate_base32_secret(secret)) {
        printf("Error: Invalid base32 secret\n");
        return 0;
    }
    
    // Check if account already exists
    FILE *file = fopen(TOTP_FILE, "r");
    if (file) {
        char line[512];
        char existing_account[TOTP_ACCOUNT_MAX_LENGTH];
        
        while (fgets(line, sizeof(line), file)) {
            if (sscanf(line, "%255[^,]", existing_account) == 1) {
                if (strcmp(existing_account, account_name) == 0) {
                    fclose(file);
                    printf("Error: Account '%s' already exists\n", account_name);
                    return 0;
                }
            }
        }
        fclose(file);
    }
    
    // Add new account
    file = fopen(TOTP_FILE, "a");
    if (!file) {
        printf("Error: Cannot open TOTP file for writing\n");
        return 0;
    }
    
    // Write account and secret to CSV
    fprintf(file, "%s,%s\n", account_name, secret);
    fclose(file);
    
    return 1;
}

int generate_totp(const char *account_name) {
    if (!account_name) {
        return 0;
    }
    
    FILE *file = fopen(TOTP_FILE, "r");
    if (!file) {
        printf("Error: No TOTP accounts found. Add an account first.\n");
        return 0;
    }
    
    char line[512];
    char stored_account[TOTP_ACCOUNT_MAX_LENGTH];
    char stored_secret[TOTP_SECRET_MAX_LENGTH];
    int found = 0;
    
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Parse CSV line
        char *comma = strchr(line, ',');
        if (!comma) continue;
        
        *comma = '\0';
        strncpy(stored_account, line, sizeof(stored_account) - 1);
        stored_account[sizeof(stored_account) - 1] = '\0';
        
        strncpy(stored_secret, comma + 1, sizeof(stored_secret) - 1);
        stored_secret[sizeof(stored_secret) - 1] = '\0';
        
        if (strcmp(stored_account, account_name) == 0) {
            found = 1;
            break;
        }
    }
    fclose(file);
    
    if (!found) {
        printf("Error: Account '%s' not found\n", account_name);
        return 0;
    }
    
    // Generate TOTP code
    char totp_code[7];
    if (!generate_totp_code(stored_secret, 0, totp_code)) {
        printf("Error: Failed to generate TOTP code\n");
        // Clear sensitive data
        memset(stored_secret, 0, sizeof(stored_secret));
        return 0;
    }
    
    int remaining = get_totp_remaining_seconds();
    printf("\nTOTP Code for '%s': %s\n", account_name, totp_code);
    printf("Valid for %d more seconds\n", remaining);
    
    // Clear sensitive data
    memset(stored_secret, 0, sizeof(stored_secret));
    memset(totp_code, 0, sizeof(totp_code));
    
    return 1;
}

void list_totp_accounts(void) {
    FILE *file = fopen(TOTP_FILE, "r");
    if (!file) {
        printf("No TOTP accounts found.\n");
        return;
    }
    
    char line[512];
    char account[TOTP_ACCOUNT_MAX_LENGTH];
    int count = 0;
    
    printf("\nTOTP Accounts:\n");
    printf("==============\n");
    
    while (fgets(line, sizeof(line), file)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Parse account name (before comma)
        char *comma = strchr(line, ',');
        if (!comma) continue;
        
        *comma = '\0';
        strncpy(account, line, sizeof(account) - 1);
        account[sizeof(account) - 1] = '\0';
        
        printf("%d. %s\n", ++count, account);
    }
    
    if (count == 0) {
        printf("No TOTP accounts found.\n");
    }
    
    fclose(file);
}

int delete_totp_account(const char *account_name) {
    if (!account_name) {
        return 0;
    }
    
    FILE *file = fopen(TOTP_FILE, "r");
    if (!file) {
        printf("Error: No TOTP accounts found\n");
        return 0;
    }
    
    // Read all entries
    char lines[1000][512];
    int line_count = 0;
    char line[512];
    
    while (fgets(line, sizeof(line), file) && line_count < 1000) {
        strcpy(lines[line_count], line);
        line_count++;
    }
    fclose(file);
    
    // Find and remove the account
    int found = 0;
    FILE *temp_file = fopen(TOTP_FILE ".tmp", "w");
    if (!temp_file) {
        printf("Error: Cannot create temporary file\n");
        return 0;
    }
    
    for (int i = 0; i < line_count; i++) {
        char account[TOTP_ACCOUNT_MAX_LENGTH];
        char *comma = strchr(lines[i], ',');
        
        if (comma) {
            *comma = '\0';
            strncpy(account, lines[i], sizeof(account) - 1);
            account[sizeof(account) - 1] = '\0';
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
        if (rename(TOTP_FILE ".tmp", TOTP_FILE) == 0) {
            printf("TOTP account '%s' deleted successfully\n", account_name);
            return 1;
        } else {
            printf("Error: Failed to update TOTP file\n");
            remove(TOTP_FILE ".tmp");
            return 0;
        }
    } else {
        remove(TOTP_FILE ".tmp");
        printf("Error: Account '%s' not found\n", account_name);
        return 0;
    }
}