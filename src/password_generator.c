#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/rand.h>
#include "password_generator.h"

static const char *LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";
static const char *UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *NUMBER_CHARS = "0123456789";
static const char *SPECIAL_CHARS = "!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~";

// Function to generate a cryptographically secure random number in a range [0, max]
static int secure_rand(int max);

// Function to generate a cryptographically secure random number in a range [0, max]
static int secure_rand(int max) {
    if (max <= 0) return 0;
    unsigned int r;
    if (RAND_bytes((unsigned char*)&r, sizeof(r)) != 1) {
        fprintf(stderr, "Error: Failed to generate secure random bytes for password generation.\n");
        exit(EXIT_FAILURE);
    }
    return r % (max + 1);
}

double calculate_entropy(int length, int character_set_size) {
    if (character_set_size <= 0) return 0.0;
    return length * log2(character_set_size);
}

char *generate_password_to_string(int length, int use_case_variance, int use_numbers, int use_special) {
    if (length < 12) {
        return NULL;
    }


    
    
    

    char character_set[256] = {0};
    strcat(character_set, LOWERCASE_CHARS);

    char required_chars[5] = {0};
    int required_chars_count = 0;

    // Add required characters
    required_chars[required_chars_count++] = LOWERCASE_CHARS[secure_rand(strlen(LOWERCASE_CHARS) - 1)];

    if (use_case_variance) {
        strcat(character_set, UPPERCASE_CHARS);
        required_chars[required_chars_count++] = UPPERCASE_CHARS[secure_rand(strlen(UPPERCASE_CHARS) - 1)];
    }
    if (use_numbers) {
        strcat(character_set, NUMBER_CHARS);
        required_chars[required_chars_count++] = NUMBER_CHARS[secure_rand(strlen(NUMBER_CHARS) - 1)];
    }
    if (use_special) {
        strcat(character_set, SPECIAL_CHARS);
        required_chars[required_chars_count++] = SPECIAL_CHARS[secure_rand(strlen(SPECIAL_CHARS) - 1)];
    }

    if (length < required_chars_count) {
        return NULL;
    }

    char *password = (char *)malloc(length + 1);
    if (!password) {
        return NULL;
    }

    // Start with the required characters
    for (int i = 0; i < required_chars_count; i++) {
        password[i] = required_chars[i];
    }

    // Fill the rest of the password with random characters from the full set
    for (int i = required_chars_count; i < length; i++) {
        password[i] = character_set[secure_rand(strlen(character_set) - 1)];
    }

    // Fisher-Yates shuffle
    for (int i = length - 1; i > 0; i--) {
        int j = secure_rand(i);
        char temp = password[i];
        password[i] = password[j];
        password[j] = temp;
    }

    password[length] = '\0';

    return password;
}

void generate_password(int length, int use_case_variance, int use_numbers, int use_special) {
    char *password = generate_password_to_string(length, use_case_variance, use_numbers, use_special);
    if (!password) {
        printf("Error: Password length must be at least 12 characters.\n");
        return;
    }


    
    
    
    char character_set[256] = {0};
    strcat(character_set, LOWERCASE_CHARS);
    if (use_case_variance) strcat(character_set, UPPERCASE_CHARS);
    if (use_numbers) strcat(character_set, NUMBER_CHARS);
    if (use_special) strcat(character_set, SPECIAL_CHARS);

    double entropy = calculate_entropy(length, strlen(character_set));
    printf("Password Entropy: %.2f bits (Higher is stronger)\n", entropy);
    printf("Generated Password: %s\n", password);
    free(password);
}