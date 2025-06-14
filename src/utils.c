#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include "utils.h"

static struct termios old_terminal;

void hide_input(void) {
    struct termios new_terminal;
    
    // Get current terminal settings
    tcgetattr(STDIN_FILENO, &old_terminal);
    new_terminal = old_terminal;
    
    // Disable echo
    new_terminal.c_lflag &= ~ECHO;
    
    // Apply new settings
    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);
}

void show_input(void) {
    // Restore original terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

void clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
}

int generate_random_password(char *password, int length, int include_symbols) {
    if (!password || length < 4 || length > 255) {
        return 0;
    }
    
    const char lowercase[] = "abcdefghijklmnopqrstuvwxyz";
    const char uppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char digits[] = "0123456789";
    const char symbols[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    char charset[256];
    strcpy(charset, lowercase);
    strcat(charset, uppercase);
    strcat(charset, digits);
    
    if (include_symbols) {
        strcat(charset, symbols);
    }
    
    int charset_len = strlen(charset);
    unsigned char random_bytes[256];
    
    if (RAND_bytes(random_bytes, length) != 1) {
        return 0;
    }
    
    // Ensure at least one character from each category
    password[0] = lowercase[random_bytes[0] % 26];
    password[1] = uppercase[random_bytes[1] % 26];
    password[2] = digits[random_bytes[2] % 10];
    
    int start_pos = 3;
    if (include_symbols && length > 3) {
        password[3] = symbols[random_bytes[3] % strlen(symbols)];
        start_pos = 4;
    }
    
    // Fill the rest randomly
    for (int i = start_pos; i < length; i++) {
        password[i] = charset[random_bytes[i] % charset_len];
    }
    
    password[length] = '\0';
    
    // Shuffle the password
    for (int i = length - 1; i > 0; i--) {
        int j = random_bytes[i] % (i + 1);
        char temp = password[i];
        password[i] = password[j];
        password[j] = temp;
    }
    
    // Clear random bytes
    memset(random_bytes, 0, sizeof(random_bytes));
    
    return 1;
}

int check_password_strength(const char *password) {
    if (!password) return 0;
    
    int length = strlen(password);
    int score = 0;
    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    
    // Check length
    if (length >= 8) score++;
    if (length >= 12) score++;
    
    // Check character types
    for (int i = 0; i < length; i++) {
        if (islower(password[i])) has_lower = 1;
        else if (isupper(password[i])) has_upper = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else has_symbol = 1;
    }
    
    if (has_lower) score++;
    if (has_upper) score++;
    if (has_digit) score++;
    if (has_symbol) score++;
    
    // Maximum score is 6, normalize to 0-4
    return (score * 4) / 6;
}

void secure_memset(void *ptr, size_t size) {
    if (ptr) {
        volatile unsigned char *p = ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

int file_exists(const char *filename) {
    if (!filename) return 0;
    
    struct stat st;
    return (stat(filename, &st) == 0);
}

int get_user_confirmation(const char *prompt) {
    if (!prompt) return 0;
    
    char input[10];
    
    printf("%s (y/n): ", prompt);
    fflush(stdout);
    
    if (fgets(input, sizeof(input), stdin)) {
        return (tolower(input[0]) == 'y');
    }
    
    return 0;
}