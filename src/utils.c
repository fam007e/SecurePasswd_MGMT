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

void securepass_clear_screen(void) {
    printf("\033[2J\033[H");
    fflush(stdout);
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

int securepass_get_input_line(char *buffer, size_t size) {
    if (fgets(buffer, size, stdin) != NULL) {
        // Remove trailing newline character if present
        buffer[strcspn(buffer, "\n")] = '\0';
        return 1;
    }
    return 0;
}

int securepass_get_hidden_input(char *buffer, size_t size) {
    hide_input();
    int result = securepass_get_input_line(buffer, size);
    show_input();
    printf("\n"); // Newline after hidden input
    return result;
}

// Secure memory clearing function
void securepass_secure_zero(void *ptr, size_t size) {
    if (ptr) {
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        while (size--) {
            *p++ = 0;
        }
    }
}

int secure_strcmp(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    int diff = len1 ^ len2;

    for (size_t i = 0; i < len1 && i < len2; i++) {
        diff |= s1[i] ^ s2[i];
    }

    return diff == 0;
}
