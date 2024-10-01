#include "utils.h"
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>

char* get_secure_input(char* buffer, size_t buffer_size) {
    struct termios old, new;

    // Turn off echo
    if (tcgetattr(STDIN_FILENO, &old) != 0)
        return NULL;
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new) != 0)
        return NULL;

    // Read the input
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
        return NULL;
    }

    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);

    // Remove trailing newline
    buffer[strcspn(buffer, "\n")] = 0;

    return buffer;
}

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}