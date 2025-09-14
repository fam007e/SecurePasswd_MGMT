#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>  // For size_t

/**
 * Hide terminal input (for password entry)
 */
void hide_input(void);

/**
 * Show terminal input (restore normal input)
 */
void show_input(void);

/**
 * Clear screen
 */
void securepass_clear_screen(void);

/**
 * Validate password strength
 * @param password The password to validate
 * @return Strength score (0-4: weak to very strong)
 */
int check_password_strength(const char *password);

/**
 * Check if file exists
 * @param filename Path to file
 * @return 1 if exists, 0 if not
 */
int file_exists(const char *filename);

/**
 * Get user confirmation (y/n)
 * @param prompt The prompt message
 * @return 1 for yes, 0 for no
 */
int get_user_confirmation(const char *prompt);

/**
 * Securely compare two strings in constant time
 * @param s1 The first string
 * @param s2 The second string
 * @return 1 if the strings are equal, 0 otherwise
 */
int secure_strcmp(const char *s1, const char *s2);

/**
 * Reads a line of input from stdin.
 * @param buffer The buffer to store the input.
 * @param size The size of the buffer.
 * @return 1 on success, 0 on failure.
 */
int securepass_get_input_line(char *buffer, size_t size);

/**
 * Reads hidden input from stdin (e.g., for passwords).
 * @param buffer The buffer to store the input.
 * @param size The size of the buffer.
 * @return 1 on success, 0 on failure.
 */
int securepass_get_hidden_input(char *buffer, size_t size);

/**
 * Securely clears a memory region.
 * @param ptr Pointer to the memory region.
 * @param size Size of the memory region in bytes.
 */
void securepass_secure_zero(void *ptr, size_t size);

#endif // UTILS_H