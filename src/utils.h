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
void clear_screen(void);

/**
 * Generate a secure random password
 * @param password Buffer to store generated password
 * @param length Length of password to generate
 * @param include_symbols Whether to include special symbols
 * @return 1 on success, 0 on failure
 */
int generate_random_password(char *password, int length, int include_symbols);

/**
 * Validate password strength
 * @param password The password to validate
 * @return Strength score (0-4: weak to very strong)
 */
int check_password_strength(const char *password);

/**
 * Secure memory clearing
 * @param ptr Pointer to memory to clear
 * @param size Size of memory to clear
 */
void secure_memset(void *ptr, size_t size);

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

#endif // UTILS_H