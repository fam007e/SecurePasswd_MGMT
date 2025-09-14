#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>
#include <stddef.h>  // For size_t

#define TOTP_INTERVAL 30  // Standard TOTP time interval in seconds
#define TOTP_DIGITS 6     // Standard TOTP code length
#define TOTP_SECRET_MAX_LENGTH 128
#define TOTP_ACCOUNT_MAX_LENGTH 256

/**
 * Add a new TOTP account with its secret
 * @param account_name The name of the account
 * @param secret The base32-encoded TOTP secret
 * @return 1 on success, 0 on failure
 */
int add_totp_account(const char *account_name, const char *secret, const char *master_password);

/**
 * Generate a TOTP code for a given account
 * @param account_name The name of the account
 * @return 1 on success, 0 on failure (displays code on success)
 */
int generate_totp(const char *account_name, const char *master_password, char *totp_code_out);

/**
 * List all TOTP accounts
 */
void list_totp_accounts(void);

/**
 * Delete a TOTP account
 * @param account_name The name of the account to delete
 * @return 1 on success, 0 on failure
 */
int delete_totp_account(const char *account_name);

/**
 * Validate a base32-encoded secret
 * @param secret The secret to validate
 * @return 1 if valid, 0 if invalid
 */
int validate_base32_secret(const char *secret);

/**
 * Generate TOTP code from secret and timestamp
 * @param secret The base32-encoded secret
 * @param timestamp The current timestamp (or 0 for current time)
 * @param code Buffer to store the generated 6-digit code
 * @return 1 on success, 0 on failure
 */
int generate_totp_code(const char *secret, uint64_t timestamp, char *code);



/**
 * Get remaining seconds until next TOTP code
 * @return Seconds remaining (0-29)
 */
int get_totp_remaining_seconds(void);

#endif // TOTP_H