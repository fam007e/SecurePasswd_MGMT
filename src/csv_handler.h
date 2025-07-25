#ifndef CSV_HANDLER_H
#define CSV_HANDLER_H

/**
 * Store a password entry in the CSV file
 * @param account The account name
 * @param username The username
 * @param encrypted_password The encrypted password
 * @return 1 on success, 0 on failure
 */
int store_password(const char *account, const char *username, const char *encrypted_password);

/**
 * Search for a password entry and display it (decrypted)
 * @param account_name The account name to search for
 * @param master_password The master password for decryption
 */
void search_password(const char *account_name, const char *master_password);

/**
 * List all stored account names
 */
void list_all_accounts(void);

/**
 * Export all passwords to a CSV file (decrypted)
 * @param filename The output filename
 * @param master_password The master password for decryption
 * @return 1 on success, 0 on failure
 */
int export_passwords(const char *filename, const char *master_password);

/**
 * Import passwords from a CSV file
 * @param filename The input filename
 * @param master_password The master password for encryption
 * @return 1 on success, 0 on failure
 */
int import_passwords(const char *filename, const char *master_password);

/**
 * Delete a password entry
 * @param account_name The account name to delete
 * @return 1 on success, 0 on failure
 */
int delete_password(const char *account_name);

#endif // CSV_HANDLER_H