#ifndef DATABASE_H
#define DATABASE_H

#include <stddef.h>
#include "sync_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A struct representing a password entry.
 */
typedef struct {
    int id;             /**< The unique ID of the entry. */
    char *service;      /**< The name of the service. */
    char *username;     /**< The username for the service. */
    char *password;     /**< The password for the service. */
    char *totp_secret;  /**< The TOTP secret for the service. */
    char *recovery_codes; /**< The recovery codes for the service (newline-separated). Used codes are prefixed with '*'. */
    long long updated_at; /**< Unix timestamp of the last local modification (sync causality). */
} PasswordEntry;

/**
 * @brief Opens and initializes the database.
 *
 * @param db_path The path to the database file.
 * @param password The master password for the database.
 * @return 0 on success, -1 on error.
 */
int database_open(const char *db_path, const char *password);

/**
 * @brief Closes the database.
 */
void database_close();

/**
 * @brief Retrieves all password entries from the database.
 *
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs. The caller is responsible for freeing this array and its contents using free_password_entries().
 */
PasswordEntry* database_get_all_entries(int *count);

/**
 * @brief Retrieves all password entries including all fields (secrets and
 *        updated_at). Used by the sync engine; do not use for list views.
 *
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs.
 */
PasswordEntry* database_get_all_entries_full(int *count);

/**
 * @brief Retrieves all deletion tombstones recorded in the database.
 *
 * Tombstones remember which (service, username) pairs were deleted and when,
 * so deletions can propagate during 2-way sync.
 *
 * @param count A pointer to an integer that will be filled with the number of tombstones.
 * @return A dynamically allocated array of sync_tombstone_t structs.
 */
sync_tombstone_t* database_get_tombstones(int *count);

/**
 * @brief OpenPGP key store: armored public/secret keys stored alongside
 *        the passwords. The label is the identity used by 2-way sync;
 *        deletions reuse the deleted_entries tombstone table with
 *        service == "GPG".
 */
typedef struct {
    int id;
    char *label;
    char *email;
    char *key_id;
    char *public_key;   /* ASCII-armored public key */
    char *private_key;  /* ASCII-armored secret key (may be empty) */
    long long updated_at;
} GpgKey;

int database_gpg_add(const GpgKey *key);
int database_gpg_update(const GpgKey *key);
int database_gpg_delete(int id);
GpgKey* database_gpg_get_all(int *count);
void database_gpg_free(GpgKey *keys, int count);

/**
 * @brief Searches for password entries by service or username.
 *
 * @param query The search query string.
 * @param count A pointer to an integer that will be filled with the number of entries.
 * @return A dynamically allocated array of PasswordEntry structs. The caller is responsible for freeing this array and its contents using free_password_entries().
 */
PasswordEntry* database_search(const char *query, int *count);

/**
 * @brief Retrieves a password entry by its identity (Service + Username).
 *
 * @param service The name of the service.
 * @param username The username for the service.
 * @return A dynamically allocated PasswordEntry struct containing full details, or NULL if not found.
 */
PasswordEntry* database_get_entry_by_identity(const char *service, const char *username);

/**
 * @brief Retrieves a single password entry with ALL details (including secrets) by ID.
 *
 * @param id The ID of the entry to retrieve.
 * @return A dynamically allocated PasswordEntry struct containing full details, or NULL if not found/error.
 *         The caller is responsible for freeing this struct using free_password_entry() (to be added) or manual free.
 */
PasswordEntry* database_get_entry_secure(int id);

/**
 * @brief Changes the master password of the database.
 *
 * @param new_password The new master password.
 * @return 0 on success, -1 on error.
 */
int database_rekey(const char *new_password);

/**
 * @brief Adds a new password entry to the database.
 *
 * @param entry A pointer to the PasswordEntry to add.
 * @return The ID of the new entry, or -1 on error.
 */
int database_add_entry(const PasswordEntry *entry);

/**
 * @brief Updates an existing password entry in the database.
 *
 * @param entry A pointer to the PasswordEntry to update.
 * @return 0 on success, -1 on error.
 */
int database_update_entry(const PasswordEntry *entry);

/**
 * @brief Deletes a password entry from the database by its ID.
 *
 * @param id The ID of the entry to delete.
 * @return 0 on success, -1 on error.
 */
int database_delete_entry(int id);

/**
 * @brief Frees a list of PasswordEntry structs.
 *
 * @param entries The array of PasswordEntry structs to free.
 * @param count The number of entries in the array.
 */
void free_password_entries(PasswordEntry *entries, int count);


#ifdef __cplusplus
}
#endif

#endif // DATABASE_H
