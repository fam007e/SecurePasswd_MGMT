#ifndef DATABASE_H
#define DATABASE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int id;
    char *service;
    char *username;
    char *password;
    char *totp_secret;
} PasswordEntry;

// Function to open and initialize the database.
// Returns 0 on success, -1 on error.
int database_open(const char *db_path, const char *password);

// Function to close the database.
void database_close();

// Function to retrieve all password entries.
// The caller is responsible for freeing the returned array and its contents.
PasswordEntry* database_get_all_entries(int *count);

// Function to add a new password entry.
// Returns the ID of the new entry, or -1 on error.
int database_add_entry(const PasswordEntry *entry);

// Function to update an existing password entry.
// Returns 0 on success, -1 on error.
int database_update_entry(const PasswordEntry *entry);

// Function to delete a password entry by its ID.
// Returns 0 on success, -1 on error.
int database_delete_entry(int id);

// Function to free a list of PasswordEntry structs.
void free_password_entries(PasswordEntry *entries, int count);


#ifdef __cplusplus
}
#endif

#endif // DATABASE_H
