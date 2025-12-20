#include "database.h"
#include "key_derivation.h"
#include <sqlcipher/sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdbool.h>

static sqlite3 *db = NULL;

// Forward declaration for internal function
static int initialize_schema();

int database_open(const char *db_path, const char *password) {
    uint8_t salt[SALT_LEN];
    uint8_t key[KEY_LEN];

    // Construct salt path
    char salt_path[256];
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path);

    // Load or generate salt
    if (load_or_generate_salt(salt_path, salt) != 0) {
        fprintf(stderr, "Failed to load or generate salt.\n");
        return -1;
    }

    // Derive key
    if (derive_key(password, salt, key) != 0) {
        fprintf(stderr, "Failed to derive key.\n");
        return -1;
    }

    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    if (sqlite3_key(db, key, KEY_LEN) != SQLITE_OK) {
        fprintf(stderr, "Failed to set database key: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        db = NULL;
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    // Test if the key is correct by trying to access the database
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "Invalid key or database file is corrupted.\n");
        sqlite3_close(db);
        db = NULL;
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    sodium_memzero(key, KEY_LEN);
    return initialize_schema();
}

void database_close() {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

PasswordEntry* database_get_all_entries(int *count) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    // First, get the count of entries
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return NULL;
    }
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        *count = 0;
        sqlite3_finalize(stmt);
        return NULL;
    }
    *count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    if (*count == 0) {
        return NULL;
    }

    PasswordEntry *entries = malloc(*count * sizeof(PasswordEntry));
    if (!entries) {
        fprintf(stderr, "Failed to allocate memory for entries\n");
        return NULL;
    }

    // Then, get all the data
    if (sqlite3_prepare_v2(db, "SELECT id, service, username, password, totp_secret, recovery_codes FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        free(entries);
        return NULL;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *service = sqlite3_column_text(stmt, 1);
        const unsigned char *username = sqlite3_column_text(stmt, 2);
        const unsigned char *password = sqlite3_column_text(stmt, 3);
        const unsigned char *totp_secret = sqlite3_column_text(stmt, 4);
        const unsigned char *recovery_codes = sqlite3_column_text(stmt, 5);

        entries[i].service = service ? strdup((const char *)service) : strdup("");
        entries[i].username = username ? strdup((const char *)username) : strdup("");
        entries[i].password = password ? strdup((const char *)password) : strdup("");
        entries[i].totp_secret = totp_secret ? strdup((const char *)totp_secret) : strdup("");
        entries[i].recovery_codes = recovery_codes ? strdup((const char *)recovery_codes) : strdup("");
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

int database_add_entry(const PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes) VALUES (?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return sqlite3_last_insert_rowid(db);
}

int database_update_entry(const PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET service = ?, username = ?, password = ?, totp_secret = ?, recovery_codes = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, entry->id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int database_delete_entry(int id) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM passwords WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    // Check if any rows were actually deleted
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);

    if (changes == 0) {
        return -1; // Entry with this ID does not exist
    }

    return 0;
}

void free_password_entries(PasswordEntry *entries, int count) {
    if (!entries) return;
    for (int i = 0; i < count; i++) {
        free(entries[i].service);
        free(entries[i].username);
        free(entries[i].password);
        free(entries[i].totp_secret);
        free(entries[i].recovery_codes);
    }
    free(entries);
}

static int initialize_schema() {
    char *err_msg = 0;
    const char *sql = "CREATE TABLE IF NOT EXISTS passwords ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                        "service TEXT NOT NULL, "
                        "username TEXT NOT NULL, "
                        "password TEXT NOT NULL, "
                        "totp_secret TEXT, "
                        "recovery_codes TEXT);";
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Migration: Check if recovery_codes column exists, if not add it
    sqlite3_stmt *stmt;
    bool has_recovery_codes = false;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(passwords)", -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 1);
            if (name && strcmp((const char *)name, "recovery_codes") == 0) {
                has_recovery_codes = true;
                break;
            }
        }
        sqlite3_finalize(stmt);
    }

    if (!has_recovery_codes) {
        const char *alter_sql = "ALTER TABLE passwords ADD COLUMN recovery_codes TEXT;";
        if (sqlite3_exec(db, alter_sql, 0, 0, &err_msg) != SQLITE_OK) {
            fprintf(stderr, "Migration error adding recovery_codes: %s\n", err_msg);
            sqlite3_free(err_msg);
        }
    }

    return 0;
}
