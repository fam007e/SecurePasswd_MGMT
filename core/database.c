#ifdef _WIN32
#include <windows.h>
#endif
#include "database.h"
#include "key_derivation.h"
#ifdef HAVE_SQLCIPHER_SUBDIR
  #include <sqlcipher/sqlite3.h>
#elif defined(HAVE_SQLCIPHER_HEADER)
  #include <sqlcipher.h>
#else
  #include <sqlite3.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>

static sqlite3 *db = NULL;
static char current_db_path[4096] = {0}; // flawfinder: ignore

// Forward declaration for internal function
static int initialize_schema();


int database_open(const char *db_path, const char *password) {
    if (!db_path) {
        return -1;
    }

    if (db) {
        sqlite3_close_v2(db);
        db = NULL;
    }

    snprintf(current_db_path, sizeof(current_db_path), "%s", db_path); // flawfinder: ignore

    uint8_t salt[SALT_LEN];
    uint8_t key[KEY_LEN];

    // Construct salt path
    char salt_path[4128]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", db_path); // flawfinder: ignore

    // Load or generate salt
    if (load_or_generate_salt(salt_path, salt) != 0) {
        fputs("Failed to load or generate salt.\n", stderr);
        return -1;
    }

    // Derive key
    if (derive_key(password, salt, key) != 0) {
        fputs("Failed to derive key.\n", stderr);
        return -1;
    }

    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fputs("Cannot open database: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        if (db) {
            sqlite3_close_v2(db);
            db = NULL;
        }
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    if (sqlite3_key(db, key, KEY_LEN) != SQLITE_OK) {
        fputs("Failed to set database key: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        sqlite3_close_v2(db);
        db = NULL;
        sodium_memzero(key, KEY_LEN);
        return -1;
    }

    sodium_memzero(key, KEY_LEN);

    if (initialize_schema() != 0) {
        sqlite3_close_v2(db);
        db = NULL;
        return -1;
    }

    return 0;
}

void database_close() {
    if (db) {
        sqlite3_close_v2(db);
        db = NULL;
        memset(current_db_path, 0, sizeof(current_db_path));
    }
}

PasswordEntry* database_get_all_entries(int *count) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    // First, get the count of entries
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM passwords", -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
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

    PasswordEntry *entries = calloc(*count, sizeof(PasswordEntry));
    if (!entries) {
        fputs("Failed to allocate memory for entries\n", stderr);
        return NULL;
    }

    // Then, get ONLY metadata (id, service, username)
    // Sensitive fields (password, totp, recovery) are intentionally NOT retrieved here.
    if (sqlite3_prepare_v2(db, "SELECT id, service, username FROM passwords ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC", -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        free(entries);
        return NULL;
    }

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < *count) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *service = sqlite3_column_text(stmt, 1);
        const unsigned char *username = sqlite3_column_text(stmt, 2);

        entries[i].service = service ? strdup((const char *)service) : strdup("");
        entries[i].username = username ? strdup((const char *)username) : strdup("");

        // Initialize sensitive fields to NULL/Empty since we didn't fetch them
        entries[i].password = NULL;
        entries[i].totp_secret = NULL;
        entries[i].recovery_codes = NULL;
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

PasswordEntry* database_search(const char *query, int *count) {
    if (!db || !query) return NULL;

    sqlite3_stmt *stmt;
    char like_query[1024]; // flawfinder: ignore
    snprintf(like_query, sizeof(like_query), "%%%s%%", query);

    // Count matching entries
    const char *count_sql = "SELECT COUNT(*) FROM passwords WHERE service LIKE ? OR username LIKE ?";
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare search count statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, like_query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, like_query, -1, SQLITE_TRANSIENT);

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

    PasswordEntry *entries = calloc(*count, sizeof(PasswordEntry));
    if (!entries) {
        fputs("Failed to allocate memory for search results\n", stderr);
        return NULL;
    }

    // Get matching metadata
    const char *search_sql = "SELECT id, service, username FROM passwords WHERE service LIKE ? OR username LIKE ? ORDER BY service COLLATE NOCASE ASC";
    if (sqlite3_prepare_v2(db, search_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare search statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        free(entries);
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, like_query, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, like_query, -1, SQLITE_TRANSIENT);

    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < *count) {
        entries[i].id = sqlite3_column_int(stmt, 0);
        const unsigned char *service = sqlite3_column_text(stmt, 1);
        const unsigned char *username = sqlite3_column_text(stmt, 2);

        entries[i].service = service ? strdup((const char *)service) : strdup("");
        entries[i].username = username ? strdup((const char *)username) : strdup("");

        entries[i].password = NULL;
        entries[i].totp_secret = NULL;
        entries[i].recovery_codes = NULL;
        i++;
    }

    sqlite3_finalize(stmt);
    return entries;
}

PasswordEntry* database_get_entry_by_identity(const char *service, const char *username) {
    if (!db || !service || !username) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes FROM passwords WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?)";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    PasswordEntry *entry = calloc(1, sizeof(PasswordEntry));
    if (!entry) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    entry->id = sqlite3_column_int(stmt, 0);
    const unsigned char *s = sqlite3_column_text(stmt, 1);
    const unsigned char *u = sqlite3_column_text(stmt, 2);
    const unsigned char *p = sqlite3_column_text(stmt, 3);
    const unsigned char *ts = sqlite3_column_text(stmt, 4);
    const unsigned char *rc = sqlite3_column_text(stmt, 5);

    entry->service = s ? strdup((const char *)s) : strdup("");
    entry->username = u ? strdup((const char *)u) : strdup("");
    entry->password = p ? strdup((const char *)p) : strdup("");
    entry->totp_secret = ts ? strdup((const char *)ts) : strdup("");
    entry->recovery_codes = rc ? strdup((const char *)rc) : strdup("");

    sqlite3_finalize(stmt);
    return entry;
}

PasswordEntry* database_get_entry_secure(int id) {
    if (!db) return NULL;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes FROM passwords WHERE id = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL; // Not found
    }

    PasswordEntry *entry = calloc(1, sizeof(PasswordEntry));
    if (!entry) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    entry->id = sqlite3_column_int(stmt, 0);
    const unsigned char *service = sqlite3_column_text(stmt, 1);
    const unsigned char *username = sqlite3_column_text(stmt, 2);
    const unsigned char *password = sqlite3_column_text(stmt, 3);
    const unsigned char *totp_secret = sqlite3_column_text(stmt, 4);
    const unsigned char *recovery_codes = sqlite3_column_text(stmt, 5);

    entry->service = service ? strdup((const char *)service) : strdup("");
    entry->username = username ? strdup((const char *)username) : strdup("");
    entry->password = password ? strdup((const char *)password) : strdup("");
    entry->totp_secret = totp_secret ? strdup((const char *)totp_secret) : strdup("");
    entry->recovery_codes = recovery_codes ? strdup((const char *)recovery_codes) : strdup("");

    sqlite3_finalize(stmt);
    return entry;
}

int database_add_entry(const PasswordEntry *entry) {
    if (!db) return -1;

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes) VALUES (?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fputs("Failed to execute statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
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
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, entry->service, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->username, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->totp_secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, entry->recovery_codes, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, entry->id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fputs("Failed to execute statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
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
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fputs("Failed to execute statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
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
                        "recovery_codes TEXT,"
                        "pwned_count INTEGER DEFAULT -1);";
    if (sqlite3_exec(db, sql, 0, 0, &err_msg) != SQLITE_OK) {
        fputs("SQL error: ", stderr);
        fputs(err_msg, stderr);
        fputs("\n", stderr);
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
            fputs("Migration error adding recovery_codes: ", stderr);
            fputs(err_msg, stderr);
            fputs("\n", stderr);
            sqlite3_free(err_msg);
        }
    }

    // Migration: Check if pwned_count column exists
    sqlite3_stmt *stmt2;
    bool has_pwned_count = false;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(passwords)", -1, &stmt2, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt2) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt2, 1);
            if (name && strcmp((const char *)name, "pwned_count") == 0) {
                has_pwned_count = true;
                break;
            }
        }
        sqlite3_finalize(stmt2);
    }

    if (!has_pwned_count) {
        const char *alter_sql = "ALTER TABLE passwords ADD COLUMN pwned_count INTEGER DEFAULT -1;";
        if (sqlite3_exec(db, alter_sql, 0, 0, &err_msg) != SQLITE_OK) {
            fputs("Migration error adding pwned_count: ", stderr);
            fputs(err_msg, stderr);
            fputs("\n", stderr);
            sqlite3_free(err_msg);
        }
    }

    return 0;
}

int database_rekey(const char *new_password) {
    if (!db || current_db_path[0] == '\0') {
        return -1;
    }

    uint8_t new_salt[SALT_LEN];
    uint8_t new_key[KEY_LEN];

    // Generate new salt
    if (sodium_init() < 0) return -1;
    randombytes_buf(new_salt, SALT_LEN);

    // Derive new key
    if (derive_key(new_password, new_salt, new_key) != 0) {
        return -1;
    }

    // Attempt SQLCipher rekey
    if (sqlite3_rekey(db, new_key, KEY_LEN) != SQLITE_OK) {
        fputs("Failed to rekey database: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        sodium_memzero(new_key, KEY_LEN);
        return -1;
    }

    sodium_memzero(new_key, KEY_LEN);

    // SQLCipher rekey succeeded, now update the salt file
    char salt_path[4128]; // flawfinder: ignore
    char salt_path_new[4128]; // flawfinder: ignore
    snprintf(salt_path, sizeof(salt_path), "%s.salt", current_db_path); // flawfinder: ignore
    snprintf(salt_path_new, sizeof(salt_path_new), "%s.salt.new", current_db_path); // flawfinder: ignore

    // Atomic-ish swap: write to .new then rename
    if (save_salt(salt_path_new, new_salt) != 0) {
        fprintf(stderr, "Failed to save new salt to %s\n", salt_path_new);
        return -1;
    }

#ifdef _WIN32
    if (!MoveFileExA(salt_path_new, salt_path, MOVEFILE_REPLACE_EXISTING)) {
#else
    if (rename(salt_path_new, salt_path) != 0) {
#endif
        fputs("Failed to rename new salt file.\n", stderr);
        return -1;
    }

    return 0;
}
