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
#include <time.h>
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

    // Hardening: zero freed pages inside the encrypted file and wipe
    // SQLCipher's heap buffers after use (safe no-ops where unsupported).
    sqlite3_exec(db, "PRAGMA secure_delete = ON;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA cipher_memory_security = ON;", NULL, NULL, NULL);

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

PasswordEntry* database_get_all_entries_full(int *count) {
    if (!db || !count) return NULL;
    *count = 0;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, service, username, password, totp_secret, recovery_codes, updated_at FROM passwords ORDER BY service COLLATE NOCASE ASC, username COLLATE NOCASE ASC";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return NULL;
    }

    int cap = 16, n = 0;
    PasswordEntry *entries = calloc((size_t)cap, sizeof(PasswordEntry));
    if (!entries) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            PasswordEntry *grown = realloc(entries, (size_t)cap * sizeof(PasswordEntry));
            if (!grown) {
                free_password_entries(entries, n);
                sqlite3_finalize(stmt);
                return NULL;
            }
            entries = grown;
            memset(&entries[n], 0, (size_t)(cap - n) * sizeof(PasswordEntry));
        }
        PasswordEntry *e = &entries[n];
        e->id = sqlite3_column_int(stmt, 0);
        const unsigned char *s = sqlite3_column_text(stmt, 1);
        const unsigned char *u = sqlite3_column_text(stmt, 2);
        const unsigned char *p = sqlite3_column_text(stmt, 3);
        const unsigned char *ts = sqlite3_column_text(stmt, 4);
        const unsigned char *rc = sqlite3_column_text(stmt, 5);
        e->service = strdup(s ? (const char *)s : "");
        e->username = strdup(u ? (const char *)u : "");
        e->password = strdup(p ? (const char *)p : "");
        e->totp_secret = strdup(ts ? (const char *)ts : "");
        e->recovery_codes = strdup(rc ? (const char *)rc : "");
        e->updated_at = (long long)sqlite3_column_int64(stmt, 6);
        if (!e->service || !e->username || !e->password || !e->totp_secret || !e->recovery_codes) {
            free_password_entries(entries, n + 1);
            sqlite3_finalize(stmt);
            return NULL;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *count = n;
    return entries;
}

sync_tombstone_t* database_get_tombstones(int *count) {
    if (!db || !count) return NULL;
    *count = 0;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT service, username, deleted_at FROM deleted_entries";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }

    int cap = 8, n = 0;
    sync_tombstone_t *tombstones = calloc((size_t)cap, sizeof(sync_tombstone_t));
    if (!tombstones) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            sync_tombstone_t *grown = realloc(tombstones, (size_t)cap * sizeof(sync_tombstone_t));
            if (!grown) {
                sync_tombstones_free(tombstones, n);
                sqlite3_finalize(stmt);
                return NULL;
            }
            tombstones = grown;
        }
        const unsigned char *s = sqlite3_column_text(stmt, 0);
        const unsigned char *u = sqlite3_column_text(stmt, 1);
        tombstones[n].service = strdup(s ? (const char *)s : "");
        tombstones[n].username = strdup(u ? (const char *)u : "");
        tombstones[n].deleted_at = (int64_t)sqlite3_column_int64(stmt, 2);
        if (!tombstones[n].service || !tombstones[n].username) {
            sync_tombstones_free(tombstones, n + 1);
            sqlite3_finalize(stmt);
            return NULL;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *count = n;
    return tombstones;
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
    if (!db || !entry) return -1;

    // Re-adding an identity that was previously deleted on this device
    // must clear the tombstone so the entry survives the next sync.
    sqlite3_stmt *tomb_stmt;
    const char *tomb_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = LOWER(?) AND LOWER(username) = LOWER(?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &tomb_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(tomb_stmt, 1, entry->service ? entry->service : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(tomb_stmt, 2, entry->username ? entry->username : "", -1, SQLITE_TRANSIENT);
        sqlite3_step(tomb_stmt);
        sqlite3_finalize(tomb_stmt);
    }

    long long now = entry->updated_at > 0 ? entry->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO passwords (service, username, password, totp_secret, recovery_codes, updated_at) VALUES (?, ?, ?, ?, ?, ?);";
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
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);

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
    if (!db || !entry) return -1;

    long long now = entry->updated_at > 0 ? entry->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE passwords SET service = ?, username = ?, password = ?, totp_secret = ?, recovery_codes = ?, updated_at = ? WHERE id = ?;";
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
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 7, entry->id);

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

    // Record a deletion tombstone first so the removal can propagate
    // during 2-way sync instead of looking like a missing entry.
    sqlite3_stmt *stmt;
    const char *identity_sql = "SELECT service, username FROM passwords WHERE id = ?;";
    if (sqlite3_prepare_v2(db, identity_sql, -1, &stmt, NULL) != SQLITE_OK) {
        fputs("Failed to prepare statement: ", stderr);
        fputs(sqlite3_errmsg(db), stderr);
        fputs("\n", stderr);
        return -1;
    }
    sqlite3_bind_int(stmt, 1, id);

    char service[512] = {0}; // flawfinder: ignore
    char username[512] = {0}; // flawfinder: ignore
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *s = sqlite3_column_text(stmt, 0);
        const unsigned char *u = sqlite3_column_text(stmt, 1);
        if (s) snprintf(service, sizeof(service), "%s", (const char *)s); // flawfinder: ignore
        if (u) snprintf(username, sizeof(username), "%s", (const char *)u); // flawfinder: ignore
    }
    sqlite3_finalize(stmt);

    if (service[0] == '\0') {
        return -1; // Entry with this ID does not exist
    }

    const char *tomb_sql = "INSERT INTO deleted_entries (service, username, deleted_at) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, service, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time(NULL));
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

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

    sqlite3_finalize(stmt);
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

    // Migration: updated_at column for sync causality. When the column is
    // first added, backfill every existing row so it participates in merges.
    sqlite3_stmt *stmt3;
    bool has_updated_at = false;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(passwords)", -1, &stmt3, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt3) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt3, 1);
            if (name && strcmp((const char *)name, "updated_at") == 0) {
                has_updated_at = true;
                break;
            }
        }
        sqlite3_finalize(stmt3);
    }

    if (!has_updated_at) {
        const char *alter_sql = "ALTER TABLE passwords ADD COLUMN updated_at INTEGER DEFAULT 0;";
        if (sqlite3_exec(db, alter_sql, 0, 0, &err_msg) != SQLITE_OK) {
            fputs("Migration error adding updated_at: ", stderr);
            fputs(err_msg, stderr);
            fputs("\n", stderr);
            sqlite3_free(err_msg);
        } else {
            const char *backfill_sql =
                "UPDATE passwords SET updated_at = CAST(strftime('%s', 'now') AS INTEGER) WHERE updated_at = 0;";
            if (sqlite3_exec(db, backfill_sql, 0, 0, &err_msg) != SQLITE_OK) {
                fputs("Migration error backfilling updated_at: ", stderr);
                fputs(err_msg, stderr);
                fputs("\n", stderr);
                sqlite3_free(err_msg);
            }
        }
    }

    // Deletion tombstones: remember which identities were removed and when,
    // so 2-way sync can propagate deletions instead of resurrecting entries.
    const char *tombstone_sql = "CREATE TABLE IF NOT EXISTS deleted_entries ("
                                 "service TEXT NOT NULL, "
                                 "username TEXT NOT NULL, "
                                 "deleted_at INTEGER NOT NULL);";
    if (sqlite3_exec(db, tombstone_sql, 0, 0, &err_msg) != SQLITE_OK) {
        fputs("SQL error (deleted_entries): ", stderr);
        fputs(err_msg, stderr);
        fputs("\n", stderr);
        sqlite3_free(err_msg);
        return -1;
    }

    // OpenPGP key store (labels are unique merge identities).
    const char *gpg_sql = "CREATE TABLE IF NOT EXISTS gpg_keys ("
                           "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                           "label TEXT NOT NULL, "
                           "email TEXT, "
                           "key_id TEXT, "
                           "public_key TEXT, "
                           "private_key TEXT, "
                           "updated_at INTEGER DEFAULT 0);";
    if (sqlite3_exec(db, gpg_sql, 0, 0, &err_msg) != SQLITE_OK) {
        fputs("SQL error (gpg_keys): ", stderr);
        fputs(err_msg, stderr);
        fputs("\n", stderr);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

/* ---------------------- OpenPGP key store CRUD ---------------------- */

int database_gpg_add(const GpgKey *key) {
    if (!db || !key || !key->label || key->label[0] == '\0') return -1;

    // Re-adding an identity that was deleted on this device must clear
    // the tombstone so the key survives the next sync.
    sqlite3_stmt *tomb_stmt;
    const char *tomb_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = 'gpg' AND LOWER(username) = LOWER(?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &tomb_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(tomb_stmt, 1, key->label, -1, SQLITE_TRANSIENT);
        sqlite3_step(tomb_stmt);
        sqlite3_finalize(tomb_stmt);
    }

    long long now = key->updated_at > 0 ? key->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO gpg_keys (label, email, key_id, public_key, private_key, updated_at) VALUES (?, ?, ?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key->label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, key->key_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, key->public_key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, key->private_key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int database_gpg_update(const GpgKey *key) {
    if (!db || !key || key->id <= 0) return -1;

    long long now = key->updated_at > 0 ? key->updated_at : (long long)time(NULL);

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE gpg_keys SET label = ?, email = ?, key_id = ?, public_key = ?, private_key = ?, updated_at = ? WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, key->label, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, key->email, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, key->key_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, key->public_key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, key->private_key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)now);
    sqlite3_bind_int(stmt, 7, key->id);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

int database_gpg_delete(int id) {
    if (!db || id <= 0) return -1;

    sqlite3_stmt *stmt;
    const char *sel = "SELECT label FROM gpg_keys WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sel, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, id);
    char label[512] = {0}; // flawfinder: ignore
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *l = sqlite3_column_text(stmt, 0);
        if (l) snprintf(label, sizeof(label), "%s", (const char *)l); // flawfinder: ignore
    }
    sqlite3_finalize(stmt);

    if (label[0] == '\0') return -1;

    // Tombstone with service "GPG" so deletions propagate during sync.
    sqlite3_stmt *tomb_stmt;
    const char *tomb_sql = "DELETE FROM deleted_entries WHERE LOWER(service) = 'gpg' AND LOWER(username) = LOWER(?);"
                            "INSERT INTO deleted_entries (service, username, deleted_at) VALUES ('GPG', ?, ?);";
    if (sqlite3_prepare_v2(db, tomb_sql, -1, &tomb_stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(tomb_stmt, 1, label, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(tomb_stmt, 2, label, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(tomb_stmt, 3, (sqlite3_int64)time(NULL));
        sqlite3_step(tomb_stmt);
        sqlite3_finalize(tomb_stmt);
    }

    const char *sql = "DELETE FROM gpg_keys WHERE id = ?;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, id);
    int rc = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

GpgKey* database_gpg_get_all(int *count) {
    if (!db || !count) return NULL;
    *count = 0;

    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, label, email, key_id, public_key, private_key, updated_at FROM gpg_keys ORDER BY label COLLATE NOCASE ASC;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return NULL;

    int cap = 8, n = 0;
    GpgKey *keys = calloc((size_t)cap, sizeof(GpgKey));
    if (!keys) {
        sqlite3_finalize(stmt);
        return NULL;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (n == cap) {
            cap *= 2;
            GpgKey *grown = realloc(keys, (size_t)cap * sizeof(GpgKey));
            if (!grown) {
                database_gpg_free(keys, n);
                sqlite3_finalize(stmt);
                return NULL;
            }
            keys = grown;
        }
        GpgKey *k = &keys[n];
        k->id = sqlite3_column_int(stmt, 0);
        const unsigned char *label = sqlite3_column_text(stmt, 1);
        const unsigned char *email = sqlite3_column_text(stmt, 2);
        const unsigned char *key_id = sqlite3_column_text(stmt, 3);
        const unsigned char *pub = sqlite3_column_text(stmt, 4);
        const unsigned char *priv = sqlite3_column_text(stmt, 5);
        k->label = strdup(label ? (const char *)label : "");
        k->email = strdup(email ? (const char *)email : "");
        k->key_id = strdup(key_id ? (const char *)key_id : "");
        k->public_key = strdup(pub ? (const char *)pub : "");
        k->private_key = strdup(priv ? (const char *)priv : "");
        k->updated_at = (long long)sqlite3_column_int64(stmt, 6);
        if (!k->label || !k->email || !k->key_id || !k->public_key || !k->private_key) {
            database_gpg_free(keys, n + 1);
            sqlite3_finalize(stmt);
            return NULL;
        }
        n++;
    }

    sqlite3_finalize(stmt);
    *count = n;
    return keys;
}

void database_gpg_free(GpgKey *keys, int count) {
    if (!keys) return;
    for (int i = 0; i < count; i++) {
        sodium_memzero(keys[i].private_key,
                       keys[i].private_key ? strlen(keys[i].private_key) : 0);
        free(keys[i].label);
        free(keys[i].email);
        free(keys[i].key_id);
        free(keys[i].public_key);
        free(keys[i].private_key);
    }
    free(keys);
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
