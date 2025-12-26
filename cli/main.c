#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <sodium.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#endif

#ifndef _MSC_VER
#include <termios.h> // For hiding input
#include <unistd.h>  // For STDIN_FILENO

// Custom getpass implementation for Linux/macOS to avoid obsolescence warnings
static char *secure_getpass(const char *prompt) {
    static char password[128];
    struct termios old_t, new_t;

    fputs(prompt, stdout);
    fflush(stdout);

    // Turn off echoing
    if (tcgetattr(STDIN_FILENO, &old_t) != 0) {
        return NULL;
    }
    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_t) != 0) {
        return NULL;
    }

    // Read password
    if (fgets(password, sizeof(password), stdin) != NULL) {
        size_t len = strlen(password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0'; // Remove newline
        }
    }

    // Restore terminal settings
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
    printf("\n");

    return password;
}

#else
#include <conio.h> // For _getch
#include <windows.h> // For console functions

// Windows-specific strndup implementation
static char* strndup(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char* result = (char*)malloc(len + 1);
    if (result) {
        memcpy(result, s, len);
        result[len] = '\0';
    }
    return result;
}


// Windows-specific getpass implementation
char *secure_getpass(const char *prompt) {
    static char password[128]; // Buffer for password
    char *p = password;
    int c;

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT)); // Disable echo

    fputs(prompt, stdout);
    fflush(stdout);

    while ((c = _getch()) != '\r' && c != '\n' && (p - password < sizeof(password) - 1)) {
        *p++ = (char)c;
    }
    *p = '\0';

    SetConsoleMode(hStdin, mode); // Restore echo
    printf("\n");

    return password;
}

#endif

#include <csv.h>

#include "key_derivation.h"
#include "password_generator.h"
#include "database.h"
#include "totp.h"
#include "pwned_check.h"

// --- Struct and Callbacks for CSV Import ---
typedef struct {
    char **fields;
    int count;
} CsvRow;

static void cli_import_field_cb(void *s, size_t len, void *data) {
    CsvRow *row = (CsvRow*)data;
    row->count++;
    row->fields = realloc(row->fields, row->count * sizeof(char*));
    row->fields[row->count - 1] = strndup((const char*)s, len);
}

static void cli_import_row_cb(int c, void *data) {
    CsvRow *row = (CsvRow*)data;
    if (row->count >= 3) {
        PasswordEntry entry;
        entry.service = row->fields[0];
        entry.username = row->fields[1];
        entry.password = row->fields[2];
        entry.totp_secret = (row->count >= 4) ? row->fields[3] : "";
        entry.recovery_codes = (row->count >= 5) ? row->fields[4] : "";

        if(database_add_entry(&entry) < 0) {
            fprintf(stderr, "Failed to import row for service: %s\n", entry.service);
        }
    }
    for (int i = 0; i < row->count; i++) {
        free(row->fields[i]);
    }
    free(row->fields);
    row->fields = NULL;
    row->count = 0;
}

// --- Forward Declarations for CLI functions ---
static void cli_list_entries();
static void cli_add_entry();
static void cli_view_entry();
static void cli_edit_entry();
static void cli_delete_entry();
static void cli_import_csv(const char* filepath);
static void cli_export_csv(const char* filepath);
static void print_help();

static void cli_health_check();

#include "pwned_check.h"
#include "platform_paths.h"


// A simple helper to read a line of input securely
static void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\r\n")] = 0; // Remove trailing newline
}

// --- CLI Implementation ---

static void cli_list_entries() {
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries || count == 0) {
        printf("No entries found.\n");
        return;
    }

    printf("%-5s %-25s %-25s\n", "ID", "Service", "Username");
    printf("--------------------------------------------------------\n");
    for (int i = 0; i < count; i++) {
        printf("%-5d %-25s %-25s\n", entries[i].id, entries[i].service, entries[i].username);
    }

    free_password_entries(entries, count);
}

static void cli_add_entry() {
    PasswordEntry entry;
    char service[256], username[256], password_buf[256], totp_buf[256], recovery[1024];

    fputs("Service: ", stdout);
    read_line(service, sizeof(service));
    fputs("Username: ", stdout);
    read_line(username, sizeof(username));

    // Securely read password
    const char *pass_ptr = secure_getpass("Password: ");
    strncpy(password_buf, pass_ptr, sizeof(password_buf) - 1);
    password_buf[sizeof(password_buf) - 1] = '\0';
    // getpass might use a static buffer, so we copied it. Clear the static one if possible?
    // standard getpass doesn't expose clearing, but we copied it.

    // Securely read TOTP Secret
    const char *totp_ptr = secure_getpass("TOTP Secret (optional): ");
    strncpy(totp_buf, totp_ptr, sizeof(totp_buf) - 1);
    totp_buf[sizeof(totp_buf) - 1] = '\0';

    fputs("Recovery Codes (optional): ", stdout);
    read_line(recovery, sizeof(recovery));

    entry.service = service;
    entry.username = username;
    entry.password = password_buf;
    entry.totp_secret = totp_buf;
    entry.recovery_codes = recovery;

    if (database_add_entry(&entry) < 0) {
        fprintf(stderr, "Error: Could not add entry.\n");
    } else {
        printf("Entry added successfully.\n");
    }
}

static void cli_view_entry() {
    printf("Enter ID of entry to view: ");
    int id;
    if (scanf("%d", &id) != 1) { id = -1; }
    while(getchar() != '\n'); // consume newline

    // This is inefficient, but we'll add a get_by_id function later if needed.
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries) {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
        return;
    }

    PasswordEntry *target = NULL;
    for(int i=0; i<count; ++i) {
        if(entries[i].id == id) {
            target = &entries[i];
            break;
        }
    }

    if (target) {
        printf("\n--- Entry %d ---\n", target->id);
        printf("Service:  %s\n", target->service ? target->service : "");
        printf("Username: %s\n", target->username ? target->username : "");
        printf("Password: %s\n", target->password ? target->password : "");
        if (target->totp_secret && strlen(target->totp_secret) > 0) {
            char* code = generate_totp_code(target->totp_secret);
            printf("TOTP:     %s\n", code ? code : "(invalid secret)");
            if(code) free(code);
        } else {
            fputs("TOTP:     (none)\n", stdout);
        }
        if (target->recovery_codes && strlen(target->recovery_codes) > 0) {
            printf("Recovery Codes:\n");
            char *codes_copy = strdup(target->recovery_codes);
            char *line = strtok(codes_copy, "\n");
            int line_count = 0;
            char *lines[100];
            while (line && line_count < 100) {
                lines[line_count++] = line;
                printf("  [%d] %s\n", line_count, line);
                line = strtok(NULL, "\n");
            }

            printf("\nMark a code as used? (Enter number, or 0 to skip): ");
            int mark_idx;
            if (scanf("%d", &mark_idx) == 1 && mark_idx > 0 && mark_idx <= line_count) {
                while(getchar() != '\n'); // consume newline
                if (lines[mark_idx-1][0] != '*') {
                    // Update in database
                    size_t new_len = strlen(target->recovery_codes) + 2; // +1 for '*'
                    char *new_codes = malloc(new_len);
                    if (new_codes) {
                        new_codes[0] = '\0';
                        size_t current_pos = 0;
                        for (int i = 0; i < line_count; i++) {
                            const char *line_text = lines[i];
                            bool is_marked = (i == mark_idx - 1);

                            int n;
                            if (is_marked) {
                                n = snprintf(new_codes + current_pos, new_len - current_pos, "*%s%s",
                                             line_text, (i < line_count - 1) ? "\n" : "");
                            } else {
                                n = snprintf(new_codes + current_pos, new_len - current_pos, "%s%s",
                                             line_text, (i < line_count - 1) ? "\n" : "");
                            }

                            if (n > 0 && (size_t)n < new_len - current_pos) {
                                current_pos += n;
                            } else {
                                // Should not happen given new_len calculation
                                break;
                            }
                        }

                        PasswordEntry updated;
                        updated.id = target->id;
                        updated.service = target->service;
                        updated.username = target->username;
                        updated.password = target->password;
                        updated.totp_secret = target->totp_secret;
                        updated.recovery_codes = new_codes;

                        if (database_update_entry(&updated) == 0) {
                            printf("Recovery code marked as used.\n");
                        } else {
                            printf("Error updating entry.\n");
                        }
                        free(new_codes);
                    } else {
                        fprintf(stderr, "Memory allocation error.\n");
                    }
                } else {
                    printf("Code already marked as used.\n");
                }
            } else if (mark_idx != 0) {
                while(getchar() != '\n'); // consume newline
            }
            free(codes_copy);
        } else {
            printf("Recovery Codes: (none)\n");
        }
        printf("----------------\n");
    } else {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
    }

    free_password_entries(entries, count);
}

static void cli_delete_entry() {
    printf("Enter ID of entry to delete: ");
    int id;
    if (scanf("%d", &id) != 1) { id = -1; }
    while(getchar() != '\n'); // consume newline

    if (database_delete_entry(id) != 0) {
        fprintf(stderr, "Error: Could not delete entry with ID %d. It may not exist.\n", id);
    } else {
        printf("Entry %d deleted successfully.\n", id);
    }
}

static void interactive_mode() {
    char choice;
    while (true) {
        printf("\n[l]ist, [a]dd, [v]iew, [e]dit, [d]elete, [g]enerate, [h]ealth-check, [i]mport, e[x]port, [q]uit\n");
        printf("> ");
        if (scanf(" %c", &choice) != 1) { choice = 0; }
        while(getchar() != '\n'); // consume trailing chars and newline

        switch (choice) {
            case 'l': cli_list_entries(); break;
            case 'a': cli_add_entry(); break;
            case 'v': cli_view_entry(); break;
            case 'd': cli_delete_entry(); break;
            case 'g': {
                char* pw = generate_password(16, true, true, true);
                printf("Generated password: %s\n", pw);
                free(pw);
                break;
            }
            case 'h': cli_health_check(); break;
            case 'i': {
                char path[256];
                fputs("Path to CSV file to import: ", stdout);
                read_line(path, sizeof(path));
                cli_import_csv(path);
                break;
            }
            case 'e': cli_edit_entry(); break;
            case 'x': {
                char path[256];
                fputs("Path to export CSV file: ", stdout);
                read_line(path, sizeof(path));
                cli_export_csv(path);
                break;
            }
            case 'q': return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc > 1) { // Non-interactive for now, can be expanded
        print_help();
        return 0;
    }

    // --- Get Master Password ---
    const char *password = secure_getpass("Enter master password: ");
    if (strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty.\n");
        return 1;
    }

    // --- Open Database ---
    char dirPath[1024];
    get_config_path(dirPath, sizeof(dirPath));

    printf("Configuration directory: %s\n", dirPath);

    // Create directory if it doesn't exist (platform-specific)
#ifdef _WIN32
    // Check if directory exists using Windows API
    DWORD attribs = GetFileAttributesA(dirPath);
    if (attribs == INVALID_FILE_ATTRIBUTES || !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Directory doesn't exist, create it
        printf("Creating directory...\n");
        if (!CreateDirectoryA(dirPath, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                fprintf(stderr, "Error: Failed to create directory '%s' (Error code: %lu)\n", dirPath, err);
                sodium_memzero((void*)password, strlen(password));
                return 1;
            }
        } else {
            printf("Directory created successfully.\n");
        }
    } else {
        printf("Directory already exists.\n");
    }
#else
    // Linux/macOS: Use POSIX mkdir
    struct stat st = {0};
    if (stat(dirPath, &st) == -1) {
        // Directory doesn't exist
        printf("Creating directory...\n");

        // Create parent directories if needed (simple version)
        // For full recursive creation, you'd need to parse the path
        if (mkdir(dirPath, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Error: Failed to create directory '%s' (%s)\n", dirPath, strerror(errno));
            sodium_memzero((void*)password, strlen(password));
            return 1;
        } else {
            printf("Directory created successfully.\n");
        }
    } else {
        printf("Directory already exists.\n");
    }
#endif

    // Construct database path
    char dbPath[2048];
#ifdef _WIN32
    snprintf(dbPath, sizeof(dbPath), "%s\\vault.db", dirPath);
#else
    snprintf(dbPath, sizeof(dbPath), "%s/vault.db", dirPath);
#endif

    printf("Database path: %s\n", dbPath);

    // Open/create the database
    if (database_open(dbPath, password) != 0) {
        fprintf(stderr, "\nError: Failed to open database.\n");
        fprintf(stderr, "Possible causes:\n");
        fprintf(stderr, "  - Incorrect master password\n");
        fprintf(stderr, "  - Insufficient file permissions\n");
        fprintf(stderr, "  - Corrupted database file\n");
        fprintf(stderr, "\nDatabase location: %s\n", dbPath);
        sodium_memzero((void*)password, strlen(password));
        return 1;
    }

    // Clear password from memory
    sodium_memzero((void*)password, strlen(password));
    printf("Database opened successfully.\n\n");

    // --- Main Application Logic ---
    interactive_mode();

    // --- Cleanup ---
    database_close();
    printf("Database closed. Exiting.\n");

    return 0;
}

// Stubs for functions to be fully implemented
static void cli_edit_entry() {
    printf("Enter ID of entry to edit: ");
    int id = 0;
    if (scanf("%d", &id) != 1) { id = -1; }
    while(getchar() != '\n'); // consume newline

    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries) {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
        return;
    }

    PasswordEntry *target = NULL;
    for(int i=0; i<count; ++i) {
        if(entries[i].id == id) {
            target = &entries[i];
            break;
        }
    }

    if (target) {
        PasswordEntry updated_entry;
        char service[256], username[256], password[256], totp[256], recovery[1024];

        printf("Service [%s]: ", target->service);
        read_line(service, sizeof(service));
        printf("Username [%s]: ", target->username);
        read_line(username, sizeof(username));
        printf("Password [%s]: ", target->password);
        read_line(password, sizeof(password));
        printf("TOTP Secret [%s]: ", target->totp_secret);
        read_line(totp, sizeof(totp));
        printf("Recovery Codes [%s]: ", target->recovery_codes ? target->recovery_codes : "(none)");
        read_line(recovery, sizeof(recovery));

        updated_entry.id = id;
        updated_entry.service = strlen(service) > 0 ? service : target->service;
        updated_entry.username = strlen(username) > 0 ? username : target->username;
        updated_entry.password = strlen(password) > 0 ? password : target->password;
        updated_entry.totp_secret = strlen(totp) > 0 ? totp : target->totp_secret;
        updated_entry.recovery_codes = strlen(recovery) > 0 ? recovery : target->recovery_codes;

        if (database_update_entry(&updated_entry) != 0) {
            fprintf(stderr, "Error: Could not update entry.\n");
        } else {
            printf("Entry updated successfully.\n");
        }

    } else {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
    }

    free_password_entries(entries, count);
}

static void cli_import_csv(const char* filepath) {
    if (strstr(filepath, "..")) {
        fprintf(stderr, "Error: Invalid file path (contains '..').\n");
        return;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s\n", filepath);
        return;
    }

    struct csv_parser p;
    if (csv_init(&p, 0) != 0) {
        fprintf(stderr, "Error: Failed to initialize CSV parser.\n");
        fclose(fp);
        return;
    }

    CsvRow row = { .fields = NULL, .count = 0 };

    char buf[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (csv_parse(&p, buf, bytes_read, cli_import_field_cb, cli_import_row_cb, &row) != bytes_read) {
            fprintf(stderr, "CSV Parse Error: %s\n", csv_strerror(csv_error(&p)));
            break;
        }
    }

    csv_fini(&p, cli_import_field_cb, cli_import_row_cb, &row);
    csv_free(&p);
    fclose(fp);

    printf("CSV import from %s finished.\n", filepath);
}

static void cli_export_csv(const char* filepath) {
    if (strstr(filepath, "..")) {
        fprintf(stderr, "Error: Invalid file path (contains '..').\n");
        return;
    }

    printf("WARNING: You are about to export your vault to a CSV file.\n");
    printf("This file will contain ALL your passwords and secrets in PLAIN TEXT.\n");
    printf("Anyone with access to this file will be able to see your credentials.\n");
    printf("Are you sure you want to continue? (y/N): ");

    char confirm[16];
    read_line(confirm, sizeof(confirm));
    if (confirm[0] != 'y' && confirm[0] != 'Y') {
        printf("Export cancelled.\n");
        return;
    }

    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries) {
        fprintf(stderr, "No entries to export.\n");
        return;
    }

    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open file for writing.\n");
        free_password_entries(entries, count);
        return;
    }

    fprintf(fp, "service,username,password,totp_secret,recovery_codes\n");
    for (int i = 0; i < count; i++) {
        fprintf(fp, "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                entries[i].service, entries[i].username, entries[i].password, entries[i].totp_secret, entries[i].recovery_codes);
    }

    fclose(fp);
    free_password_entries(entries, count);
    printf("Exported %d entries to %s\n", count, filepath);
}

static void cli_health_check() {
    printf("Performing password health check...\n");
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries || count == 0) {
        printf("No entries to check.\n");
        return;
    }

    // Check for short passwords (less than 16 characters for high security)
    printf("\n--- Short Passwords (less than 16 characters) ---\n");
    bool short_found = false;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(entries[i].password);
        if (len < 16) {
            printf("  [ID %d] %s - %s: Password is only %zu characters (recommended: 16+)\n",
                   entries[i].id, entries[i].service, entries[i].username, len);
            short_found = true;
        }
    }
    if (!short_found) {
        printf("No short passwords found.\n");
    }

    // Check for low entropy passwords (missing character types)
    printf("\n--- Low Entropy Passwords (missing character types) ---\n");
    bool low_entropy_found = false;
    for (int i = 0; i < count; i++) {
        const char *pwd = entries[i].password;
        bool has_upper = false, has_lower = false, has_digit = false, has_special = false;

        for (size_t j = 0; j < strlen(pwd); j++) {
            if (pwd[j] >= 'A' && pwd[j] <= 'Z') has_upper = true;
            else if (pwd[j] >= 'a' && pwd[j] <= 'z') has_lower = true;
            else if (pwd[j] >= '0' && pwd[j] <= '9') has_digit = true;
            else has_special = true;
        }

        if (!has_upper || !has_lower || !has_digit || !has_special) {
            printf("  [ID %d] %s - %s: Missing ", entries[i].id, entries[i].service, entries[i].username);
            bool first = true;
            if (!has_upper) { printf("uppercase"); first = false; }
            if (!has_lower) { printf("%slowercase", first ? "" : ", "); first = false; }
            if (!has_digit) { printf("%snumbers", first ? "" : ", "); first = false; }
            if (!has_special) { printf("%ssymbols", first ? "" : ", "); }
            printf("\n");
            low_entropy_found = true;
        }
    }
    if (!low_entropy_found) {
        printf("All passwords have good character variety.\n");
    }

    // Check for reused passwords
    printf("\n--- Reused Passwords ---\n");
    bool reused_found = false;
    for (int i = 0; i < count; i++) {
        int reuse_count = 0;
        int reused_ids[256];  // Store IDs of entries with same password

        for (int j = 0; j < count; j++) {
            if (i != j && strcmp(entries[i].password, entries[j].password) == 0) {
                if (reuse_count == 0) {
                    reused_ids[reuse_count++] = entries[i].id;
                }
                reused_ids[reuse_count++] = entries[j].id;
            }
        }

        if (reuse_count > 0) {
            // Only print once per unique password (check if this is the first occurrence)
            bool is_first = true;
            for (int k = 0; k < i; k++) {
                if (strcmp(entries[i].password, entries[k].password) == 0) {
                    is_first = false;
                    break;
                }
            }

            if (is_first) {
                printf("  Password reused across %d services: ", reuse_count);
                for (int k = 0; k < reuse_count; k++) {
                    for (int m = 0; m < count; m++) {
                        if (entries[m].id == reused_ids[k]) {
                            printf("[ID %d] %s", reused_ids[k], entries[m].service);
                            if (k < reuse_count - 1) printf(", ");
                            break;
                        }
                    }
                }
                printf("\n");
                reused_found = true;
            }
        }
    }
    if (!reused_found) {
        printf("No reused passwords found.\n");
    }

    printf("\n--- Pwned Passwords (checking via HIBP API) ---\n");
    bool pwned_found = false;
    for (int i = 0; i < count; i++) {
        printf("Checking password for ID %d... \r", entries[i].id);
        fflush(stdout);
        int pwned_count = is_password_pwned(entries[i].password);
        if (pwned_count > 0) {
            printf("\n  [ID %d] %s - %s: Found in %d breaches!\n", entries[i].id, entries[i].service, entries[i].username, pwned_count);
            pwned_found = true;
        }
    }
    printf("\n");
    if (!pwned_found) {
        printf("No pwned passwords found.\n");
    }

    free_password_entries(entries, count);
    printf("\nHealth check complete.\n");
}

static void print_help() {
    printf("Usage: securepasswd_cli\n");
    printf("The application runs in interactive mode.\n");
}
