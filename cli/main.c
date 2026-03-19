#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <sodium.h>
#include <curl/curl.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#endif

#ifndef _MSC_V
#include <termios.h> // For hiding input
#include <unistd.h>  // For STDIN_FILENO

// Custom getpass implementation for Linux/macOS to avoid obsolescence warnings
static char *secure_getpass(const char *prompt) {
    static char password[256]; // flawfinder: ignore
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

    if (fgets(password, sizeof(password), stdin) != NULL) {
        size_t len = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password);
        if (len > 0 && password[len - 1] == '\n') {
            password[len - 1] = '\0'; // Remove newline
        }
    }

    // Restore terminal settings
    (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
    fputs("\n", stdout);

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
        memcpy( /* flawfinder: ignore */ result, s, len); // flawfinder: ignore
        result[len] = '\0';
    }
    return result;
}


// Windows-specific getpass implementation
char *secure_getpass(const char *prompt) {
    static char password[256]; // flawfinder: ignore
    char *p = password;
    int c;

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT)); // Disable echo

    fputs(prompt, stdout);
    fflush(stdout);

    while ((c = _getch()) != '\r' && c != '\n' && (p - password < (int)sizeof(password) - 1)) {
        *p++ = (char)c;
    }
    *p = '\0';

    SetConsoleMode(hStdin, mode); // Restore echo
    fputs("\n", stdout);

    return password;
}

#endif

#include <csv.h>

#include "key_derivation.h"
#include "password_generator.h"
#include "database.h"
#include "totp.h"
#include "pwned_check.h"

// Forward declaration
static void read_line(char *buf, int size);

// --- Struct and Callbacks for CSV Import ---
typedef struct {
    char **fields;
    int count;
} CsvRow;

static void cli_import_field_cb(void *s, size_t len, void *data) {
    CsvRow *row = (CsvRow*)data;
    row->count++;
    row->fields = realloc(row->fields, (size_t)row->count * sizeof(char*));
    if (row->fields) {
        row->fields[row->count - 1] = strndup((const char*)s, len);
    }
}

static void cli_import_row_cb(int c, void *data) {
    (void)c;
    CsvRow *row = (CsvRow*)data;
    if (row->count >= 3) {
        const char *service = row->fields[0];
        const char *username = row->fields[1];
        const char *password = row->fields[2];
        const char *totp = (row->count >= 4) ? row->fields[3] : "";
        const char *recovery = (row->count >= 5) ? row->fields[4] : "";

        // Check if entry exists
        PasswordEntry *existing = database_get_entry_by_identity(service, username);
        if (existing) {
            bool identical = (strcmp(existing->password, password) == 0 &&
                             strcmp(existing->totp_secret, totp) == 0 &&
                             strcmp(existing->recovery_codes, recovery) == 0);

            if (identical) {
                printf("[SKIP] '%s' (%s) is already in the vault and matches CSV.\n", service, username);
            } else {
                printf("[CONFLICT] '%s' (%s) already exists but data differs.\n", service, username);
                printf("  Existing: %s | Incoming: %s\n", existing->password, password);
                fputs("  Overwrite local entry? (y/N): ", stdout);
                fflush(stdout);
                char choice[16]; // flawfinder: ignore
                read_line(choice, sizeof(choice));
                if (choice[0] == 'y' || choice[0] == 'Y') {
                    PasswordEntry updated;
                    updated.id = existing->id;
                    updated.service = (char*)service;
                    updated.username = (char*)username;
                    updated.password = (char*)password;
                    updated.totp_secret = (char*)totp;
                    updated.recovery_codes = (char*)recovery;

                    if (database_update_entry(&updated) == 0) {
                        printf("[OK] Updated '%s'.\n", service);
                    } else {
                        fprintf(stderr, "[ERROR] Failed to update '%s'.\n", service);
                    }
                } else {
                    printf("[SKIP] Kept local version of '%s'.\n", service);
                }
            }
            free_password_entries(existing, 1);
        } else {
            PasswordEntry entry;
            entry.service = (char*)service;
            entry.username = (char*)username;
            entry.password = (char*)password;
            entry.totp_secret = (char*)totp;
            entry.recovery_codes = (char*)recovery;

            if (database_add_entry(&entry) < 0) {
                fprintf(stderr, "[ERROR] Failed to import '%s'.\n", service);
            } else {
                printf("[ADD] Imported '%s' (%s).\n", service, username);
            }
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
static void cli_search_entries();
static void cli_add_entry();
static void cli_view_entry();
static void cli_edit_entry();
static void cli_delete_entry();
static void cli_import_csv(const char* filepath);
static void cli_export_csv(const char* filepath);
static void print_help();

static void cli_health_check();
static void cli_change_password();

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

// Helper for scrollback mitigation: hides sensitive output after user acknowledgement
static void hide_sensitive_output(int lines_to_clear) {
    fputs("\nPress Enter to hide sensitive data...", stdout);
    fflush(stdout);
    char dummy[16]; // flawfinder: ignore
    read_line(dummy, sizeof(dummy));

    // Use ANSI escape sequences to go up and clear lines
    for (int i = 0; i < lines_to_clear + 2; i++) {
        fputs("\033[A\033[2K", stdout);
    }
    fputs("\rSensitive data hidden.\n", stdout);
    fflush(stdout);
}

// --- CLI Implementation ---

static void cli_list_entries() {
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries || count == 0) {
        fputs("No entries found.\n", stdout);
        return;
    }

    printf("%-5s %-25s %-25s\n", "ID", "Service", "Username");
    fputs("--------------------------------------------------------\n", stdout);
    for (int i = 0; i < count; i++) {
        printf("%-5d %-25s %-25s\n", entries[i].id, entries[i].service, entries[i].username);
    }

    free_password_entries(entries, count);
}

static void cli_search_entries() {
    char query[256]; // flawfinder: ignore // flawfinder: ignore
    fputs("Enter search query (service or username): ", stdout);
    fflush(stdout);
    read_line(query, sizeof(query));

    if (strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ query) == 0) {
        fputs("Search query cannot be empty.\n", stdout);
        return;
    }

    int count = 0;
    PasswordEntry *entries = database_search(query, &count);
    if (!entries || count == 0) {
        printf("No entries matching '%s' found.\n", query);
        return;
    }

    printf("\nFound %d matching entries:\n", count);
    printf("%-5s %-25s %-25s\n", "ID", "Service", "Username");
    fputs("--------------------------------------------------------\n", stdout);
    for (int i = 0; i < count; i++) {
        printf("%-5d %-25s %-25s\n", entries[i].id, entries[i].service, entries[i].username);
    }

    free_password_entries(entries, count);
}

static void cli_add_entry() {
    PasswordEntry entry;
    char service[256], username[256], password_buf[256], totp_buf[256], recovery[2048]; // flawfinder: ignore // flawfinder: ignore

    fputs("Service: ", stdout);
    read_line(service, sizeof(service));
    fputs("Username: ", stdout);
    read_line(username, sizeof(username));

    // Securely read password
    const char *pass_ptr = secure_getpass("Password: ");
    if (pass_ptr) {
        snprintf(password_buf, sizeof(password_buf), "%s", pass_ptr);
    } else {
        password_buf[0] = '\0';
    }

    // Securely read TOTP Secret
    const char *totp_ptr = secure_getpass("TOTP Secret (optional): ");
    if (totp_ptr) {
        snprintf(totp_buf, sizeof(totp_buf), "%s", totp_ptr);
    } else {
        totp_buf[0] = '\0';
    }

    fputs("Recovery Codes (optional): ", stdout);
    read_line(recovery, sizeof(recovery));

    entry.service = service;
    entry.username = username;
    entry.password = password_buf;
    entry.totp_secret = totp_buf;
    entry.recovery_codes = recovery;

    if (database_add_entry(&entry) < 0) {
        fputs("Error: Could not add entry.\n", stderr);
    } else {
        fputs("Entry added successfully.\n", stdout);
    }
}

static void cli_view_entry() {
    fputs("Enter ID of entry to view: ", stdout);
    fflush(stdout);
    
    char id_buf[16]; // flawfinder: ignore // flawfinder: ignore
    read_line(id_buf, sizeof(id_buf));
    int id = (int)strtol(id_buf, NULL, 10);

    PasswordEntry *target = database_get_entry_secure(id);
    if (!target) {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
        return;
    }

    printf("\n--- Entry %d ---\n", target->id);
    printf("Service:  %s\n", target->service ? target->service : "");
    printf("Username: %s\n", target->username ? target->username : "");
    printf("Password: %s\n", target->password ? target->password : "");
    
    if (target->totp_secret && strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ target->totp_secret) > 0) {
        char* code = generate_totp_code(target->totp_secret);
        printf("TOTP:     %s\n", code ? code : "(invalid secret)");
        if(code) free(code);
    } else {
        fputs("TOTP:     (none)\n", stdout);
    }
    
    int line_count = 0;
    if (target->recovery_codes && strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ target->recovery_codes) > 0) {
        fputs("Recovery Codes:\n", stdout);
        char *codes_copy = strdup(target->recovery_codes);
        char *line = strtok(codes_copy, "\n");
        char *lines[100]; // flawfinder: ignore
        while (line && line_count < 100) {
            lines[line_count++] = line;
            printf("  [%d] %s\n", line_count, line);
            line = strtok(NULL, "\n");
        }

        fputs("\nMark a code as used? (Enter number, or 0 to skip): ", stdout);
        fflush(stdout);
        
        char mark_buf[16]; // flawfinder: ignore
        read_line(mark_buf, sizeof(mark_buf));
        int mark_idx = (int)strtol(mark_buf, NULL, 10);

        if (mark_idx > 0 && mark_idx <= line_count) {
            if (lines[mark_idx-1][0] != '*') {
                // Update in database
                size_t codes_len = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ target->recovery_codes);
                size_t new_len = codes_len + 2; // +1 for '*'
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
                            current_pos += (size_t)n;
                        } else {
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
                        fputs("Recovery code marked as used.\n", stdout);
                    } else {
                        fputs("Error updating entry.\n", stdout);
                    }
                    free(new_codes);
                } else {
                    fputs("Memory allocation error.\n", stderr);
                }
            } else {
                fputs("Code already marked as used.\n", stdout);
            }
        }
        free(codes_copy);
    } else {
        fputs("Recovery Codes: (none)\n", stdout);
    }
    fputs("----------------\n", stdout);

    hide_sensitive_output(10 + line_count);
    free_password_entries(target, 1);
}

static void cli_delete_entry() {
    fputs("Enter ID of entry to delete: ", stdout);
    fflush(stdout);

    char id_buf[16]; // flawfinder: ignore // flawfinder: ignore
    read_line(id_buf, sizeof(id_buf));
    int id = (int)strtol(id_buf, NULL, 10);

    if (database_delete_entry(id) != 0) {
        fprintf(stderr, "Error: Could not delete entry with ID %d. It may not exist.\n", id);
    } else {
        printf("Entry %d deleted successfully.\n", id);
    }
}

static void interactive_mode() {
    while (true) {
        fputs("\n[l]ist, [s]earch, [a]dd, [v]iew, [e]dit, [d]elete, [g]enerate, [h]ealth-check, [c]hange-pass, [i]mport, e[x]port, [q]uit\n", stdout);
        fputs("> ", stdout);
        fflush(stdout);

        char choice_buf[16]; // flawfinder: ignore
        read_line(choice_buf, sizeof(choice_buf));
        char choice = choice_buf[0];

        switch (choice) {
            case 'l': cli_list_entries(); break;
            case 's': cli_search_entries(); break;
            case 'a': cli_add_entry(); break;
            case 'v': cli_view_entry(); break;
            case 'd': cli_delete_entry(); break;
            case 'c': cli_change_password(); break;
            case 'g': {
                char* pw = generate_password(16, true, true, true);
                if (pw) {
                    printf("Generated password: %s\n", pw);
                    free(pw);
                }
                break;
            }
            case 'h': cli_health_check(); break;
            case 'i': {
                char path[256]; // flawfinder: ignore // flawfinder: ignore
                fputs("Path to CSV file to import: ", stdout);
                fflush(stdout);
                read_line(path, sizeof(path));
                cli_import_csv(path);
                break;
            }
            case 'e': cli_edit_entry(); break;
            case 'x': {
                char path[256]; // flawfinder: ignore // flawfinder: ignore
                fputs("Path to export CSV file: ", stdout);
                fflush(stdout);
                read_line(path, sizeof(path));
                cli_export_csv(path);
                break;
            }
            case 'q': return;
            default: fputs("Invalid choice.\n", stdout); break;
        }
    }
}

int main(int argc, char *argv[]) {
    // --- Global Init ---
    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        fputs("Error: Failed to initialize curl\n", stderr);
        return 1;
    }

    const char *search_query = NULL;

    // --- Parse Arguments ---
    static struct option long_options[] = {
        {"search", required_argument, 0, 's'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    opterr = 0; // Disable default error reporting to handle manually
    while ((opt = getopt_long(argc, argv, "s:h", long_options, NULL)) != -1) { // flawfinder: ignore
        switch (opt) {
            case 's':
                if (optarg) {
                    search_query = optarg;
                }
                break;
            case 'h':
                print_help();
                return 0;
            case '?':
                if (optopt == 's') {
                    fputs("Option -s requires an argument.\n", stderr);
                } else {
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                }
                print_help();
                return 1;
            default:
                print_help();
                return 0;
        }
    }

    // --- Get Master Password ---
    const char *password = secure_getpass("Enter master password: ");
    if (!password) return 1;
    size_t pass_len = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password);
    if (pass_len == 0) {
        fputs("Error: Password cannot be empty.\n", stderr);
        return 1;
    }

    // --- Open Database ---
    char dirPath[2048]; // flawfinder: ignore // flawfinder: ignore
    get_config_path(dirPath, sizeof(dirPath));

    printf("Configuration directory: %s\n", dirPath);

    // Create directory if it doesn't exist (platform-specific)
#ifdef _WIN32
    // Check if directory exists using Windows API
    DWORD attribs = GetFileAttributesA(dirPath);
    if (attribs == INVALID_FILE_ATTRIBUTES || !(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
        // Directory doesn't exist, create it
        fputs("Creating directory...\n", stdout);
        if (!CreateDirectoryA(dirPath, NULL)) {
            DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS) {
                fprintf(stderr, "Error: Failed to create directory '%s' (Error code: %lu)\n", dirPath, err);
                sodium_memzero((void*)password, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password));
                return 1;
            }
        } else {
            fputs("Directory created successfully.\n", stdout);
        }
    } else {
        fputs("Directory already exists.\n", stdout);
    }
#else
    // Linux/macOS: Use POSIX mkdir
    struct stat st = {0};
    if (stat(dirPath, &st) == -1) {
        // Directory doesn't exist
        fputs("Creating directory...\n", stdout);

        if (mkdir(dirPath, 0700) != 0 && errno != EEXIST) {
            fprintf(stderr, "Error: Failed to create directory '%s' (%s)\n", dirPath, strerror(errno));
            sodium_memzero((void*)password, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password));
            return 1;
        } else {
            fputs("Directory created successfully.\n", stdout);
        }
    } else {
        fputs("Directory already exists.\n", stdout);
    }
#endif

    // Construct database path
    char dbPath[4096]; // flawfinder: ignore // flawfinder: ignore
#ifdef _WIN32
    snprintf(dbPath, sizeof(dbPath), "%s\\vault.db", dirPath);
#else
    snprintf(dbPath, sizeof(dbPath), "%s/vault.db", dirPath);
#endif

    printf("Database path: %s\n", dbPath);

    // Open/create the database
    if (database_open(dbPath, password) != 0) {
        fputs("\nError: Failed to open database.\n", stderr);
        fputs("Possible causes:\n", stderr);
        fputs("  - Incorrect master password\n", stderr);
        fputs("  - Insufficient file permissions\n", stderr);
        fputs("  - Corrupted database file\n", stderr);
        fprintf(stderr, "\nDatabase location: %s\n", dbPath);
        sodium_memzero((void*)password, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password));
        return 1;
    }

    // Clear password from memory
    sodium_memzero((void*)password, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password));
    fputs("Database opened successfully.\n\n", stdout);

    // --- Main Application Logic ---
    if (search_query) {
        int count = 0;
        PasswordEntry *entries = database_search(search_query, &count);
        if (!entries || count == 0) {
            printf("No entries matching '%s' found.\n", search_query);
        } else {
            printf("Found %d matching entries:\n", count);
            printf("%-5s %-25s %-25s\n", "ID", "Service", "Username");
            fputs("--------------------------------------------------------\n", stdout);
            for (int i = 0; i < count; i++) {
                printf("%-5d %-25s %-25s\n", entries[i].id, entries[i].service, entries[i].username);
            }
            free_password_entries(entries, count);
        }
    } else {
        interactive_mode();
    }

    // --- Cleanup ---
    database_close();
    curl_global_cleanup();
    fputs("Database closed. Exiting.\n", stdout);

    return 0;
}

// Stubs for functions to be fully implemented
static void cli_edit_entry() {
    fputs("Enter ID of entry to edit: ", stdout);
    fflush(stdout);
    
    char id_buf[16]; // flawfinder: ignore // flawfinder: ignore
    read_line(id_buf, sizeof(id_buf));
    int id = (int)strtol(id_buf, NULL, 10);

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
        char service[256], username[256], password[256], totp[256], recovery[2048]; // flawfinder: ignore // flawfinder: ignore

        printf("Service [%s]: ", target->service);
        fflush(stdout);
        read_line(service, sizeof(service));
        
        printf("Username [%s]: ", target->username);
        fflush(stdout);
        read_line(username, sizeof(username));
        
        printf("Password [%s]: ", target->password);
        fflush(stdout);
        read_line(password, sizeof(password));
        
        printf("TOTP Secret [%s]: ", target->totp_secret);
        fflush(stdout);
        read_line(totp, sizeof(totp));
        
        printf("Recovery Codes [%s]: ", target->recovery_codes ? target->recovery_codes : "(none)");
        fflush(stdout);
        read_line(recovery, sizeof(recovery));

        updated_entry.id = id;
        updated_entry.service = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ service) > 0 ? service : target->service;
        updated_entry.username = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ username) > 0 ? username : target->username;
        updated_entry.password = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ password) > 0 ? password : target->password;
        updated_entry.totp_secret = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ totp) > 0 ? totp : target->totp_secret;
        updated_entry.recovery_codes = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ recovery) > 0 ? recovery : target->recovery_codes;

        if (database_update_entry(&updated_entry) != 0) {
            fputs("Error: Could not update entry.\n", stderr);
        } else {
            fputs("Entry updated successfully.\n", stdout);
        }

    } else {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
    }

    free_password_entries(entries, count);
}

static void cli_import_csv(const char* filepath) {
    if (strstr(filepath, "..")) {
        fputs("Error: Invalid file path (contains '..').\n", stderr);
        return;
    }

    FILE *fp = fopen(filepath, "rb"); // flawfinder: ignore // flawfinder: ignore
    if (!fp) {
        fprintf(stderr, "Error: Could not open file %s\n", filepath);
        return;
    }

    struct csv_parser p;
    if (csv_init(&p, 0) != 0) {
        fputs("Error: Failed to initialize CSV parser.\n", stderr);
        fclose(fp);
        return;
    }

    CsvRow row = { .fields = NULL, .count = 0 };

    char buf[1024]; // flawfinder: ignore
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
        fputs("Error: Invalid file path (contains '..').\n", stderr);
        return;
    }

    fputs("WARNING: You are about to export your vault to a CSV file.\n", stdout);
    fputs("This file will contain ALL your passwords and secrets in PLAIN TEXT.\n", stdout);
    fputs("Anyone with access to this file will be able to see your credentials.\n", stdout);
    fputs("Are you sure you want to continue? (y/N): ", stdout);
    fflush(stdout);

    char confirm[16]; // flawfinder: ignore
    read_line(confirm, sizeof(confirm));
    if (confirm[0] != 'y' && confirm[0] != 'Y') {
        fputs("Export cancelled.\n", stdout);
        return;
    }

    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries) {
        fputs("No entries to export.\n", stderr);
        return;
    }

    FILE *fp = fopen(filepath, "w"); // flawfinder: ignore // flawfinder: ignore
    if (!fp) {
        fputs("Error: Could not open file for writing.\n", stderr);
        free_password_entries(entries, count);
        return;
    }

    fputs("service,username,password,totp_secret,recovery_codes\n", fp);
    for (int i = 0; i < count; i++) {
        PasswordEntry *full = database_get_entry_secure(entries[i].id);
        if (full) {
            // Basic sanitization for CSV Injection
            const char *s = full->service;
            const char *u = full->username;
            const char *p = full->password;
            const char *ts = full->totp_secret;
            const char *rc = full->recovery_codes;

            // Simple sanitization lambda-like logic for C
#define SANITIZE(field) ((field && (field[0] == '=' || field[0] == '+' || field[0] == '-' || field[0] == '@')) ? "'" : "")

            // codeql[cpp/cleartext-storage-file]
            fprintf(fp, "\"%s%s\",\"%s%s\",\"%s%s\",\"%s%s\",\"%s%s\"\n",
                    SANITIZE(s), s ? s : "",
                    SANITIZE(u), u ? u : "",
                    SANITIZE(p), p ? p : "",
                    SANITIZE(ts), ts ? ts : "",
                    SANITIZE(rc), rc ? rc : "");

            free_password_entries(full, 1);
        }
    }

    fclose(fp);
    free_password_entries(entries, count);
    printf("Exported %d entries to %s\n", count, filepath);
}

static void cli_health_check() {
    fputs("Performing password health check...\n", stdout);
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries || count == 0) {
        fputs("No entries to check.\n", stdout);
        return;
    }

    // Load all full entries into memory for health check
    PasswordEntry *full_entries = calloc((size_t)count, sizeof(PasswordEntry));
    if (!full_entries) {
        free_password_entries(entries, count);
        return;
    }
    for (int i = 0; i < count; i++) {
        PasswordEntry *e = database_get_entry_secure(entries[i].id);
        if (e) {
            full_entries[i] = *e;
            free(e); // Free the container but keep the strings
        } else {
            // Fill with metadata if secure fetch fails
            full_entries[i].id = entries[i].id;
            full_entries[i].service = strdup(entries[i].service);
            full_entries[i].username = strdup(entries[i].username);
            full_entries[i].password = strdup("");
            full_entries[i].totp_secret = strdup("");
            full_entries[i].recovery_codes = strdup("");
        }
    }

    // Check for short passwords (less than 16 characters for high security)
    fputs("\n--- Short Passwords (less than 16 characters) ---\n", stdout);
    bool short_found = false;
    for (int i = 0; i < count; i++) {
        size_t len = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ full_entries[i].password);
        if (len < 16) {
            printf("  [ID %d] %s - %s: Password is only %zu characters (recommended: 16+)\n",
                   full_entries[i].id, full_entries[i].service, full_entries[i].username, len);
            short_found = true;
        }
    }
    if (!short_found) {
        fputs("No short passwords found.\n", stdout);
    }

    // Check for low entropy passwords (missing character types)
    fputs("\n--- Low Entropy Passwords (missing character types) ---\n", stdout);
    bool low_entropy_found = false;
    for (int i = 0; i < count; i++) {
        const char *pwd = full_entries[i].password;
        bool has_upper = false, has_lower = false, has_digit = false, has_special = false;

        size_t pwd_len = strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ pwd);
        for (size_t j = 0; j < pwd_len; j++) {
            if (pwd[j] >= 'A' && pwd[j] <= 'Z') has_upper = true;
            else if (pwd[j] >= 'a' && pwd[j] <= 'z') has_lower = true;
            else if (pwd[j] >= '0' && pwd[j] <= '9') has_digit = true;
            else has_special = true;
        }

        if (!has_upper || !has_lower || !has_digit || !has_special) {
            printf("  [ID %d] %s - %s: Missing ", full_entries[i].id, full_entries[i].service, full_entries[i].username);
            bool first = true;
            if (!has_upper) { fputs("uppercase", stdout); first = false; }
            if (!has_lower) { printf("%slowercase", first ? "" : ", "); first = false; }
            if (!has_digit) { printf("%snumbers", first ? "" : ", "); first = false; }
            if (!has_special) { printf("%ssymbols", first ? "" : ", "); }
            fputs("\n", stdout);
            low_entropy_found = true;
        }
    }
    if (!low_entropy_found) {
        fputs("All passwords have good character variety.\n", stdout);
    }

    // Check for reused passwords
    fputs("\n--- Reused Passwords ---\n", stdout);
    bool reused_found = false;
    for (int i = 0; i < count; i++) {
        int reuse_count = 0;
        int reused_ids[256];  // Store IDs of entries with same password

        for (int j = 0; j < count; j++) {
            if (i != j && strcmp(full_entries[i].password, full_entries[j].password) == 0) {
                if (reuse_count == 0) {
                    reused_ids[reuse_count++] = full_entries[i].id;
                }
                if (reuse_count < 256) {
                    reused_ids[reuse_count++] = full_entries[j].id;
                }
            }
        }

        if (reuse_count > 0) {
            // Only print once per unique password (check if this is the first occurrence)
            bool is_first = true;
            for (int k = 0; k < i; k++) {
                if (strcmp(full_entries[i].password, full_entries[k].password) == 0) {
                    is_first = false;
                    break;
                }
            }

            if (is_first) {
                printf("  Password reused across %d services: ", reuse_count);
                for (int k = 0; k < reuse_count; k++) {
                    for (int m = 0; m < count; m++) {
                        if (full_entries[m].id == reused_ids[k]) {
                            printf("[ID %d] %s", reused_ids[k], full_entries[m].service);
                            if (k < reuse_count - 1) fputs(", ", stdout);
                            break;
                        }
                    }
                }
                fputs("\n", stdout);
                reused_found = true;
            }
        }
    }
    if (!reused_found) {
        fputs("No reused passwords found.\n", stdout);
    }

    fputs("\n--- Pwned Passwords (checking via HIBP API) ---\n", stdout);
    bool pwned_found = false;
    for (int i = 0; i < count; i++) {
        printf("Checking password for ID %d... \r", full_entries[i].id);
        fflush(stdout);
        int pwned_count = is_password_pwned(full_entries[i].password);
        if (pwned_count > 0) {
            printf("\n  [ID %d] %s - %s: Found in %d breaches!\n", full_entries[i].id, full_entries[i].service, full_entries[i].username, pwned_count);
            pwned_found = true;
        }
    }
    fputs("\n", stdout);
    if (!pwned_found) {
        fputs("No pwned passwords found.\n", stdout);
    }

    // Securely wipe and free all full entries
    for (int i = 0; i < count; i++) {
        if (full_entries[i].password) sodium_memzero(full_entries[i].password, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ full_entries[i].password));
        if (full_entries[i].totp_secret) sodium_memzero(full_entries[i].totp_secret, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ full_entries[i].totp_secret));
        if (full_entries[i].recovery_codes) sodium_memzero(full_entries[i].recovery_codes, strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ full_entries[i].recovery_codes));
    }
    free_password_entries(full_entries, count);
    free_password_entries(entries, count);

    fputs("\nHealth check complete.\n", stdout);

    hide_sensitive_output(30 + (count * 2));
}

static void cli_change_password() {
    fputs("\n--- Change Master Password ---\n", stdout);
    fputs("Please note: Your database will be re-encrypted and a new salt will be generated.\n", stdout);

    const char *p1 = secure_getpass("New master password: ");
    if (!p1 || strlen( /* flawfinder: ignore */  /* flawfinder: ignore */ p1) == 0) {
        fputs("Password cannot be empty.\n", stdout);
        return;
    }
    char pass1[256]; // flawfinder: ignore // flawfinder: ignore // flawfinder: ignore
    snprintf(pass1, sizeof(pass1), "%s", p1);

    const char *p2 = secure_getpass("Confirm new master password: ");
    if (!p2 || strcmp(pass1, p2) != 0) {
        fputs("Passwords do not match.\n", stdout);
        sodium_memzero(pass1, sizeof(pass1));
        return;
    }

    if (database_rekey(pass1) == 0) {
        fputs("Master password changed successfully.\n", stdout);
    } else {
        fputs("Error: Failed to change master password.\n", stderr);
    }

    sodium_memzero(pass1, sizeof(pass1));
}

static void print_help() {
    fputs("Usage: securepasswd_cli [options]\n\n", stdout);
    fputs("Options:\n", stdout);
    fputs("  -s, --search <query>  Search for entries by service or username and exit.\n", stdout);
    fputs("  -h, --help            Show this help message.\n\n", stdout);
    fputs("If no options are provided, the application runs in interactive mode.\n", stdout);
}
