#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <sodium.h>
#include <unistd.h> // For getpass
#include <termios.h> // For hiding input
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

void cli_import_field_cb(void *s, size_t len, void *data) {
    CsvRow *row = (CsvRow*)data;
    row->count++;
    row->fields = realloc(row->fields, row->count * sizeof(char*));
    row->fields[row->count - 1] = strndup(s, len);
}

void cli_import_row_cb(int c, void *data) {
    CsvRow *row = (CsvRow*)data;
    if (row->count >= 3) {
        PasswordEntry entry;
        entry.service = row->fields[0];
        entry.username = row->fields[1];
        entry.password = row->fields[2];
        entry.totp_secret = (row->count >= 4) ? row->fields[3] : "";

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
void cli_list_entries();
void cli_add_entry();
void cli_view_entry();
void cli_edit_entry();
void cli_delete_entry();
void cli_import_csv(const char* filepath);
void cli_export_csv(const char* filepath);
void print_help();

void cli_health_check();

// --- Helper Functions ---

// A simple helper to read a line of input securely
void read_line(char *buf, int size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\r\n")] = 0; // Remove trailing newline
}

// --- CLI Implementation ---

void cli_list_entries() {
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

void cli_add_entry() {
    PasswordEntry entry;
    char service[256], username[256], password[256], totp[256];

    printf("Service: ");
    read_line(service, sizeof(service));
    printf("Username: ");
    read_line(username, sizeof(username));
    printf("Password: ");
    read_line(password, sizeof(password));
    printf("TOTP Secret (optional): ");
    read_line(totp, sizeof(totp));

    entry.service = service;
    entry.username = username;
    entry.password = password;
    entry.totp_secret = totp;

    if (database_add_entry(&entry) < 0) {
        fprintf(stderr, "Error: Could not add entry.\n");
    } else {
        printf("Entry added successfully.\n");
    }
}

void cli_view_entry() {
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
        printf("Service:  %s\n", target->service);
        printf("Username: %s\n", target->username);
        printf("Password: %s\n", target->password);
        if (target->totp_secret && strlen(target->totp_secret) > 0) {
            char* code = generate_totp_code(target->totp_secret);
            printf("TOTP:     %s\n", code ? code : "(invalid secret)");
            if(code) free(code);
        } else {
            printf("TOTP:     (none)\n");
        }
        printf("----------------\n");
    } else {
        fprintf(stderr, "Could not find entry with ID %d\n", id);
    }

    free_password_entries(entries, count);
}

void cli_delete_entry() {
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

void interactive_mode() {
    char choice;
    while (true) {
        printf("\n[l]ist, [a]dd, [v]iew, [e]dit, [d]elete, [g]enerate, [h]ealth-check, [i]mport, [e]xport, [q]uit\n");
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
                printf("Path to CSV file to import: ");
                read_line(path, sizeof(path));
                cli_import_csv(path);
                break;
            }
            case 'e': {
                char path[256];
                printf("Path to export CSV file: ");
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
    char *password = getpass("Enter master password: ");

    // --- Open Database ---
    char dbPath[1024];
    const char* configHome = getenv("XDG_CONFIG_HOME");
    if (configHome) {
        snprintf(dbPath, sizeof(dbPath), "%s/SecurePasswd_MGMT/vault.db", configHome);
    } else {
        snprintf(dbPath, sizeof(dbPath), "%s/.config/SecurePasswd_MGMT/vault.db", getenv("HOME"));
    }
    
    // This is a simplified way to ensure the directory exists.
    char dirPath[1024];
    strncpy(dirPath, dbPath, sizeof(dirPath));
    *strrchr(dirPath, '/') = '\0';
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dirPath);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to create directory: %s\n", dirPath);
    }

    if (database_open(dbPath, password) != 0) {
        fprintf(stderr, "Failed to open database. Check master password or file permissions.\n");
        sodium_memzero(password, strlen(password));
        return 1;
    }
    sodium_memzero(password, strlen(password));
    printf("Database opened successfully.\n");

    // --- Main Application Logic ---
    interactive_mode();

    // --- Cleanup ---
    database_close();
    printf("Database closed. Exiting.\n");

    return 0;
}

// Stubs for functions to be fully implemented
void cli_edit_entry() {
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
        char service[256], username[256], password[256], totp[256];

        printf("Service [%s]: ", target->service);
        read_line(service, sizeof(service));
        printf("Username [%s]: ", target->username);
        read_line(username, sizeof(username));
        printf("Password [%s]: ", target->password);
        read_line(password, sizeof(password));
        printf("TOTP Secret [%s]: ", target->totp_secret);
        read_line(totp, sizeof(totp));

        updated_entry.id = id;
        updated_entry.service = strlen(service) > 0 ? service : target->service;
        updated_entry.username = strlen(username) > 0 ? username : target->username;
        updated_entry.password = strlen(password) > 0 ? password : target->password;
        updated_entry.totp_secret = strlen(totp) > 0 ? totp : target->totp_secret;

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

void cli_import_csv(const char* filepath) {
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

void cli_export_csv(const char* filepath) {
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

    fprintf(fp, "service,username,password,totp_secret\n");
    for (int i = 0; i < count; i++) {
        fprintf(fp, "\"%s\",\"%s\",\"%s\",\"%s\"\n",
                entries[i].service, entries[i].username, entries[i].password, entries[i].totp_secret);
    }

    fclose(fp);
    free_password_entries(entries, count);
    printf("Exported %d entries to %s\n", count, filepath);
}

void cli_health_check() {
    printf("Performing password health check...\n");
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    if (!entries || count == 0) {
        printf("No entries to check.\n");
        return;
    }

    printf("\n--- Weak Passwords (less than 12 characters) ---\n");
    bool weak_found = false;
    for (int i = 0; i < count; i++) {
        if (strlen(entries[i].password) < 12) {
            printf("  [ID %d] %s - %s\n", entries[i].id, entries[i].service, entries[i].username);
            weak_found = true;
        }
    }
    if (!weak_found) {
        printf("No weak passwords found.\n");
    }

    // TODO: Implement reused password check.

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

void print_help() {
    printf("Usage: securepasswd_cli\n");
    printf("The application runs in interactive mode.\n");
}