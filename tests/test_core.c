#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h> // For unlink

#include "core/key_derivation.h"
#include "core/database.h"
#include "core/totp.h"
#include <sodium.h>
#include <stdlib.h>

const char* TEST_DB = "test_vault.db";

void test_database_lifecycle() {
    printf("--- Running Test: Database Lifecycle ---\n");

    // 1. Test opening and creating the database
    assert(database_open(TEST_DB, "test_password") == 0);
    printf("  [PASSED] database_open with correct key\n");

    // 2. Test adding an entry
    PasswordEntry entry = { .service = "TestService", .username = "TestUser", .password = "TestPass", .totp_secret = "JBSWY3DPEHPK3PXP" };
    int new_id = database_add_entry(&entry);
    assert(new_id > 0);
    printf("  [PASSED] database_add_entry\n");

    // 3. Test retrieving the entry
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    assert(count == 1);
    assert(entries[0].id == new_id);
    assert(strcmp(entries[0].service, "TestService") == 0);
    free_password_entries(entries, count);
    printf("  [PASSED] database_get_all_entries\n");

    // 4. Test updating the entry
    PasswordEntry updated_entry = { .id = new_id, .service = "UpdatedService", .username = "UpdatedUser", .password = "UpdatedPass", .totp_secret = "" };
    assert(database_update_entry(&updated_entry) == 0);
    entries = database_get_all_entries(&count);
    assert(count == 1);
    assert(strcmp(entries[0].service, "UpdatedService") == 0);
    free_password_entries(entries, count);
    printf("  [PASSED] database_update_entry\n");

    // 5. Test deleting the entry
    assert(database_delete_entry(new_id) == 0);
    entries = database_get_all_entries(&count);
    assert(count == 0);
    printf("  [PASSED] database_delete_entry\n");

    database_close();

    // 6. Test opening with wrong key
    assert(database_open(TEST_DB, "wrong_password") != 0);
    printf("  [PASSED] database_open with incorrect key fails\n");

    unlink(TEST_DB); // Clean up test database file
    printf("--- Test Complete ---\n\n");
}

void test_totp_generation() {
    printf("--- Running Test: TOTP Generation ---\n");
    // Test vector from RFC 6238 for SHA1
    // Secret: "12345678901234567890"
    // Time: 59
    // Expected code: 287082
    // Base32 of secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    char* code = generate_totp_code_at_time("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59);
    assert(strcmp(code, "287082") == 0);
    printf("  [PASSED] TOTP generation matches RFC 6238 test vector\n");
    free(code);
    printf("--- Test Complete ---\n\n");
}

int main() {
    test_database_lifecycle();
    test_totp_generation();

    printf("All tests passed!\n");
    return 0;
}