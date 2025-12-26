#include <stdio.h>
#include <assert.h>
#include <string.h>
#ifndef _MSC_VER
#include <unistd.h> // For unlink
#else
#include <io.h> // For _unlink
#define unlink _unlink
#endif

#include "core/key_derivation.h"
#include "core/database.h"
#include "core/totp.h"
#include <sodium.h>
#include <stdlib.h>

const char* TEST_DB = "test_vault.db";

static void test_database_lifecycle() {
    printf("--- Running Test: Database Lifecycle ---\n");

    // 1. Test opening and creating the database
    assert(database_open(TEST_DB, "test_password") == 0);
    fputs("  [PASSED] database_open with correct key\n", stdout);

    // 2. Test adding an entry
    PasswordEntry entry = { .service = "TestService", .username = "TestUser", .password = "TestPass", .totp_secret = "JBSWY3DPEHPK3PXP", .recovery_codes = "CODE1\nCODE2" };
    int new_id = database_add_entry(&entry);
    assert(new_id > 0);
    fputs("  [PASSED] database_add_entry\n", stdout);

    // 3. Test retrieving the entry
    int count = 0;
    PasswordEntry *entries = database_get_all_entries(&count);
    assert(count == 1);
    assert(entries != NULL);
    assert(entries[0].id == new_id);
    assert(strcmp(entries[0].service, "TestService") == 0);
    assert(strcmp(entries[0].recovery_codes, "CODE1\nCODE2") == 0);
    free_password_entries(entries, count);
    fputs("  [PASSED] database_get_all_entries\n", stdout);

    // 4. Test updating the entry
    PasswordEntry updated_entry = { .id = new_id, .service = "UpdatedService", .username = "UpdatedUser", .password = "UpdatedPass", .totp_secret = "", .recovery_codes = "NEWCODE" };
    assert(database_update_entry(&updated_entry) == 0);
    entries = database_get_all_entries(&count);
    assert(count == 1);
    assert(entries != NULL);
    assert(strcmp(entries[0].service, "UpdatedService") == 0);
    assert(strcmp(entries[0].recovery_codes, "NEWCODE") == 0);
    free_password_entries(entries, count);
    fputs("  [PASSED] database_update_entry\n", stdout);

    // 5. Test deleting the entry
    assert(database_delete_entry(new_id) == 0);
    entries = database_get_all_entries(&count);
    assert(count == 0);
    assert(entries == NULL);
    fputs("  [PASSED] database_delete_entry\n", stdout);

    // 6. Test deleting non-existent entry (should fail)
    assert(database_delete_entry(9999) != 0);
    fputs("  [PASSED] database_delete_entry fails for non-existent entry\n", stdout);

    // 7. Test deleting already-deleted entry (should fail)
    assert(database_delete_entry(new_id) != 0);
    fputs("  [PASSED] database_delete_entry fails for already-deleted entry\n", stdout);

    database_close();

    // 8. Test opening with wrong key
    assert(database_open(TEST_DB, "wrong_password") != 0);
    fputs("  [PASSED] database_open with incorrect key fails\n", stdout);

    unlink(TEST_DB); // Clean up test database file
    fputs("--- Test Complete ---\n\n", stdout);
}

static void test_totp_generation() {
    printf("--- Running Test: TOTP Generation ---\n");
    // Test vector from RFC 6238 for SHA1
    // Secret: "12345678901234567890"
    // Time: 59
    // Expected code: 287082
    // Base32 of secret: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    char* code = generate_totp_code_at_time("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59);
    assert(strcmp(code, "287082") == 0);
    fputs("  [PASSED] TOTP generation matches RFC 6238 test vector\n", stdout);
    free(code);
    fputs("--- Test Complete ---\n\n", stdout);
}

int main() {
    test_database_lifecycle();
    test_totp_generation();

    printf("All tests passed!\n");
    return 0;
}
