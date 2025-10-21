#include <stdlib.h>
#include <stdio.h>
#include "core/pwned_check.h"
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <io.h> // For _access
#define access _access
#endif
#include <string.h>
#include "core/key_derivation.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "cli/password_generator.h"

static void test_generate_password_length(void **state) {
    (void) state; /* unused */
    char *password = generate_password(16, true, true, true);
    assert_non_null(password);
    assert_int_equal(strlen(password), 16);
    free(password);
}

static void test_generate_password_charset(void **state) {
    (void) state; /* unused */
    char *password = generate_password(32, false, false, false);
    assert_non_null(password);
    for (int i = 0; i < strlen(password); i++) {
        assert_in_range(password[i], 'a', 'z');
    }
    free(password);

    password = generate_password(32, true, false, false);
    assert_non_null(password);
    bool has_upper = false;
    for (int i = 0; i < strlen(password); i++) {
        if (password[i] >= 'A' && password[i] <= 'Z') {
            has_upper = true;
            break;
        }
    }
    assert_true(has_upper);
    free(password);
}

static void test_derive_key(void **state) {
    (void) state; /* unused */
    uint8_t key[KEY_LEN];
    uint8_t salt[SALT_LEN];
    memset(salt, 0, SALT_LEN);
    int result = derive_key("password", salt, key);
    assert_int_equal(result, 0);
}

static void test_load_or_generate_salt(void **state) {
    (void) state; /* unused */
    uint8_t salt[SALT_LEN];
    const char* salt_path = "test.salt";
    int result = load_or_generate_salt(salt_path, salt);
    assert_int_equal(result, 0);
    assert_true(access(salt_path, F_OK) == 0);
    uint8_t salt2[SALT_LEN];
    result = load_or_generate_salt(salt_path, salt2);
    assert_int_equal(result, 0);
    assert_memory_equal(salt, salt2, SALT_LEN);
    remove(salt_path);
}

static void test_is_password_pwned(void **state) {
    (void) state; /* unused */
    // This test makes a real network request and may be slow.
    int pwn_count = is_password_pwned("password");
    assert_true(pwn_count > 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_generate_password_length),
        cmocka_unit_test(test_generate_password_charset),
        cmocka_unit_test(test_derive_key),
        cmocka_unit_test(test_load_or_generate_salt),
        cmocka_unit_test(test_is_password_pwned),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
