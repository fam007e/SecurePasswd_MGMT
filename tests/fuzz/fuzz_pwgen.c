/* libFuzzer harness for the password generator.
 *
 * Exercises adversarial length arguments (0, 1, huge) and every charset
 * combination against the generator's buffer math. The generated password
 * must always have exactly the requested length and only characters from
 * the requested classes.
 *
 * Build/run: see fuzz_snapshot.c.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "password_generator.h"

static int in_class(char c, const char *set) {
    return strchr(set, c) != NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    int len = (int)(data[0] | (data[1] << 8)); /* 0..65535, adversarial */
    bool upper = data[2] & 0x01;
    bool num = data[2] & 0x02;
    bool special = data[2] & 0x04;
    (void)data[3];

    char *pw = generate_password(len, upper, num, special);
    if (!pw) return 0;

    /* flawfinder: ignore */
    if (strlen(pw) != (size_t)len) {
        abort(); /* length contract violation */
    }

    for (int i = 0; i < len; i++) {
        char c = pw[i];
        int ok = (c >= 'a' && c <= 'z') ||
                 (upper && c >= 'A' && c <= 'Z') ||
                 (num && c >= '0' && c <= '9');
        if (!ok && special) {
            ok = in_class(c, "!@#$%^&*()");
        }
        if (!ok) abort(); /* character outside requested classes */
    }

    memset(pw, 0, (size_t)len);
    free(pw);
    return 0;
}
