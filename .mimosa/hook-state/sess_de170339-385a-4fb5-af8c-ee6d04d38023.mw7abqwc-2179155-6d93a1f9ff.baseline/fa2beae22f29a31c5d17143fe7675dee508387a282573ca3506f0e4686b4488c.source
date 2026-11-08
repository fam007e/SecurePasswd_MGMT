/* libFuzzer harness for the TOTP engine.
 *
 * The base32 secret is attacker-shaped in practice: users paste secrets by
 * hand, CSV import and 2-way sync carry secrets verbatim, and the TOTP
 * validation gate runs on top of this decoder. Feeds arbitrary NUL-terminated
 * strings plus arbitrary timestamps into generate_totp_code_at_time(),
 * targeting the (secret_len * 5 + 7) / 8 allocation math, the base32
 * decoder's bounds, and the HMAC path.
 *
 * Build/run: see fuzz_snapshot.c.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "totp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 9 || size > 4096 + 8) return 0;

    /* Last 8 bytes: arbitrary timestamp (covers negative, 0, far future). */
    time_t t = 0;
    memcpy(&t, data + size - 8, sizeof(t));

    /* Everything before: the secret, forced NUL-terminated. */
    size_t secret_len = size - 8;
    char *secret = malloc(secret_len + 1);
    if (!secret) return 0;
    memcpy(secret, data, secret_len);
    secret[secret_len] = '\0';

    char *code = generate_totp_code_at_time(secret, t);
    if (code) {
        /* A produced code must be exactly 6 digits. */
        if (strlen(code) != 6) {
            abort(); /* contract violation, not just a crash */
        }
        for (int i = 0; i < 6; i++) {
            if (code[i] < '0' || code[i] > '9') abort();
        }
        free(code);
    }

    free(secret);
    return 0;
}
