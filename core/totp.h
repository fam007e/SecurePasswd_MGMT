#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generates a 6-digit TOTP code from a base32-encoded secret.
// The caller is responsible for freeing the returned string.
char* generate_totp_code(const char *base32_secret);

// Generates a 6-digit TOTP code from a base32-encoded secret for a specific time.
// The caller is responsible for freeing the returned string.
char* generate_totp_code_at_time(const char *base32_secret, time_t current_time);

#ifdef __cplusplus
}
#endif

#endif // TOTP_H
