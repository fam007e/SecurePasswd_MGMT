#include "password_generator.h"
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

char *generate_password(int len, bool upper, bool num, bool special) {
    if (sodium_init() < 0) {
        return NULL;
    }

    char *pw = malloc(len + 1);
    if (!pw) return NULL;

    const char *lower_set = "abcdefghijklmnopqrstuvwxyz";
    const char *upper_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *num_set = "0123456789";
    const char *special_set = "!@#$%^&*()";

    char charset[128] = "";
    strcat(charset, lower_set);

    int pos = 0;
    // Always include a lowercase
    pw[pos++] = lower_set[randombytes_uniform(strlen(lower_set))];

    if (upper) {
        strcat(charset, upper_set);
        if (pos < len) pw[pos++] = upper_set[randombytes_uniform(strlen(upper_set))];
    }
    if (num) {
        strcat(charset, num_set);
        if (pos < len) pw[pos++] = num_set[randombytes_uniform(strlen(num_set))];
    }
    if (special) {
        strcat(charset, special_set);
        if (pos < len) pw[pos++] = special_set[randombytes_uniform(strlen(special_set))];
    }

    // Fill the rest of the password
    for (; pos < len; pos++) {
        pw[pos] = charset[randombytes_uniform(strlen(charset))];
    }

    // Shuffle the password to avoid predictable positions
    for (int i = len - 1; i > 0; i--) {
        uint32_t j = randombytes_uniform(i + 1);
        char tmp = pw[i];
        pw[i] = pw[j];
        pw[j] = tmp;
    }

    pw[len] = '\0';
    return pw;
}
