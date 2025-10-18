#include "password_generator.h"
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

char *generate_password(int len, bool upper, bool num, bool special) {
    if (sodium_init() < 0) {
        return NULL;
    }

    char charset[128] = "abcdefghijklmnopqrstuvwxyz";
    if (upper) strcat(charset, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (num) strcat(charset, "0123456789");
    if (special) strcat(charset, "!@#$%^&*()");

    char *pw = malloc(len + 1);
    if (!pw) return NULL;

    for (int i = 0; i < len; i++) {
        pw[i] = charset[randombytes_uniform(strlen(charset))];
    }
    pw[len] = '\0';
    return pw;
}
