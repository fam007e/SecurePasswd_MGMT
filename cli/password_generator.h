#ifndef PASSWORD_GENERATOR_H
#define PASSWORD_GENERATOR_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

char *generate_password(int len, bool upper, bool num, bool special);

#ifdef __cplusplus
}
#endif

#endif // PASSWORD_GENERATOR_H
