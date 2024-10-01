#ifndef TOTP_H
#define TOTP_H

char* generate_totp(const char* secret);
int setup_totp(const char* account, const char* secret);
char* generate_totp_for_account(const char* account);

#endif // TOTP_H