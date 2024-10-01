#ifndef CSV_HANDLER_H
#define CSV_HANDLER_H

int write_password(const char* account, const char* username, const char* password, const char* totp_secret);
char** read_passwords();
int import_passwords(const char* filename);
int export_passwords(const char* filename);

#endif // CSV_HANDLER_H