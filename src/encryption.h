#ifndef ENCRYPTION_H
#define ENCRYPTION_H

int init_encryption(const char* master_password);
char* encrypt_password(const char* password);
char* decrypt_password(const char* encrypted_password);
void cleanup_encryption();

#endif // ENCRYPTION_H