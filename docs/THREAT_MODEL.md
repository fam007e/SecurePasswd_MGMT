# Threat Model

This document outlines the threat model for the SecurePasswd_MGMT application based on the STRIDE methodology.

## STRIDE Methodology

STRIDE is a threat modeling methodology that helps to identify and categorize threats. It stands for:

- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

---

### Spoofing

**Threat:** An attacker could try to create a fake master password prompt to capture the user's master password.

**Countermeasure:** SecurePasswd_MGMT is a local client-side application. The user is in control of launching the application, which significantly reduces the risk of a spoofed prompt. The user should ensure they are running the legitimate application from a trusted location.

---

### Tampering

**Threat:** An attacker with local access to the user's machine could try to tamper with the encrypted database file (`vault.db`) to corrupt data or gain unauthorized access.

**Countermeasure:** The database is encrypted using SQLCipher, which employs an authenticated encryption scheme (AES-256 in CBC mode with HMAC-SHA1). This ensures both the confidentiality and integrity of the data. Any tampering with the database file will be detected by the HMAC, and the application will fail to open the database.

---

### Repudiation

**Threat:** A user could theoretically deny having added or modified a password entry.

**Countermeasure:** The application does not have a strong notion of user identity beyond the master password and does not maintain a detailed audit trail of user actions. For a local, single-user password manager, this is considered a low-risk threat. The primary goal is to protect the user's data from unauthorized access, not to provide non-repudiation.

---

### Information Disclosure

**Threat:** An attacker could gain access to the user's stored passwords and TOTP secrets.

**Countermeasures:**
- **Encryption at Rest:** The entire database is encrypted at rest using AES-256. The encryption key is derived from the user's master password using Argon2id, a strong and slow key derivation function.
- **Master Password Not Stored:** The master password is never stored on disk.
- **Secure Memory Handling:** The derived encryption key is cleared from memory after use with the `sodium_memzero()` function to prevent it from being exposed in a memory dump.
- **Restrictive File Permissions:** The application data directory is created with restrictive permissions (`0700` on Unix-like systems) to prevent other users on the system from accessing the database file.

---

### Denial of Service

**Threat:** An attacker could delete the `vault.db` or `vault.db.salt` files, making the user's passwords inaccessible.

**Countermeasure:** This is a general threat for any local application. The user is responsible for backing up their important data, including the password database and salt file.

**Threat:** An attacker could attempt to brute-force the master password.

**Countermeasure:** The use of Argon2id as the key derivation function makes brute-force attacks computationally expensive and slow, significantly increasing the time and resources required for a successful attack.

---

### Elevation of Privilege

**Threat:** A vulnerability in the application's code could allow an attacker to execute arbitrary code with the privileges of the application.

**Countermeasures:**
- **Secure Build Process:** The application is built with security hardening flags (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro,-z,now`) to mitigate common vulnerabilities like buffer overflows and memory corruption.
- **Modern C/C++:** The codebase uses modern C/C++ practices and avoids dangerous functions where possible.
- **Input Validation:** The application performs input validation to prevent vulnerabilities like buffer overflows and format string bugs (though this is an area for continuous improvement).
