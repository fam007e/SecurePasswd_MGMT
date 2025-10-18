# Security Policy

## Table of Contents
- [Security Overview](#security-overview)
- [Cryptographic Implementation](#cryptographic-implementation)
- [Data Protection](#data-protection)
- [Memory Management](#memory-management)
- [File System Security](#file-system-security)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)

## Security Overview

SecurePasswd_MGMT is designed with security-first principles and implements defense-in-depth strategies using modern, vetted cryptographic libraries. This document outlines the comprehensive security measures implemented to protect user data.

### Security Goals
- **Confidentiality:** Protect sensitive data using state-of-the-art authenticated encryption.
- **Integrity:** Ensure data has not been tampered with.
- **Privacy:** Local-only storage with no network dependencies.

## Cryptographic Implementation

### Encryption
- **Algorithm:** AES-256
- **Details:** The database is encrypted using SQLCipher, which uses AES-256 in CBC mode by default.
- **Library:** **SQLCipher**, a widely-used, open-source library that provides transparent 256-bit AES encryption of SQLite database files.

### Key Derivation Function (KDF)
**Specifications:**
- **Algorithm:** **Argon2id**
- **Details:** Argon2 is the winner of the Password Hashing Competition (2015) and is widely considered the best-in-class KDF. The `id` variant provides a hybrid approach that is resistant to both side-channel and GPU cracking attacks.
- **Library:** The official `libargon2` reference implementation.
- **Parameters:** Secure defaults are used for memory cost, time cost, and parallelism to make brute-force attacks computationally infeasible.

### Random Number Generation
- **Source:** Libsodium's `randombytes_buf()` function.
- **Usage:** Salt generation for Argon2.
- **Quality:** Uses the operating system's best available Cryptographically Secure Pseudorandom Number Generator (CSPRNG), such as `/dev/urandom`.

## Data Protection

### Master Password Security Flow

```mermaid
graph TD
    A[User Input] --> B[Master Password]
    B --> C{Salt File Exists?}
    C -- Yes --> D[Load Salt]
    C -- No --> E[Generate and Save Salt]
    D --> F[Argon2id Key Derivation]
    E --> F
    F --> G[32-byte Encryption Key Generated]
    G --> H[SQLCipher Encrypted Database]
```

### Data Storage Format
- **Salt File (`vault.db.salt`):** Stores the unique salt used for key derivation. This file is created in the same directory as the database.
- **Database File (`vault.db`):** An encrypted SQLite database containing all the user's data. The encryption is handled by SQLCipher.

## Memory Management

Sensitive data (master password, derived keys, plaintext data) is explicitly cleared from memory as soon as it is no longer needed using `sodium_memzero()` or a similar secure memory wiping function.

## File System Security

- **Secure Permissions:** The application data directory is created with the most restrictive permissions possible (`0700` on Unix-like systems), ensuring only the owner can access it.
- **Default Location:** Data is stored in a standard, OS-specific location (`~/.config/SecurePasswd_MGMT` on Linux, `%APPDATA%\SecurePasswd_MGMT` on Windows) to avoid cluttering user directories.

## Secure Build Process

The project uses **CMake**, a modern and cross-platform build system generator. Security is a primary consideration in the build process.

- **Dependency Management:** CMake's `find_package` and `pkg_check_modules` are used to locate required libraries like Libsodium, Argon2, and SQLCipher, ensuring they are present before building.
- **Compiler Flags:** Security hardening flags (e.g., `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Wl,-z,relro`) are explicitly set in the `CMakeLists.txt` for production builds.

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1.  **DO NOT** open a public GitHub issue.
2.  Contact the maintainer directly via a secure channel or use GitHub's private vulnerability reporting feature.
3.  Provide detailed steps to reproduce the vulnerability.

*This security policy is a living document and will be updated as the project evolves.*
