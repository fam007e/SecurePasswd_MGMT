# Security Policy

## Supported Versions

SecurePassManager is currently in its initial release phase. We are committed to providing security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2024.10.01.01 | :white_check_mark: |
| < 2024.10.01.00 | :x:                |

## Reporting a Vulnerability

We take the security of SecurePassManager seriously. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us responsibly.

### Reporting Process

1. **Do not report security vulnerabilities through public GitHub issues.**

2. Please send an email to [@securepassmanager](mailto:faisalmoshiur+secpasswd@gmail.com) with the subject line "SecurePassManager Security Vulnerability".

3. Include the following details in your report:
   - Type of issue (e.g., buffer overflow, encryption weakness, etc.)
   - Full paths of source file(s) related to the issue
   - The location of the affected source code (tag/branch/commit or direct URL)
   - Any special configuration required to reproduce the issue
   - Step-by-step instructions to reproduce the issue
   - Proof-of-concept or exploit code (if possible)
   - Impact of the issue, including how an attacker might exploit it

4. Allow up to 48 hours for an initial response to your report.

### What to expect

- A response acknowledging your report within 48 hours.
- An evaluation of the reported vulnerability.
- A plan for addressing the vulnerability, if confirmed.
- A public disclosure after the vulnerability has been addressed.

We appreciate your efforts and will make every effort to acknowledge your contributions.

## Security Measures in SecurePassManager

SecurePassManager implements the following security measures:

### Encryption

- AES-256 encryption in GCM mode for all stored data.
- Encryption keys are derived from the user's master password using a secure key derivation function.

### Key Derivation

- PBKDF2-HMAC-SHA256 with a minimum of 100,000 iterations.
- A unique salt is generated for each user to prevent rainbow table attacks.

### Memory Protection

- Sensitive data (e.g., master password, encryption keys) is securely wiped from memory after use.
- We use `mlock()` to prevent sensitive memory pages from being swapped to disk.

### Input Validation and Sanitization

- All user inputs are validated and sanitized to prevent injection attacks and buffer overflows.
- We use prepared statements for any operations involving user input.

### Local Operation

- SecurePassManager operates entirely locally, with no network communication, eliminating risks associated with data transmission.

### Secure Random Number Generation

- We use cryptographically secure random number generators (provided by OpenSSL) for all security-critical operations.

### Version Control and Code Signing

- All releases are tagged and signed with GPG keys.
- We provide checksums for all released binaries.

## Best Practices for Users

To maximize security when using SecurePassManager:

1. Use a strong, unique master password (we recommend at least 16 characters).
2. Never share your master password or store it in plain text.
3. Regularly update to the latest version of SecurePassManager.
4. Use full-disk encryption on your device.
5. Be cautious when exporting password data and securely delete any exported files when no longer needed.

## Third-Party Libraries

SecurePassManager uses the following third-party libraries:

- OpenSSL 3.3.0 or later: For cryptographic operations
- liboath 2.6.7 or later: For TOTP functionality

We monitor these dependencies for security updates and incorporate them promptly.

## Security Audits

We are open to independent security audits. If you're interested in conducting a security audit, please contact us at [audit@securepassmanager](mailto:faisalmoshiur+secpasswdaudit@gmail.com).

## Threat Model

SecurePassManager is designed to protect against:

1. Unauthorized access to the password database file
2. Memory dumping attacks
3. Brute-force attacks on the master password
4. Tampering with the application binary

It does not protect against:

1. Malware on the user's system
2. Physical access to the user's unlocked device
3. Weakness of individual passwords stored in the database

## Disclaimer

While we strive for the highest level of security, no system is 100% secure. Users should use SecurePassManager as part of a comprehensive security strategy.

---

This security policy is subject to change. Please check regularly for updates.

Last updated: 2024.10.02
