# Contributing to SecurePassManager

Thank you for your interest in contributing to SecurePassManager! We welcome contributions of all kinds, from bug reports and documentation improvements to new features and security enhancements.

## Security-Focused Development

Given the nature of this project, security is our top priority. All contributions must adhere to the following security guidelines:

- **No Plaintext Secrets:** Usernames, passwords, and TOTP secrets must be encrypted when stored. No sensitive information should ever be written to disk in plaintext.
- **Use Established Cryptographic Libraries:** All cryptographic operations must be implemented using well-vetted libraries like OpenSSL. Do not implement custom cryptographic primitives.
- **Secure Memory Handling:** Sensitive data must be cleared from memory as soon as it is no longer needed. Use `memset()` or a similar function to overwrite sensitive data in memory.
- **Input Validation:** All input from users or files must be validated to prevent vulnerabilities like buffer overflows.
- **Constant-Time Operations:** When comparing sensitive data (e.g., password hashes), use constant-time comparison functions to prevent timing attacks.

## Code Review

All pull requests, especially those that touch security-sensitive code, will undergo a thorough code review. Be prepared to explain your changes and justify your design decisions.

## Testing

- **Unit Tests:** All new features should be accompanied by unit tests.
- **Cryptographic Testing:** Any changes to cryptographic functions must be accompanied by tests that verify the correctness of the implementation.
- **Security Regression Tests:** We aim to build a suite of security regression tests to prevent old vulnerabilities from reappearing.

## How to Contribute

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes, adhering to the security guidelines above.
4. Add or update tests as needed.
5. Submit a pull request.