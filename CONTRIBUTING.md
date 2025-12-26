# Contributing to SecurePasswd_MGMT

Thank you for your interest in contributing! We welcome contributions of all kinds, from bug reports and documentation improvements to new features and security enhancements.

## Security-Focused Development

Given the nature of this project, security is our top priority. All contributions must adhere to the following security guidelines:

- **No Plaintext Secrets:** Usernames, passwords, and TOTP secrets must be encrypted when stored. No sensitive information should ever be written to disk in plaintext.
- **Use Established Cryptographic Libraries:** All cryptographic operations must be implemented using well-vetted, modern libraries. This project uses **SQLCipher** for database encryption and **libargon2** for key derivation. Do not implement custom cryptographic primitives.
- **Secure Memory Handling:** Sensitive data must be cleared from memory as soon as it is no longer needed. Use `sodium_memzero()` or a similar secure function to overwrite sensitive data in memory.
- **Input Validation:** All input from users or files must be validated to prevent vulnerabilities like buffer overflows. **Avoid banned C functions like `strcat`, `strcpy`, and `sprintf`; use safer, bounded alternatives like `strncat`, `strncpy`, and `snprintf`.**
- **Constant-Time Operations:** When comparing sensitive data, use constant-time comparison functions where appropriate to prevent timing attacks.

## Code Review

All pull requests, especially those that touch security-sensitive code in the `core/` directory, will undergo a thorough code review. Be prepared to explain your changes and justify your design decisions.

## Coding Style

To maintain a consistent and readable codebase, we adhere to the following coding style guidelines:

- **Brace Style:** Allman style (braces on new lines).
  ```c
  if (condition)
  {
      // ...
  }
  ```
- **Indentation:** 4 spaces.
- **Line Length:** 80 characters.
- **Naming Conventions:**
  - Functions: `snake_case` (e.g., `database_open()`)
  - Variables: `snake_case` (e.g., `db_path`)
  - Structs: `PascalCase` (e.g., `PasswordEntry`)
  - Enums: `PascalCase`
  - Macros: `UPPER_CASE_SNAKE_CASE` (e.g., `KEY_LEN`)
- **Comments:** Use `//` for single-line comments and `/* ... */` for multi-line comments. Explain *why* you are doing something, not *what* you are doing.

## Testing

- **Unit Tests:** All new features should be accompanied by unit tests. The project uses CTest to manage and run tests.
- **Cryptographic Testing:** Any changes to cryptographic functions must be accompanied by tests that verify the correctness of the implementation.
- **Static Analysis:** Contributors are expected to run `cppcheck` and `flawfinder` on their changes to ensure no new security or logic warnings are introduced.
  ```bash
  cppcheck --enable=all --suppress=missingIncludeSystem cli/ core/
  flawfinder .
  ```
- **Runtime Sanitizers:** It is recommended to build and test with sanitizers enabled to catch runtime errors.
  ```bash
  cmake -DCMAKE_C_FLAGS="-fsanitize=address,undefined" ..
  make && ctest
  ```

## How to Contribute

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes, adhering to the security guidelines above.
4.  Add or update tests in the `tests/` directory and ensure they pass by running `ctest` in the `build` directory.
5.  Submit a pull request.

## Release Guidelines

To create a new release:

1.  **Create Git Tag:** Create an annotated Git tag in the format `vYYYY.MM.DD` (e.g., `v2025.10.19`).
2.  **Push the tag:** Push the tag to the `main` branch.
3.  **Generate Packages:** The CI/CD pipeline will automatically build and generate platform-specific packages (deb, Arch, Windows, macOS) upon pushing a new tag. These will be available on the GitHub Releases page.
