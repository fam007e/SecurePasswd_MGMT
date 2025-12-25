# Changelog

All notable changes to SecurePasswd_MGMT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to date-based versioning (YYYY.MM.DD).

## [Unreleased]

### Security
- **Buffer Overflow Protection:** Replaced unsafe `strcat` usage with safer memory operations in CLI view logic to prevent potential buffer overflows.
- **Secure Input:** Replaced standard input reading with `getpass` in the CLI to prevent sensitive data (passwords, TOTP secrets) from being echoed to the console.
- **Path Traversal Mitigation:** Added validation to CSV import/export functions to reject file paths containing `..`, preventing directory traversal attacks.
- **Crypto Modernization:** Updated the Have I Been Pwned (HIBP) check to use the modern OpenSSL `EVP_Digest` API, replacing the deprecated `SHA1` function.
- **Undefined Behavior Fixes:** Resolved signed integer overflow and misaligned memory access issues in TOTP generation (`core/totp.c`) identified by UBSan.
- **Memory Safety:** Fixed a memory leak in the HIBP check (`core/pwned_check.c`) and ensured proper memory management in CLI operations.
- **Robustness:** Added NULL checks for environment variables (`HOME`, `LOCALAPPDATA`) in `core/platform_paths.c` to prevent undefined behavior in restricted environments.

### Refactor
- **Encapsulation:** Applied `static` linkage to internal CLI functions to improve code structure and reduce namespace pollution.

### Development
- **Static Analysis:** Integrated `cppcheck` into the development workflow to catch static analysis issues.
- **Sanitizers:** Verified codebase stability using AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan).

## [2025.12.20]

### Added
- **2FA Recovery Codes:** Added support for managing 2FA recovery codes in both GUI and CLI.
- **Recovery Toggle:** Added a visual toggle in the GUI for recovery codes with dynamic icons.
- **Secure Exit:** Added a dedicated exit action with a custom SVG icon.
- **Password Entropy:** Guaranteed character diversity in the password generator using a secured Fisher-Yates shuffle.

### Changed
- **GUI Refinement:** Transitioned to a modern, icon-only toolbar UI; removed text-based menus.
- **Core Architecture:** Relocated password generator to the core library for better modularity.
- **CLI Parity:** Achieved full feature parity with the GUI, including interactive editing and recovery codes.

### Fixed
- **GUI Stability:** Resolved a segmentation fault caused by uninitialized menu pointers.
- **TOTP Display:** Fixed the "stuck" state of the TOTP progress bar when switching entries.
- **Theme Persistence:** Improved the consistency of theme loading and saving.

---

## [2025.10.25]

### Added
- **Desktop Integration:** Added desktop integration for Linux (`.desktop` file) and improved the Windows installer.
- **GUI Icon:** Added a proper application icon for the Windows GUI executable.

### Changed
- **Cross-Platform Compatibility:** Enhanced cross-platform path handling, particularly for Windows.
- **Database Path:** Unified the database path for both the CLI and GUI applications to ensure consistency.

### Fixed
- **Windows GUI:** Removed the console window that appeared when running the GUI application on Windows.
- **TOTP Display:** Fixed issues with TOTP code display.
- **CI:** Addressed a CI issue by reinstalling `pcre2`.

---

## Version History

For releases and version history, see [GitHub Releases](https://github.com/fam007e/SecurePasswd_MGMT/releases).

---

## Categories Legend

- **Added:** New features
- **Changed:** Changes in existing functionality
- **Deprecated:** Soon-to-be removed features
- **Removed:** Removed features
- **Fixed:** Bug fixes
- **Security:** Vulnerability fixes and security enhancements
