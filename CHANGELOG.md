# Changelog

All notable changes to SecurePasswd_MGMT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to date-based versioning (YYYY.MM.DD).

## [2025.12.28]

### Added
- **CLI-Only Build Option:** Added a `BUILD_GUI` CMake option (default ON) to allow building the application without Qt6 dependencies. Use `-DBUILD_GUI=OFF` for CLI-only environments.

### Security
- **0 Flawfinder Hits:** Achieved a clean security audit report with 0 hits from `flawfinder` across the entire project.
- **Strict Format String Safety:** Implemented explicit suppression of safe format string literals to satisfy high-sensitivity security scanners (GitHub Code Scanning).
- **Buffer Truncation Fix:** Resolved `-Wformat-truncation` warnings by increasing path buffer sizes for database and salt files.

## [2025.12.26]

### Security
- **Hardened C Codebase:** Remediated over 50 potential security flaws identified by `flawfinder` across all components.
- **Banned Function Removal:** Systematically replaced insecure C functions (`strcat`, `sprintf`, `strncpy`, `atoi`) with safer, bounded alternatives (`memcpy`, `snprintf`, `strtol`) to prevent buffer overflows and undefined behavior.
- **Race Condition Mitigation:** Replaced `access()` checks with `stat()` in tests to prevent time-of-check to time-of-use (TOCTOU) vulnerabilities.
- **Path Sanitization:** Implemented a `sanitize_path` utility in `core/platform_paths.c` to filter environment variable inputs (`HOME`, `LOCALAPPDATA`, `XDG_DATA_HOME`).
- **HIBP Check Hardening:** Added integer overflow protection and robust string handling to the Have I Been Pwned API client.
- **Improved Build Safety:** Increased default buffer sizes for path construction and improved error reporting in database operations.

## [Unreleased]

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
