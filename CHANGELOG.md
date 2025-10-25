# Changelog

All notable changes to SecurePasswd_MGMT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to date-based versioning (YYYY.MM.DD).

## [Unreleased]

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