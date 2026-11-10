# Changelog

All notable changes to SecurePasswd_MGMT will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to date-based versioning (YYYY.MM.DD).

## [2026.11.10]

### Fixed
- **Health Check crash:** Closing the Password Health Check dialog while the Have I Been Pwned check was still running crashed the app (use-after-free in the background worker). The worker no longer touches the dialog after it is destroyed and stops promptly. (Latent since the HIBP feature landed.)
- **Sync merge hardening:** The OpenPGP key-store merge (`sync_merge_gpg_keys`) now symmetrically guards NULL key labels in both identity-lookup loops, the GPG tombstone lookup rejects NULL labels, and identity-less keys are never propagated during a merge — closing all paths flagged by a deep static-analysis scan.
- **QSS theme loading:** Switched from `QFile` filesystem read to `QResource` for the QSS template, eliminating the CWE-362 race condition flagged by code-scanning alert #525 (FF1040) — zero filesystem surface.
- **`cppcheck` struct warnings:** Resolved `uninitMemberVarNoCtor` warnings across GUI headers (`Palette::id/name`, `GUIPasswordEntry::id`, `PwnedResult::pwnCount`) with in-class default member initializers.
- **List navigation UX:** First account entry auto-selected on load and after search; Tab goes directly from search bar to account list; Down Arrow / Enter from search jumps to the list.

### Changed
- **Scanner hygiene:** All 18 Flawfinder code-scanning alerts verified as false positives and annotated in code with per-site justifications (comparison-only pointer arrays, constant format strings, generator-owned strings, provably-bounded test copies, Qt resource paths).

### Added
- **Keyboard shortcuts:** Comprehensive shortcuts across all GUI views — toolbar (`Alt+K` GPG keys, `Alt+Shift+P` palette, `Alt+Shift+M` mark used), list (`Enter`/double-click edit, `Delete` remove, `Esc` clear search, `Down`/`Enter` jump from search), dialogs (`Ctrl+S` save, `Ctrl+N` new key, `Ctrl+Shift+C` copy key, `Alt+G` generate, `Ctrl+C` copy sync code, `Alt+R` recovery codes), and `&` mnemonics in the Password Generator.
- **Keyboard Shortcuts Reference:** New section in `docs/USER_GUIDE.md` documenting every shortcut.
- **Fuzzing:** New `fuzz_gpgmerge` harness (libFuzzer + ASan/UBSan) covering the SPSNAP03 key-store parser, the merge engine on hostile input, tombstone cross-application, and serialize/re-parse round-trips.
- **Tests:** cmocka contract test for NULL-label merge inputs; CI Cppcheck gate stays at zero findings.

## [2026.11.08]

### Added
- **Two-Way Mobile Sync (v2):** Complete rewrite of mobile sync as an interactive, mutually-authenticated session: 512-bit pairing secret (vsync2 QR), ephemeral X25519 + HKDF-SHA256 key derivation bound to the handshake transcript, ChaCha20-Poly1305 frames with sequence-number nonces and type-bound AAD, key-confirmation exchange, and deterministic newer-wins merge with deletion tombstones (`updated_at` column + `deleted_entries` table).
- **OpenPGP Key Storage:** Armored public/secret GPG keys as first-class vault records (`gpg_keys` table) with a desktop manager dialog and full 2-way sync support via the SPSNAP03 key-store section (`SYNC_FRAME_GPG`).
- **Color Palettes:** Three curated palettes (Nord, Dracula, Solarized), each with dark and light variants, selected from an exclusive-checkmark toolbar menu; themes are generated from a token template (`theme_template.qss` + `gui/themes.cpp`).
- **Tri-State Theme:** Follow System / Light / Dark menu replaces the binary toggle; the OS color scheme is followed live (Qt 6.5 `colorSchemeChanged`) and legacy `theme` settings migrate.
- **Configurable Sync Port:** Preferred LAN port persisted per session with automatic fallback and re-bind handling.
- **libFuzzer Targets:** Four fuzz harnesses (snapshot parser, AEAD frames, TOTP engine, password generator — with output-contract assertions) running in CI under ASan/UBSan; the snapshot harness also self-merges hostile records.
- **F-Droid Reproducibility (Android):** Gradle dependency verification (871 pinned artifacts, strict CI), wrapper checksum pin, two-build byte-identity verification, published SHA256SUMS, hardened CSPRNG shim (getrandom, bias-free rejection sampling), OpenSSL bumped to 3.3.7.
- **Android Feature Parity:** Two-way sync client, OpenPGP key screen, color palettes, tri-state theme cycle, alphabet fast-scroller, themed splash screen, app-icon masquerading (5 launcher aliases incl. a black & white minimalist variant and Calculator/Notes/Files disguises).

### Changed
- **DESIGN_TOKENS.md:** Shared design contract (palettes, shapes, behavior, copy) mirrored across both repositories.
- **Sync Summary Format:** Cross-platform one-line result summary (`Added X · Updated Y · Deleted Z · Conflicts W`).
- **Icons:** New palette and key glyphs; theme/recovery/exit icons recolored to `currentColor` for correct contrast in both themes.

### Removed
- **One-Shot Sync Protocol:** The legacy `vsync:` encrypted-dump sync (`sync_service.c`) is removed; old clients are rejected with an update prompt (breaking change — desktop and Android must ship together).

### Fixed
- **Session Cleanup:** Pairing secret and ephemeral keys are wiped on dialog close; a 30s inactivity timeout aborts stalled sessions; the ERROR frame is now actually delivered to the mobile side.
- **Key Confirmation:** Constant-time comparison (`sync_ct_equal`) for the transcript check.
- **Windows Build:** `sync_protocol.c` guards `<strings.h>` for MSVC.
- **Silent Docs Exclusion:** `.gitignore`'s blanket `docs/` rule had excluded `DESIGN_TOKENS.md` from the repository.

## [2026.11.03]

### Added
- **OSSign Code Signing Automation:** Added `.github/workflows/request-signing.yml` to trigger automated Authenticode code signing via OSSign trusted workflows on version tag releases.
- **CPack License Resource:** Added `CPACK_RESOURCE_FILE_LICENSE` to display the project license during Windows NSIS installer setup.
- **Seamless Windows Upgrades:** Configured `CPACK_PACKAGE_INSTALL_DIRECTORY` and `CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL` in `CMakeLists.txt` to replace older versions cleanly and prevent duplicate directory accumulation.

### Changed
- **Dependencies Baseline:** Updated vcpkg `builtin-baseline` to release `2026.10.16` (`9eec002df1cd109f8f104cd966a763daf9751489`) for latest security patches across OpenSSL, curl, and SQLCipher.
- **Issue & PR Templates:** Hardened GitHub issue templates and pull request templates, removing generic mobile/web fields in favor of desktop-specific diagnostics (CLI/GUI, OS, install package).
- **Discord Notification Workflow:** Hardened webhook payloads with `allowed_mentions` protection, link markdown sanitization, and graceful skips on forks.

### Fixed
- **Uninstaller Start Menu Leftovers:** Corrected NSIS icon deletion variable to `$MUI_TEMP` in `CPACK_NSIS_DELETE_ICONS_EXTRA`, ensuring Start Menu shortcuts and folders are completely removed upon uninstallation.
- **TOTP Empty/Invalid Key Handling:** Fixed `generate_totp_code_at_time` in `core/totp.c` to reject zero-length and non-base32 secrets, preventing spurious TOTP codes from displaying for entries without a 2FA secret.
- **CI Dependency Consistency:** Aligned Windows vcpkg setup in `.github/workflows/release.yml` with the manifest's `builtin-baseline`.

## [2026.06.05]

### Added
- **Linux PNG Icon:** Added installation of a 64x64 PNG icon to `${CMAKE_INSTALL_DATADIR}/icons/hicolor/64x64/apps` for better integration with Linux desktop environments that may not support SVG icons natively.
- **Documentation Hardening:** Improved Doxygen documentation coverage for GUI and Core components, fixed Markdown rendering issues in generated HTML, and expanded `IMAGE_PATH` to resolve broken icons in API docs.

### Changed
- **CMake Cleanup:** Cleaned up redundant whitespace in `gui/CMakeLists.txt` for better maintainability.

## [2026.05.30]

### Fixed
- **LAN IP Detection:** Improved local network IP detection for synchronization and standardized on port `33261` with automatic fallback.
- **Static Analysis:** Refactored raw loops to `std::find_if` in synchronization logic to improve code readability and satisfy `cppcheck` requirements.

## [2026.05.16]

### Fixed
- **Integer Overflow:** Cast multiplication operands to `long` in `qrcodegen` to prevent overflow when computing QR code module counts.
- **CPack Packaging:** Added comprehensive runtime dependencies for Debian packages (`.deb`) in `CMakeLists.txt`, ensuring compatibility across multiple Debian/Ubuntu versions (Bullseye to Sid, 20.04 to 26.04) and supporting `t64` variants.

## [2026.03.14]

### Added
- **Mobile Sync:** Introduced `sync_service.c` for secure mobile synchronization using Chacha20-Poly1305 encryption for vault and salt.
- **Pwned Password Check:** Integrated `pwned_check.c` to verify password safety against the Have I Been Pwned (HIBP) API.
- **Badge Documentation:** Added CI build status, AUR version, and Repology badges to the README for better project status visibility.

### Changed
- **Argon2 Security:** Increased Argon2 `MEMORY_COST` from 64MB (`1 << 16`) to 128MB (`1 << 17`) to enhance resistance against hardware-accelerated brute-force attacks.
- **QR Code Refactoring:** Improved QR code generation logic in `qrcodegen` using `std::accumulate` for more idiomatic and efficient module counting.

### Fixed
- **Windows CI:** Updated vcpkg baseline to resolve `getopt-win32` download failure (404 Not Found).
- **Static Analysis:** Addressed multiple findings from `cppcheck` to improve overall code quality and security.
- **CI Reliability:** Updated include paths in GitHub Actions workflows to ensure consistent build environments.
- **Win32 Compatibility:** Added missing `windows.h` include for improved Windows API support.
- **Compiler Warnings:** Increased salt path buffer sizes to resolve `-Wformat-truncation` warnings during build.
- **Header Fixes:** Included `<numeric>` in `qrcodegen` to resolve missing symbol errors for `std::accumulate`.

## [2026.01.06]

### Security
- **Thread Safety:** Replaced non-thread-safe `strtok` with `strtok_r` in the pwned password check to prevent race conditions during concurrent validation.

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

## [2026.01.17]

### Fixed
- **Windows Build:** Resolved MSVC error C1083 (`sqlite3.h` not found) by implementing a robust, multi-layer SQLCipher detection strategy in CMake.
- **Cross-Platform SQLCipher:** Consolidated SQLCipher linking logic to prioritize `vcpkg` and `pkg-config` targets, ensuring correct header propagation on Windows, macOS, and Linux (including Arch Linux subdirectories).

### Added
- **Smart Path Derivation:** Implemented automatic include path derivation from library file paths as a fallback for manual build environments.
- **Improved Build Diagnostics:** Added status messaging during the CMake configuration phase to help debug dependency resolution.

## [2026.02.07]

### Security
- **Fetch on Demand:** Implemented a more secure data fetching model where sensitive fields (passwords, TOTP secrets, recovery codes) are only retrieved from the database when explicitly viewing or exporting an entry. This prevents secrets from lingering in memory during general navigation and list operations.
- **Improved Static Analysis:** Achieved 100% pass rate in local CI/CD verification using `cppcheck` and `flawfinder`. Remediated multiple findings and implemented justified suppressions for false positives (including CWE-134 format strings).
- **CodeQL Remediation:** Suppressed intentional cleartext storage alerts in the export feature to achieve a clean CodeQL report.
- **Runtime Verification:** All tests now pass with AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) enabled.

### Fixed
- **Resource Leak:** Fixed a FILE pointer leak in high-level GUI export functionality (`gui/mainwindow.cpp`).
- **Core Test Stability:** Fixed a segmentation fault in `core_tests` related to the new secure fetching pattern.
- **NULL Pointer Safety:** Added proactive NULL checks in database open operations to prevent potential crashes.
- **Windows Build Fix:** Resolved `MOVEFILE_REPLACE_EXISTING` undeclared identifier error in `core/database.c` by adding missing `<windows.h>` include.

## [2026.03.19]

### Added
- **Global Search:** Implemented a new searching engine (`database_search`) allowing case-insensitive search by service or username across both CLI and GUI.
- **Identity-Based Conflict Resolution:** Introduced `database_get_entry_by_identity` to automatically detect duplicate entries during CSV imports, providing users with interactive "Overwrite" or "Skip" options.
- **Dedicated Search Bar:** Added a real-time search interface to the main GUI window for rapid entry retrieval.
- **CLI Search Flag:** Added `-s/--search` command-line argument to quickly find entries without entering interactive mode.

### Security
- **Structural Hardening:** Conducted a comprehensive refactor to replace over 280 manual `flawfinder: ignore` overrides with structural security fixes, achieving **0 High Severity (Level 4/5) hits** in core and CLI source code.
- **Memory Safety:** Standardized on `calloc` for all `PasswordEntry` array allocations, ensuring zero-initialization and preventing "garbage pointer" crashes during memory cleanup.
- **Safe I/O Patterns:** Systematically replaced `printf` prompts with `fputs` and `scanf` with `read_line` (utilizing `fgets`) to eliminate format string and buffer overflow risks.
- **Cross-Platform File I/O:** Transitioned GUI file operations to Qt's `QFile` and `QTextStream` classes for more robust and portable path and data handling.
- **Banned Function Removal:** Further reduced reliance on potentially dangerous functions like `atoi` and `strncpy` in favor of more robust alternatives like `strtol` and `snprintf`.
- **Environment Hardening:** Added explicit length validation for untrusted environment variable inputs (`getenv`) used in path construction.

### Fixed
- **CLI Variable Scope:** Fixed a `cppcheck` style warning in `cli/main.c` by reducing the scope of the interactive choice variable.
- **Test Coverage:** Added new unit tests to `test_core.c` specifically for search accuracy, case-insensitivity, and identity retrieval.
- **Header Integrity:** Fixed missing Qt headers (`QStatusBar`, `QListWidget`) in `mainwindow.cpp` to ensure successful compilation.

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
