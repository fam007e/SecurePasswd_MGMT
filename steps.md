# SecurePassManager X - Implementation Steps

This document outlines the step-by-step plan to evolve SecurePassManager into a cross-platform application with both a robust Command-Line Interface (CLI) and a modern Graphical User Interface (GUI), leveraging the existing secure C core.

## Phase 1: Foundation & C Core Preparation

### Step 1.1: C Core Refactoring for Library Export (Completed)
- **Objective:** Isolate core functionalities into a shared library that can be linked by both the CLI and the future GUI.
- **Tasks:**
    - Reviewed `src/` to identify functions for encryption, decryption, key derivation, password generation, TOTP generation, and CSV handling.
    - Created `src/securepass_core.h` for the public API.
    - Migrated the C core build system from `Makefile` to `CMake` to build `libsecurepasscore`.
    - Integrated `libcsv` into the CMake build.
    - Corrected `liboath` function calls and linking issues.
- **Status:** Completed. `libsecurepasscore.so` and `securepass` executable build successfully.

### Step 1.2: Enhance Existing CLI (Optional but Recommended)
- **Objective:** Update the existing CLI (`main.c`) to link against the new `libsecurepasscore` and potentially add minor enhancements.
- **Tasks:**
    - Modify `main.c` to use the API exposed by `libsecurepasscore`.
    - Verify all existing CLI functionalities work correctly.
    - Consider adding command-line options for new core features (e.g., `--argon2-params` if Argon2 is implemented).

### Step 1.3: Implement Argon2 in C Core
- **Objective:** Replace PBKDF2 with Argon2 for master password key derivation.
- **Tasks:**
    - **Implementation:** Integrate the official `libargon2` C library.
    - Implement Argon2 within `libsecurepasscore` for master password hashing.
    - Update the `master.key` file format to store Argon2 parameters (salt, memory cost, time cost, parallelism).
    - Implement a migration path for existing PBKDF2 `master.key` files to Argon2 (e.g., prompt user to re-enter master password to upgrade).

### Step 1.4: Implement XChaCha20-Poly1305 in C Core
- **Objective:** Replace AES-256 with XChaCha20-Poly1305 for data encryption/decryption.
- **Tasks:**
    - **Implementation:** Utilize OpenSSL's EVP interface for XChaCha20-Poly1305.
    - Implement XChaCha20-Poly1305 within `libsecurepasscore` for all data encryption/decryption.
    - Implement a migration path for existing AES-256 encrypted data (e.g., decrypt with old, re-encrypt with new).

## Phase 2: Flutter GUI Development - Setup & FFI Integration

### Step 2.1: Flutter Project Setup
- **Objective:** Create the basic Flutter project structure.
- **Tasks:**
    - Create a new Flutter project (`flutter create securepass_x_gui`).
    - Add necessary Flutter dependencies (e.g., `ffi`, `path_provider`, `local_auth`).

### Step 2.2: FFI Bindings Generation
- **Objective:** Generate Dart bindings to interact with the C core library.
- **Tasks:**
    - **Research:** Determine the best approach for FFI bindings (e.g., `package:ffigen` for automated generation or manual binding).
    - Generate Dart FFI bindings for the API exposed by `libsecurepasscore.h`.

### Step 2.3: Cross-Platform C Library Integration with Flutter
- **Objective:** Configure the Flutter project to build and link the C core library for all target platforms.
- **Tasks:**
    - **Research:** How to manage native dependencies in Flutter for desktop (Linux, macOS, Windows) and mobile (Android).
    - Configure platform-specific build files (e.g., `CMakeLists.txt` for desktop, `build.gradle` for Android) to include and link `libsecurepasscore`.

### Step 2.4: Basic GUI - Master Password & Unlock
- **Objective:** Implement the initial user interface for setting up and unlocking the vault.
- **Tasks:**
    - Design and implement the UI for master password setup (first run) and vault unlock.
    - Use FFI to call `securepass_authenticate` and `securepass_setup_master_password` from the C core.
    - Implement secure input handling (obscured text) in the Flutter UI.

## Phase 3: Feature Implementation (GUI & Shared Core)

### Step 3.1: Password Management (CRUD)
- **Objective:** Implement the core password management functionalities in the GUI.
- **Tasks:**
    - Design UI for adding, viewing, editing, and deleting password entries.
    - Use FFI to call C core functions for encryption, decryption, and data storage/retrieval.

### Step 3.2: TOTP Management
- **Objective:** Implement TOTP secret management and code generation.
- **Tasks:**
    - Design UI for adding TOTP secrets and displaying generated codes.
    - Use FFI to call C core TOTP generation functions.

### Step 3.3: Password Generator Integration
- **Objective:** Integrate the secure password generator into the GUI.
- **Tasks:**
    - Design UI for password generation with customizable options (length, character sets).
    - Use FFI to call the C core's password generation function.

### Step 3.4: Data Import/Export
- **Objective:** Provide GUI options for importing and exporting password data.
- **Tasks:**
    - Design UI for selecting import/export file paths.
    - Use FFI to call C core CSV handling functions.

### Step 3.5: Secure Clipboard Integration
- **Objective:** Implement secure handling of copied passwords.
- **Tasks:**
    - Implement platform-specific Flutter logic to copy passwords to the clipboard.
    - Implement a timer to automatically clear the clipboard after a short, configurable duration.

### Step 3.6: Biometric Authentication
- **Objective:** Integrate biometric unlock for convenience.
- **Tasks:**
    - Use `local_auth` package to integrate with OS-level biometrics.
    - Upon successful biometric authentication, use FFI to call the C core's master password validation (using a securely stored hash of the master password, not the master password itself).

### Step 3.7: Data Directory Management
- **Objective:** Ensure correct and customizable data directory handling.
- **Tasks:**
    - Implement logic to determine default data directory based on OS (Linux/macOS: `~/.config/securepass/`, Windows: `%APPDATA%\securepass\`, Termux: `~/.config/securepass/`).
    - Provide a GUI option to override the default data directory via an environment variable or in-app setting.

## Phase 4: Advanced Features & Polish

### Step 4.1: Password Health Check
- **Objective:** Provide insights into password strength and security.
- **Tasks:**
    - Implement local analysis for password strength, reuse detection, and potential breaches (using a local, securely updated database of compromised hashes).
    - Design UI to display health check results and recommendations.

### Step 4.2: Optional Encrypted Sync (Future Iteration)
- **Objective:** Implement secure, optional cross-device synchronization.
- **Tasks:**
    - Design architecture for self-hosted (WebDAV, SFTP) or client-side encrypted cloud sync.
    - Implement synchronization logic, ensuring end-to-end encryption.

### Step 4.3: Browser Extension (Separate Project - Future Iteration)
- **Objective:** Develop companion browser extensions for autofill.
- **Tasks:**
    - Design communication protocol between desktop app and browser extensions.
    - Develop extensions for major browsers.

### Step 4.4: Comprehensive Testing & Deployment
- **Objective:** Ensure application quality, security, and broad availability.
- **Tasks:**
    - Develop extensive unit, widget, and integration tests for the Flutter app.
    - Conduct security audits and penetration testing.
    - Set up CI/CD pipelines for automated testing and building.
    - Package and distribute the application for Linux, macOS, Windows, and Android (APK for Termux).
