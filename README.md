# SecurePasswd_MGMT

<p align="center">
  <img src="gui/icons/app_icon.svg" alt="SecurePasswd_MGMT icon" width="128"/>
</p>

**SecurePasswd_MGMT** is a modern, cross-platform password manager and two-factor authenticator (TOTP) designed with state-of-the-art security. It provides a secure solution for managing passwords and 2FA tokens locally, with both a fast command-line interface (CLI) and a user-friendly graphical user interface (GUI).

## Key Security Features

- **End-to-End Encryption:** All sensitive data is encrypted at rest in a SQLCipher encrypted database.
- **State-of-the-Art Key Derivation:** **Argon2id**, the winner of the Password Hashing Competition, is used to derive the encryption key from your master password, providing maximum resistance against brute-force attacks.
- **Secure Password Generator:** A built-in, cryptographically secure password generator to create strong, unique passwords.
- **Memory Safety:** Sensitive data is explicitly cleared from memory after use.
- **Secure Storage:** All data is stored locally, encrypted, in a secure directory.

## Table of Contents
- [Key Security Features](#key-security-features)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Security](#security)
- [Project Structure](#project-structure)
- [Contribution](#contribution)
- [License](#license)

## Features

### Command-Line Interface (CLI)
- **Fast & Efficient:** A lightweight, terminal-based interface for all core functionalities.
- **Interactive Menu:** Easy-to-use menu for adding, searching, and managing passwords and TOTP secrets.
- **Command-Line Options:** Generate passwords directly from the command line.
- **Hidden Password Input:** Protects your master password from shoulder-surfing.

### Graphical User Interface (GUI)
- **Modern & Intuitive:** A clean, user-friendly interface built with the Qt framework.
- **Full Feature Set:** Access all features, including password management, TOTP generation, import/export, and password health checks.
- **Secure Clipboard:** Automatically clears copied passwords and TOTP codes from the clipboard after 30 seconds.
- **Real-time TOTP:** Displays TOTP codes with a progress bar indicating the time until the next code is generated.
- **Password Health Check:** Analyzes your passwords for weaknesses (e.g., reuse, short length) and provides recommendations.

## Requirements

- **C/C++ Compiler** (GCC, Clang, MSVC)
- **CMake** (version 3.10 or higher)
- **Libsodium** library
- **Argon2** library (`libargon2`)
- **SQLCipher** library
- **LibCSV** library
- **Qt6** Framework (for the GUI)
- **OpenSSL**
- **cURL**

### Installation of Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libsodium-dev libargon2-dev libsqlcipher-dev libcsv-dev qt6-base-dev libssl-dev libcurl4-openssl-dev
```

**macOS (Homebrew):**
```bash
brew install cmake libsodium argon2 sqlcipher libcsv qt6 openssl curl
```

**Arch Linux:**
```bash
sudo pacman -Syu --needed base-devel cmake libsodium argon2 sqlcipher libcsv qt6-base openssl curl
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc-c++ cmake libsodium-devel argon2-devel sqlcipher-devel libcsv-devel qt6-qtbase-devel openssl-devel libcurl-devel
```

**Windows (vcpkg):**

On Windows, this project uses `vcpkg` to manage dependencies. The setup is handled automatically when building with the provided Visual Studio solution, but if you are building manually, you will need to set up vcpkg first.

1.  **Clone vcpkg:**
    ```bash
    git clone https://github.com/microsoft/vcpkg.git
    ./vcpkg/bootstrap-vcpkg.bat
    ```

2.  **Install dependencies:**
    ```bash
    ./vcpkg/vcpkg install --triplet x64-windows
    ```

    When you run CMake, you must point it to the vcpkg toolchain file:
    ```bash
    cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=path/to/your/vcpkg/scripts/buildsystems/vcpkg.cmake
    ```

## Installation

### Pre-built Packages

Pre-built packages for various platforms are available on the [GitHub Releases](https://github.com/fam007e/SecurePasswd_MGMT/releases) page.

### Build from Source

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/fam007e/SecurePasswd_MGMT.git
    cd SecurePasswd_MGMT
    ```

2.  **Install Dependencies:**
    Follow the instructions in the "Installation of Dependencies" section above.

3.  **Configure the build:**
    ```bash
    mkdir build && cd build
    cmake ..
    ```
    For Windows with MSVC, you might need to specify the generator:
    ```bash
    cmake .. -G "Visual Studio 17 2022" -A x64
    ```

4.  **Compile the project:**
    ```bash
    cmake --build . --config Release
    ```

    The compiled binaries (`securepasswd_cli` and `securepasswd_gui`) will be created in the `build/bin` (or `build/Release` on Windows) directory.

## Usage

### GUI Application
To run the graphical interface, execute the `securepasswd_gui` binary from within your build directory:
```bash
# From the project root directory
./build/bin/securepasswd_gui
```
On the first run, you will be prompted to create a new master password, which will be used to encrypt your vault.

### Command-Line Interface
To run the command-line interface, execute the `securepasswd_cli` binary:
```bash
# From the project root directory
./build/bin/securepasswd_cli
```
The CLI provides an interactive menu for managing your passwords and TOTP secrets.

## Security

This project was designed with a security-first mindset, incorporating modern, vetted cryptographic primitives. For a detailed breakdown of the security architecture, see our **[Security Policy](SECURITY.md)**.

## Project Structure

```
SecurePasswd_MGMT/
├── .github/          # GitHub Actions workflows and issue templates
├── cmake/            # CMake helper scripts (e.g., for Windows deployment)
├── core/             # Core C library (encryption, password management)
├── cli/              # C command-line interface
├── gui/              # C++ Qt Graphical User Interface
├── tests/            # Unit and integration tests
├── CMakeLists.txt    # Root CMake build script
├── README.md         # This file
├── CONTRIBUTION.md   # Guidelines for contributing
├── SECURITY.md       # Detailed security policy
└── LICENSE           # Project license
```

## Contribution

We welcome contributions! Please read our [Contribution Guidelines](CONTRIBUTION.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
