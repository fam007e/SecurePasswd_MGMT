# SecurePassManager

[![Version](https://img.shields.io/github/v/release/fam007e/SecurePasswd_MGMT?color=%230567ff&label=Latest%20Release&style=for-the-badge)](https://github.com/fam007e/SecurePasswd_MGMT/releases/latest)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=for-the-badge)](https://github.com/fam007e/SecurePasswd_MGMT)
[![Security](https://img.shields.io/badge/security-hardened-red.svg?style=for-the-badge)](SECURITY.md)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg?style=for-the-badge)

**SecurePassManager** is a robust, command-line password manager and two-factor authenticator (TOTP) designed with security and ease of use in mind. It provides a secure solution for managing passwords and 2FA tokens locally, ensuring your sensitive data remains protected and easily accessible.

## 🔐 Key Security Features

- **End-to-End Encryption:** AES-256 encryption for all sensitive data, including usernames, passwords, and TOTP secrets.
- **Strong Key Derivation:** PBKDF2 with 10,000 iterations is used to derive the encryption key from your master password.
- **Secure Password Generator:** A built-in, cryptographically secure password generator to create strong, unique passwords.
- **Robust Parsing:** Uses a well-tested CSV parsing library to prevent parsing-related vulnerabilities.
- **Memory Safety:** Sensitive data is explicitly cleared from memory after use.
- **Secure Storage:** Encrypted data is stored in `.dat` files to prevent accidental exposure.

## Table of Contents
- [🔐 Key Security Features](#-key-security-features)
- [✨ Features](#-features)
- [📋 Requirements](#-requirements)
- [🚀 Installation](#-installation)
- [📖 Usage](#-usage)
- [⚙️ Build Options](#️-build-options)
- [🛡️ Security](#️-security)
- [📁 Project Structure](#-project-structure)
- [🤝 Contribution](#-contribution)
- [📄 License](#-license)
- [⚠️ Disclaimer](#️-disclaimer)
- [🆘 Support](#-support)
- [🙏 Acknowledgments](#-acknowledgments)

## ✨ Features

### 🔑 Secure Password Management
- **AES-256 encryption** for all stored data
- Add, retrieve, and search password entries
- Master password protection with **PBKDF2 key derivation**
- Automatic data directory creation and management

### 🔢 Cryptographically Secure Password Generator
- Generate strong, customizable passwords from the command line
- Control length, character sets (lowercase, uppercase, numbers, special characters)
- Entropy calculation for password strength assessment

### 🔐 Two-Factor Authentication (TOTP)
- Generate **TOTP codes** for 2FA-enabled accounts
- Add and manage TOTP secrets securely
- Real-time TOTP code generation compatible with Google Authenticator

### 📦 Data Portability
- **Import and export** password data securely in CSV format
- Maintain data integrity across different systems
- Backup and restore functionality

### 💻 User-Friendly CLI
- Intuitive command-line interface with interactive menus
- **Hidden password input** for enhanced security
- Clear help and version information
- Cross-platform compatibility (Linux, macOS)

### 🏠 Local Storage
- All data stored locally for **maximum privacy**
- No network connectivity required
- Secure file permissions (0700) for data directory
- **Data Directory:** By default, `SecurePassManager` creates a `data/` directory in the same location as the executable. This directory is secured with `0700` permissions (read, write, execute for owner only).
- **Sensitive Files:**
    - `data/master.key`: Stores the PBKDF2 hash and salt of your master password. This file is critical for authentication and decryption.
    - `data/passwords.dat`: Contains all your encrypted password entries.
    - `data/totp.dat`: Stores your encrypted TOTP secrets.
    **IMPORTANT:** Never share these files or store them in insecure locations. Always ensure your `data/` directory is protected.

## 📋 Requirements

- **GCC compiler** (version 7.5.0 or higher)
- **OpenSSL library** (version 1.1.1 or higher)
- **POSIX-compliant operating system** (Linux, macOS, Unix-like systems)

### 📦 Installation of Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev liboath-dev
```

**macOS (Homebrew):**
```bash
brew install gcc openssl oath-toolkit
```

**Arch Linux:**
```bash
sudo pacman -Syu --needed base-devel openssl oath-toolkit
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc gcc-c++ make openssl-devel liboath-devel
```

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/fam007e/SecurePasswd_MGMT.git
   cd SecurePasswd_MGMT
   ```

2. **Compile the project:**
   ```bash
   make
   ```

   The compiled binary `securepass` will be created in the project root directory.

3. **Optional - Install system-wide:**
   ```bash
   sudo make install
   ```

## 📖 Usage

### Basic Usage

Run the program:
```bash
./securepass
```

On first run, you'll be prompted to set up a master password. This password will be used to encrypt and decrypt all your stored data.

### 📱 Interactive Menu

```
SecurePassManager Menu:
1. Add new password
2. Search for password
3. Generate TOTP code
4. Add new TOTP account
5. Export passwords
6. Import passwords
7. Exit
```

### 🔐 First Time Setup

When you run SecurePassManager for the first time:
1. The program creates a `data/` directory with secure permissions (0700)
2. You'll be prompted to create a master password
3. The master password is hashed using **PBKDF2** with 10,000 iterations and stored securely

### 📋 Command Line Options

```bash
./securepass [OPTIONS]

Options:
  -h, --help     Show help message and exit
  -v, --version  Show version information and exit

  --generate-password  Generate a cryptographically secure password
  -l, --length <num>   Specify password length (default: 12, min: 12)
  -c, --case-variance  Include uppercase characters
  -n, --numbers        Include numbers
  -s, --special        Include special characters
```

**Examples:**
```bash
./securepass --version
./securepass --help
./securepass --generate-password -l 16 -c -n -s
./securepass --generate-password
```

## 🛡️ Security

For a comprehensive security analysis, see our **[Security Policy](SECURITY.md)**.

## 📁 Project Structure

```
SecurePasswd_MGMT/
├── .github/                  # GitHub Actions workflows and issue templates
├── lib/                      # External libraries (e.g., libcsv)
├── src/                      # Core source code
│   ├── csv_handler.c         # CSV file reading and writing
│   ├── csv_parser.c          # CSV parsing logic
│   ├── data_path.h           # Defines data directory path
│   ├── encryption.c          # AES-256 encryption/decryption
│   ├── main.c                # Main application logic and CLI handling
│   ├── password_generator.c  # Secure password generation
│   ├── totp.c                # TOTP generation and management
│   └── utils.c               # Utility functions (e.g., secure input)
├── tests/                    # Unit tests for various modules
├── Makefile                  # Build automation
├── README.md                 # Project overview and usage
├── CONTRIBUTION.md           # Guidelines for contributing
├── SECURITY.md               # Detailed security policy
└── LICENSE                   # Project license
```

## 🤝 Contribution

We welcome contributions to SecurePassManager! Please read our [Contribution Guidelines](CONTRIBUTION.md) for details on our code of conduct and the process for submitting pull requests.

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
