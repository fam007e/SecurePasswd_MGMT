# SecurePassManager

[![Version](https://img.shields.io/github/v/release/fam007e/SecurePasswd_MGMT?color=%230567ff&label=Latest%20Release&style=for-the-badge)](https://github.com/fam007e/SecurePasswd_MGMT/releases/latest)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=for-the-badge)](https://github.com/fam007e/SecurePasswd_MGMT)
[![Security](https://img.shields.io/badge/security-hardened-red.svg?style=for-the-badge)](SECURITY.md)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg?style=for-the-badge)

**SecurePassManager** is a robust, command-line password manager and two-factor authenticator (TOTP) designed with security and ease of use in mind. It provides a secure solution for managing passwords and 2FA tokens locally, ensuring your sensitive data remains protected and easily accessible.

## 🔐 Key Security Features

- **Military-Grade Encryption:** AES-256 encryption with PBKDF2 key derivation (10,000 iterations)
- **Memory Protection:** Sensitive data automatically cleared from memory after use
- **Hardened Compilation:** Built with comprehensive security flags (stack protection, ASLR, RELRO)
- **Local Storage Only:** No network connectivity required - your data never leaves your device
- **Secure File Permissions:** Data directory created with 0700 permissions (owner access only)

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

## 📋 Requirements

- **GCC compiler** (version 7.5.0 or higher)
- **OpenSSL library** (version 1.1.1 or higher)
- **liboath library** (version 2.6.2 or higher)
- **POSIX-compliant operating system** (Linux, macOS, Unix-like systems)

### 📦 Installation of Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev oathtool liboath0 liboath-dev

# Optional development tools
sudo apt-get install cppcheck checksec valgrind clang-format clang-tidy lcov
```

**macOS (Homebrew):**
```bash
brew install gcc openssl oath-toolkit

# Optional development tools
brew install cppcheck valgrind llvm lcov
```

**Arch Linux:**
```bash
sudo pacman -Syu --needed base-devel openssl oath-toolkit

# Optional development tools  
sudo pacman -S --needed cppcheck checksec valgrind clang lcov
```

**Fedora/RHEL:**
```bash
sudo dnf install gcc gcc-c++ make openssl-devel liboath-devel oathtool

# Optional development tools
sudo dnf install cppcheck checksec valgrind clang-tools-extra lcov
```

**Quick Setup (Auto-detect system):**
```bash
make dev-setup
```

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/fam007e/SecurePasswd_MGMT.git
   cd SecurePasswd_MGMT
   ```

2. **Check dependencies:**
   ```bash
   make check-deps
   ```

3. **Compile the project:**
   ```bash
   make              # Standard secure build (recommended)
   make debug        # Debug build with symbols
   make release      # Optimized release build with LTO
   ```

   The compiled binary `securepass` will be created in the project root directory.

4. **Optional - Install system-wide:**
   ```bash
   sudo make install     # Install to /usr/local/bin
   sudo make uninstall   # Remove from system
   ```

## ⚙️ Build Options

| Command | Description | Use Case |
|---------|-------------|----------|
| `make` or `make all` | Standard secure build with hardening flags | **Recommended for production use** |
| `make debug` | Debug build with symbols, no optimization | Development and debugging |
| `make release` | Maximum optimization with LTO | Performance-critical deployments |
| `make test` | Run basic functionality tests | Verify build integrity |
| `make security-check` | Analyze binary security features | Security verification |
| `make package` | Create distribution package with checksums | Release preparation |

### 🛠️ Development & Quality Assurance

| Command | Description | Requirements |
|---------|-------------|--------------|
| `make lint` | Code linting and style checks | cppcheck, clang-tidy |
| `make format` | Auto-format code | clang-format |
| `make memcheck` | Memory leak detection | valgrind |
| `make coverage` | Build with coverage support | gcov, lcov |
| `make quality` | Run all quality checks | All QA tools |

### 🔒 Security-Focused Compilation

The project automatically compiles with comprehensive security hardening:

```makefile
# Security Features Enabled by Default:
-fstack-protector-strong    # Stack buffer overflow protection
-D_FORTIFY_SOURCE=2        # Runtime buffer overflow detection  
-pie -fPIE                 # Position Independent Executable (ASLR)
-Wformat -Werror=format-security  # Format string protection
-fstack-clash-protection   # Stack clash attack prevention
-fcf-protection           # Control flow integrity (Intel CET)
-Wl,-z,relro -Wl,-z,now   # Full RELRO linking protection
-Wl,-z,noexecstack        # Non-executable stack
```

**Verify security features:**
```bash
make security-check
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
1. Add new password       - Store encrypted password entries
2. Search for password    - Find and decrypt stored passwords  
3. Generate TOTP code     - Create time-based one-time passwords
4. Add new TOTP account   - Store TOTP secrets securely
5. Export passwords       - Export data to CSV format
6. Import passwords       - Import data from CSV format
7. Exit                   - Safely exit the application
```

### 🔐 First Time Setup

When you run SecurePassManager for the first time:
1. The program creates a `data/` directory with secure permissions (0700)
2. You'll be prompted to create a master password
3. The master password is hashed using **PBKDF2** with 10,000 iterations and stored securely
4. A cryptographically secure salt is generated using OpenSSL's `RAND_bytes()`

### 📋 Command Line Options

```bash
./securepass [OPTIONS]

Options:
  -h, --help     Show help message and exit
  -v, --version  Show version information and exit
  help           Show help message and exit
```

**Examples:**
```bash
./securepass --version    # Show version: YYYY.MM.DD format
./securepass --help       # Display detailed usage information
```

## 🛡️ Security

SecurePassManager implements **defense-in-depth** security principles:

### 🔐 Cryptographic Security
- **Encryption:** AES-256 (Advanced Encryption Standard) for all stored data
- **Key Derivation:** PBKDF2-SHA256 with 10,000 iterations for secure key derivation
- **Salt Generation:** Cryptographically secure random salt using OpenSSL `RAND_bytes()`
- **Random Number Generation:** OpenSSL CSPRNG for all random data

### 🛡️ Memory Protection
- **Secure Clearing:** Sensitive data wiped from memory using `memset()` after use
- **Stack Protection:** Compiler-level stack buffer overflow protection
- **Input Security:** Hidden password input prevents shoulder surfing attacks

### 📁 File System Security
- **Secure Permissions:** Data directory created with `0700` permissions (owner-only access)
- **Local Storage:** All operations performed locally without network connectivity
- **File Integrity:** Corruption detection through failed decryption attempts

### 🔒 Binary Hardening
- **ASLR:** Position Independent Executable for address space randomization
- **Stack Canaries:** Detection of stack buffer overflows at runtime
- **RELRO:** Read-only relocation and immediate binding
- **Non-executable Stack:** Prevention of code execution on stack

For a comprehensive security analysis, see our **[Security Policy](SECURITY.md)**.

### 🚨 Security Verification

Verify your build's security features:
```bash
make security-check
```

This will show:
- Enabled compiler security flags
- Binary security analysis (requires `checksec`)
- Static code analysis results (requires `cppcheck`)

## 📁 Project Structure

```
SecurePasswd_MGMT/
├── 📄 CONTRIBUTION.md           # Contribution guidelines
├── 📁 data/                     # Auto-created directory for encrypted data
│   ├── 🔐 master.key           # Master password hash and salt
│   ├── 🔐 passwords.dat        # Encrypted password storage
│   └── 🔐 totp.dat             # TOTP secrets storage
├── 📁 lib/                     # External library headers
│   ├── 📁 liboath/
│   │   └── 📄 oath.h           # TOTP library header
│   │   └── 📄 openssl.h        # OpenSSL library header
│   └── 📄 README.md
├── 📄 LICENSE                  # MIT License
├── 📄 Makefile                 # Build system with security features
├── 📄 README.md                # This file
├── 📄 SECURITY.md              # Detailed security documentation
└── 📁 src/                     # Source code
    ├── 📄 csv_handler.c        # CSV import/export functionality
    ├── 📄 csv_handler.h
    ├── 📄 encryption.c         # AES-256 encryption implementation
    ├── 📄 encryption.h
    ├── 📄 main.c               # Main program logic and UI
    ├── 📄 totp.c               # TOTP generation and management
    ├── 📄 totp.h
    ├── 📄 utils.c              # Utility functions (input handling, etc.)
    ├── 📄 utils.h
    └── 📄 version.h            # Version information
```

## 💾 Data Storage

| File | Purpose | Security |
|------|---------|----------|
| `data/master.key` | Master password hash + salt | PBKDF2-SHA256, 10K iterations |
| `data/passwords.dat` | Encrypted password entries | AES-256 encryption |
| `data/totp.dat` | TOTP secrets | AES-256 encryption |

**File Permissions:** All data files created with restricted permissions (owner read/write only)

## 🔄 Backup & Recovery

### Creating Backups
```bash
# Export to CSV (encrypted with master password)
./securepass
# Choose option 5: Export passwords

# Manual backup of encrypted data
cp -r data/ backup-$(date +%Y%m%d)/
```

### Restoring from Backup
```bash
# Restore from CSV export
./securepass  
# Choose option 6: Import passwords

# Manual restore of encrypted data
cp -r backup-YYYYMMDD/ data/
```

## 🤝 Contribution

We welcome contributions to SecurePassManager! Please read our [Contribution Guidelines](CONTRIBUTION.md) for details on our code of conduct and the process for submitting pull requests.

### 🚀 Quick Start for Contributors

```bash
# Setup development environment
make dev-setup

# Run quality checks
make quality

# Submit your changes
git commit -m "feat: your feature description"
```

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

While SecurePassManager is designed with security as a top priority, no system can guarantee absolute security. Users are responsible for:

- 🔑 Maintaining the confidentiality and strength of their master password
- 💾 Regular backups of their encrypted data  
- 🧠 Understanding the risks associated with storing sensitive information
- 🔄 Keeping the software updated with latest security patches
- 🖥️ Using the software on trusted, secure systems

**Important:** This software is provided "as-is" without warranty. Use at your own risk.

## 🆘 Support

For bug reports, feature requests, or general questions:

- 🔍 Search existing [Issues](https://github.com/fam007e/SecurePasswd_MGMT/issues) on GitHub
- 🐛 Open a new issue if your question remains unanswered
- 📖 Check our documentation for common usage patterns
- 🛡️ For security issues, see our [Security Policy](SECURITY.md)

### 📈 Project Status

- ✅ **Active Development:** Regular updates and security patches
- 🔒 **Security Focused:** Comprehensive security measures implemented  
- 🧪 **Well Tested:** Extensive quality assurance and testing
- 📚 **Well Documented:** Comprehensive documentation and examples

## 🙏 Acknowledgments

- [OpenSSL](https://www.openssl.org/) for cryptographic operations
- [liboath](http://www.nongnu.org/oath-toolkit/) for TOTP functionality  
- All contributors who have helped improve this project
- The security community for responsible disclosure practices

---

**🛡️ Thank you for choosing SecurePassManager. Your security is our priority!**

*Made with ❤️ for secure password management*