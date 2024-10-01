# SecurePassManager

## Overview

SecurePassManager is a robust, command-line password manager and two-factor authenticator (TOTP) designed with security and ease of use in mind. It provides a secure solution for managing passwords and 2FA tokens locally, ensuring your sensitive data remains protected and easily accessible.

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Security](#security)
6. [Project Structure](#project-structure)
7. [Contributing](#contributing)
8. [Testing](#testing)
9. [License](#license)
10. [Disclaimer](#disclaimer)
11. [Support](#support)
12. [Acknowledgments](#acknowledgments)

## Features

- **Secure Password Management**:
  - AES-256 encryption for all stored data
  - Add, retrieve, edit, and delete password entries
  - Search functionality for quick access to stored credentials
- **Two-Factor Authentication (TOTP)**:
  - Generate TOTP codes for 2FA-enabled accounts
  - Add and manage TOTP secrets
- **Data Portability**:
  - Import and export password data securely
- **User-Friendly CLI**: Intuitive command-line interface for all operations
- **Master Password Protection**: Single point of access secured by a master password
- **Local Storage**: All data stored locally for maximum privacy

## Requirements

- GCC compiler (version 7.5.0 or higher)
- OpenSSL library (version 1.1.1 or higher)
- liboath library (version 2.6.2 or higher)
- POSIX-compliant operating system (Linux, macOS, etc.)

## Installation

### Prerequisites

Ensure you have the required libraries installed:

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install gcc libssl-dev liboath-dev
```

#### macOS (using Homebrew):
```bash
brew install gcc openssl oath-toolkit
```

#### Arch Linux:
```bash
sudo pacman -S gcc openssl oath-toolkit
```

### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/SecurePasswd_MGMT.git
   cd SecurePasswd_MGMT
   ```

2. Compile the project:
   ```bash
   make
   ```

3. (Optional) Run tests:
   ```bash
   make test
   ```

The compiled binary `securepass` will be created in the project root directory.

## Usage

Run the program:
```bash
./securepass
```

Follow the on-screen prompts to:
- Set up your master password (on first run)
- Add new passwords or TOTP accounts
- Retrieve stored passwords
- Generate TOTP codes
- Import or export password data

For detailed usage instructions, refer to the [User Manual](docs/USER_MANUAL.md).

## Security

- **Encryption**: AES-256 encryption for all stored data
- **Key Derivation**: PBKDF2 with SHA-256 for secure key derivation from the master password
- **Memory Protection**: Sensitive data is securely wiped from memory after use
- **No Network Access**: All operations are performed locally without internet connectivity

For a detailed security analysis, see our [Security Policy](SECURITY.md).

## Project Structure

```
SecurePasswd_MGMT/
├── src/
│   ├── main.c
│   ├── encryption.c
│   ├── csv_handler.c
│   ├── totp.c
│   └── utils.c
├── include/
│   ├── encryption.h
│   ├── csv_handler.h
│   ├── totp.h
│   └── utils.h
├── tests/
│   └── test_main.c
├── data/
│   └── README.md
├── lib/
│   └── README.md
├── docs/
│   └── USER_MANUAL.md
├── Makefile
├── README.md
├── LICENSE
├── CONTRIBUTING.md
└── SECURITY.md
```

## Contributing

We welcome contributions to SecurePassManager! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Testing

Run the test suite with:
```bash
make test
```

For more information on testing, see [TESTING.md](TESTING.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

While SecurePassManager is designed with security as a top priority, no system can guarantee absolute security. Users are responsible for maintaining the confidentiality of their master password and for any risks associated with storing sensitive information.

## Support

For bug reports, feature requests, or general questions:
1. Check the [FAQ](docs/FAQ.md) for common questions
2. Search existing [Issues](https://github.com/yourusername/SecurePasswd_MGMT/issues) on GitHub
3. Open a new issue if your question remains unanswered

## Acknowledgments

- [OpenSSL](https://www.openssl.org/) for cryptographic operations
- [liboath](http://www.nongnu.org/oath-toolkit/) for TOTP functionality
- All contributors who have helped improve this project

---

Thank you for choosing SecurePassManager. Your security is our priority!