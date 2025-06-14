# 🤝 Contributing to SecurePassManager

[![Contributors](https://img.shields.io/badge/Contributors-Welcome-brightgreen.svg?style=for-the-badge)](https://github.com/fam007e/SecurePasswd_MGMT/graphs/contributors)
[![Code Quality](https://img.shields.io/badge/Code%20Quality-High-blue.svg?style=for-the-badge)](#code-quality-standards)
[![Security First](https://img.shields.io/badge/Security-First-red.svg?style=for-the-badge)](#security-considerations)
[![Testing](https://img.shields.io/badge/Testing-Required-orange.svg?style=for-the-badge)](#testing-requirements)

Thank you for your interest in contributing to **SecurePassManager**! This document provides comprehensive guidelines for contributing to our secure password management solution. We welcome contributions of all kinds, from bug reports and documentation improvements to new features and security enhancements.

## Table of Contents
- [🚀 Quick Start](#-quick-start)
- [🎯 Ways to Contribute](#-ways-to-contribute)
- [🛠️ Development Setup](#️-development-setup)
- [📋 Code Quality Standards](#-code-quality-standards)
- [🔒 Security Considerations](#-security-considerations)
- [🧪 Testing Requirements](#-testing-requirements)
- [📝 Documentation Guidelines](#-documentation-guidelines)
- [🔄 Pull Request Process](#-pull-request-process)
- [🐛 Bug Reports](#-bug-reports)
- [✨ Feature Requests](#-feature-requests)
- [📚 Learning Resources](#-learning-resources)
- [🏆 Recognition](#-recognition)
- [📞 Getting Help](#-getting-help)

## 🚀 Quick Start

### For First-Time Contributors

1. **🍴 Fork the Repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/SecurePasswd_MGMT.git
   cd SecurePasswd_MGMT
   ```

2. **🔧 Set Up Development Environment**
   ```bash
   # Auto-detect and install dependencies
   make dev-setup
   
   # Verify setup
   make check-deps
   ```

3. **🏗️ Build and Test**
   ```bash
   # Build with debug symbols
   make debug
   
   # Run tests
   make test
   
   # Check code quality
   make quality
   ```

4. **🌟 Make Your First Contribution**
   - Start with documentation improvements or minor bug fixes
   - Look for issues labeled `good-first-issue` or `help-wanted`
   - Join our discussions to understand project priorities

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test
make debug && make test

# Run quality checks
make quality

# Commit changes
git commit -m "feat: add your feature description"

# Push and create pull request
git push origin feature/your-feature-name
```

## 🎯 Ways to Contribute

### 🔧 Code Contributions
- **Core Features:** Password management, TOTP, encryption improvements
- **Security Enhancements:** Cryptographic implementations, hardening measures
- **Platform Support:** Cross-platform compatibility improvements
- **Performance Optimization:** Memory usage, speed improvements
- **CLI/UX Improvements:** Better user interface and experience

### 📚 Documentation
- **User Documentation:** Usage examples, tutorials, troubleshooting guides
- **Developer Documentation:** API documentation, architecture guides
- **Security Documentation:** Threat model updates, security analysis
- **Translation:** Internationalization and localization support

### 🐛 Bug Fixes
- **Security Vulnerabilities:** Critical security issues (follow responsible disclosure)
- **Functionality Bugs:** Incorrect behavior, crashes, data corruption
- **Compatibility Issues:** Platform-specific problems
- **Memory Leaks:** Resource management improvements

### 🧪 Testing & Quality Assurance
- **Unit Tests:** Test coverage for new and existing functionality
- **Integration Tests:** End-to-end testing scenarios
- **Security Testing:** Penetration testing, vulnerability assessments
- **Performance Testing:** Benchmarking and optimization

### 🔍 Code Review
- **Security Reviews:** Cryptographic code review, security analysis
- **Code Quality:** Style, maintainability, best practices
- **Architecture Review:** Design patterns, modularity
- **Documentation Review:** Accuracy, clarity, completeness

## 🛠️ Development Setup

### Prerequisites

Before contributing, ensure you have the required development tools:

```bash
# Check system requirements
make check-deps

# Install dependencies (auto-detects your system)
make dev-setup
```

### Required Dependencies

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| **GCC** | 7.5.0+ | C compiler with security features |
| **OpenSSL** | 1.1.1+ | Cryptographic operations |
| **liboath** | 2.6.2+ | TOTP functionality |
| **Make** | 3.81+ | Build system |

### Optional Development Tools

| Tool | Purpose | Installation |
|------|---------|-------------|
| **cppcheck** | Static analysis | `apt install cppcheck` |
| **valgrind** | Memory debugging | `apt install valgrind` |
| **clang-format** | Code formatting | `apt install clang-format` |
| **clang-tidy** | Code linting | `apt install clang-tidy` |
| **checksec** | Binary security analysis | `apt install checksec` |
| **lcov** | Code coverage | `apt install lcov` |

### Development Environment Verification

```bash
# Verify complete development setup
make dev-verify

# Expected output:
# ✓ GCC compiler found
# ✓ OpenSSL library found  
# ✓ liboath library found
# ✓ Development tools available
# ✓ Build system ready
```

## 📋 Code Quality Standards

### 🎨 Code Style

SecurePassManager follows **consistent C coding standards** with security focus:

#### Formatting Standards
```c
// Function naming: snake_case
int validate_master_password(const char *password);

// Variable naming: snake_case  
char master_password[256];
unsigned char salt[16];

// Constants: UPPER_SNAKE_CASE
#define MAX_PASSWORD_LENGTH 256
#define PBKDF2_ITERATIONS 10000

// Indentation: 4 spaces (no tabs)
if (condition) {
    // 4-space indentation
    function_call();
}
```

#### Security-Focused Coding Standards
```c
// Always check return values
if (RAND_bytes(salt, 16) != 1) {
    fprintf(stderr, "Error: Failed to generate random salt\n");
    exit(1);
}

// Clear sensitive data after use
memset(password, 0, sizeof(password));
memset(secret, 0, sizeof(secret));

// Use secure string functions
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';

// Input validation
if (strlen(input) >= MAX_INPUT_SIZE) {
    fprintf(stderr, "Error: Input too long\n");
    return -1;
}
```

### 🔍 Code Quality Tools

```bash
# Automatic code formatting
make format

# Static analysis
make lint

# Security analysis  
make security-check

# Memory leak detection
make memcheck

# Run all quality checks
make quality
```

### 📏 Code Quality Metrics

All contributions must meet these standards:

| Metric | Requirement | Tool |
|--------|------------|------|
| **Static Analysis** | Zero critical issues | cppcheck |
| **Memory Safety** | Zero leaks/errors | valgrind |
| **Code Coverage** | >80% for new code | gcov/lcov |
| **Security Features** | All flags enabled | checksec |
| **Documentation** | All public functions | doxygen |

### 🏗️ Build Targets for Development

```bash
# Development builds
make debug          # Debug build with symbols
make release        # Optimized release build
make sanitize       # Build with AddressSanitizer

# Quality assurance
make lint           # Code linting and analysis
make format         # Auto-format code
make memcheck       # Memory leak detection
make coverage       # Build with coverage support

# Security verification
make security-check # Analyze binary security features
make hardening-test # Test security hardening measures
```

## 🔒 Security Considerations

### 🛡️ Security-First Development

**All contributions involving security-sensitive code must:**

1. **Follow Secure Coding Practices**
   - Input validation and bounds checking
   - Secure memory management
   - Proper error handling
   - Cryptographic best practices

2. **Undergo Security Review**
   - Peer review by security-knowledgeable contributors
   - Analysis of potential attack vectors
   - Verification of cryptographic implementations
   - Testing against common vulnerabilities

3. **Maintain Security Documentation**
   - Update threat model if applicable
   - Document security assumptions
   - Explain cryptographic choices
   - Provide security test cases

### 🔐 Cryptographic Code Guidelines

When working with cryptographic functionality:

```c
// Use established libraries (OpenSSL)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

// Always check cryptographic function returns
if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
    fprintf(stderr, "Error: Hash computation failed\n");
    EVP_MD_CTX_free(ctx);
    return -1;
}

// Use secure random number generation
if (RAND_bytes(buffer, buffer_size) != 1) {
    fprintf(stderr, "Error: Random number generation failed\n");
    return -1;
}

// Clear sensitive data immediately
OPENSSL_cleanse(sensitive_data, sizeof(sensitive_data));
```

### 🚨 Security Vulnerability Handling

**Critical Security Issues:**
- Follow responsible disclosure process
- Do not commit security fixes to public branches initially
- Coordinate with maintainers for security releases
- Provide detailed impact assessment

**Security Review Requirements:**
- All cryptographic code requires expert review
- Memory management code needs careful examination
- Input parsing requires fuzzing and boundary testing
- Authentication logic needs comprehensive testing

### 🔍 Security Testing

```bash
# Security-focused testing
make security-test     # Run security test suite
make fuzz             # Fuzzing test (if available)
make static-analysis  # Comprehensive static analysis
make threat-model     # Generate threat model analysis
```

## 🧪 Testing Requirements

### 📊 Test Coverage Requirements

| Component | Coverage Requirement | Test Types |
|-----------|---------------------|------------|
| **Cryptographic Functions** | 100% | Unit, Integration, Security |
| **Core Logic** | >90% | Unit, Integration |
| **Input Validation** | 100% | Unit, Fuzzing |
| **Memory Management** | >95% | Unit, Memory Testing |
| **Error Handling** | >85% | Unit, Edge Cases |

### 🧪 Test Categories

#### Unit Tests
```c
// Example unit test structure
void test_password_encryption(void) {
    char password[] = "test_password";
    char encrypted[256];
    char decrypted[256];
    
    // Test encryption
    assert(encrypt_password(password, encrypted) == 0);
    
    // Test decryption
    assert(decrypt_password(encrypted, decrypted) == 0);
    
    // Verify round-trip
    assert(strcmp(password, decrypted) == 0);
    
    // Clean up
    memset(password, 0, sizeof(password));
    memset(encrypted, 0, sizeof(encrypted));
    memset(decrypted, 0, sizeof(decrypted));
}
```

#### Integration Tests
```bash
# Test complete workflows
./test_scripts/test_password_workflow.sh
./test_scripts/test_totp_workflow.sh
./test_scripts/test_import_export.sh
```

#### Security Tests
```bash
# Memory safety testing
make memcheck

# Buffer overflow testing
make buffer-overflow-test

# Cryptographic verification
make crypto-test
```

### 🔬 Testing Best Practices

1. **Test-Driven Development**
   - Write tests before implementing features
   - Ensure tests fail before implementation
   - Verify tests pass after implementation

2. **Security Testing**
   - Test with malicious inputs
   - Verify secure memory clearing
   - Test cryptographic edge cases
   - Validate error handling paths

3. **Performance Testing**
   - Benchmark cryptographic operations
   - Test with large datasets
   - Verify memory usage patterns
   - Profile execution time

### 🚀 Running Tests

```bash
# Basic functionality tests
make test

# Comprehensive test suite
make test-all

# Security-focused tests
make security-test

# Performance benchmarks
make benchmark

# Memory leak detection
make memcheck

# Code coverage analysis
make coverage
```

## 📝 Documentation Guidelines

### 📚 Documentation Requirements

All contributions should include appropriate documentation:

#### Code Documentation
```c
/**
 * @brief Encrypts a password using AES-256 encryption
 * 
 * This function takes a plaintext password and encrypts it using
 * AES-256 encryption with a key derived from the master password.
 * The encrypted result is stored in the provided output buffer.
 * 
 * @param plaintext The plaintext password to encrypt
 * @param encrypted Buffer to store the encrypted password (must be at least 256 bytes)
 * @param key The encryption key derived from master password
 * 
 * @return 0 on success, -1 on failure
 * 
 * @note The input plaintext is securely cleared after encryption
 * @warning The encrypted buffer must be large enough to hold the result
 * 
 * @see decrypt_password() for the corresponding decryption function
 */
int encrypt_password(const char *plaintext, char *encrypted, const unsigned char *key);
```

#### Function Documentation Standards
- **Brief description** of what the function does
- **Detailed explanation** of the algorithm or approach
- **Parameter descriptions** with types and constraints
- **Return value** explanation
- **Notes** about security considerations
- **Warnings** about potential pitfalls
- **Cross-references** to related functions

### 📖 User Documentation

#### README Updates
- Update feature lists for new functionality
- Add usage examples for new commands
- Update installation instructions if needed
- Modify compatibility information

#### Usage Examples
```bash
# Example: Adding documentation for new feature
## 🔐 New Feature: Password Strength Analysis

SecurePassManager now includes password strength analysis:

1. **Analyze Password Strength:**
   ```bash
   ./securepass --analyze-strength
   ```

2. **Set Minimum Strength Requirements:**
   ```bash
   ./securepass --set-min-strength high
   ```
```

### 🔒 Security Documentation

#### Security Impact Assessment
For security-related changes, include:
- **Threat model impact** analysis
- **Risk assessment** of the change
- **Mitigation strategies** implemented
- **Testing methodology** used

#### Security Documentation Template
```markdown
## Security Impact Analysis

### Change Description
Brief description of the security-related change.

### Threat Model Impact
- **New threats introduced:** None/List of new threats
- **Threats mitigated:** List of threats addressed
- **Risk level change:** Decreased/Unchanged/Increased

### Implementation Security
- **Cryptographic standards compliance:** Yes/No/N/A
- **Memory safety verified:** Yes/No
- **Input validation implemented:** Yes/No
- **Error handling secure:** Yes/No

### Testing Performed
- **Security test cases:** List of security tests
- **Penetration testing:** Performed/Not applicable
- **Code review:** Completed by [reviewer]
- **Static analysis:** Clean/Issues found and resolved
```

## 🔄 Pull Request Process

### 📋 Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] **Code Quality**
  - [ ] Code follows project style guidelines
  - [ ] All functions are documented
  - [ ] Static analysis passes without critical issues
  - [ ] Code is formatted correctly (`make format`)

- [ ] **Testing**
  - [ ] All existing tests pass
  - [ ] New tests added for new functionality
  - [ ] Test coverage meets requirements
  - [ ] Memory leak testing passes (`make memcheck`)

- [ ] **Security**
  - [ ] Security review completed (for security-sensitive changes)
  - [ ] No hardcoded secrets or credentials
  - [ ] Secure coding practices followed
  - [ ] Binary hardening features verified (`make security-check`)

- [ ] **Documentation**
  - [ ] Code documentation updated
  - [ ] User documentation updated (if applicable)
  - [ ] Security documentation updated (if applicable)
  - [ ] CHANGELOG.md updated

### 🚀 Pull Request Template

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security enhancement
- [ ] Documentation update
- [ ] Performance improvement

## Security Impact
- [ ] No security impact
- [ ] Security enhancement
- [ ] Potential security impact (requires security review)

## Testing Performed
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed
- [ ] Security testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Code is commented (particularly complex areas)
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] All checks pass

## Additional Notes
Any additional information or context about the changes.
```

### 🔍 Review Process

1. **Automated Checks**
   - Code quality analysis
   - Security scanning
   - Test execution
   - Build verification

2. **Manual Review**
   - Code review by maintainers
   - Security review (for security-sensitive changes)
   - Documentation review
   - Architecture review (for significant changes)

3. **Testing**
   - Functional testing
   - Integration testing
   - Security testing
   - Performance testing (if applicable)

4. **Approval and Merge**
   - Maintainer approval required
   - Security team approval (for security changes)
   - Automated merge after approvals

### ⏱️ Review Timeline

- **Initial Response:** Within 2-3 business days
- **Code Review:** Within 1 week for standard changes
- **Security Review:** Within 2 weeks for security changes
- **Final Approval:** After all requirements met

## 🐛 Bug Reports

### 🔍 Before Reporting a Bug

1. **Search Existing Issues**
   - Check if the bug has already been reported
   - Look for similar issues or related discussions
   - Check closed issues for potential solutions

2. **Verify the Bug**
   - Reproduce the issue consistently
   - Test with the latest version
   - Try with minimal configuration
   - Check if it's environment-specific

### 📝 Bug Report Template

```markdown
## Bug Description
A clear and concise description of the bug.

## Steps to Reproduce
1. Step one
2. Step two
3. Step three
4. Bug occurs

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- **OS:** [e.g., Ubuntu 20.04, macOS 12.0]
- **SecurePassManager Version:** [e.g., 2024.06.14]
- **GCC Version:** [e.g., 9.3.0]
- **OpenSSL Version:** [e.g., 1.1.1f]
- **liboath Version:** [e.g., 2.6.2]

## Additional Context
- Error messages (if any)
- Log output
- Configuration details
- Screenshots (if applicable)

## Security Impact
- [ ] No security impact
- [ ] Potential security vulnerability (use private reporting)
- [ ] Data corruption risk
- [ ] Availability impact
```

### 🚨 Security Bug Reports

For security vulnerabilities:
- **DO NOT** create public issues
- Use GitHub's private vulnerability reporting
- Email maintainers directly if needed
- Follow responsible disclosure timeline

## ✨ Feature Requests

### 💡 Feature Request Guidelines

Before requesting a feature:
1. **Check existing requests** in [issues and discussions](https://github.com/fam007e/SecurePasswd_MGMT/issues)
2. **Consider security implications** of the proposed feature
3. **Think about implementation complexity** and maintenance burden
4. **Provide clear use cases** and benefits

### 📋 Feature Request Template

```markdown
## Feature Description
A clear and concise description of the proposed feature.

## Problem Statement
What problem does this feature solve?

## Proposed Solution
How should this feature work?

## Alternatives Considered
Alternative approaches you've considered.

## Use Cases
- Use case 1: Description
- Use case 2: Description
- Use case 3: Description

## Security Considerations
- Does this feature introduce new attack vectors?
- Are there privacy implications?
- What are the security requirements?

## Implementation Complexity
- [ ] Simple (minor addition)
- [ ] Moderate (requires some refactoring)
- [ ] Complex (significant architecture changes)
- [ ] Major (fundamental changes required)

## Additional Context
Any other context, mockups, or examples.
```

### 🎯 Feature Prioritization

Features are prioritized based on:
- **Security impact** and risk assessment
- **User demand** and community support
- **Implementation complexity** and resource requirements
- **Alignment** with project goals and roadmap
- **Maintenance burden** and long-term sustainability

## 📚 Learning Resources

### 🔐 Security Resources

#### Cryptography
- [Cryptography Engineering](https://www.schneier.com/books/cryptography_engineering/) by Schneier, Ferguson, and Kohno
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/publications)

#### Secure Coding
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)

### 💻 Development Resources

#### C Programming
- [The C Programming Language](https://en.wikipedia.org/wiki/The_C_Programming_Language) by Kernighan and Ritchie
- [Expert C Programming](https://www.amazon.com/Expert-Programming-Peter-van-Linden/dp/0131774298) by van der Linden
- [Modern C](https://modernc.gforge.inria.fr/) by Jens Gustedt

#### Tools and Testing
- [Valgrind Documentation](https://valgrind.org/docs/manual/)
- [GCC Security Features](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- [Static Analysis Tools](https://github.com/analysis-tools-dev/static-analysis)

### 🏗️ Build System and DevOps
- [GNU Make Manual](https://www.gnu.org/software/make/manual/)
- [Autotools Tutorial](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)
- [CMake Best Practices](https://cmake.org/cmake/help/latest/guide/tutorial/)

## 🏆 Recognition

### 🌟 Contributor Recognition

We recognize and appreciate all contributions:

#### Hall of Fame
Contributors who make significant impacts are recognized in:
- **README.md** acknowledgments section
- **Release notes** for major contributions
- **Security advisories** for security researchers
- **Annual contributor highlights**

#### Contribution Types Recognized
- **Code Contributions:** Features, bug fixes, optimizations
- **Security Contributions:** Vulnerability reports, security enhancements
- **Documentation:** User guides, developer documentation
- **Testing:** Test cases, quality assurance, bug reports
- **Community:** Helping other users, project promotion

### 🎖️ Badges and Recognition

| Contribution Type | Recognition |
|------------------|-------------|
| **First Contribution** | Welcome badge, special mention |
| **Security Research** | Security researcher recognition |
| **Major Feature** | Feature contributor badge |
| **Long-term Contributor** | Core contributor status |
| **Documentation** | Documentation contributor badge |

### 📊 Contribution Metrics

We track and celebrate:
- **Code contributions:** Lines of code, commits, features
- **Issue resolution:** Bugs fixed, questions answered
- **Code review:** Reviews performed, quality improvements
- **Documentation:** Guides written, examples provided
- **Security:** Vulnerabilities found, security improvements

## 📞 Getting Help

### 💬 Communication Channels

#### GitHub Discussions
- **General Questions:** Use GitHub Discussions for general questions
- **Feature Discussions:** Discuss proposed features and improvements
- **Development Help:** Get help with development setup and contribution process

#### GitHub Issues
- **Bug Reports:** Report bugs and issues
- **Feature Requests:** Request new features
- **Security Issues:** Use private reporting for security vulnerabilities

### 🆘 Getting Support

#### Development Support
- **Setup Issues:** Problems with development environment setup
- **Build Problems:** Compilation and linking issues
- **Testing Help:** Assistance with testing and quality assurance
- **Code Reviews:** Request for code review and feedback

#### Mentorship Program
For new contributors:
- **Mentorship matching** with experienced contributors
- **Guided first contribution** process
- **Regular check-ins** and support
- **Learning path** recommendations

### 📅 Office Hours
Regular community office hours (if applicable):
- **When:** Weekly/Monthly (TBD based on community size)
- **Where:** Video call/Chat (links provided)
- **Topics:** Open discussion, Q&A, project planning

### 🎓 Learning Support

#### Code Review Learning
- **Pair review sessions** for learning
- **Review guideline** explanations
- **Security review** training

#### Security Training
- **Secure coding** workshops
- **Cryptography** fundamentals
- **Threat modeling** sessions

## 🔒 Final Notes

### 🎯 Project Goals Alignment

All contributions should align with SecurePassManager's core principles:
- **Security First:** Security is never compromised for convenience
- **Privacy Focused:** User data remains local and private
- **Reliability:** Robust, tested, and maintainable code
- **Simplicity:** Clean, understandable, and well-documented solutions

### 📜 Code License

By contributing to SecurePassManager, you agree that your contributions will be licensed under the same MIT License that covers the project.

### 🤝 Code of Conduct

We foster an inclusive and welcoming community. All contributors are expected to:
- **Be respectful** and professional in all interactions
- **Welcome newcomers** and help them learn
- **Focus on constructive** feedback and discussion
- **Respect different viewpoints** and experiences
- **Report inappropriate behavior** to maintainers. Please report unacceptable behavior to [@fam007e](mailto:faisalmoshiur+secpasswdreport@gmail.com).

### 🙏 Thank You

Thank you for contributing to SecurePassManager! Your efforts help make secure password management accessible to everyone. Whether you're fixing a typo, adding a feature, or improving security, every contribution matters.

---

**🔒 Remember: Security is a shared responsibility. Every line of code, every review, and every test contributes to the security of all users.**

*Happy contributing! 🚀*

---

**Document Version:** 2025.06.14  
**Last Updated:** June 14, 2025  
**Next Review:** September 14, 2025
