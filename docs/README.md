# SecurePasswd_MGMT Documentation

This directory contains detailed documentation for SecurePasswd_MGMT development and changes.

## Documentation Files

### DESIGN_TOKENS.md
The shared design contract for desktop and Android: color palettes (Nord,
Dracula, Solarized — each dark and light), shape scale, theme behavior
(tri-state: Follow System / Light / Dark), and user-visible copy.

### THREAT_MODEL.md
STRIDE threat model, including the LAN 2-way sync session and the Android
companion attack surface.

### TESTING.md
Test suites, sanitizer runs, fuzz targets and CI verification summary.

### USER_GUIDE.md
GUI walkthrough: entries, TOTP, OpenPGP keys, palettes/themes, two-way sync.

## Main Documentation

The following documentation files are located in the project root:

### README.md
Project overview, installation instructions, usage guide, and feature descriptions.

### SECURITY.md
Security policy documenting:
- Cryptographic implementation details (AES-256, Argon2id, libsodium)
- Data protection measures
- Memory management practices
- File system security
- Password strength validation requirements
- Compliance standards

### CHANGELOG.md
Version history following Keep a Changelog format, documenting all fixes, changes, additions, and security enhancements.

### CONTRIBUTING.md
Guidelines for contributing to the project, including security-focused development practices, code review process, and testing requirements.

## Quick Reference

### Security Standards Enforced
- **Minimum Password Length:** 16 characters
- **Required Character Types:** Uppercase, lowercase, numbers, symbols
- **Entropy Target:** 98.7 bits (exceeds NIST 80-bit minimum)
- **Password Reuse:** Detected and reported
- **Breach Detection:** HIBP API integration

### Compliance
- NIST SP 800-63B (Digital Identity Guidelines)
- OWASP Password Storage Cheat Sheet
- CIS Controls v8 (Password Policy Requirements)
- ISO 27001 (Information Security Management)

## For Developers

### Modified Files Summary
1. `core/database.c` - Delete entry verification, recovery codes support
2. `cli/main.c` - Enhanced health check, feature parity with GUI
3. `gui/healthcheckdialog.cpp` - Updated thresholds
4. `gui/mainwindow.{h,cpp}` - Segfault fix, icon-only toolbar, recovery toggle
5. `gui/main.cpp` - Database status check
6. `gui/entrydialog.{h,cpp}` - Entry validation, recovery codes display logic
7. `core/password_generator.{h,c}` - Relocated to core, guaranteed entropy shuffle

### Build Status
- CLI: Building successfully
- GUI: Building successfully
- Tests: All passing

### Testing Locations
- Unit tests: `tests/test_core.c`, `tests/test_cmocka.c`, `tests/test_sync_protocol.c` (13 protocol tests)
- Fuzz targets: `tests/fuzz/` (snapshot, frames, TOTP, password generator)
- Test execution: `ctest --test-dir build`

## Additional Resources

### GitHub Repository
https://github.com/fam007e/SecurePasswd_MGMT

### Issue Tracking
Report bugs and request features via GitHub Issues.

### Security Vulnerabilities
**DO NOT** open public issues for security vulnerabilities. Contact maintainers directly or use GitHub's private vulnerability reporting feature.

---

Last Updated: November 2026
