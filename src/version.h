#ifndef VERSION_H
#define VERSION_H

// VERSION is defined by Makefile via -DVERSION flag
// If not defined (e.g., during development without make), use fallback
#ifndef VERSION
#define VERSION "dev-build"
#endif

// Additional version-related constants
#define PROGRAM_NAME "SecurePassManager"
#define AUTHOR "fam007e"
#define REPOSITORY_URL "https://github.com/fam007e/SecurePasswd_MGMT"

// Version display function declaration
void print_version(void);
void print_help(void);

#endif // VERSION_H