CC = gcc

# Base compiler flags
CFLAGS = -Wall -Wextra -I./src -I/usr/include

# Security-focused compilation flags
SECURITY_FLAGS = -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                 -Wformat -Werror=format-security -pie -fPIE \
                 -fstack-clash-protection -fcf-protection

# Additional hardening flags (optional, comment out if causing issues)
HARDENING_FLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# Combine all flags
CFLAGS += $(SECURITY_FLAGS)

# Linker flags
LDFLAGS = -lcrypto -loath -lssl $(HARDENING_FLAGS)

# Version definition
VERSION := $(shell date +%Y.%m.%d)
CFLAGS += -DVERSION=\"$(VERSION)\"

# Check if oath.h exists in the system
OATH_SYSTEM := $(shell if [ -f /usr/include/liboath/oath.h ]; then echo 1; else echo 0; fi)
ifeq ($(OATH_SYSTEM),0)
    # Use local oath.h
    CFLAGS += -I./lib
endif

# Source files
SRCS = src/main.c src/encryption.c src/csv_handler.c src/totp.c src/utils.c
OBJS = $(SRCS:.c=.o)
HEADERS = src/encryption.h src/csv_handler.h src/totp.h src/utils.h src/version.h

# Target executable
TARGET = securepass

# Default target
.PHONY: all clean debug release install uninstall check-deps test package

all: $(TARGET)

# Verify dependencies are installed
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists openssl || (echo "ERROR: OpenSSL development headers not found" && exit 1)
	@pkg-config --exists liboath || echo "WARNING: liboath not found via pkg-config, trying fallback"
	@[ -f /usr/include/liboath/oath.h ] || [ -f ./lib/oath.h ] || (echo "ERROR: oath.h not found" && exit 1)
	@echo "Dependencies OK"

# Standard build with security flags
$(TARGET): check-deps $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Debug build (removes optimization, adds debug symbols)
debug: CFLAGS += -g -O0 -DDEBUG
debug: CFLAGS := $(filter-out -O2,$(CFLAGS))
debug: $(TARGET)

# Release build (additional optimizations)
release: CFLAGS += -O3 -DNDEBUG -flto
release: LDFLAGS += -flto
release: $(TARGET)

# Compile object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Test target
test: $(TARGET)
	@echo "Running basic tests..."
	@./$(TARGET) --version >/dev/null || (echo "ERROR: Binary doesn't run" && exit 1)
	@./$(TARGET) --help >/dev/null || (echo "ERROR: Help command failed" && exit 1)
	@echo "Basic tests passed"

# Package target for distribution
package: release
	@VERSION=$$(./$(TARGET) --version | grep -o '[0-9]\{4\}\.[0-9]\{2\}\.[0-9]\{2\}' || date +%Y.%m.%d); \
	mkdir -p dist; \
	tar -czvf dist/$(TARGET)-$$VERSION-$$(uname -s)-$$(uname -m).tar.gz $(TARGET); \
	cd dist && sha256sum $(TARGET)-$$VERSION-$$(uname -s)-$$(uname -m).tar.gz > $(TARGET)-$$VERSION-$$(uname -s)-$$(uname -m).tar.gz.sha256; \
	echo "Package created: dist/$(TARGET)-$$VERSION-$$(uname -s)-$$(uname -m).tar.gz"

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf data/ dist/

# Install (optional - adjust paths as needed)
install: $(TARGET)
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(TARGET) $(DESTDIR)/usr/local/bin/

# Uninstall
uninstall:
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)

# Security analysis targets (require additional tools)
.PHONY: security-check static-analysis

# Static analysis with cppcheck (if available)
static-analysis:
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "Running static analysis with cppcheck..."; \
		cppcheck --enable=all --std=c99 --platform=unix64 --suppress=missingIncludeSystem src/; \
	else \
		echo "cppcheck not found. Install with: sudo apt-get install cppcheck"; \
	fi

# Security-focused checks
security-check: static-analysis
	@echo "=== Security Compilation Check ==="
	@echo "Compiler: $(CC)"
	@echo "Security flags: $(SECURITY_FLAGS)"
	@echo "Hardening flags: $(HARDENING_FLAGS)"
	@if command -v checksec >/dev/null 2>&1 && [ -f $(TARGET) ]; then \
		echo "=== Binary Security Analysis ==="; \
		checksec --file=$(TARGET); \
	else \
		echo "checksec not found or binary not built. Install with: sudo apt-get install checksec"; \
	fi

# Memory check target (requires valgrind)
.PHONY: memcheck
memcheck: debug
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Running memory check with valgrind..."; \
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) --help; \
	else \
		echo "valgrind not found. Install with: sudo apt-get install valgrind"; \
	fi

# Code coverage (requires gcov)
.PHONY: coverage
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: clean $(TARGET)
	@echo "Building with coverage support..."
	@echo "Run your tests, then use 'make coverage-report' to generate report"

# Generate coverage report
.PHONY: coverage-report
coverage-report:
	@if command -v gcov >/dev/null 2>&1; then \
		echo "Generating coverage report..."; \
		gcov $(SRCS); \
		if command -v lcov >/dev/null 2>&1; then \
			lcov --capture --directory . --output-file coverage.info; \
			lcov --remove coverage.info '/usr/*' --output-file coverage.info; \
			if command -v genhtml >/dev/null 2>&1; then \
				genhtml coverage.info --output-directory coverage_html; \
				echo "Coverage report generated in coverage_html/index.html"; \
			fi; \
		fi; \
	else \
		echo "gcov not found. Install with: sudo apt-get install gcc"; \
	fi

# Format code (requires clang-format)
.PHONY: format
format:
	@if command -v clang-format >/dev/null 2>&1; then \
		echo "Formatting code..."; \
		find src/ -name "*.c" -o -name "*.h" | xargs clang-format -i; \
		echo "Code formatted"; \
	else \
		echo "clang-format not found. Install with: sudo apt-get install clang-format"; \
	fi

# Lint code (requires various tools)
.PHONY: lint
lint: static-analysis
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "Running additional lint checks..."; \
		cppcheck --enable=style,performance,portability --std=c99 src/; \
	fi
	@if command -v clang-tidy >/dev/null 2>&1; then \
		echo "Running clang-tidy..."; \
		clang-tidy src/*.c -- $(CFLAGS); \
	else \
		echo "clang-tidy not found. Install with: sudo apt-get install clang-tidy"; \
	fi

# All quality checks
.PHONY: quality
quality: lint security-check test
	@echo "All quality checks completed"

# Development setup
.PHONY: dev-setup
dev-setup:
	@echo "Installing development dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Detected Debian/Ubuntu system"; \
		sudo apt-get update; \
		sudo apt-get install -y build-essential libssl-dev liboath-dev liboath0 oathtool; \
		sudo apt-get install -y cppcheck checksec valgrind clang-format clang-tidy lcov; \
	elif command -v pacman >/dev/null 2>&1; then \
		echo "Detected Arch Linux system"; \
		sudo pacman -Syu --needed --noconfirm base-devel openssl oath-toolkit; \
		sudo pacman -S --needed --noconfirm cppcheck checksec valgrind clang lcov; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Detected Fedora/RHEL system"; \
		sudo dnf install -y gcc gcc-c++ make openssl-devel liboath-devel oathtool; \
		sudo dnf install -y cppcheck checksec valgrind clang-tools-extra lcov; \
	elif command -v yum >/dev/null 2>&1; then \
		echo "Detected CentOS/RHEL system"; \
		sudo yum groupinstall -y "Development Tools"; \
		sudo yum install -y openssl-devel liboath-devel oathtool; \
		sudo yum install -y cppcheck valgrind clang lcov; \
		echo "Note: checksec may need to be installed manually on CentOS/RHEL"; \
	elif command -v apk >/dev/null 2>&1; then \
		echo "Detected Alpine Linux system"; \
		sudo apk update; \
		sudo apk add build-base openssl-dev oath-toolkit-dev oath-toolkit; \
		sudo apk add cppcheck valgrind clang-extra-tools lcov; \
		echo "Note: checksec may need to be installed manually on Alpine"; \
	elif command -v zypper >/dev/null 2>&1; then \
		echo "Detected openSUSE system"; \
		sudo zypper install -y gcc gcc-c++ make libopenssl-devel liboath-devel oathtool; \
		sudo zypper install -y cppcheck valgrind clang-tools lcov; \
		echo "Note: checksec may need to be installed manually on openSUSE"; \
	elif command -v emerge >/dev/null 2>&1; then \
		echo "Detected Gentoo system"; \
		sudo emerge --ask=n sys-devel/gcc sys-devel/make dev-libs/openssl app-crypt/oath-toolkit; \
		sudo emerge --ask=n dev-util/cppcheck dev-util/valgrind sys-devel/clang dev-util/lcov; \
		echo "Note: checksec may need to be installed manually on Gentoo"; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Detected macOS with Homebrew"; \
		brew install gcc make openssl oath-toolkit; \
		brew install cppcheck valgrind llvm lcov; \
		echo "Note: checksec may need to be installed manually on macOS"; \
	else \
		echo "Package manager not detected. Please install dependencies manually:"; \
		echo ""; \
		echo "Required packages:"; \
		echo "  - C compiler (gcc/clang)"; \
		echo "  - make"; \
		echo "  - OpenSSL development headers"; \
		echo "  - liboath development headers"; \
		echo "  - oath-toolkit/oathtool"; \
		echo ""; \
		echo "Optional development tools:"; \
		echo "  - cppcheck (static analysis)"; \
		echo "  - checksec (binary security analysis)"; \
		echo "  - valgrind (memory debugging)"; \
		echo "  - clang-format/clang-tidy (code formatting/linting)"; \
		echo "  - lcov (code coverage)"; \
		exit 1; \
	fi
	@echo "Development environment set up successfully"

# Show build information
.PHONY: info
info:
	@echo "=== Build Information ==="
	@echo "Target: $(TARGET)"
	@echo "Version: $(VERSION)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "Sources: $(SRCS)"
	@echo "Objects: $(OBJS)"
	@echo "Headers: $(HEADERS)"
	@echo "OATH System: $(OATH_SYSTEM)"

# Help target
help:
	@echo "Available targets:"
	@echo "  all              - Build with security flags (default)"
	@echo "  debug            - Build with debug symbols, no optimization"
	@echo "  release          - Build with maximum optimization"
	@echo "  test             - Run basic functionality tests"
	@echo "  package          - Create distribution package with checksums"
	@echo "  clean            - Remove build artifacts and data directory"
	@echo "  install          - Install to /usr/local/bin"
	@echo "  uninstall        - Remove from /usr/local/bin"
	@echo ""
	@echo "Development targets:"
	@echo "  dev-setup        - Install development dependencies (Ubuntu/Debian)"
	@echo "  check-deps       - Verify required dependencies are installed"
	@echo "  format           - Format code with clang-format"
	@echo "  lint             - Run code linting with multiple tools"
	@echo "  quality          - Run all quality checks (lint + security + test)"
	@echo ""
	@echo "Analysis targets:"
	@echo "  static-analysis  - Run static code analysis (requires cppcheck)"
	@echo "  security-check   - Run security analysis (requires checksec)"
	@echo "  memcheck         - Run memory leak detection (requires valgrind)"
	@echo "  coverage         - Build with coverage support"
	@echo "  coverage-report  - Generate coverage report (after coverage build)"
	@echo ""
	@echo "Information targets:"
	@echo "  info             - Show build configuration information"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Security features enabled by default:"
	@echo "  - Stack protection (-fstack-protector-strong)"
	@echo "  - Format string protection (-Wformat -Werror=format-security)"
	@echo "  - Position Independent Executable (-pie -fPIE)"
	@echo "  - Buffer overflow detection (-D_FORTIFY_SOURCE=2)"
	@echo "  - Stack clash protection (-fstack-clash-protection)"
	@echo "  - Control Flow Integrity (-fcf-protection)"
	@echo "  - RELRO linking (-Wl,-z,relro -Wl,-z,now)"