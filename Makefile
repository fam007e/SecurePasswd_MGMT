CC = gcc
CFLAGS = -Wall -Wextra -I./src -I/usr/include
LDFLAGS = -lcrypto -loath -lssl

SRCS = src/main.c src/encryption.c src/csv_handler.c src/totp.c src/utils.c
OBJS = $(SRCS:.c=.o)
TARGET = securepass

# Test source files (add your test files here)
TEST_SRCS = tests/test_main.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_TARGET = run_tests

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TEST_TARGET): $(filter-out src/main.o, $(OBJS)) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TEST_OBJS) $(TARGET) $(TEST_TARGET)