CC = gcc
CFLAGS = -Wall -Wextra -I./src -I/usr/include
LDFLAGS = -lcrypto -loath -lssl

# Version definition
VERSION := $(shell date +%Y.%m.%d)
CFLAGS += -DVERSION=\"$(VERSION)\"

# Check if oath.h exists in the system
OATH_SYSTEM := $(shell if [ -f /usr/include/liboath/oath.h ]; then echo 1; else echo 0; fi)

ifeq ($(OATH_SYSTEM),0)
    # Use local oath.h
    CFLAGS += -I./lib
endif

SRCS = src/main.c src/encryption.c src/csv_handler.c src/totp.c src/utils.c
OBJS = $(SRCS:.c=.o)
HEADERS = src/encryption.h src/csv_handler.h src/totp.h src/utils.h src/version.h
TARGET = securepass

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)