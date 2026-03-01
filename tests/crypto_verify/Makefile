CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11 -pthread
LDFLAGS := -lssl -lcrypto -lpthread

crypto_verify: crypto_verify.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f crypto_verify

.PHONY: clean
