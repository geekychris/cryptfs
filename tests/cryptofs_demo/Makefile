CC      ?= gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11
LDFLAGS := -lssl -lcrypto

cryptofs_demo: cryptofs_demo.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f cryptofs_demo

.PHONY: clean
