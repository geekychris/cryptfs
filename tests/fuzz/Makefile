# CryptoFS Fuzz Harnesses
#
# Requires clang (libFuzzer ships with clang's compiler-rt) and libssl-dev.
# Not wired into `make test`/`make full-test`/`make all` -- opt-in only,
# see the top-level Makefile's fuzz-build/fuzz-replay targets.

# NB: plain `CC ?= clang` would not take effect here -- make's built-in
# implicit-rules database already defines CC=cc before this file is even
# parsed, so `?=` (which only assigns if a variable is *unset*) is a no-op.
# Override on the command line instead: `make CC=clang-18 fuzz-build`.
CC      := clang
CRYPTO  := ../crypto_verify
CFLAGS  := -g -O1 -fsanitize=fuzzer,address,undefined -std=c11 -I$(CRYPTO)
LDFLAGS := -lssl -lcrypto

TARGETS := fuzz_extent_crypto fuzz_parse_file

# Bounded time per target for a CI run (overridable: make fuzz FUZZ_SECONDS=600)
FUZZ_SECONDS ?= 300

.PHONY: all build replay fuzz clean

all: build

build: $(TARGETS)

fuzz_extent_crypto: fuzz_extent_crypto.c $(CRYPTO)/cryptofs_crypto.h
	$(CC) $(CFLAGS) -o $@ fuzz_extent_crypto.c $(LDFLAGS)

fuzz_parse_file: fuzz_parse_file.c $(CRYPTO)/cryptofs_crypto.h
	$(CC) $(CFLAGS) -o $@ fuzz_parse_file.c $(LDFLAGS)

# Fast regression gate: replay the checked-in corpus with no new mutation.
# Exits non-zero if any seed crashes or trips a sanitizer.
replay: build
	./fuzz_extent_crypto -runs=0 corpus/fuzz_extent_crypto/
	./fuzz_parse_file -runs=0 corpus/fuzz_parse_file/

# Bounded-time fuzzing run for CI/local use.
fuzz: build
	./fuzz_extent_crypto -max_total_time=$(FUZZ_SECONDS) corpus/fuzz_extent_crypto/
	./fuzz_parse_file -max_total_time=$(FUZZ_SECONDS) corpus/fuzz_parse_file/

clean:
	rm -f $(TARGETS)
	rm -f crash-* oom-* timeout-* leak-*
