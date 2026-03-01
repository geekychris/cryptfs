# CryptoFS - Top-Level Build Orchestration
#
# Usage:
#   make all          - build kernel module + userspace
#   make kernel       - build kernel module only
#   make daemon       - build key management daemon
#   make cli          - build admin CLI
#   make test         - run integration tests
#   make bench        - run benchmarks
#   make docker-test  - run Docker-based tests
#   make clean        - clean all build artifacts
#   make install      - install kernel module + userspace binaries
#   make vm-up        - start development VM
#   make vm-ssh       - SSH into development VM
#

.PHONY: all kernel daemon cli test test-stress test-all bench docker-test clean install \
        vm-up vm-ssh vm-halt check fmt full-test test-crypto demo

# Default: build everything
all: kernel daemon cli

# ---- Kernel Module ----

kernel:
	$(MAKE) -C kernel

kernel-clean:
	$(MAKE) -C kernel clean

kernel-install:
	$(MAKE) -C kernel install

kernel-check:
	$(MAKE) -C kernel check

# ---- Rust Daemon ----

daemon:
	cargo build --manifest-path daemon/Cargo.toml --release

daemon-debug:
	cargo build --manifest-path daemon/Cargo.toml

daemon-test:
	cargo test --manifest-path daemon/Cargo.toml

daemon-clean:
	cargo clean --manifest-path daemon/Cargo.toml

# ---- Rust CLI ----

cli:
	cargo build --manifest-path cli/Cargo.toml --release

cli-debug:
	cargo build --manifest-path cli/Cargo.toml

cli-clean:
	cargo clean --manifest-path cli/Cargo.toml

# ---- Combined Operations ----

clean: kernel-clean daemon-clean cli-clean
	rm -rf target/

install: kernel-install
	install -m 755 daemon/target/release/cryptofs-keyd /usr/local/bin/
	install -m 755 cli/target/release/cryptofs-admin /usr/local/bin/
	mkdir -p /etc/cryptofs /var/lib/cryptofs/keys /var/run/cryptofs /var/log/cryptofs

# ---- Testing ----

test: daemon-test
	@echo "Running integration tests..."
	@for t in tests/integration/test_basic_ops.sh \
	          tests/integration/test_random_access.sh \
	          tests/integration/test_append.sh \
	          tests/integration/test_concurrent.sh; do \
		echo "--- Running $$t ---"; \
		bash $$t || true; \
	done

test-stress:
	bash tests/integration/test_stress.sh

test-stress-light:
	STRESS_LEVEL=light bash tests/integration/test_stress.sh

test-stress-heavy:
	STRESS_LEVEL=heavy bash tests/integration/test_stress.sh

test-policy:
	bash tests/integration/test_policy_uid.sh

test-docker:
	bash tests/integration/test_docker.sh

# Build everything and run all tests (the full pipeline)
full-test:
	bash build_and_test.sh

full-test-heavy:
	bash build_and_test.sh --stress heavy

full-test-all:
	bash build_and_test.sh --stress heavy --include-docker --include-bench

# ---- Crypto Verification (Docker, no kernel required) ----

test-crypto:
	docker compose -f docker/docker-compose.yml build crypto-verify
	docker compose -f docker/docker-compose.yml run --rm crypto-verify

# ---- Encryption Demo (writes files to host for inspection) ----

DEMO_ENC := $(CURDIR)/demo_encrypted
DEMO_PT  := $(CURDIR)/demo_plaintext

demo:
	@mkdir -p $(DEMO_ENC) $(DEMO_PT)
	@rm -rf $(DEMO_ENC)/* $(DEMO_PT)/*
	DEMO_ENCRYPTED=$(DEMO_ENC) DEMO_PLAINTEXT=$(DEMO_PT) \
	  docker compose -f docker/docker-compose.yml build cryptofs-demo
	DEMO_ENCRYPTED=$(DEMO_ENC) DEMO_PLAINTEXT=$(DEMO_PT) \
	  docker compose -f docker/docker-compose.yml run --rm cryptofs-demo
	@echo ""
	@echo "═══ Inspect from your Mac ═══════════════════════════════"
	@echo "  Plaintext: $(DEMO_PT)/"
	@echo "  Encrypted: $(DEMO_ENC)/"
	@echo ""
	@echo "  Try:"
	@echo "    cat $(DEMO_PT)/hello.txt"
	@echo "    hexdump -C $(DEMO_ENC)/hello.txt | head -20"
	@echo "    ls -la $(DEMO_PT)/ $(DEMO_ENC)/"
	@echo "═════════════════════════════════════════════════════════"

bench:
	bash tests/bench/run_fio.sh

bench-compare:
	python3 tests/bench/compare_results.py

# ---- Docker ----

docker-build:
	docker compose -f docker/docker-compose.yml build

docker-test: docker-build
	docker compose -f docker/docker-compose.yml up test-basic

docker-bench: docker-build
	docker compose -f docker/docker-compose.yml up test-bench baseline-bench

# ---- Development VM ----

vm-up:
	cd vagrant && vagrant up

vm-ssh:
	cd vagrant && vagrant ssh

vm-halt:
	cd vagrant && vagrant halt

vm-destroy:
	cd vagrant && vagrant destroy -f

# ---- Code Quality ----

check: kernel-check
	cargo clippy --manifest-path daemon/Cargo.toml -- -D warnings
	cargo clippy --manifest-path cli/Cargo.toml -- -D warnings

fmt:
	cargo fmt --manifest-path daemon/Cargo.toml
	cargo fmt --manifest-path cli/Cargo.toml

# ---- Quick Start (for development) ----

# Load module, start daemon, mount filesystem
quickstart:
	@echo "=== CryptoFS Quick Start ==="
	@echo "1. Loading kernel module..."
	sudo insmod kernel/cryptofs.ko
	@echo "2. Starting daemon..."
	sudo daemon/target/release/cryptofs-keyd --foreground &
	@sleep 1
	@echo "3. Generating key..."
	cli/target/release/cryptofs-admin key generate --label default
	@echo "4. Mount with: cryptofs-admin mount /path/to/source /path/to/mountpoint"
	@echo "=== Ready ==="
