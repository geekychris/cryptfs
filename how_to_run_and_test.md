# How to Run and Test CryptoFS

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Linux kernel | 6.1+ | With `CONFIG_CRYPTO_AES`, `CONFIG_CRYPTO_GCM` enabled |
| Kernel headers | Matching running kernel | `linux-headers-$(uname -r)` |
| GCC / build-essential | — | Standard C build tools |
| Rust | 1.75+ | For daemon and CLI |
| Docker | 20.10+ | Optional — for container tests |
| fio | 3.0+ | Optional — for benchmarks |
| Python 3 | 3.8+ | Optional — for benchmark comparison |

If developing on macOS (Apple Silicon or Intel), use the included Vagrant/QEMU VM — the kernel module can only build and load on Linux.

---

## 1. Development Environment Setup (macOS)

CryptoFS kernel development requires a Linux kernel. On macOS, use the bundled Vagrant VM:

```bash
# Install Vagrant and the QEMU provider
brew install vagrant qemu
vagrant plugin install vagrant-qemu

# Start the ARM64 Ubuntu 24.04 VM (QEMU with HVF acceleration)
make vm-up

# SSH in
make vm-ssh

# Inside the VM, the project is synced to /home/vagrant/cryptofs
```

The VM is provisioned with all build dependencies (kernel headers, Rust, Docker, fio). Three convenience scripts are installed:

- `cryptofs-build` — builds the kernel module
- `cryptofs-load` — loads (or reloads) `cryptofs.ko`
- `cryptofs-test-mount` — mounts CryptoFS at `/opt/cryptofs/mount`

To stop or destroy the VM:

```bash
make vm-halt      # suspend
make vm-destroy   # delete entirely
```

---

## 2. Building

### Build everything (kernel module + daemon + CLI)

```bash
make all
```

### Build individual components

```bash
make kernel          # kernel module only (requires Linux)
make daemon          # Rust key management daemon (release build)
make cli             # Rust admin CLI (release build)
make daemon-debug    # debug build of daemon
make cli-debug       # debug build of CLI
```

### Install (after building)

```bash
sudo make install
```

This copies `cryptofs.ko` to `/lib/modules/...`, the `cryptofs-keyd` and `cryptofs-admin` binaries to `/usr/local/bin/`, and creates `/etc/cryptofs/`, `/var/lib/cryptofs/keys/`, `/var/run/cryptofs/`, and `/var/log/cryptofs/`.

---

## 3. Running CryptoFS

### Step-by-step startup

```bash
# 1. Load the kernel module
sudo insmod kernel/cryptofs.ko

# 2. Start the key management daemon (foreground for debugging)
sudo daemon/target/release/cryptofs-keyd --foreground

# 3. Generate a master encryption key
cli/target/release/cryptofs-admin key generate --label my-key
# Note the key UUID printed

# 4. Unlock the key (enters daemon memory)
cli/target/release/cryptofs-admin key unlock <key-id>

# 5. Activate (pushes to kernel keyring)
cli/target/release/cryptofs-admin key activate <key-id>

# 6. Mount an encrypted directory
sudo mount -t cryptofs /path/to/source /path/to/mountpoint
```

### Quick-start (convenience target)

```bash
make quickstart
```

This loads the module, starts the daemon, and generates a default key.

### Shutting down

```bash
sudo umount /path/to/mountpoint
sudo rmmod cryptofs
# Stop the daemon (Ctrl-C if foreground, or kill the PID)
```

---

## 4. Running Tests

CryptoFS includes multiple test tiers. All test commands assume you are at the project root.

### 4a. Unit tests (Rust daemon)

```bash
make daemon-test
# Runs: cargo test --manifest-path daemon/Cargo.toml
```

### 4b. Integration tests

Requires CryptoFS to be mounted. The integration suite covers:

| Test script | What it validates |
|---|---|
| `test_basic_ops.sh` | 18 tests — create, read, write, truncate, rename, delete, permissions, symlinks, hardlinks, large files |
| `test_random_access.sh` | 6 tests — seek, partial reads, overwrite at offset, extent-boundary reads |
| `test_append.sh` | 5 tests — append small/large data, mixed append+read, multi-append |
| `test_concurrent.sh` | 4 tests — parallel writes, parallel reads, mixed read/write, file locking |
| `test_policy_uid.sh` | UID-based policy enforcement — authorized vs. unauthorized access |
| `test_docker.sh` | 5 tests — container read/write, authorized/unauthorized containers, volume persistence |

Run all integration tests:

```bash
make test
```

Run individual suites:

```bash
bash tests/integration/test_basic_ops.sh
bash tests/integration/test_random_access.sh
bash tests/integration/test_append.sh
bash tests/integration/test_concurrent.sh
```

Run policy tests:

```bash
make test-policy
```

Run Docker container tests:

```bash
make test-docker
# or: make docker-test  (builds containers first)
```

### 4c. Stress test (data integrity)

The stress test is an exhaustive, multi-section data integrity suite that writes data through CryptoFS and verifies every byte with SHA-256.

**10 sections tested:**

1. **Graduated file sizes** — 0 B through 500 MB (random data, hash-verified)
2. **Known-pattern fills** — zeros, 0xFF, repeating, alternating byte patterns
3. **Extent-boundary edge cases** — files sized at 4095, 4096, 4097, 8191, 8192 bytes, etc.
4. **Overwrite-in-place cycles** — repeated overwrites of the same file, verified each time
5. **Append-then-verify** — incremental appends with full re-verification after each
6. **Random-offset patching** — write at random offsets, re-read and verify whole file
7. **Concurrent multi-process** — 8 workers × 50 files writing simultaneously, then cross-verified
8. **Create/verify/delete churn** — rapid file lifecycle (200–1000 files depending on level)
9. **Unmount/remount persistence** — write, unmount, remount, re-verify
10. **Large-file streaming** — single large file (50–500 MB) with per-extent spot-checks

**Three stress levels:**

| Level | File sizes tested | Large file | Churn files | Overwrite cycles | Append cycles |
|---|---|---|---|---|---|
| `light` | 11 variants, up to 10 MB | 50 MB | 200 | 10 | 50 |
| `medium` (default) | 18 variants, up to 100 MB | 200 MB | 500 | 25 | 100 |
| `heavy` | 27 variants, up to 500 MB | 500 MB | 1000 | 50 | 200 |

Run the stress test:

```bash
make test-stress              # medium (default)
make test-stress-light        # light
make test-stress-heavy        # heavy

# Or set environment variables directly:
STRESS_LEVEL=heavy NUM_WORKERS=16 bash tests/integration/test_stress.sh
```

### 4d. Benchmarks (fio)

```bash
make bench               # run fio benchmarks on encrypted mount
make bench-compare       # generate comparison report (encrypted vs. baseline)
```

Docker-based benchmarks:

```bash
make docker-bench        # runs both encrypted and baseline benchmarks in containers
```

---

## 5. The Full Pipeline: `build_and_test.sh`

The `build_and_test.sh` script automates the entire workflow — build, mount setup, test execution, teardown, and final report — in a single command.

### Phases

| Phase | Description |
|---|---|
| 1. Build | Compiles kernel module (Linux only), daemon, and CLI |
| 2. Unit tests | Runs `cargo test` for the daemon |
| 3. Setup | Loads `cryptofs.ko`, starts daemon, mounts CryptoFS |
| 4. Integration tests | Runs all 5 integration test scripts |
| 5. Stress test | Runs the full data integrity stress test |
| 6. Docker tests | Container tests (optional, `--include-docker`) |
| 7. Benchmarks | fio performance tests (optional, `--include-bench`) |
| Teardown | Unmounts, unloads module, kills daemon, cleans temp files |
| Report | Prints pass/fail status for every suite with elapsed time |

### Usage

```bash
# Default: build + all tests at medium stress
./build_and_test.sh

# Heavy stress level
./build_and_test.sh --stress heavy

# Include optional Docker and benchmark phases
./build_and_test.sh --include-docker --include-bench

# Everything at maximum intensity
./build_and_test.sh --stress heavy --include-docker --include-bench

# Skip the build step (assumes already built)
./build_and_test.sh --skip-build

# Build only, no tests
./build_and_test.sh --build-only
```

### Makefile shortcuts

```bash
make full-test           # ./build_and_test.sh
make full-test-heavy     # ./build_and_test.sh --stress heavy
make full-test-all       # ./build_and_test.sh --stress heavy --include-docker --include-bench
```

### Environment overrides

| Variable | Default | Description |
|---|---|---|
| `LOWER_DIR` | `/tmp/cryptofs_lower` | Backing directory for lower filesystem |
| `MOUNT_DIR` | `/tmp/cryptofs_mount` | CryptoFS mount point |
| `STRESS_LEVEL` | `medium` | `light`, `medium`, or `heavy` |
| `NUM_WORKERS` | `8` | Parallel workers for concurrent tests |
| `KDIR` | Auto-detect | Kernel build directory |

### Example output

```
════════════════════════════════════════════════════════════
  CryptoFS — Build & Test
════════════════════════════════════════════════════════════
 Date:          Sat Feb 28 12:00:00 UTC 2026
 Host:          Linux 6.8.0-45-generic aarch64
 Stress level:  medium
 Workers:       8

...

════════════════════════════════════════════════════════════
  Final Report
════════════════════════════════════════════════════════════
  ✓  Kernel module build
  ✓  Daemon build
  ✓  CLI build
  ✓  Daemon unit tests              test result: ok. 12 passed
  ✓  Load kernel module
  ✓  Start daemon
  ✓  Mount cryptofs
  ✓  Basic file operations           Results: 18/18 passed
  ✓  Random access                   Results: 6/6 passed
  ✓  Append operations               Results: 5/5 passed
  ✓  Concurrent access               Results: 4/4 passed
  ✓  UID policy                      Results: 4/4 passed
  ✓  Stress test (medium)            Passed: 87  Failed: 0  Data verified: 1.2GB

 Total suites:    13
 Passed:          13
 Failed:          0
 Duration:        247s

 ═══════════════════════════════════════════════════════════
   ✓  ALL SUITES PASSED
 ═══════════════════════════════════════════════════════════
```

---

## 6. Code Quality

```bash
make check     # sparse static analysis (kernel) + clippy (Rust)
make fmt        # rustfmt for daemon and CLI
```

---

## 7. Troubleshooting

**Module won't load**
- Check `dmesg | tail -20` for errors
- Ensure kernel headers match: `ls /lib/modules/$(uname -r)/build`
- Verify AES/GCM support: `grep -o aes /proc/cpuinfo`

**Tests fail with "not a mount point"**
- CryptoFS must be mounted before running integration or stress tests
- Use `build_and_test.sh` which handles mount setup automatically

**Daemon won't start**
- Check if another instance is running: `pgrep cryptofs-keyd`
- Check socket file: `ls -la /var/run/cryptofs/keyd.sock`
- Run in foreground for debug output: `cryptofs-keyd --foreground --log-level debug`

**Stress test OOM on small VMs**
- Use `STRESS_LEVEL=light` for VMs with <4 GB RAM
- Reduce workers: `NUM_WORKERS=2`

**Mac: "cannot set up real cryptofs mount"**
- This is expected — kernel modules require Linux
- Use `make vm-ssh` to enter the Vagrant VM, then run tests from there
