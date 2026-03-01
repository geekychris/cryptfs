# CryptoFS — Kernel-Level Transparent Encryption Filesystem for Linux

CryptoFS is a Linux kernel module that provides transparent, per-file AES-256-GCM encryption at the VFS layer. Inspired by [Thales CipherTrust Transparent Encryption (CTE)](https://cpl.thalesgroup.com/encryption/transparent-encryption), it allows applications to read and write files normally while all data is encrypted on the underlying storage — no application changes required.

Authorized processes see plaintext. Unauthorized processes see raw ciphertext or are blocked from writing. Access is governed by per-process policies based on UID, GID, binary path, binary hash, or process name.

---

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Encryption Details](#encryption-details)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Quick Start](#quick-start)
- [Key Management](#key-management)
- [Access Policies](#access-policies)
- [Docker Integration](#docker-integration)
- [Testing](#testing)
- [Benchmarking](#benchmarking)
- [Development Environment (macOS)](#development-environment-macos)
- [Configuration Reference](#configuration-reference)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Key Features

- **Transparent encryption** — applications need no modifications; encryption and decryption happen at the VFS layer, invisible to userspace
- **AES-256-GCM** — authenticated encryption via the Linux kernel Crypto API; detects tampering through per-extent GCM authentication tags
- **Per-file encryption keys** — each file gets a unique 256-bit File Encryption Key (FEK), wrapped by a master key; compromising one FEK does not expose other files
- **4 KB extent-based processing** — encryption operates on page-aligned 4096-byte extents, enabling efficient random access without decrypting entire files
- **Per-process access control** — fine-grained policies by UID, GID, executable path, binary SHA-256 hash, or process name
- **Full VFS operation support** — sequential I/O, random-access reads/writes, append, truncate, mmap, rename, symlinks, hardlinks
- **Stacked filesystem** — mounts on top of any existing filesystem (ext4, xfs, btrfs, etc.) without reformatting
- **Docker compatible** — mount encrypted volumes into containers via host bind mounts
- **Key management daemon** — local keystore with Argon2id-protected master keys; architecture supports extension to external KMS (HashiCorp Vault, AWS KMS, etc.)
- **Audit logging** — kernel ring-buffer audit trail for all access events, policy changes, and key operations
- **Comprehensive test suite** — integration tests, multi-section stress test with SHA-256 data integrity verification, fio benchmarks, and Docker container tests

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Userspace                              │
│                                                                 │
│  ┌──────────────┐    ┌───────────────┐    ┌─────────────────┐  │
│  │ cryptofs-    │    │ cryptofs-keyd │    │  Applications   │  │
│  │ admin (CLI)  │    │   (daemon)    │    │  (any process)  │  │
│  └──────┬───────┘    └──────┬────────┘    └───────┬─────────┘  │
│         │ netlink           │ keyring             │ syscalls    │
│  ═══════╪═══════════════════╪═════════════════════╪═══════════  │
│         │ Kernel            │                     │             │
│  ┌──────┴───────────────────┴─────────────────────┴──────────┐  │
│  │              cryptofs.ko (stacked filesystem)             │  │
│  │                                                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │   Policy    │  │   Crypto     │  │   Netlink       │  │  │
│  │  │   Engine    │  │   Engine     │  │   Interface     │  │  │
│  │  └─────────────┘  └──────────────┘  └─────────────────┘  │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐  │  │
│  │  │  VFS Ops    │  │  Inode/File  │  │   Audit Ring    │  │  │
│  │  │  (stacked)  │  │  Management  │  │   Buffer        │  │  │
│  │  └─────────────┘  └──────────────┘  └─────────────────┘  │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │         Lower Filesystem (ext4 / xfs / btrfs / ...)       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction

1. **Applications** issue normal POSIX file operations (`open`, `read`, `write`, etc.)
2. **cryptofs.ko** intercepts these via VFS and checks the **policy engine** against the calling process
3. For authorized processes: data passes through the **crypto engine** (AES-256-GCM encrypt on write, decrypt on read) before reaching the lower filesystem
4. For unauthorized processes: reads return raw ciphertext; writes are denied with `EACCES`
5. **cryptofs-keyd** manages master keys in userspace, injecting them into the kernel keyring via the **netlink interface**
6. **cryptofs-admin** provides the administrator CLI for key lifecycle, policy management, mount/unmount, status, and audit queries

---

## Project Structure

```
encrypted_fs/
├── kernel/                  # Linux kernel module (C)
│   ├── cryptofs.h           # Main header — data structures, constants, prototypes
│   ├── main.c               # Module init/exit, filesystem type registration
│   ├── super.c              # Superblock operations (mount, umount, statfs)
│   ├── dentry.c             # Dentry operations (revalidate, release)
│   ├── lookup.c             # Lookup and inode instantiation
│   ├── file.c               # File operations (read, write, open, release, fsync, llseek)
│   ├── inode.c              # Inode operations (create, mkdir, unlink, rename, etc.)
│   ├── crypto.c             # AES-256-GCM encrypt/decrypt, FEK wrap/unwrap, nonce derivation
│   ├── mmap.c               # Memory-mapped I/O support (readpage, writepage)
│   ├── policy.c             # Per-process access control policy engine
│   ├── netlink.c            # Generic netlink interface for userspace communication
│   ├── audit.c              # Kernel ring-buffer audit logging
│   └── Makefile             # Out-of-tree kernel module build
│
├── daemon/                  # Key management daemon (Rust)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # Daemon entry point, signal handling, socket server
│       ├── keystore.rs      # Encrypted key storage with Argon2id key derivation
│       ├── provider.rs      # KMS provider trait + local implementation
│       ├── keyring.rs       # Linux kernel keyring integration
│       ├── api.rs           # Unix socket API (JSON-RPC style)
│       └── audit.rs         # Daemon-side audit logging
│
├── cli/                     # Admin CLI (Rust)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # CLI entry point, argument parsing (clap)
│       └── commands/
│           ├── mod.rs       # Command dispatch
│           ├── mount.rs     # mount / umount subcommands
│           ├── key.rs       # key generate / list / unlock / activate / rotate / etc.
│           ├── policy.rs    # policy add / list / remove
│           ├── status.rs    # status display
│           └── audit.rs     # audit log query
│
├── tests/
│   ├── integration/
│   │   ├── test_basic_ops.sh      # 18 tests: CRUD, permissions, symlinks, large files
│   │   ├── test_random_access.sh  # 6 tests: seek, partial reads, extent boundaries
│   │   ├── test_append.sh         # 5 tests: append, mixed append+read
│   │   ├── test_concurrent.sh     # 4 tests: parallel writes/reads, file locking
│   │   ├── test_policy_uid.sh     # UID policy enforcement
│   │   ├── test_docker.sh         # 5 tests: container access, auth/unauth
│   │   └── test_stress.sh         # 10-section exhaustive data integrity validation
│   └── bench/
│       ├── run_fio.sh             # fio sequential/random read/write benchmarks
│       └── compare_results.py     # Encrypted vs. baseline performance comparison
│
├── docker/
│   ├── Dockerfile.test            # Test container (Ubuntu 24.04 + fio + tools)
│   ├── docker-compose.yml         # Services: test-basic, test-bench, baseline, auth/unauth
│   └── test_entrypoint.sh         # Container test entry point
│
├── vagrant/
│   ├── Vagrantfile                # QEMU ARM64 Ubuntu 24.04 VM with HVF
│   └── provision.sh               # Installs kernel headers, Rust, Docker, fio, convenience scripts
│
├── docs/
│   ├── encryption-format.md       # On-disk format specification (header, extents, nonces)
│   └── admin-guide.md             # Administration guide (keys, policies, Docker, troubleshooting)
│
├── Makefile                       # Top-level build orchestration (40+ targets)
├── build_and_test.sh              # Full pipeline: build → test → stress → report
└── how_to_run_and_test.md         # Detailed testing and run guide
```

---

## How It Works

### Stacked Filesystem Model

CryptoFS is a *stacked* (or overlay) filesystem, similar to eCryptfs and wrapfs. It registers as a Linux filesystem type (`cryptofs`) and mounts on top of an existing directory:

```bash
sudo mount -t cryptofs /data/encrypted /mnt/decrypted
```

The **lower directory** (`/data/encrypted`) contains the actual encrypted files. The **upper mount** (`/mnt/decrypted`) presents the decrypted view to authorized processes. CryptoFS intercepts all VFS operations and transforms data between the two layers.

### Data Flow

**Authorized write:**
```
write() → VFS → cryptofs → policy check ✓ → split into 4 KB extents
  → AES-256-GCM encrypt each extent → write ciphertext + GCM tags to lower filesystem
```

**Authorized read:**
```
read() → VFS → cryptofs → policy check ✓ → read encrypted extents from lower filesystem
  → AES-256-GCM decrypt + verify GCM tag → return plaintext to application
```

**Unauthorized read:**
```
read() → VFS → cryptofs → policy check ✗ → return raw ciphertext (no decryption)
```

**Unauthorized write:**
```
write() → VFS → cryptofs → policy check ✗ → return -EACCES (denied)
```

---

## Encryption Details

### Algorithm

- **Cipher:** AES-256-GCM (via Linux kernel Crypto API)
- **Key size:** 256 bits (32 bytes)
- **Nonce size:** 96 bits (12 bytes)
- **Auth tag:** 128 bits (16 bytes) per extent

### Key Hierarchy

```
Master Key (256-bit, stored encrypted by daemon with Argon2id)
  └── wraps (AES-256-GCM) → File Encryption Key (FEK, 256-bit, unique per file)
                               └── derives (HMAC-SHA256) → Per-extent nonce (96-bit)
```

- **Master key** is stored on disk encrypted with a passphrase via Argon2id key derivation. It is unlocked into daemon memory, then injected into the kernel keyring when activated.
- **FEK** is randomly generated when a file is created. It is stored in the file header, wrapped (encrypted) by the master key.
- **Per-extent nonce** is derived deterministically: `HMAC-SHA256(FEK, inode_number || extent_index)` truncated to 12 bytes. This guarantees nonce uniqueness without storing nonces on disk.

### On-Disk File Format

```
┌────────────────────────────┐  Offset 0
│     File Header (128 B)    │
├────────────────────────────┤  Offset 128
│  Extent 0: Ciphertext      │  4096 bytes
│  Extent 0: Auth Tag        │  16 bytes
├────────────────────────────┤  Offset 4240
│  Extent 1: Ciphertext      │  4096 bytes
│  Extent 1: Auth Tag        │  16 bytes
├────────────────────────────┤
│          ...                │
├────────────────────────────┤
│  Extent N: Ciphertext      │  ≤ 4096 bytes (last may be partial)
│  Extent N: Auth Tag        │  16 bytes
└────────────────────────────┘
```

**File header fields (128 bytes):**

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Magic: `"CRYPTOFS"` |
| 8 | 4 | Version (1) |
| 12 | 4 | Flags |
| 16 | 48 | Encrypted FEK (32-byte key + 16-byte GCM tag) |
| 64 | 12 | FEK wrapping nonce |
| 76 | 8 | Logical (plaintext) file size |
| 84 | 44 | Reserved |

**Offset translation:** For logical offset `L`, the lower file offset is `128 + (L / 4096) * 4112 + (L % 4096)`.

**Storage overhead:** 128 bytes per file + 16 bytes per 4 KB extent (~0.4% for a 1 MB file).

For the complete on-disk format specification, see [docs/encryption-format.md](docs/encryption-format.md).

---

## Prerequisites

- **Linux kernel 6.1+** with headers installed and `CONFIG_CRYPTO_AES` + `CONFIG_CRYPTO_GCM` enabled
- **GCC** and standard build tools (`build-essential`)
- **Rust 1.75+** (for the daemon and CLI)
- **Docker 20.10+** (optional, for container tests)
- **fio 3.0+** (optional, for benchmarks)
- **Python 3.8+** (optional, for benchmark comparison)

For macOS development, see [Development Environment (macOS)](#development-environment-macos).

---

## Building

### Build all components

```bash
make all     # builds kernel module + daemon + CLI (release)
```

### Build individually

```bash
make kernel          # kernel module (cryptofs.ko)
make daemon          # key daemon (daemon/target/release/cryptofs-keyd)
make cli             # admin CLI (cli/target/release/cryptofs-admin)
```

### Install system-wide

```bash
sudo make install
```

Installs `cryptofs.ko` to the kernel modules directory, `cryptofs-keyd` and `cryptofs-admin` to `/usr/local/bin/`, and creates configuration directories under `/etc/cryptofs/`, `/var/lib/cryptofs/`, `/var/run/cryptofs/`, and `/var/log/cryptofs/`.

### Clean

```bash
make clean
```

---

## Quick Start

```bash
# 1. Build everything
make all

# 2. Load the kernel module
sudo insmod kernel/cryptofs.ko

# 3. Start the key daemon
sudo daemon/target/release/cryptofs-keyd --foreground &

# 4. Generate and activate a master key
cli/target/release/cryptofs-admin key generate --label my-key
cli/target/release/cryptofs-admin key unlock <key-id>
cli/target/release/cryptofs-admin key activate <key-id>

# 5. Mount
mkdir -p /tmp/cryptofs_lower /tmp/cryptofs_mount
sudo mount -t cryptofs /tmp/cryptofs_lower /tmp/cryptofs_mount

# 6. Use it — files written to /tmp/cryptofs_mount are encrypted on disk
echo "secret data" > /tmp/cryptofs_mount/test.txt
cat /tmp/cryptofs_mount/test.txt      # → "secret data" (authorized)
cat /tmp/cryptofs_lower/test.txt      # → encrypted binary (on disk)
```

Or use the convenience target:

```bash
make quickstart
```

---

## Key Management

CryptoFS uses a two-tier key architecture managed by the `cryptofs-keyd` daemon.

### Key lifecycle

```bash
# Generate a new master key (stored encrypted on disk)
cryptofs-admin key generate --label production-key-1

# List all keys
cryptofs-admin key list

# Unlock a key (decrypt into daemon memory)
cryptofs-admin key unlock <key-id>

# Activate (inject into kernel keyring — now usable by the module)
cryptofs-admin key activate <key-id>

# Rotate (generate new key material, re-wrap existing FEKs)
cryptofs-admin key rotate <key-id>

# Deactivate (revoke from kernel)
cryptofs-admin key deactivate <key-id> --serial <serial>

# Lock (clear from daemon memory)
cryptofs-admin key lock <key-id>
```

### Import existing key material

```bash
cryptofs-admin key import --label imported --hex <64-char-hex-string>
cryptofs-admin key import --label imported --file /path/to/key.hex
```

### Daemon configuration

```
cryptofs-keyd [OPTIONS]
  --socket <path>       Unix socket (default: /var/run/cryptofs/keyd.sock)
  --key-dir <path>      Key storage (default: /var/lib/cryptofs/keys)
  --audit-log <path>    Audit log (default: /var/log/cryptofs/keyd.log)
  --pid-file <path>     PID file (default: /var/run/cryptofs/keyd.pid)
  --foreground          Don't daemonize
  --log-level <level>   trace | debug | info | warn | error
```

---

## Access Policies

When policies are configured, CryptoFS defaults to **deny** — only explicitly allowed processes get plaintext access. When no policies exist, all processes have access (proof-of-concept convenience mode).

### Policy types

| Type | Matches on | Example |
|---|---|---|
| `uid` | User ID | `--value 1000` |
| `gid` | Group ID | `--value 100` |
| `binary-path` | Executable path | `--value /usr/bin/myapp` |
| `binary-hash` | SHA-256 of executable | `--value <hex-hash>` |
| `process-name` | Process comm | `--value nginx` |

### Managing policies

```bash
# Allow UID 1000
cryptofs-admin policy add --dir /mnt/decrypted --type uid --value 1000 --perm allow

# Allow a specific binary
cryptofs-admin policy add --dir /mnt/decrypted --type binary-path \
    --value /usr/bin/myapp --perm allow

# Allow by tamper-resistant binary hash
SHA=$(sha256sum /usr/bin/myapp | awk '{print $1}')
cryptofs-admin policy add --dir /mnt/decrypted --type binary-hash \
    --value $SHA --perm allow

# List all policies
cryptofs-admin policy list

# Remove a policy
cryptofs-admin policy remove <rule-id>
```

---

## Docker Integration

### Recommended: host-mount approach

Mount CryptoFS on the host, then bind-mount the decrypted view into containers:

```bash
# Host
sudo mount -t cryptofs /data/encrypted /mnt/decrypted

# Container sees decrypted data
docker run -v /mnt/decrypted:/data myapp
```

### Docker Compose test infrastructure

The `docker/` directory provides pre-built test containers:

```bash
make docker-build    # build test containers
make docker-test     # run basic file operation tests in container
make docker-bench    # run fio benchmarks (encrypted + baseline)
```

Container services defined in `docker/docker-compose.yml`:

| Service | Description |
|---|---|
| `test-basic` | Basic file ops through encrypted mount |
| `test-bench` | fio benchmarks on encrypted filesystem |
| `baseline-bench` | fio benchmarks without encryption (baseline) |
| `authorized` | Container running as UID 1000 (policy-allowed) |
| `unauthorized` | Container running as UID 65534 (should see ciphertext) |

---

## Testing

CryptoFS has an extensive multi-tier test suite. See [how_to_run_and_test.md](how_to_run_and_test.md) for detailed instructions.

### Quick reference

```bash
# Unit tests (Rust daemon)
make daemon-test

# All integration tests
make test

# Stress test (data integrity, 10 sections, SHA-256 verified)
make test-stress              # medium intensity
make test-stress-light        # light
make test-stress-heavy        # heavy (up to 500 MB files)

# Docker container tests
make test-docker

# Full automated pipeline (build → unit → mount → integration → stress → report)
make full-test                # medium stress
make full-test-heavy          # heavy stress
make full-test-all            # heavy + Docker + benchmarks
```

### Test coverage

| Suite | Tests | What it validates |
|---|---|---|
| `test_basic_ops.sh` | 18 | Create, read, write, truncate, rename, delete, permissions, symlinks, hardlinks, large files |
| `test_random_access.sh` | 6 | Seek, partial reads, overwrite at offset, extent-boundary I/O |
| `test_append.sh` | 5 | Append, mixed append+read, multi-append |
| `test_concurrent.sh` | 4 | Parallel writes, parallel reads, mixed r/w, file locking |
| `test_policy_uid.sh` | — | UID-based access policy enforcement |
| `test_docker.sh` | 5 | Container read/write, auth/unauth containers, volume persistence |
| `test_stress.sh` | 10 sections | Graduated sizes (0 B–500 MB), patterns, extent boundaries, overwrites, appends, random-offset patches, concurrent workers, file churn, unmount/remount persistence, large-file streaming |

### The `build_and_test.sh` pipeline

A single script that orchestrates the complete build-and-test workflow:

1. Build kernel module, daemon, CLI
2. Run daemon unit tests
3. Load module, start daemon, mount CryptoFS
4. Run all integration test suites
5. Run the data integrity stress test
6. (Optional) Docker tests and fio benchmarks
7. Tear down mount, unload module, kill daemon
8. Print a full pass/fail report

```bash
./build_and_test.sh
./build_and_test.sh --stress heavy --include-docker --include-bench
```

---

## Benchmarking

```bash
# Run fio benchmarks (sequential and random I/O)
make bench

# Compare encrypted vs. baseline performance
make bench-compare

# Docker-based benchmarks (both encrypted and native)
make docker-bench
```

Benchmark results are written to `docker/results/` when using Docker Compose.

---

## Development Environment (macOS)

Since `cryptofs.ko` is a Linux kernel module, it cannot compile or run on macOS. The project includes a Vagrant-managed QEMU VM for development:

```bash
# Prerequisites (Homebrew)
brew install vagrant qemu
vagrant plugin install vagrant-qemu

# Start the VM (ARM64 Ubuntu 24.04, 4 GB RAM, 4 CPUs, HVF acceleration)
make vm-up

# SSH into the VM
make vm-ssh

# Project is synced via rsync to /home/vagrant/cryptofs
# All build dependencies are pre-installed
```

The Vagrant VM provisions:
- Linux kernel headers for the running kernel
- GCC, make, libelf-dev, libssl-dev, flex, bison, bc
- Rust toolchain (via rustup)
- Docker
- fio, strace, ltrace, jq, tree
- Convenience scripts: `cryptofs-build`, `cryptofs-load`, `cryptofs-test-mount`

### VM management

```bash
make vm-up        # start VM
make vm-ssh       # SSH into VM
make vm-halt      # suspend VM
make vm-destroy   # delete VM
```

---

## Configuration Reference

### Makefile targets

| Target | Description |
|---|---|
| `make all` | Build kernel module + daemon + CLI (release) |
| `make kernel` | Build kernel module only |
| `make daemon` | Build daemon (release) |
| `make cli` | Build CLI (release) |
| `make daemon-debug` | Build daemon (debug) |
| `make cli-debug` | Build CLI (debug) |
| `make install` | Install all components system-wide |
| `make clean` | Remove all build artifacts |
| `make test` | Run unit + integration tests |
| `make test-stress` | Run stress test (medium) |
| `make test-stress-light` | Run stress test (light) |
| `make test-stress-heavy` | Run stress test (heavy) |
| `make test-policy` | Run policy enforcement tests |
| `make test-docker` | Run Docker container tests |
| `make full-test` | Full pipeline (build + all tests) |
| `make full-test-heavy` | Full pipeline with heavy stress |
| `make full-test-all` | Full pipeline + Docker + benchmarks |
| `make bench` | Run fio benchmarks |
| `make bench-compare` | Compare benchmark results |
| `make docker-build` | Build Docker test containers |
| `make docker-test` | Run Docker tests |
| `make docker-bench` | Run Docker benchmarks |
| `make quickstart` | Load module, start daemon, generate key |
| `make check` | Static analysis (sparse + clippy) |
| `make fmt` | Format Rust code |
| `make vm-up` | Start Vagrant VM |
| `make vm-ssh` | SSH into Vagrant VM |
| `make vm-halt` | Suspend Vagrant VM |
| `make vm-destroy` | Delete Vagrant VM |

### Environment variables

| Variable | Default | Used by |
|---|---|---|
| `LOWER_DIR` | `/tmp/cryptofs_lower` | `build_and_test.sh`, test scripts |
| `MOUNT_DIR` | `/tmp/cryptofs_mount` | `build_and_test.sh`, test scripts |
| `STRESS_LEVEL` | `medium` | `test_stress.sh`, `build_and_test.sh` |
| `NUM_WORKERS` | `8` | `test_stress.sh`, `build_and_test.sh` |
| `KDIR` | `/lib/modules/$(uname -r)/build` | Kernel module Makefile |
| `CRYPTOFS_MOUNT` | `/tmp/cryptofs_mount` | Docker Compose |
| `BASELINE_DIR` | `/tmp/cryptofs_baseline` | Docker Compose |

---

## Security Considerations

- **Threat model:** CryptoFS protects data at rest on the underlying storage. An attacker with access to the raw disk or lower directory sees only ciphertext. It does *not* protect against a compromised kernel or root access on a running system with keys loaded.
- **GCM authentication:** Every 4 KB extent has a GCM authentication tag. Tampering with ciphertext is detected at read time, preventing silent corruption.
- **Nonce safety:** Nonces are derived deterministically via HMAC-SHA256, not stored. This avoids nonce-reuse bugs but means overwriting the same extent with the same data produces the same ciphertext (this is acceptable for a storage encryption layer).
- **Key protection:** Master keys are stored encrypted on disk with Argon2id key derivation. They are held in daemon memory only while unlocked and in the kernel keyring only while activated.
- **Policy enforcement:** Policies are enforced in kernel space. Binary-hash policies are resistant to binary replacement attacks. Process-name policies are weaker (processes can set `comm`).
- **Memory safety:** The kernel module is written in C and operates in ring 0. The Rust userspace components (daemon, CLI) benefit from Rust's memory safety guarantees.

---

## Troubleshooting

**Module won't load**
- Check `dmesg | tail -20` for detailed error messages
- Verify kernel headers match the running kernel: `uname -r` vs. `ls /lib/modules/`
- Ensure kernel crypto support: `grep -o aes /proc/cpuinfo` and check `CONFIG_CRYPTO_AES`, `CONFIG_CRYPTO_GCM` in kernel config

**Decryption failures / GCM tag mismatch**
- Verify the correct master key is activated: `cryptofs-admin key list`
- Check `dmesg` for "GCM auth tag mismatch" messages
- The lower filesystem may have corruption — run `fsck`

**Daemon won't start**
- Check for existing instances: `pgrep cryptofs-keyd`
- Remove stale socket: `rm /var/run/cryptofs/keyd.sock`
- Run with debug logging: `cryptofs-keyd --foreground --log-level debug`

**Integration tests fail**
- Ensure CryptoFS is mounted: `mountpoint /tmp/cryptofs_mount`
- Use `build_and_test.sh` which handles all setup/teardown automatically

**Performance issues**
- Verify AES hardware acceleration: `grep aes /proc/cpuinfo`
- Run `make bench` and `make bench-compare` to measure overhead
- Ensure `CONFIG_CRYPTO_AES_ARM64_CE` or equivalent is enabled for hardware-accelerated AES

**macOS: "not Linux" warnings**
- This is expected — kernel module operations require Linux
- Use `make vm-ssh` to enter the Vagrant QEMU VM, then run builds and tests there

---

## License

GPL-2.0 — see individual source file headers for details.
