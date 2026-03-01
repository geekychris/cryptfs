# CryptoFS — Ubuntu Build, Install & Test Guide

This guide covers building, installing, and testing CryptoFS on Ubuntu (22.04 or 24.04). It also explains how to run the Docker-based encryption demo with host-mounted volumes, and how to log into the container interactively for manual inspection.

---

## 1. Prerequisites

### System requirements

- Ubuntu 22.04 LTS or 24.04 LTS (x86_64 or ARM64)
- Linux kernel 6.1+ with `CONFIG_CRYPTO_AES` and `CONFIG_CRYPTO_GCM` enabled (default on Ubuntu)
- 4 GB+ RAM recommended (2 GB minimum for light stress tests)
- Docker 20.10+ (for container-based tests and demo)

### Install build dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    linux-headers-$(uname -r) \
    libelf-dev \
    libssl-dev \
    pkg-config \
    bc flex bison \
    kmod \
    git curl wget \
    fio strace jq tree \
    python3 python3-pip
```

### Install Rust (for daemon and CLI)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version   # should be 1.75+
```

### Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# Log out and back in, or:
newgrp docker
docker --version
```

### Verify kernel crypto support

```bash
# Check AES hardware acceleration (optional but recommended for performance)
grep -o aes /proc/cpuinfo | head -1

# Confirm kernel config supports AES-GCM
grep -E 'CONFIG_CRYPTO_(AES|GCM)=' /boot/config-$(uname -r)
# Expected: CONFIG_CRYPTO_AES=y  CONFIG_CRYPTO_GCM=y (or =m)
```

---

## 2. Clone and Build

### Clone the repository

```bash
git clone <repo-url> cryptofs
cd cryptofs
```

### Build the kernel module

The kernel module is built out-of-tree against your running kernel's headers:

```bash
make kernel
```

This runs `make -C /lib/modules/$(uname -r)/build M=$(pwd)/kernel modules` under the hood and produces `kernel/cryptofs.ko`.

**If the build fails**, check these common issues:

```bash
# 1. Verify kernel headers are installed and match your running kernel
uname -r
ls /lib/modules/$(uname -r)/build
# If missing:
sudo apt-get install linux-headers-$(uname -r)

# 2. If you upgraded your kernel but haven't rebooted, the headers won't match.
#    Reboot, then reinstall headers for the new kernel.

# 3. Build against a specific kernel version:
make kernel KDIR=/lib/modules/6.8.0-45-generic/build
```

### Build the daemon and CLI

```bash
make daemon          # key management daemon (Rust, release build)
make cli             # admin CLI (Rust, release build)
```

### Build everything at once

```bash
make all             # kernel module + daemon + CLI
```

This produces:
- `kernel/cryptofs.ko` — the kernel module
- `daemon/target/release/cryptofs-keyd` — the key management daemon
- `cli/target/release/cryptofs-admin` — the admin CLI

---

## 3. Install the Kernel Module

### Option A: Manual load with insmod (development)

For development and testing, load the module directly from the build directory:

```bash
# Load
sudo insmod kernel/cryptofs.ko

# Verify it loaded
lsmod | grep cryptofs
# Expected output:
#   cryptofs   98304  0

# Check kernel log for init message
sudo dmesg | tail -5
# Expected: "cryptofs: module loaded" or similar

# Verify it registered as a filesystem type
cat /proc/filesystems | grep cryptofs
# Expected: nodev   cryptofs

# Unload when done
sudo rmmod cryptofs
```

`insmod` loads the `.ko` file directly by path. It does **not** handle dependencies and the module is not persistent across reboots.

### Option B: Install to system module directory (modprobe)

Install the module so `modprobe` can find it:

```bash
# Install module to /lib/modules/$(uname -r)/extra/
sudo make -C kernel install

# Update module dependency database
sudo depmod -a

# Now load with modprobe (resolves dependencies automatically)
sudo modprobe cryptofs

# Verify
lsmod | grep cryptofs
```

`modprobe` is preferred over `insmod` for installed modules because it resolves dependencies and reads module options from `/etc/modprobe.d/`.

### Option C: Auto-load on boot

To have CryptoFS load automatically at boot:

```bash
# 1. Install the module (Option B above)
sudo make -C kernel install
sudo depmod -a

# 2. Add to auto-load list
echo 'cryptofs' | sudo tee /etc/modules-load.d/cryptofs.conf

# 3. (Optional) Set module parameters if needed
# echo 'options cryptofs debug=1' | sudo tee /etc/modprobe.d/cryptofs.conf

# 4. Verify it will load on next boot
cat /etc/modules-load.d/cryptofs.conf
```

After reboot, confirm:

```bash
lsmod | grep cryptofs
cat /proc/filesystems | grep cryptofs
```

### Option D: DKMS (auto-rebuild on kernel updates)

DKMS automatically recompiles the module whenever you install a new kernel. This is the recommended approach for long-lived installations.

```bash
# 1. Install DKMS
sudo apt-get install -y dkms

# 2. Create the DKMS source directory
sudo mkdir -p /usr/src/cryptofs-1.0
sudo cp kernel/*.c kernel/*.h kernel/Makefile /usr/src/cryptofs-1.0/

# 3. Create a dkms.conf
sudo tee /usr/src/cryptofs-1.0/dkms.conf > /dev/null <<'EOF'
PACKAGE_NAME="cryptofs"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="cryptofs"
DEST_MODULE_LOCATION[0]="/extra"
AUTOINSTALL="yes"
MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build modules"
CLEAN="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build clean"
EOF

# 4. Register and build with DKMS
sudo dkms add -m cryptofs -v 1.0
sudo dkms build -m cryptofs -v 1.0
sudo dkms install -m cryptofs -v 1.0

# 5. Verify
sudo modprobe cryptofs
lsmod | grep cryptofs

# Check DKMS status
dkms status
# Expected: cryptofs/1.0, <kernel-version>, x86_64: installed
```

Now when Ubuntu installs a new kernel (e.g. via `apt upgrade`), DKMS will automatically rebuild `cryptofs.ko` for the new kernel.

To remove the DKMS registration:

```bash
sudo dkms remove -m cryptofs -v 1.0 --all
sudo rm -rf /usr/src/cryptofs-1.0
```

### Install userspace binaries

The full `make install` also installs the daemon and CLI:

```bash
sudo make install
```

This copies:
- `cryptofs-keyd` and `cryptofs-admin` to `/usr/local/bin/`
- Creates `/etc/cryptofs/`, `/var/lib/cryptofs/keys/`, `/var/run/cryptofs/`, `/var/log/cryptofs/`

---

## 4. Quick Start — Mount and Use

With the module loaded (via any method above):

```bash
# 1. Load the kernel module (skip if using auto-load or already loaded)
sudo modprobe cryptofs    # or: sudo insmod kernel/cryptofs.ko

# 2. Start the key daemon (foreground for visibility)
sudo cryptofs-keyd --foreground &
# Or from the build directory:
# sudo daemon/target/release/cryptofs-keyd --foreground &

# 3. Generate a master key
cryptofs-admin key generate --label my-key
# Note the key UUID printed

# 4. Unlock and activate the key
cryptofs-admin key unlock <key-id>
cryptofs-admin key activate <key-id>

# 5. Create directories and mount
mkdir -p /tmp/cryptofs_lower /tmp/cryptofs_mount
sudo mount -t cryptofs /tmp/cryptofs_lower /tmp/cryptofs_mount

# 6. Verify the mount
mount | grep cryptofs
# Expected: /tmp/cryptofs_lower on /tmp/cryptofs_mount type cryptofs (rw,relatime)

# 7. Test it — write through the encrypted mount, inspect the raw lower directory
echo "hello encrypted world" > /tmp/cryptofs_mount/test.txt
cat /tmp/cryptofs_mount/test.txt          # → "hello encrypted world" (authorized)
hexdump -C /tmp/cryptofs_lower/test.txt | head   # → binary ciphertext on disk
```

Or use the convenience target:

```bash
make quickstart
```

### Persistent mount via /etc/fstab

To mount CryptoFS automatically at boot (requires the module to be auto-loaded per section 3):

```bash
# Create persistent directories
sudo mkdir -p /data/cryptofs_lower /mnt/cryptofs

# Add to fstab
echo '/data/cryptofs_lower /mnt/cryptofs cryptofs defaults 0 0' | sudo tee -a /etc/fstab

# Test (mount without reboot)
sudo mount /mnt/cryptofs
```

**Note:** The key daemon must be running and a key activated before the mount will work. For production, set up `cryptofs-keyd` as a systemd service that starts before the mount.

### Shut down

```bash
sudo umount /tmp/cryptofs_mount
sudo rmmod cryptofs    # or: sudo modprobe -r cryptofs
# Stop the daemon (Ctrl-C if foreground, or kill the PID)
```

---

## 5. Running Tests

### 5a. Automated full pipeline

The easiest way to build and run all tests:

```bash
# Default: build + all tests at medium stress
./build_and_test.sh

# Heavy stress level
./build_and_test.sh --stress heavy

# Include Docker tests and benchmarks
./build_and_test.sh --stress heavy --include-docker --include-bench

# Skip build (if already built)
./build_and_test.sh --skip-build
```

This handles all setup (load module, start daemon, mount) and teardown automatically.

### 5b. Unit tests (Rust daemon)

```bash
make daemon-test
```

### 5c. Integration tests (requires CryptoFS mounted)

Run all:

```bash
make test
```

Run individually:

```bash
bash tests/integration/test_basic_ops.sh       # 18 tests: CRUD, permissions, symlinks
bash tests/integration/test_random_access.sh    # 6 tests: seek, partial reads, extents
bash tests/integration/test_append.sh           # 5 tests: append, mixed ops
bash tests/integration/test_concurrent.sh       # 4 tests: parallel reads/writes
```

### 5d. Stress test (data integrity)

```bash
make test-stress              # medium (default)
make test-stress-light        # light (smaller files, fewer cycles)
make test-stress-heavy        # heavy (up to 500 MB files)

# Custom settings
STRESS_LEVEL=heavy NUM_WORKERS=16 bash tests/integration/test_stress.sh
```

### 5e. Policy tests

```bash
make test-policy
```

### 5f. Benchmarks (fio)

```bash
make bench                # run fio on encrypted mount
make bench-compare        # generate comparison report
make docker-bench         # Docker-based benchmarks
```

---

## 6. Docker Crypto Verification (No Kernel Required)

This test validates the AES-256-GCM encryption path in userspace using OpenSSL — it does **not** need the kernel module loaded. Useful for verifying the crypto implementation works before loading the module.

```bash
make test-crypto
```

This builds and runs a Docker container that executes 20 tests covering:
- AES-256-GCM encrypt/decrypt round-trips
- Key wrapping/unwrapping
- Nonce derivation (HMAC-SHA256)
- Extent-based encryption layout
- Tamper detection (ciphertext and tag bit-flips)

---

## 7. Docker Encryption Demo (Host-Mounted Files)

The demo writes identical data to an encrypted directory (using the CryptoFS on-disk format) and a plaintext directory. Both directories are mounted from the host so you can inspect the files directly.

### Run the demo

```bash
make demo
```

This:
1. Creates `demo_encrypted/` and `demo_plaintext/` in the project directory
2. Builds and runs the `cryptofs-demo` Docker container
3. Runs 26 tests (file creation, decrypt verification, random access, append, overwrite, tamper detection)
4. Prints paths for host-side inspection

### Inspect results on the host

```bash
# Read a plaintext file
cat demo_plaintext/hello.txt

# View the same file's encrypted version
hexdump -C demo_encrypted/hello.txt | head -20

# Compare file sizes (encrypted files are larger due to header + auth tags)
ls -la demo_plaintext/
ls -la demo_encrypted/

# Compare a binary file
diff <(xxd demo_plaintext/large.bin | head -20) <(xxd demo_encrypted/large.bin | head -20)
```

### Change the output directories

By default, files go to `$PROJECT_DIR/demo_encrypted/` and `$PROJECT_DIR/demo_plaintext/`. To change this:

```bash
DEMO_ENCRYPTED=/path/to/encrypted DEMO_PLAINTEXT=/path/to/plaintext make demo
```

---

## 8. Interactive Docker — Manual Testing and Inspection

This section shows how to bring up the Docker containers interactively so you can run tests by hand and inspect results.

### 8a. Interactive crypto verification

Build the image, then run it with a shell instead of the default entrypoint:

```bash
# Build
docker compose -f docker/docker-compose.yml build crypto-verify

# Run interactively (override entrypoint with shell)
docker compose -f docker/docker-compose.yml run --rm --entrypoint /bin/sh crypto-verify
```

Inside the container:

```sh
# Run the test suite
crypto_verify

# The binary outputs pass/fail for each of the 20 tests
# You can also inspect the binary:
crypto_verify --help   # if help is available
```

### 8b. Interactive encryption demo (with host-mounted volumes)

```bash
# Create host directories
mkdir -p demo_encrypted demo_plaintext

# Build the image
DEMO_ENCRYPTED=$(pwd)/demo_encrypted DEMO_PLAINTEXT=$(pwd)/demo_plaintext \
  docker compose -f docker/docker-compose.yml build cryptofs-demo

# Start an interactive shell in the container (volumes mounted)
DEMO_ENCRYPTED=$(pwd)/demo_encrypted DEMO_PLAINTEXT=$(pwd)/demo_plaintext \
  docker compose -f docker/docker-compose.yml run --rm --entrypoint /bin/sh cryptofs-demo
```

Inside the container:

```sh
# Run the full demo test suite
cryptofs_demo

# After the tests complete, inspect files inside the container:
ls -la /data/encrypted/
ls -la /data/plaintext/

# View plaintext
cat /data/plaintext/hello.txt

# View encrypted (binary)
od -A x -t x1z /data/encrypted/hello.txt | head -20

# Compare sizes
du -b /data/plaintext/hello.txt /data/encrypted/hello.txt

# Check the master key file
od -A x -t x1z /data/encrypted/.master_key | head -5

# Exit the container
exit
```

The files persist on the host after you exit:

```bash
# Back on the host — files are still in the mounted directories
cat demo_plaintext/hello.txt
hexdump -C demo_encrypted/hello.txt | head -20
```

### 8c. Interactive test-basic container (against a live CryptoFS mount)

This requires CryptoFS to be mounted on the host at `/tmp/cryptofs_mount` (or wherever `$CRYPTOFS_MOUNT` points).

```bash
# Build the test image
docker compose -f docker/docker-compose.yml build test-basic

# Run with an interactive shell
docker compose -f docker/docker-compose.yml run --rm --entrypoint /bin/bash test-basic
```

Inside the container:

```bash
# The CryptoFS mount is at /data
ls -la /data/

# Run the built-in basic test
test_entrypoint.sh basic

# Or run tests manually:
echo "manual test" > /data/manual.txt
cat /data/manual.txt
sha256sum /data/manual.txt

# Write a larger file and verify
dd if=/dev/urandom of=/data/big_test.dat bs=4096 count=1000
sha256sum /data/big_test.dat
# Read it back
sha256sum /data/big_test.dat   # should match

# Random access write at offset
python3 -c "
import os
f = os.open('/data/random_test.dat', os.O_CREAT|os.O_WRONLY)
os.lseek(f, 8192, os.SEEK_SET)
os.write(f, b'HELLO AT OFFSET 8192')
os.close(f)
"
dd if=/data/random_test.dat bs=1 skip=8192 count=20

# Run fio micro-benchmark
fio --name=test --directory=/data --rw=randread --bs=4k --size=16M \
    --numjobs=1 --runtime=10 --time_based

# Clean up
rm -f /data/manual.txt /data/big_test.dat /data/random_test.dat

exit
```

### 8d. Keep a container running in the background

If you want to keep a container running and exec into it repeatedly:

```bash
# Start in detached mode
DEMO_ENCRYPTED=$(pwd)/demo_encrypted DEMO_PLAINTEXT=$(pwd)/demo_plaintext \
  docker compose -f docker/docker-compose.yml run -d --rm --entrypoint sleep \
  cryptofs-demo infinity

# Find the container ID
docker ps   # note the CONTAINER ID or NAME

# Exec into it as many times as you like
docker exec -it <container-id> /bin/sh

# Run tests, inspect files, etc.
cryptofs_demo
ls -la /data/encrypted/ /data/plaintext/

# When done, stop the container
docker stop <container-id>
```

---

## 9. Troubleshooting

### Module won't load

```bash
dmesg | tail -20
# Check kernel headers match:
ls /lib/modules/$(uname -r)/build
# If missing:
sudo apt-get install linux-headers-$(uname -r)
```

### "No such file or directory" for kernel build

```bash
# Some Ubuntu versions need a symlink:
ls -la /lib/modules/$(uname -r)/build
# If broken, reinstall headers:
sudo apt-get install --reinstall linux-headers-$(uname -r)
```

### Daemon won't start

```bash
pgrep cryptofs-keyd              # check for existing instances
sudo rm -f /var/run/cryptofs/keyd.sock   # remove stale socket
# Run in debug mode:
sudo cryptofs-keyd --foreground --log-level debug
```

### Integration tests fail with "not a mount point"

CryptoFS must be mounted first. Either use `build_and_test.sh` (handles setup automatically) or mount manually per Section 4.

### Docker permission denied

```bash
# Make sure your user is in the docker group
groups | grep docker
# If not:
sudo usermod -aG docker $USER
newgrp docker
```

### Stress test OOM on small VMs

```bash
STRESS_LEVEL=light NUM_WORKERS=2 bash tests/integration/test_stress.sh
```

### Demo files not appearing on host

Make sure the volume paths are absolute and inside a Docker-shared directory:

```bash
# Use project directory (recommended)
DEMO_ENCRYPTED=$(pwd)/demo_encrypted DEMO_PLAINTEXT=$(pwd)/demo_plaintext make demo
```
