# CryptoFS Guarded Key Access

Guarded mode gives each user control over their own encryption key. Unlike transparent mode (where the admin pre-loads keys for everyone), guarded mode requires a user to explicitly unlock their key before they can access encrypted files. If they haven't unlocked it, file opens fail with `ENOKEY`.

---

## How It Works

1. Admin creates a policy binding a user (e.g. UID 1000) to a key with `access_mode = guarded`.
2. The key is **not** loaded into the kernel key table — it stays locked.
3. When the user wants to read encrypted files, they run `session-unlock`, which puts the key into their Linux session keyring.
4. On file open, the kernel calls `request_key()` to look for the key in the calling process's session keyring.
5. If found → file is decrypted. If not → `ENOKEY`.
6. The key can auto-expire after a timeout, or the user can revoke it manually.

---

## Admin Setup

### 1. Generate a key for the user

```bash
cryptofs-admin key generate --label user-alice
# Note the key UUID, e.g. f7e2a1b3-0000-0000-0000-000000000000
```

### 2. Create a guarded policy

Bind the key to the user's UID with guarded access mode:

```bash
cryptofs-admin policy add --dir /mnt/decrypted \
    --type uid --value 1000 --perm allow \
    --key-id f7e2a1b3-0000-0000-0000-000000000000 \
    --access-mode guarded
```

Other policy types work too — `gid`, `binary-path`, `binary-hash`, `process-name`:

```bash
# By group
cryptofs-admin policy add --dir /mnt/decrypted \
    --type gid --value 1001 --perm allow \
    --key-id <key-id> --access-mode guarded

# By application binary
cryptofs-admin policy add --dir /mnt/decrypted \
    --type binary-path --value /usr/bin/myapp --perm allow \
    --key-id <key-id> --access-mode guarded
```

### 3. Verify the policy

```bash
cryptofs-admin policy list
# Shows rule ID, type, value, key_id, access_mode=guarded
```

### 4. Remove a policy

```bash
cryptofs-admin policy remove <rule-id>
```

That's it for admin setup. The key stays locked until the user unlocks it themselves.

---

## User Workflow

### Unlock the key

```bash
cryptofs-admin key session-unlock <key-id>
# Prompts for passphrase
# On success: key is added to your session keyring
```

What happens behind the scenes:
- CLI sends the passphrase to the daemon, which validates it and returns the raw key material.
- CLI calls `add_key("logon", "cryptofs:<key_id_hex>", key_data, SESSION_KEYRING)` to store it in your session keyring.
- Only processes in your login session can see this key.

### Access encrypted files

```bash
cat /mnt/decrypted/secret.txt    # works — key is in your session keyring
```

### Auto-expire the key

```bash
cryptofs-admin key session-unlock <key-id> --timeout 3600
# Key automatically expires after 1 hour
```

### Revoke early

```bash
# List keys in your session keyring
keyctl show @s

# Revoke the CryptoFS key
keyctl revoke <key-serial>
```

After the key expires or is revoked, file opens return `ENOKEY` until you unlock again.

---

## What happens without the key

If a user's session keyring does not contain the required key:

- **Reads** fail with "Required key not available" (`ENOKEY`).
- **Writes** are blocked with "Permission denied" (`EACCES`).
- Other users with their own guarded keys are unaffected — each user's keyring is independent.

---

## Real-World Example: Encrypting Solr Indexes

CryptoFS is a **stacked overlay filesystem**. You choose what to encrypt by choosing what to mount it over. The key insight: you can mount CryptoFS at **the same path** as the lower directory, so the application sees no difference — its files just happen to be encrypted on disk.

### Same-path (overlay) mount

Stop Solr, mount CryptoFS over its data directory, start Solr again. Solr never knows.

```bash
# Stop Solr first
sudo systemctl stop solr

# Mount CryptoFS over the SAME path
sudo mount -t cryptofs /var/solr/data /var/solr/data

# Solr still reads/writes to /var/solr/data — it has no idea.
# On disk the files are encrypted; through the mount they're plaintext.
sudo systemctl start solr
```

What's happening:
- **Before mount:** `/var/solr/data` is a regular directory on ext4/xfs. Files are plaintext.
- **After mount:** `/var/solr/data` is now a CryptoFS overlay. New writes go through CryptoFS and are encrypted on disk. Reads are decrypted transparently.
- **On disk:** The underlying ext4/xfs directory still holds the files, but they contain CryptoFS headers + AES-256-GCM ciphertext.
- **Unmount:** `sudo umount /var/solr/data` removes the overlay. Direct access to the directory now shows raw ciphertext.

### Separate-path mount

You can also use a separate lower directory if you prefer to keep ciphertext in a different location:

```bash
mkdir -p /data/solr-encrypted
sudo mount -t cryptofs /data/solr-encrypted /var/solr/data

# Solr writes to /var/solr/data → ciphertext lands in /data/solr-encrypted/
```

### Multiple mounts

You can encrypt different directory trees independently, each with their own keys and policies:

```bash
# Encrypt Solr indexes
sudo mount -t cryptofs /var/solr/data /var/solr/data
cryptofs-admin policy add --dir /var/solr/data \
    --type uid --value 8983 --perm allow \
    --key-id $SOLR_KEY --access-mode transparent

# Encrypt Elasticsearch data (different key)
sudo mount -t cryptofs /var/lib/elasticsearch /var/lib/elasticsearch
cryptofs-admin policy add --dir /var/lib/elasticsearch \
    --type uid --value 1000 --perm allow \
    --key-id $ES_KEY --access-mode transparent

# Encrypt PostgreSQL tablespace (guarded mode)
sudo mount -t cryptofs /var/lib/postgresql/data /var/lib/postgresql/data
cryptofs-admin policy add --dir /var/lib/postgresql/data \
    --type uid --value 5432 --perm allow \
    --key-id $PG_KEY --access-mode guarded
```

Each mount is independent — different keys, different policies, different access modes. Unmounting one has no effect on the others.

### Persistent mounts via /etc/fstab

```bash
# Add to /etc/fstab for automatic mount on boot
/var/solr/data            /var/solr/data            cryptofs defaults 0 0
/var/lib/elasticsearch    /var/lib/elasticsearch    cryptofs defaults 0 0
```

The key daemon must be running and keys activated before the mounts will work. Set up `cryptofs-keyd` as a systemd service that starts before these mounts.

---

# Installing the Kernel Module

## Ubuntu (x86_64 and ARM64)

### Prerequisites

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
    git
```

### Verify kernel crypto support

```bash
grep -E 'CONFIG_CRYPTO_(AES|GCM)=' /boot/config-$(uname -r)
# Expected: CONFIG_CRYPTO_AES=y  CONFIG_CRYPTO_GCM=y (or =m)
```

### Build

```bash
git clone https://github.com/geekychris/cryptfs.git
cd cryptfs
make kernel
```

### Load (development)

```bash
sudo insmod kernel/cryptofs.ko
lsmod | grep cryptofs
cat /proc/filesystems | grep cryptofs
```

### Install with modprobe

```bash
sudo make -C kernel install
sudo depmod -a
sudo modprobe cryptofs
```

### Auto-load on boot

```bash
sudo make -C kernel install
sudo depmod -a
echo 'cryptofs' | sudo tee /etc/modules-load.d/cryptofs.conf
```

### DKMS (survives kernel upgrades)

```bash
sudo apt-get install -y dkms
sudo mkdir -p /usr/src/cryptofs-1.0
sudo cp kernel/*.c kernel/*.h kernel/Makefile /usr/src/cryptofs-1.0/

sudo tee /usr/src/cryptofs-1.0/dkms.conf > /dev/null <<'EOF'
PACKAGE_NAME="cryptofs"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="cryptofs"
DEST_MODULE_LOCATION[0]="/extra"
AUTOINSTALL="yes"
MAKE[0]="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build modules"
CLEAN="make -C ${kernel_source_dir} M=${dkms_tree}/${PACKAGE_NAME}/${PACKAGE_VERSION}/build clean"
EOF

sudo dkms add -m cryptofs -v 1.0
sudo dkms build -m cryptofs -v 1.0
sudo dkms install -m cryptofs -v 1.0

# Verify
sudo modprobe cryptofs
dkms status
```

### Install userspace tools

```bash
# Build daemon and CLI (requires Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
make daemon cli

# Install
sudo make install
```

---

## Raspberry Pi (Raspberry Pi OS / Debian)

Raspberry Pi OS is Debian-based, so the process is similar to Ubuntu with a few differences.

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    raspberrypi-kernel-headers \
    libelf-dev \
    libssl-dev \
    pkg-config \
    bc flex bison \
    kmod \
    git
```

> **Note:** On Raspberry Pi OS, use `raspberrypi-kernel-headers` instead of `linux-headers-$(uname -r)`. This package provides the kernel headers matching the Pi's kernel.

### Verify kernel crypto support

```bash
# Check for hardware crypto (Pi 3/4/5 have NEON-accelerated AES)
grep -o 'aes\|neon\|pmull' /proc/cpuinfo | sort -u

# Check kernel config
zcat /proc/config.gz | grep -E 'CONFIG_CRYPTO_(AES|GCM)='
# If /proc/config.gz doesn't exist:
grep -E 'CONFIG_CRYPTO_(AES|GCM)=' /boot/config-$(uname -r) 2>/dev/null || \
  modprobe configs && zcat /proc/config.gz | grep -E 'CONFIG_CRYPTO_(AES|GCM)='
```

### Build

```bash
git clone https://github.com/geekychris/cryptfs.git
cd cryptfs
make kernel
```

If the build fails with missing headers:

```bash
# Ensure headers match your running kernel
uname -r
ls /lib/modules/$(uname -r)/build

# If the symlink is broken or missing, reinstall:
sudo apt-get install --reinstall raspberrypi-kernel-headers

# After a kernel update, reboot first, then reinstall headers:
sudo reboot
sudo apt-get install raspberrypi-kernel-headers
```

### Load and install

Same as Ubuntu:

```bash
# Development
sudo insmod kernel/cryptofs.ko
lsmod | grep cryptofs

# Persistent install
sudo make -C kernel install
sudo depmod -a
sudo modprobe cryptofs

# Auto-load on boot
echo 'cryptofs' | sudo tee /etc/modules-load.d/cryptofs.conf
```

### DKMS on Raspberry Pi

Works identically to the Ubuntu DKMS steps above. Install `dkms` with:

```bash
sudo apt-get install -y dkms
```

Then follow the same DKMS commands from the Ubuntu section.

### Install userspace tools

```bash
# Install Rust (ARM builds take longer on Pi — be patient)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Build (may take several minutes on Pi 3/4, faster on Pi 5)
make daemon cli
sudo make install
```

### Performance notes

- **Pi 5**: Best performance — ARMv8.2 with full AES/PMULL crypto extensions.
- **Pi 4**: Good performance — ARMv8 NEON-accelerated AES.
- **Pi 3**: Functional but slower — ARMv8 with software GCM fallback on some kernels.
- **Pi Zero 2 W**: Same SoC as Pi 3, works but not recommended for heavy workloads.

---

## Mount and test

After installing on either platform:

```bash
# Start the daemon
sudo cryptofs-keyd --foreground &

# Generate and activate a key
cryptofs-admin key generate --label my-key
cryptofs-admin key unlock <key-id>
cryptofs-admin key activate <key-id>

# Mount
mkdir -p /tmp/cryptofs_lower /tmp/cryptofs_mount
sudo mount -t cryptofs /tmp/cryptofs_lower /tmp/cryptofs_mount

# Write and verify
echo "hello" > /tmp/cryptofs_mount/test.txt
cat /tmp/cryptofs_mount/test.txt          # plaintext
hexdump -C /tmp/cryptofs_lower/test.txt | head  # ciphertext on disk
```
