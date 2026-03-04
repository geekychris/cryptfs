# Solr on CryptoFS — Kernel-Level Encrypted Search Index

Apache Solr 9 running with its index stored on a **CryptoFS encrypted mount**. Encryption is transparent at the Linux kernel VFS layer — no FUSE, no application changes, no userspace encryption overhead.

## Architecture

```
┌─────────────── Vagrant VM (Linux aarch64) ───────────────┐
│                                                           │
│  ┌──── Docker Container ────┐                             │
│  │  Solr 9                  │                             │
│  │  reads/writes to         │                             │
│  │  /var/solr/data ─────────┼── bind mount ──┐            │
│  └──────────────────────────┘                │            │
│                                              ▼            │
│                                   /tmp/cryptofs_mount     │
│                                   (decrypted view)        │
│                                        │                  │
│                                   cryptofs.ko             │
│                                   (kernel VFS layer)      │
│                                        │                  │
│                                   /tmp/cryptofs_lower     │
│                                   (encrypted on disk)     │
│                                                           │
│  set_key (netlink) ─── kernel key table ─── cryptofs.ko   │
└───────────────────────────────────────────────────────────┘
      ▲                                            ▲
      │ vagrant ssh                                │ port 8984
      │                                            │
┌─────┴──── Mac Host ──────────────────────────────┴────────┐
│  vagrant/  (project root synced via rsync)                │
│  curl http://localhost:8984/solr/                         │
└───────────────────────────────────────────────────────────┘
```

**Data flow:**

1. Solr writes index data to `/var/solr/data` inside the container
2. Docker's bind mount maps this to `/tmp/cryptofs_mount/solr-home` in the VM
3. `cryptofs.ko` intercepts the VFS write, splits data into 4KB extents
4. Each extent is encrypted with AES-256-GCM using a per-file key (FEK)
5. Ciphertext + auth tags are written to `/tmp/cryptofs_lower/solr-home`
6. Reads follow the reverse path: read ciphertext → decrypt → verify GCM tag → return plaintext

**Key management:** The master encryption key is injected directly into the
kernel module's internal key table via the `set_key` netlink tool. With no
access policies configured, the module operates in **TRANSPARENT mode** — all
processes that can reach the mount see decrypted data. This is the simplest
configuration for demos. (The GUARDED mode, which restricts decryption to
specific UIDs/binaries via the daemon + CLI + kernel keyring, is covered in the
main project docs.)

**Key difference from FUSE-based encryption:**
CryptoFS operates entirely in kernel space. There are no userspace context switches for I/O, no FUSE daemon, and no `/dev/fuse` device. The encryption is invisible to both Solr and Docker.

## Prerequisites

- macOS with Apple Silicon (the Vagrant VM uses QEMU with HVF acceleration)
- [Vagrant](https://www.vagrantup.com/) and the QEMU provider installed
- The Vagrant VM provisioned and running (`cd vagrant && vagrant up`)

## Quick Start

```bash
# 1. Start the VM (if not already running)
cd vagrant && vagrant up

# 2. Sync project files and SSH into the VM
vagrant rsync && vagrant ssh

# 3. Inside the VM — run the setup and demo
cd cryptofs
./solr-cryptofs/setup.sh          # build, mount, inject key, start Solr
./solr-cryptofs/demo.sh           # index docs, search, verify encryption
```

To skip the build step (e.g. kernel module already compiled):

```bash
./solr-cryptofs/setup.sh --skip-build
```

To tear down:

```bash
./solr-cryptofs/teardown.sh
```

## Logging Into the Vagrant VM

From the `vagrant/` directory on your Mac:

```bash
# SSH into the VM
vagrant ssh

# You land at /home/vagrant. The project is at:
cd cryptofs
```

You can also run one-off commands without an interactive session:

```bash
vagrant ssh -c "cd cryptofs && ./solr-cryptofs/demo.sh"
```

The VM is an Ubuntu 24.04 ARM64 box running under QEMU with 4 GB RAM and 4 CPUs.

## Viewing the VM Filesystem From the Mac

The project source is synced into the VM at `/home/vagrant/cryptofs` via rsync.
Push updates from the Mac with:

```bash
vagrant rsync
```

> **Caution:** `vagrant rsync` overwrites the VM's `/home/vagrant/cryptofs`
> with the Mac's source tree. This **wipes build artifacts** (compiled `.ko`,
> Rust binaries, `tools/set_key`). If you've already built inside the VM,
> either do a full rebuild after syncing or copy individual files with:
> ```bash
> vagrant ssh -c "cat > /home/vagrant/cryptofs/path/to/file" < path/to/file
> ```

To inspect files inside the VM from the Mac, use `vagrant ssh -c`:

```bash
# List the encrypted lower directory (ciphertext on disk)
vagrant ssh -c "ls -la /tmp/cryptofs_lower/solr-home/demo/data/index/"

# List the decrypted mount (plaintext via CryptoFS)
vagrant ssh -c "ls -la /tmp/cryptofs_mount/solr-home/demo/data/index/"

# View the CryptoFS header of an encrypted file
vagrant ssh -c "hexdump -C /tmp/cryptofs_lower/solr-home/demo/data/index/segments_2 | head"

# Check what's mounted
vagrant ssh -c "mount | grep cryptofs"

# Check kernel module is loaded
vagrant ssh -c "lsmod | grep cryptofs"

# View kernel log for CryptoFS messages
vagrant ssh -c "sudo dmesg | grep cryptofs | tail -20"
```

## Accessing Solr

### From inside the VM

```bash
# Full-text search
curl 'http://localhost:8983/solr/demo/select?q=encryption&defType=edismax&qf=title+content'

# Field search
curl 'http://localhost:8983/solr/demo/select?q=category:security'
```

### From your Mac (via port forwarding)

The Vagrantfile forwards VM port 8983 → **host port 8984** (to avoid
conflicting with the `solr-encrypted` Docker container on 8983):

```bash
# Search from the Mac
curl 'http://localhost:8984/solr/demo/select?q=encryption&defType=edismax&qf=title+content'

# Solr admin UI
open http://localhost:8984/solr/
```

### Inspecting the Solr container

```bash
# From inside the VM:
docker exec -it solr-cryptofs bash

# Check Solr sees normal (decrypted) files
ls /var/solr/data/demo/data/index/

# View container logs
docker logs solr-cryptofs
```

## What the Demo Shows

### 1. Solr Works Normally
- Creates a core, indexes 5 documents, runs full-text and faceted searches
- Zero changes to Solr configuration or behavior

### 2. File Names Are Preserved
Unlike FUSE-encrypted filesystems (gocryptfs, eCryptfs) that encrypt filenames, CryptoFS preserves the directory structure:

```
/tmp/cryptofs_mount/solr-home/demo/data/index/    (decrypted view)
    _0.fdt, _0.fdm, segments_2, ...

/tmp/cryptofs_lower/solr-home/demo/data/index/    (encrypted on disk)
    _0.fdt, _0.fdm, segments_2, ...     ← same filenames!
```

### 3. File Contents Are Encrypted
Every file in the lower directory has a fixed 128-byte CryptoFS header followed
by AES-256-GCM ciphertext. Each file on disk is exactly **4240 bytes**
(128-byte header + one 4096-byte extent + 16-byte GCM auth tag) regardless of
plaintext size (files smaller than 4 KB are zero-padded to a full extent):

```
Decrypted (_0.fdt via mount):
00000000: 3fd7 6db6 ...   ← normal Lucene segment data

Encrypted (_0.fdt in lower dir):
00000000: 4352 5950 544f 4653  ← "CRYPTOFS" magic
00000008: 0100 0000 0000 0000  ← version, flags
00000010: [encrypted FEK]      ← 48 bytes (key + GCM tag)
00000040: [FEK nonce]          ← 12 bytes
0000004c: [file size]          ← 8 bytes
00000080: [AES-256-GCM ciphertext + auth tags per 4KB extent]
```

### 4. Encryption Overhead
- 128 bytes per file (header with encrypted per-file key)
- 16 bytes per 4 KB extent (GCM authentication tag)
- ~0.4% overhead for typical files

## Manually Comparing Encrypted vs Decrypted

From inside the VM (or via `vagrant ssh -c "..."` from the Mac):

```bash
# Same file, two views:
hexdump -C /tmp/cryptofs_mount/solr-home/demo/data/index/segments_2 | head
hexdump -C /tmp/cryptofs_lower/solr-home/demo/data/index/segments_2 | head

# The mount shows normal Lucene data; the lower dir shows CRYPTOFS header + ciphertext
```

From the Mac:

```bash
vagrant ssh -c "hexdump -C /tmp/cryptofs_mount/solr-home/demo/data/index/segments_2 | head"
vagrant ssh -c "hexdump -C /tmp/cryptofs_lower/solr-home/demo/data/index/segments_2 | head"
```

## How It Differs from the `solr-encrypted/` Docker Demo

The `solr-encrypted/` directory contains an earlier proof-of-concept that uses **gocryptfs** (a FUSE-based encrypted filesystem) running inside a Docker container on macOS. Key differences:

- **solr-encrypted:** FUSE-based (gocryptfs), encrypts filenames, runs entirely in Docker on macOS, no kernel module
- **solr-cryptofs:** Kernel VFS module (`cryptofs.ko`), preserves filenames, runs in Vagrant Linux VM, key injected via netlink into kernel key table, zero userspace I/O hops

## Troubleshooting

**Solr not reachable from Mac on port 8984:**
Ensure the VM is running and port forwarding is active:
```bash
vagrant status
vagrant port
```

**`ENOKEY` ("Required key not available") when writing to mount:**
The master key must be injected **after** mounting — the key table is
per-superblock and created fresh at mount time. Run teardown and setup again:
```bash
./solr-cryptofs/teardown.sh && ./solr-cryptofs/setup.sh --skip-build
```

**`vagrant rsync` wipes build artifacts:**
Use `cat` to copy individual files instead (see "Viewing the VM Filesystem"
above).
