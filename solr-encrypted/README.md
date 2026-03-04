# Solr with Encrypted Index

A Docker container running Apache Solr 9 whose index is **encrypted at rest** using [gocryptfs](https://nuetzlich.net/gocryptfs/) (AES-256-GCM, FUSE-based). The host-mounted volume only ever contains ciphertext — plaintext is only accessible inside the running container.

## Architecture

```
┌─────────────────── Docker Container ───────────────────┐
│                                                         │
│  Solr 9  ←──reads/writes──→  /data/decrypted (FUSE)   │
│                                    │                    │
│                              gocryptfs                  │
│                                    │                    │
│                              /data/encrypted            │
│                                    │                    │
└────────────────────────────────────┼────────────────────┘
                                     │  bind mount
                              ./encrypted_data/
                         (host sees only ciphertext)
```

**How it works:**

1. The host directory `./encrypted_data/` is bind-mounted into the container at `/data/encrypted`
2. On startup, `gocryptfs` creates a FUSE mount at `/data/decrypted` that transparently encrypts/decrypts
3. Solr's data directory (`SOLR_HOME`) is set to `/data/decrypted/solr`
4. All Solr reads/writes pass through gocryptfs, which encrypts before writing to `/data/encrypted`
5. The host volume only ever sees encrypted filenames and encrypted file contents

**Key components:**

- **Dockerfile** — Extends `solr:9`, installs `gocryptfs` and `fuse3`, configures FUSE permissions
- **entrypoint.sh** — Initializes gocryptfs (first run), mounts FUSE decrypted view, copies Solr configsets, starts Solr as the `solr` user
- **docker-compose.yml** — Binds `./encrypted_data` from host, grants `SYS_ADMIN` capability and `/dev/fuse` access for FUSE
- **demo.sh** — End-to-end demo: creates a core, indexes documents, runs searches, verifies encryption on host

## Quick Start

```bash
# Build and start
docker compose up -d

# Run the demo (indexes docs, searches, verifies encryption)
./demo.sh

# Stop
docker compose down
```

### Custom Encryption Password

The default password is `solr-encrypted-demo`. Override it with:

```bash
ENCRYPTION_PASSWORD=my-secret-key docker compose up -d
```

### Clean Reset

To wipe all encrypted data and start fresh:

```bash
docker compose down
rm -rf ./encrypted_data
docker compose up -d
```

## Accessing the Container (Shell)

Docker containers don't run SSH. Instead, use `docker exec` to get a shell inside the running container.

### Interactive Shell as Root

```bash
docker exec -it solr-encrypted bash
```

This drops you into a root shell inside the container. From here you can inspect the decrypted index, check FUSE mounts, and explore the filesystem.

### Interactive Shell as the Solr User

```bash
docker exec -it -u solr solr-encrypted bash
```

This gives you a shell as the `solr` user (uid 8983), which is the user that owns the Solr process.

### One-Off Commands (No Interactive Shell)

```bash
# Check FUSE mounts
docker exec solr-encrypted mount | grep fuse

# List Solr cores
docker exec solr-encrypted ls /data/decrypted/solr/

# Check Solr process
docker exec solr-encrypted ps aux | grep solr

# View container logs
docker logs solr-encrypted
```

## Directory Structure: Container vs Host

This is the key insight of the setup. **The same data looks completely different** depending on whether you view it from inside the container (decrypted) or from the host (encrypted).

### Inside the Container (Decrypted — Plaintext)

```bash
$ docker exec solr-encrypted ls -la /data/decrypted/solr/
drwxr-xr-x 6 solr solr  192 ...  .
drwxr-xr-x 5 solr solr  160 ...  ..
drwxr-xr-x 5 solr solr  160 ...  configsets
drwxr-xr-x 5 solr solr  160 ...  demo
-rw-r--r-- 1 solr solr 3648 ...  solr.xml

$ docker exec solr-encrypted ls -la /data/decrypted/solr/demo/
drwxr-xr-x 5 solr solr 160 ...  .
-rw-r--r-- 1 solr solr  93 ...  core.properties
drwxr-xr-x 6 solr solr 192 ...  data

$ docker exec solr-encrypted ls /data/decrypted/solr/demo/data/index/
_0.fdm                    _0_Lucene90_0.dvd         _0_Lucene912_0.pos
_0.fdt                    _0_Lucene90_0.dvm         _0_Lucene912_0.psm
_0.fdx                    _0_Lucene912_0.doc        _0_Lucene912_0.tim
_0.fnm                    _0_Lucene912_0.tip        _0_Lucene912_0.tmd
_0.nvd                    _0.nvm                    _0.si
segments_2                write.lock
```

The index files are standard Lucene segment files — readable, recognizable names, normal contents.

Readable file contents:

```bash
$ docker exec solr-encrypted cat /data/decrypted/solr/demo/core.properties
#Written by CorePropertiesLocator
name=demo
configSet=_default
```

### On the Host (Encrypted — Ciphertext)

```bash
$ ls -la ./encrypted_data/
-r--------  1 chris  staff  385 ...  gocryptfs.conf
-r--r-----  1 chris  staff   16 ...  gocryptfs.diriv
drwxr-xr-x  6 chris  staff  192 ...  nEDGnZvpvCwWysDAjFM9ZQ

$ find ./encrypted_data/ -maxdepth 3 -type d
./encrypted_data/
./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ
./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ/sdq1oWIAPCr_uZsMEQJ5Wg
./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ/sdq1oWIAPCr_uZsMEQJ5Wg/pS1rg2nHc8_rJ7ZKhHT5Dg
./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ/3YOdQgIzmEMXiNJC9RKj0w
./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ/3YOdQgIzmEMXiNJC9RKj0w/c-kUiGguWDc4RKL_pKverg
```

Every filename is encrypted (Base64-like random strings). The directory structure is obscured — you cannot tell that `nEDGnZvpvCwWysDAjFM9ZQ` maps to `solr/` or that `sdq1oWIAPCr_uZsMEQJ5Wg` maps to `demo/`.

File contents are encrypted binary:

```bash
$ xxd ./encrypted_data/nEDGnZvpvCwWysDAjFM9ZQ/cQRyCDI--wejOKNzPfxLhQ | head -4
00000000: 0002 58df 377d 09a9 518a 281d a608 7b88  ..X.7}..Q.(...{.
00000010: 38a1 2abc e94f 4e44 a3cf 7456 244d b50a  8.*..OND..tV$M..
00000020: 24e3 4a53 a682 5788 69ac 4f8a ca45 7afe  $.JS..W.i.O..Ez.
00000030: 6214 60a1 1f4a 5d23 40b4 dbcf 9260 271d  b.`..J]#@....`'.
```

There are 140 encrypted files corresponding to the Solr index, configsets, and metadata — none readable from the host.

### Side-by-Side Summary

```
Container (/data/decrypted)          Host (./encrypted_data)
─────────────────────────────        ─────────────────────────────
solr/                                nEDGnZvpvCwWysDAjFM9ZQ/
  solr.xml                             cQRyCDI--wejOKNzPfxLhQ
  demo/                                sdq1oWIAPCr_uZsMEQJ5Wg/
    core.properties                      pS1rg2nHc8_rJ7ZKhHT5Dg/
    data/index/                            TQNqLF7OY_-rn3JgP8lA7A/
      _0.fdt                                 w6G3RITOxZ5137ivp2kQ-Q
      _0.fdm                                 cUaLkryremMDIkZtEYFevw
      segments_2                             jxWW-4PhNSKi--YjVbI1nQ
      ...                                    ...
```

## Searching the Encrypted Index

Once the container is running and the demo has been run, Solr is accessible at `http://localhost:8983`.

### Full-Text Search (eDisMax)

```bash
# Search across title and content fields
curl 'http://localhost:8983/solr/demo/select?q=encryption&defType=edismax&qf=title+content'

# Multi-term search
curl 'http://localhost:8983/solr/demo/select?q=docker+security&defType=edismax&qf=title+content'
```

### Field-Specific Search

```bash
# Search by category
curl 'http://localhost:8983/solr/demo/select?q=category:security'

# Search by author
curl 'http://localhost:8983/solr/demo/select?q=author:"Alice Johnson"'
```

### Faceted Search

```bash
curl 'http://localhost:8983/solr/demo/select?q=*:*&facet=true&facet.field=category&rows=0'
```

### Solr Admin UI

Open http://localhost:8983/solr/ in a browser for the full Solr admin interface.

## How Encryption Works

**gocryptfs** provides transparent, file-level encryption using FUSE (Filesystem in Userspace).

- **Algorithm**: AES-256-GCM (authenticated encryption with associated data)
- **Filename encryption**: EME wide-block encryption (each filename is individually encrypted)
- **Key derivation**: scrypt KDF from the password → master key
- **File-level**: Each file is encrypted independently (no full-volume block device needed)
- **Metadata files**:
  - `gocryptfs.conf` — stores the encrypted master key (encrypted with the password-derived key)
  - `gocryptfs.diriv` — per-directory initialization vector for filename encryption

### Security Properties

- An attacker with access to `./encrypted_data/` on the host sees only ciphertext
- Filenames reveal nothing about the Solr index structure
- File sizes are padded to 4KB blocks, partially obscuring content sizes
- AES-256-GCM provides both confidentiality and integrity (tamper detection)
- The plaintext is **only** available inside the running container's FUSE mount

### Persistence

Encrypted data survives container restarts — the `./encrypted_data/` volume on the host retains the ciphertext. On the next `docker compose up`, gocryptfs re-mounts and decrypts using the same password.

## Requirements

- Docker with Compose v2+
- `SYS_ADMIN` capability (required for FUSE mounts inside containers)
- `/dev/fuse` device access

## Troubleshooting

### Container exits immediately

Check logs for FUSE errors:

```bash
docker logs solr-encrypted
```

Common cause: `/dev/fuse` not available. Ensure Docker Desktop has sufficient permissions.

### "Permission denied" on FUSE mount

The container must run with `SYS_ADMIN` capability. Verify your `docker-compose.yml` includes:

```yaml
cap_add:
  - SYS_ADMIN
devices:
  - /dev/fuse:/dev/fuse
```

### Solr core creation fails

If the encrypted data directory has stale state from a prior run, reset it:

```bash
docker compose down
rm -rf ./encrypted_data
docker compose up -d
```
