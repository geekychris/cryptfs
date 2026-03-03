# Solr with Encrypted Index

A Docker container running Apache Solr whose index is **encrypted at rest** using [gocryptfs](https://nuetzlich.net/gocryptfs/) (AES-256-GCM, FUSE-based).

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
                                     │  (volume mount)
                              ./encrypted_data/
                         (host: only ciphertext visible)
```

- **Inside the container**: Solr reads/writes its index through a gocryptfs FUSE mount (transparent encryption)
- **On the host**: the mounted `./encrypted_data/` directory contains only encrypted ciphertext — filenames and file contents are both encrypted

## Quick Start

```bash
# Build and start the container
docker compose up -d

# Make demo script executable and run it
chmod +x demo.sh
./demo.sh

# Stop the container
docker compose down
```

## Custom Encryption Password

```bash
ENCRYPTION_PASSWORD=my-secret-key docker compose up -d
```

## What the Demo Shows

1. Creates a Solr core (`demo`)
2. Indexes 5 sample documents with full-text content
3. Runs search queries (keyword, phrase, category filter, faceted)
4. Inspects the host-mounted `./encrypted_data/` to prove:
   - Filenames are encrypted (random-looking names)
   - File contents are encrypted (binary ciphertext)

## Manual Search Examples

While the container is running:

```bash
# Full-text search
curl 'http://localhost:8983/solr/demo/select?q=encryption'

# Field-specific search
curl 'http://localhost:8983/solr/demo/select?q=category:security'

# Faceted search
curl 'http://localhost:8983/solr/demo/select?q=*:*&facet=true&facet.field=category'
```

## Requirements

- Docker with Compose v2
- The container requires `SYS_ADMIN` capability and `/dev/fuse` for the FUSE mount

## How Encryption Works

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Scope**: Each file is encrypted individually; filenames are also encrypted
- **Key derivation**: scrypt from the password
- **Metadata**: `gocryptfs.conf` and `gocryptfs.diriv` in the encrypted directory store the encrypted master key and directory IV
- **Persistence**: encrypted data survives container restarts (stored on host volume)
