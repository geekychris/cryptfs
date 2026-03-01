# CryptoFS Administration Guide

## Installation

### Build from Source

```bash
# Build all components
make all

# Install (requires root)
sudo make install
```

This installs:
- `cryptofs.ko` kernel module in `/lib/modules/$(uname -r)/`
- `cryptofs-keyd` daemon in `/usr/local/bin/`
- `cryptofs-admin` CLI in `/usr/local/bin/`
- Configuration directories in `/etc/cryptofs/`, `/var/lib/cryptofs/`, `/var/run/cryptofs/`

## Key Management

### Generate a Master Key

```bash
cryptofs-admin key generate --label production-key-1
# Enter passphrase when prompted
# Returns: Generated key: <uuid>
```

### Key Lifecycle

```bash
# List all keys
cryptofs-admin key list

# Unlock a key (load into daemon memory)
cryptofs-admin key unlock <key-id>

# Activate (inject into kernel keyring)
cryptofs-admin key activate <key-id>

# Rotate (generate new key material)
cryptofs-admin key rotate <key-id>

# Deactivate (revoke from kernel)
cryptofs-admin key deactivate <key-id> --serial <serial>

# Lock (clear from daemon memory)
cryptofs-admin key lock <key-id>
```

### Import an Existing Key

```bash
# From hex string
cryptofs-admin key import --label imported --hex <64-char-hex>

# From file
cryptofs-admin key import --label imported --file /path/to/key.hex
```

## Mounting Filesystems

```bash
# Basic mount
sudo mount -t cryptofs /data/encrypted /mnt/decrypted

# With key ID
sudo mount -t cryptofs -o key_id=<uuid> /data/encrypted /mnt/decrypted

# Unmount
sudo umount /mnt/decrypted

# Or via CLI
cryptofs-admin mount /data/encrypted /mnt/decrypted --key-id <uuid>
cryptofs-admin umount /mnt/decrypted
```

## Access Policies

Policies control which processes can access plaintext data.

### Policy Types

- `uid` — Match by user ID
- `gid` — Match by group ID
- `binary-path` — Match by executable path
- `binary-hash` — Match by SHA-256 of the executable
- `process-name` — Match by process name (comm)

### Managing Policies

```bash
# Allow UID 1000
cryptofs-admin policy add --dir /mnt/decrypted --type uid --value 1000 --perm allow

# Allow a specific application
cryptofs-admin policy add --dir /mnt/decrypted --type binary-path \
    --value /usr/bin/myapp --perm allow

# Allow by binary hash (tamper-resistant)
SHA=$(sha256sum /usr/bin/myapp | awk '{print $1}')
cryptofs-admin policy add --dir /mnt/decrypted --type binary-hash \
    --value $SHA --perm allow

# List policies
cryptofs-admin policy list
cryptofs-admin policy list --dir /mnt/decrypted

# Remove a policy
cryptofs-admin policy remove <rule-id>
```

### Default Behavior

- **No policies configured**: All processes can access plaintext (PoC convenience mode)
- **With policies**: Default DENY — only explicitly allowed processes get plaintext
- Unauthorized reads return raw ciphertext
- Unauthorized writes are blocked with `-EACCES`

## Docker Integration

### Host-Mount Approach (Recommended)

Mount CryptoFS on the host, then bind-mount into containers:

```bash
# On host
sudo mount -t cryptofs /data/encrypted /mnt/decrypted

# Container gets the decrypted view
docker run -v /mnt/decrypted:/data myapp
```

### Testing with Docker Compose

```bash
# Build test containers
make docker-build

# Run basic tests
make docker-test

# Run benchmarks
make docker-bench
```

## Daemon Configuration

The `cryptofs-keyd` daemon accepts these options:

```
--socket <path>     Unix socket path (default: /var/run/cryptofs/keyd.sock)
--key-dir <path>    Encrypted key storage (default: /var/lib/cryptofs/keys)
--audit-log <path>  Audit log file (default: /var/log/cryptofs/keyd.log)
--pid-file <path>   PID file (default: /var/run/cryptofs/keyd.pid)
--foreground        Run in foreground (don't daemonize)
--log-level <level> Log level: trace, debug, info, warn, error
```

## Monitoring

### Status

```bash
cryptofs-admin status
```

### Audit Log

```bash
# Recent events
cryptofs-admin audit --count 50

# JSON output (for log aggregation)
cryptofs-admin --format json audit --count 100
```

## Troubleshooting

### Module won't load
- Check `dmesg` for error messages
- Ensure kernel headers match running kernel: `uname -r`
- Verify module was built for correct architecture

### Decryption failures
- Check `dmesg` for "GCM auth tag mismatch" messages
- Verify the correct key is activated
- Lower filesystem may be corrupted — check with `fsck`

### Performance issues
- Run `make bench` to measure overhead
- Check if AES hardware acceleration is available: `grep -o aes /proc/cpuinfo`
- Ensure `CONFIG_CRYPTO_AES` and `CONFIG_CRYPTO_GCM` are enabled in kernel
