# CryptoFS On-Disk Encryption Format

## File Layout

Each encrypted file on the lower filesystem has the following structure:

```
┌────────────────────────────┐  Offset 0
│     File Header (128 B)    │
├────────────────────────────┤  Offset 128
│   Extent 0: Ciphertext     │  4096 bytes
│   Extent 0: Auth Tag       │  16 bytes
├────────────────────────────┤  Offset 4240
│   Extent 1: Ciphertext     │  4096 bytes
│   Extent 1: Auth Tag       │  16 bytes
├────────────────────────────┤  Offset 8352
│          ...                │
├────────────────────────────┤
│   Extent N: Ciphertext     │  ≤4096 bytes (last extent may be shorter)
│   Extent N: Auth Tag       │  16 bytes
└────────────────────────────┘
```

## File Header (128 bytes)

```
Offset  Size  Field
------  ----  -----
0       8     Magic bytes: "CRYPTOFS"
8       4     Version (currently 1)
12      4     Flags (reserved)
16      4     Cipher algorithm ID (1 = AES-256-GCM)
20      4     Extent size (4096)
24      48    Encrypted FEK (32-byte key + 16-byte GCM tag, wrapped by master key)
72      12    FEK wrapping nonce
84      32    Master key ID (UUID, for key lookup)
116     4     Original file size (lower 32 bits)
120     4     Original file size (upper 32 bits)
124     4     Header checksum (CRC32)
```

## Extent Format

Each extent on disk occupies 4112 bytes:

- **Ciphertext**: 4096 bytes (AES-256-GCM encrypted plaintext)
- **Authentication tag**: 16 bytes (GCM tag for integrity verification)

The last extent may contain fewer than 4096 bytes of meaningful data. The actual plaintext size is tracked in the file header.

## Nonce Derivation

Each extent uses a unique 12-byte nonce derived deterministically:

```
nonce = HMAC-SHA256(FEK, inode_number || extent_index)[0:12]
```

This ensures:
- No nonce reuse across extents within a file
- No nonce reuse across files (different FEKs)
- Deterministic: same extent always produces same nonce (important for random access)

## Key Hierarchy

```
Master Key (256-bit, stored encrypted by daemon)
  └── wraps → File Encryption Key (FEK, 256-bit, unique per file)
                └── derives → Per-extent nonce (12-byte, via HMAC)
```

## Offset Translation

For a logical file offset `L`:
- **Extent index**: `L / 4096`
- **Offset within extent**: `L % 4096`
- **Lower file offset**: `128 + (extent_index * 4112) + offset_within_extent`

## Size Calculation

- **Logical size** (as seen by applications): Stored in file header
- **Physical size** (on lower filesystem): `128 + ceil(logical_size / 4096) * 4112`
- **Overhead per file**: 128 bytes header + 16 bytes per extent
- **For a 1MB file**: ~4.2 KB overhead (~0.4%)
