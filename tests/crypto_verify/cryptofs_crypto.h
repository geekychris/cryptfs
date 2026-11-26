/* SPDX-License-Identifier: GPL-2.0 */
/*
 * CryptoFS — Userspace Crypto Primitives (shared by crypto_verify and the
 * fuzz harnesses under tests/fuzz/)
 *
 * Replicates the kernel module's exact AES-256-GCM encryption scheme using
 * OpenSSL so the crypto path can be exercised without a Linux VM. See
 * kernel/cryptofs.h and kernel/crypto.c for the in-kernel counterparts.
 */

#ifndef CRYPTOFS_CRYPTO_H
#define CRYPTOFS_CRYPTO_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── constants (must match kernel/cryptofs.h exactly) ────────────── */

#define CRYPTOFS_KEY_SIZE        32
#define CRYPTOFS_NONCE_SIZE      12
#define CRYPTOFS_TAG_SIZE        16
#define CRYPTOFS_EXTENT_SIZE     4096
#define CRYPTOFS_EXTENT_DISK_SIZE (CRYPTOFS_EXTENT_SIZE + CRYPTOFS_TAG_SIZE)
#define CRYPTOFS_HEADER_SIZE     128
#define CRYPTOFS_FILE_MAGIC      0x4352595046533031ULL
#define CRYPTOFS_VERSION         1
#define CRYPTOFS_FLAG_ENCRYPTED  0x01

/* ── on-disk file header (byte-compatible with the kernel struct) ── */

struct cryptofs_file_header {
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    uint8_t  encrypted_fek[CRYPTOFS_KEY_SIZE + CRYPTOFS_TAG_SIZE];
    uint8_t  fek_nonce[CRYPTOFS_NONCE_SIZE];
    uint64_t file_size;
    uint8_t  reserved[44];
} __attribute__((packed));

/* ── parse/decrypt result codes ──────────────────────────────────── */

enum cryptofs_parse_result {
    CRYPTOFS_PARSE_OK = 0,
    CRYPTOFS_PARSE_ERR_TOO_SHORT,
    CRYPTOFS_PARSE_ERR_BAD_MAGIC,
    CRYPTOFS_PARSE_ERR_FEK_UNWRAP,
    CRYPTOFS_PARSE_ERR_SIZE_OVERFLOW,
    CRYPTOFS_PARSE_ERR_TRUNCATED,
    CRYPTOFS_PARSE_ERR_DECRYPT,
    CRYPTOFS_PARSE_ERR_NOMEM,
};

/* ── helper: little-endian store/load (matches kernel cpu_to_le64) ─ */

static inline void put_le64(uint8_t *dst, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        dst[i] = (uint8_t)(v >> (i * 8));
}

static inline uint64_t get_le64(const uint8_t *src)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)src[i] << (i * 8);
    return v;
}

/* ── crypto primitives (mirror kernel/crypto.c) ──────────────────── */

/*
 * Derive nonce = HMAC-SHA256(fek, le64(inode_no) || le64(extent_idx))
 * truncated to 12 bytes.
 */
static inline int derive_nonce(const uint8_t *fek, uint64_t inode_no,
                                uint64_t extent_idx, uint8_t *nonce)
{
    uint8_t data[16], hash[32];
    unsigned int hash_len = 32;

    put_le64(data,     inode_no);
    put_le64(data + 8, extent_idx);

    if (!HMAC(EVP_sha256(), fek, CRYPTOFS_KEY_SIZE,
              data, sizeof(data), hash, &hash_len))
        return -1;

    memcpy(nonce, hash, CRYPTOFS_NONCE_SIZE);
    return 0;
}

/*
 * AES-256-GCM encrypt (one extent).
 * plaintext: CRYPTOFS_EXTENT_SIZE bytes
 * ciphertext: CRYPTOFS_EXTENT_SIZE bytes
 * tag: CRYPTOFS_TAG_SIZE bytes
 */
static inline int encrypt_extent(const uint8_t *key, const uint8_t *nonce,
                                  const uint8_t *plaintext,
                                  uint8_t *ciphertext, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;

    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CRYPTOFS_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, CRYPTOFS_EXTENT_SIZE) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            CRYPTOFS_TAG_SIZE, tag) != 1)
        goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * AES-256-GCM decrypt (one extent).
 * Returns 0 on success, -1 on auth failure. Never crashes regardless of
 * whether ciphertext/tag/key/nonce are adversarial.
 */
static inline int decrypt_extent(const uint8_t *key, const uint8_t *nonce,
                                  const uint8_t *ciphertext, const uint8_t *tag,
                                  uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;

    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CRYPTOFS_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, plaintext, &len,
                          ciphertext, CRYPTOFS_EXTENT_SIZE) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            CRYPTOFS_TAG_SIZE, (void *)tag) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        goto out;  /* auth failure lands here */
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * AES-256-GCM wrap/unwrap for arbitrary-length data (used for FEK).
 */
static inline int gcm_wrap(const uint8_t *key, const uint8_t *nonce,
                            const uint8_t *pt, int pt_len,
                            uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;

    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CRYPTOFS_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            CRYPTOFS_TAG_SIZE, tag) != 1)
        goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static inline int gcm_unwrap(const uint8_t *key, const uint8_t *nonce,
                              const uint8_t *ct, int ct_len,
                              const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ret = -1;

    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CRYPTOFS_NONCE_SIZE, NULL) != 1)
        goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            CRYPTOFS_TAG_SIZE, (void *)tag) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1)
        goto out;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Parse a whole lower-file byte buffer the way the kernel VFS read path
 * does (kernel/file.c: cryptofs_read_iter): header -> FEK unwrap -> derive
 * extent count from the header's file_size -> decrypt each extent in turn,
 * truncating the final extent to file_size. Every exit path is a clean
 * error code; this function must never crash or read past buf_len
 * regardless of how adversarial buf/buf_len/master_key are.
 *
 * On success returns CRYPTOFS_PARSE_OK, sets *out_plaintext to a
 * caller-owned buffer (NULL if file_size == 0) and *out_len to file_size.
 * On any other return value, *out_plaintext is NULL and *out_len is 0.
 */
static inline int cryptofs_parse_and_decrypt_file(const uint8_t *buf, size_t buf_len,
                                                   const uint8_t *master_key,
                                                   uint8_t **out_plaintext,
                                                   uint64_t *out_len)
{
    const struct cryptofs_file_header *hdr;
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    uint64_t file_size, num_extents, extents_len, required_len, produced;
    uint8_t *plaintext = NULL;

    *out_plaintext = NULL;
    *out_len = 0;

    if (buf_len < CRYPTOFS_HEADER_SIZE)
        return CRYPTOFS_PARSE_ERR_TOO_SHORT;

    hdr = (const struct cryptofs_file_header *)buf;

    if (get_le64((const uint8_t *)&hdr->magic) != CRYPTOFS_FILE_MAGIC)
        return CRYPTOFS_PARSE_ERR_BAD_MAGIC;

    if (gcm_unwrap(master_key, hdr->fek_nonce,
                   hdr->encrypted_fek, CRYPTOFS_KEY_SIZE,
                   hdr->encrypted_fek + CRYPTOFS_KEY_SIZE, fek) != 0)
        return CRYPTOFS_PARSE_ERR_FEK_UNWRAP;

    file_size = get_le64((const uint8_t *)&hdr->file_size);

    /* num_extents = ceil(file_size / CRYPTOFS_EXTENT_SIZE), overflow-safe */
    num_extents = file_size == 0 ? 0 : (file_size - 1) / CRYPTOFS_EXTENT_SIZE + 1;

    if (__builtin_mul_overflow(num_extents, (uint64_t)CRYPTOFS_EXTENT_DISK_SIZE, &extents_len))
        return CRYPTOFS_PARSE_ERR_SIZE_OVERFLOW;
    if (__builtin_add_overflow(extents_len, (uint64_t)CRYPTOFS_HEADER_SIZE, &required_len))
        return CRYPTOFS_PARSE_ERR_SIZE_OVERFLOW;
    if (required_len > (uint64_t)buf_len)
        return CRYPTOFS_PARSE_ERR_TRUNCATED;

    if (file_size > 0) {
        plaintext = malloc(file_size);
        if (!plaintext)
            return CRYPTOFS_PARSE_ERR_NOMEM;
    }

    produced = 0;
    for (uint64_t i = 0; i < num_extents; i++) {
        const uint8_t *extent = buf + CRYPTOFS_HEADER_SIZE + i * CRYPTOFS_EXTENT_DISK_SIZE;
        const uint8_t *tag = extent + CRYPTOFS_EXTENT_SIZE;
        uint8_t nonce[CRYPTOFS_NONCE_SIZE];
        uint8_t dec[CRYPTOFS_EXTENT_SIZE];
        uint64_t remaining, copy_len;

        /* inode_no is fixed at 0: this parse helper has no inode context,
         * unlike the kernel which derives the nonce from the real inode
         * number. The FEK is still unique per file, so extents still get
         * unique nonces within this synthetic file. */
        if (derive_nonce(fek, 0, i, nonce) != 0) {
            free(plaintext);
            *out_plaintext = NULL;
            *out_len = 0;
            return CRYPTOFS_PARSE_ERR_DECRYPT;
        }

        if (decrypt_extent(fek, nonce, extent, tag, dec) != 0) {
            free(plaintext);
            *out_plaintext = NULL;
            *out_len = 0;
            return CRYPTOFS_PARSE_ERR_DECRYPT;
        }

        remaining = file_size - produced;
        copy_len = remaining < CRYPTOFS_EXTENT_SIZE ? remaining : CRYPTOFS_EXTENT_SIZE;
        memcpy(plaintext + produced, dec, copy_len);
        produced += copy_len;
    }

    *out_plaintext = plaintext;
    *out_len = file_size;
    return CRYPTOFS_PARSE_OK;
}

#endif /* CRYPTOFS_CRYPTO_H */
