// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS — Userspace Encryption Path Verification
 *
 * Replicates the kernel module's exact AES-256-GCM encryption scheme
 * using OpenSSL so the crypto path can be tested without a Linux VM.
 *
 * Tests:
 *   1. HMAC-SHA256 nonce derivation
 *   2. Single-extent encrypt/decrypt round-trip
 *   3. Multi-extent file simulation (header + N extents)
 *   4. FEK wrap/unwrap round-trip
 *   5. Tamper detection (ciphertext + tag bit-flips)
 *   6. Concurrent pthreads encrypt/decrypt
 *   7. Data-integrity patterns (zeros, 0xFF, alternating, sequential)
 *   8. Partial-extent handling
 *   9. Extent-boundary/offset calculations
 *  10. Overwrite re-encryption
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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

/* ── test bookkeeping ─────────────────────────────────────────────── */

static int pass_count;
static int fail_count;

#define RUN_TEST(fn) do {                          \
    printf("  %-52s ", #fn);                       \
    fflush(stdout);                                \
    if (fn()) { printf("PASS\n"); pass_count++; }  \
    else       { printf("FAIL\n"); fail_count++; } \
} while (0)

/* ── helper: little-endian store (matches kernel cpu_to_le64) ───── */

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
static int derive_nonce(const uint8_t *fek, uint64_t inode_no,
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
static int encrypt_extent(const uint8_t *key, const uint8_t *nonce,
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
 * Returns 0 on success, -1 on auth failure.
 */
static int decrypt_extent(const uint8_t *key, const uint8_t *nonce,
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
static int gcm_wrap(const uint8_t *key, const uint8_t *nonce,
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

static int gcm_unwrap(const uint8_t *key, const uint8_t *nonce,
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

/* ── helper: fill buffer with a pattern ──────────────────────────── */

static void fill_pattern(uint8_t *buf, size_t len, uint8_t pattern)
{
    memset(buf, pattern, len);
}

static void fill_sequential(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(i & 0xFF);
}

/* ================================================================= */
/*                         T E S T S                                 */
/* ================================================================= */

/* 1. Nonce derivation ─────────────────────────────────────────────── */

static int test_nonce_deterministic(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    uint8_t n1[CRYPTOFS_NONCE_SIZE], n2[CRYPTOFS_NONCE_SIZE];

    RAND_bytes(fek, sizeof(fek));
    if (derive_nonce(fek, 42, 7, n1)) return 0;
    if (derive_nonce(fek, 42, 7, n2)) return 0;
    return memcmp(n1, n2, CRYPTOFS_NONCE_SIZE) == 0;
}

static int test_nonce_unique_per_extent(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    uint8_t nonces[16][CRYPTOFS_NONCE_SIZE];

    RAND_bytes(fek, sizeof(fek));
    for (int i = 0; i < 16; i++)
        if (derive_nonce(fek, 1, (uint64_t)i, nonces[i])) return 0;

    /* Every pair must differ */
    for (int i = 0; i < 16; i++)
        for (int j = i + 1; j < 16; j++)
            if (memcmp(nonces[i], nonces[j], CRYPTOFS_NONCE_SIZE) == 0)
                return 0;
    return 1;
}

static int test_nonce_unique_per_inode(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    uint8_t n1[CRYPTOFS_NONCE_SIZE], n2[CRYPTOFS_NONCE_SIZE];

    RAND_bytes(fek, sizeof(fek));
    if (derive_nonce(fek, 100, 0, n1)) return 0;
    if (derive_nonce(fek, 200, 0, n2)) return 0;
    return memcmp(n1, n2, CRYPTOFS_NONCE_SIZE) != 0;
}

static int test_nonce_unique_per_key(void)
{
    uint8_t fek1[CRYPTOFS_KEY_SIZE], fek2[CRYPTOFS_KEY_SIZE];
    uint8_t n1[CRYPTOFS_NONCE_SIZE], n2[CRYPTOFS_NONCE_SIZE];

    RAND_bytes(fek1, sizeof(fek1));
    RAND_bytes(fek2, sizeof(fek2));
    if (derive_nonce(fek1, 1, 0, n1)) return 0;
    if (derive_nonce(fek2, 1, 0, n2)) return 0;
    return memcmp(n1, n2, CRYPTOFS_NONCE_SIZE) != 0;
}

/* 2. Single-extent round-trip ─────────────────────────────────────── */

static int test_single_extent_roundtrip(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt, sizeof(pt));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;
    if (decrypt_extent(fek, nonce, ct, tag, dec)) return 0;
    return memcmp(pt, dec, CRYPTOFS_EXTENT_SIZE) == 0;
}

static int test_ciphertext_differs_from_plaintext(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt, sizeof(pt));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;
    return memcmp(pt, ct, CRYPTOFS_EXTENT_SIZE) != 0;
}

/* 3. Multi-extent file simulation ─────────────────────────────────── */

static int test_multi_extent_file(void)
{
    const int NUM_EXTENTS = 8;
    uint8_t master_key[CRYPTOFS_KEY_SIZE], fek[CRYPTOFS_KEY_SIZE];
    uint8_t wrap_nonce[CRYPTOFS_NONCE_SIZE], wrap_tag[CRYPTOFS_TAG_SIZE];
    uint8_t wrapped_fek[CRYPTOFS_KEY_SIZE];
    struct cryptofs_file_header hdr;

    RAND_bytes(master_key, sizeof(master_key));
    RAND_bytes(fek, sizeof(fek));

    /* Build header */
    memset(&hdr, 0, sizeof(hdr));
    put_le64((uint8_t *)&hdr.magic, CRYPTOFS_FILE_MAGIC);
    hdr.version = CRYPTOFS_VERSION;
    hdr.flags = CRYPTOFS_FLAG_ENCRYPTED;
    put_le64((uint8_t *)&hdr.file_size,
             (uint64_t)NUM_EXTENTS * CRYPTOFS_EXTENT_SIZE);

    /* Wrap FEK */
    RAND_bytes(wrap_nonce, sizeof(wrap_nonce));
    if (gcm_wrap(master_key, wrap_nonce, fek, CRYPTOFS_KEY_SIZE,
                 wrapped_fek, wrap_tag))
        return 0;
    memcpy(hdr.encrypted_fek, wrapped_fek, CRYPTOFS_KEY_SIZE);
    memcpy(hdr.encrypted_fek + CRYPTOFS_KEY_SIZE, wrap_tag, CRYPTOFS_TAG_SIZE);
    memcpy(hdr.fek_nonce, wrap_nonce, CRYPTOFS_NONCE_SIZE);

    /* Simulate file: header + encrypted extents */
    size_t file_size = CRYPTOFS_HEADER_SIZE +
                       (size_t)NUM_EXTENTS * CRYPTOFS_EXTENT_DISK_SIZE;
    uint8_t *file_buf = calloc(1, file_size);
    if (!file_buf) return 0;

    memcpy(file_buf, &hdr, CRYPTOFS_HEADER_SIZE);

    /* Encrypt each extent */
    uint8_t pt[CRYPTOFS_EXTENT_SIZE];
    uint8_t nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t *original = malloc((size_t)NUM_EXTENTS * CRYPTOFS_EXTENT_SIZE);
    if (!original) { free(file_buf); return 0; }

    for (int i = 0; i < NUM_EXTENTS; i++) {
        fill_sequential(pt, sizeof(pt));
        pt[0] = (uint8_t)i; /* make each extent distinct */
        memcpy(original + (size_t)i * CRYPTOFS_EXTENT_SIZE,
               pt, CRYPTOFS_EXTENT_SIZE);

        if (derive_nonce(fek, 1000, (uint64_t)i, nonce)) goto fail;

        uint8_t *dst = file_buf + CRYPTOFS_HEADER_SIZE +
                       (size_t)i * CRYPTOFS_EXTENT_DISK_SIZE;
        uint8_t ct_tag[CRYPTOFS_TAG_SIZE];

        if (encrypt_extent(fek, nonce, pt, dst, ct_tag)) goto fail;
        memcpy(dst + CRYPTOFS_EXTENT_SIZE, ct_tag, CRYPTOFS_TAG_SIZE);
    }

    /* === Read path: parse header, unwrap FEK, decrypt extents === */
    struct cryptofs_file_header *rhdr = (struct cryptofs_file_header *)file_buf;
    if (get_le64((uint8_t *)&rhdr->magic) != CRYPTOFS_FILE_MAGIC) goto fail;

    uint8_t recovered_fek[CRYPTOFS_KEY_SIZE];
    if (gcm_unwrap(master_key, rhdr->fek_nonce,
                   rhdr->encrypted_fek, CRYPTOFS_KEY_SIZE,
                   rhdr->encrypted_fek + CRYPTOFS_KEY_SIZE,
                   recovered_fek))
        goto fail;

    if (memcmp(fek, recovered_fek, CRYPTOFS_KEY_SIZE) != 0) goto fail;

    for (int i = 0; i < NUM_EXTENTS; i++) {
        uint8_t *src = file_buf + CRYPTOFS_HEADER_SIZE +
                       (size_t)i * CRYPTOFS_EXTENT_DISK_SIZE;
        uint8_t ext_tag[CRYPTOFS_TAG_SIZE];
        memcpy(ext_tag, src + CRYPTOFS_EXTENT_SIZE, CRYPTOFS_TAG_SIZE);

        uint8_t dec[CRYPTOFS_EXTENT_SIZE];
        if (derive_nonce(recovered_fek, 1000, (uint64_t)i, nonce)) goto fail;
        if (decrypt_extent(recovered_fek, nonce, src, ext_tag, dec)) goto fail;

        if (memcmp(dec, original + (size_t)i * CRYPTOFS_EXTENT_SIZE,
                   CRYPTOFS_EXTENT_SIZE) != 0)
            goto fail;
    }

    free(original);
    free(file_buf);
    return 1;

fail:
    free(original);
    free(file_buf);
    return 0;
}

/* 4. FEK wrap/unwrap ──────────────────────────────────────────────── */

static int test_fek_wrap_unwrap(void)
{
    uint8_t master[CRYPTOFS_KEY_SIZE], fek[CRYPTOFS_KEY_SIZE];
    uint8_t nonce[CRYPTOFS_NONCE_SIZE], tag[CRYPTOFS_TAG_SIZE];
    uint8_t wrapped[CRYPTOFS_KEY_SIZE], unwrapped[CRYPTOFS_KEY_SIZE];

    RAND_bytes(master, sizeof(master));
    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(nonce, sizeof(nonce));

    if (gcm_wrap(master, nonce, fek, CRYPTOFS_KEY_SIZE, wrapped, tag))
        return 0;
    if (gcm_unwrap(master, nonce, wrapped, CRYPTOFS_KEY_SIZE, tag, unwrapped))
        return 0;
    return memcmp(fek, unwrapped, CRYPTOFS_KEY_SIZE) == 0;
}

static int test_fek_wrong_master_key(void)
{
    uint8_t master[CRYPTOFS_KEY_SIZE], wrong[CRYPTOFS_KEY_SIZE];
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], wrapped[CRYPTOFS_KEY_SIZE];
    uint8_t out[CRYPTOFS_KEY_SIZE];

    RAND_bytes(master, sizeof(master));
    RAND_bytes(wrong, sizeof(wrong));
    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(nonce, sizeof(nonce));

    if (gcm_wrap(master, nonce, fek, CRYPTOFS_KEY_SIZE, wrapped, tag))
        return 0;
    /* Unwrap with wrong key must fail */
    return gcm_unwrap(wrong, nonce, wrapped, CRYPTOFS_KEY_SIZE, tag, out) != 0;
}

/* 5. Tamper detection ─────────────────────────────────────────────── */

static int test_tamper_ciphertext(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt, sizeof(pt));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;

    ct[100] ^= 0x01; /* flip one bit */
    return decrypt_extent(fek, nonce, ct, tag, dec) != 0;
}

static int test_tamper_tag(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt, sizeof(pt));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;

    tag[0] ^= 0x01; /* flip one bit in the auth tag */
    return decrypt_extent(fek, nonce, ct, tag, dec) != 0;
}

static int test_tamper_wrong_nonce(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];
    uint8_t bad_nonce[CRYPTOFS_NONCE_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt, sizeof(pt));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;

    /* Use nonce for a different extent */
    if (derive_nonce(fek, 1, 1, bad_nonce)) return 0;
    return decrypt_extent(fek, bad_nonce, ct, tag, dec) != 0;
}

/* 6. Concurrent pthreads ─────────────────────────────────────────── */

struct thread_args {
    int thread_id;
    int ok;
};

static void *concurrent_worker(void *arg)
{
    struct thread_args *ta = (struct thread_args *)arg;
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));

    for (int i = 0; i < 50; i++) {
        RAND_bytes(pt, sizeof(pt));
        if (derive_nonce(fek, (uint64_t)ta->thread_id,
                         (uint64_t)i, nonce)) {
            ta->ok = 0;
            return NULL;
        }
        if (encrypt_extent(fek, nonce, pt, ct, tag)) {
            ta->ok = 0;
            return NULL;
        }
        if (decrypt_extent(fek, nonce, ct, tag, dec)) {
            ta->ok = 0;
            return NULL;
        }
        if (memcmp(pt, dec, CRYPTOFS_EXTENT_SIZE) != 0) {
            ta->ok = 0;
            return NULL;
        }
    }
    ta->ok = 1;
    return NULL;
}

static int test_concurrent_crypto(void)
{
    const int N = 8;
    pthread_t threads[8];
    struct thread_args args[8];

    for (int i = 0; i < N; i++) {
        args[i].thread_id = i;
        args[i].ok = 0;
        pthread_create(&threads[i], NULL, concurrent_worker, &args[i]);
    }
    for (int i = 0; i < N; i++)
        pthread_join(threads[i], NULL);

    for (int i = 0; i < N; i++)
        if (!args[i].ok) return 0;
    return 1;
}

/* 7. Data-integrity patterns ──────────────────────────────────────── */

static int roundtrip_pattern(uint8_t *pt)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t ct[CRYPTOFS_EXTENT_SIZE], tag[CRYPTOFS_TAG_SIZE];
    uint8_t dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    if (derive_nonce(fek, 99, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;
    if (decrypt_extent(fek, nonce, ct, tag, dec)) return 0;
    return memcmp(pt, dec, CRYPTOFS_EXTENT_SIZE) == 0;
}

static int test_pattern_zeros(void)
{
    uint8_t pt[CRYPTOFS_EXTENT_SIZE];
    fill_pattern(pt, sizeof(pt), 0x00);
    return roundtrip_pattern(pt);
}

static int test_pattern_ones(void)
{
    uint8_t pt[CRYPTOFS_EXTENT_SIZE];
    fill_pattern(pt, sizeof(pt), 0xFF);
    return roundtrip_pattern(pt);
}

static int test_pattern_alternating(void)
{
    uint8_t pt[CRYPTOFS_EXTENT_SIZE];
    fill_pattern(pt, sizeof(pt), 0xAA);
    return roundtrip_pattern(pt);
}

static int test_pattern_sequential(void)
{
    uint8_t pt[CRYPTOFS_EXTENT_SIZE];
    fill_sequential(pt, sizeof(pt));
    return roundtrip_pattern(pt);
}

/* 8. Partial extent ───────────────────────────────────────────────── */

static int test_partial_extent(void)
{
    /* Kernel zero-pads partial extents before encryption.
     * Simulate: 100 bytes of data + zeros -> encrypt full extent -> decrypt
     * -> verify first 100 bytes match and rest are zero.
     */
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt[CRYPTOFS_EXTENT_SIZE], ct[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE], dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    memset(pt, 0, sizeof(pt));
    RAND_bytes(pt, 100); /* only first 100 bytes are "user data" */

    if (derive_nonce(fek, 1, 0, nonce)) return 0;
    if (encrypt_extent(fek, nonce, pt, ct, tag)) return 0;
    if (decrypt_extent(fek, nonce, ct, tag, dec)) return 0;

    /* Full extent must round-trip exactly (including the zero padding) */
    return memcmp(pt, dec, CRYPTOFS_EXTENT_SIZE) == 0;
}

/* 9. Extent boundary / offset calculations ────────────────────────── */

static int test_extent_offset_calc(void)
{
    /* Mirror the kernel's offset translation helpers:
     *   extent_index(offset)  = offset / 4096
     *   extent_offset(offset) = offset % 4096
     *   logical_to_lower(offset) = 128 + (idx * 4112) + off
     */
    int ok = 1;

    struct { uint64_t logical; uint64_t idx; uint64_t off; uint64_t lower; } cases[] = {
        { 0,       0, 0,    128 },
        { 4095,    0, 4095, 128 + 4095 },
        { 4096,    1, 0,    128 + 4112 },
        { 4097,    1, 1,    128 + 4112 + 1 },
        { 8192,    2, 0,    128 + 2*4112 },
        { 1000000, 1000000/4096, 1000000%4096,
          128 + (1000000/4096)*4112 + (1000000%4096) },
    };
    int n = sizeof(cases) / sizeof(cases[0]);

    for (int i = 0; i < n; i++) {
        uint64_t idx = cases[i].logical / CRYPTOFS_EXTENT_SIZE;
        uint64_t off = cases[i].logical % CRYPTOFS_EXTENT_SIZE;
        uint64_t lower = CRYPTOFS_HEADER_SIZE +
                         idx * CRYPTOFS_EXTENT_DISK_SIZE + off;

        if (idx != cases[i].idx || off != cases[i].off ||
            lower != cases[i].lower) {
            fprintf(stderr, "    offset calc mismatch at logical=%lu\n",
                    (unsigned long)cases[i].logical);
            ok = 0;
        }
    }
    return ok;
}

/* 10. Overwrite re-encryption ─────────────────────────────────────── */

static int test_overwrite_reencrypt(void)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE], nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t pt1[CRYPTOFS_EXTENT_SIZE], pt2[CRYPTOFS_EXTENT_SIZE];
    uint8_t ct1[CRYPTOFS_EXTENT_SIZE], ct2[CRYPTOFS_EXTENT_SIZE];
    uint8_t tag1[CRYPTOFS_TAG_SIZE], tag2[CRYPTOFS_TAG_SIZE];
    uint8_t dec[CRYPTOFS_EXTENT_SIZE];

    RAND_bytes(fek, sizeof(fek));
    RAND_bytes(pt1, sizeof(pt1));
    RAND_bytes(pt2, sizeof(pt2));
    if (derive_nonce(fek, 1, 0, nonce)) return 0;

    /* First write */
    if (encrypt_extent(fek, nonce, pt1, ct1, tag1)) return 0;

    /* Overwrite same extent with different data (same nonce) */
    if (encrypt_extent(fek, nonce, pt2, ct2, tag2)) return 0;

    /* Ciphertexts must differ (different plaintext) */
    if (memcmp(ct1, ct2, CRYPTOFS_EXTENT_SIZE) == 0) return 0;

    /* Decrypt the overwrite: must yield pt2 */
    if (decrypt_extent(fek, nonce, ct2, tag2, dec)) return 0;
    if (memcmp(pt2, dec, CRYPTOFS_EXTENT_SIZE) != 0) return 0;

    /* Old ciphertext with old tag must still decrypt to pt1 */
    if (decrypt_extent(fek, nonce, ct1, tag1, dec)) return 0;
    return memcmp(pt1, dec, CRYPTOFS_EXTENT_SIZE) == 0;
}

/* ================================================================= */

int main(void)
{
    printf("════════════════════════════════════════════════════════════\n");
    printf("  CryptoFS — Encryption Path Verification\n");
    printf("════════════════════════════════════════════════════════════\n\n");

    printf("  [1] Nonce derivation\n");
    RUN_TEST(test_nonce_deterministic);
    RUN_TEST(test_nonce_unique_per_extent);
    RUN_TEST(test_nonce_unique_per_inode);
    RUN_TEST(test_nonce_unique_per_key);

    printf("\n  [2] Single-extent encrypt/decrypt\n");
    RUN_TEST(test_single_extent_roundtrip);
    RUN_TEST(test_ciphertext_differs_from_plaintext);

    printf("\n  [3] Multi-extent file simulation\n");
    RUN_TEST(test_multi_extent_file);

    printf("\n  [4] FEK wrap/unwrap\n");
    RUN_TEST(test_fek_wrap_unwrap);
    RUN_TEST(test_fek_wrong_master_key);

    printf("\n  [5] Tamper detection\n");
    RUN_TEST(test_tamper_ciphertext);
    RUN_TEST(test_tamper_tag);
    RUN_TEST(test_tamper_wrong_nonce);

    printf("\n  [6] Concurrent crypto (8 threads × 50 extents)\n");
    RUN_TEST(test_concurrent_crypto);

    printf("\n  [7] Data-integrity patterns\n");
    RUN_TEST(test_pattern_zeros);
    RUN_TEST(test_pattern_ones);
    RUN_TEST(test_pattern_alternating);
    RUN_TEST(test_pattern_sequential);

    printf("\n  [8] Partial extent\n");
    RUN_TEST(test_partial_extent);

    printf("\n  [9] Extent offset calculations\n");
    RUN_TEST(test_extent_offset_calc);

    printf("\n  [10] Overwrite re-encryption\n");
    RUN_TEST(test_overwrite_reencrypt);

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("  Results:  %d passed,  %d failed\n",
           pass_count, fail_count);
    printf("════════════════════════════════════════════════════════════\n");

    return fail_count > 0 ? 1 : 0;
}
