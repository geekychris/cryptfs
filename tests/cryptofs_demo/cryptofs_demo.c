// SPDX-License-Identifier: GPL-2.0
/*
 * CryptoFS — Encryption Demo & Proof
 *
 * Writes identical data to two directories:
 *   /data/plaintext/   — raw plaintext files
 *   /data/encrypted/   — files in CryptoFS on-disk format
 *                        (128-byte header + AES-256-GCM encrypted 4KB extents)
 *
 * Both directories are Docker-volume-mounted to the host, so you can
 * inspect them directly from macOS with cat / hexdump / diff.
 *
 * Tested file-access patterns:
 *   • Sequential create & write (small, exact-extent, multi-extent, large)
 *   • Full-file decrypt & verify
 *   • Random-access write at arbitrary offsets (incl. cross-extent)
 *   • Random-access read at arbitrary offsets
 *   • Append
 *   • Overwrite-in-place
 *   • Tamper detection (flip a bit → decryption must fail)
 *   • Binary fill patterns (zeros, 0xFF, alternating, sequential)
 *   • Batch of many small files
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <pthread.h>

/* ── CryptoFS constants (must match kernel) ─────────────────────── */

#define KEY_SZ     32
#define NONCE_SZ   12
#define TAG_SZ     16
#define EXT_SZ     4096
#define EXT_DISK   (EXT_SZ + TAG_SZ)          /* 4112 */
#define HDR_SZ     128
#define MAGIC      0x4352595046533031ULL       /* "CRYPFS01" */
#define VERSION    1
#define FL_ENC     0x01

/* ── on-disk file header ────────────────────────────────────────── */

struct hdr {
    uint64_t magic;
    uint32_t version;
    uint32_t flags;
    uint8_t  wrapped_fek[KEY_SZ + TAG_SZ];    /* 48 bytes */
    uint8_t  fek_nonce[NONCE_SZ];
    uint64_t file_size;
    uint8_t  reserved[44];
} __attribute__((packed));

/* ── globals ────────────────────────────────────────────────────── */

static uint8_t g_master[KEY_SZ];
static const char *g_enc;       /* e.g. "/data/encrypted" */
static const char *g_pt;        /* e.g. "/data/plaintext" */
static int g_pass, g_fail;

#define T_OK(name) do { printf("  ✓  %-55s PASS\n", name); g_pass++; } while(0)
#define T_FAIL(name) do { printf("  ✗  %-55s FAIL\n", name); g_fail++; } while(0)
#define CHECK(name, cond) do { if (cond) T_OK(name); else T_FAIL(name); } while(0)

static size_t zmin(size_t a, size_t b) { return a < b ? a : b; }

/* ── little-endian helpers ──────────────────────────────────────── */

static void le64_put(uint8_t *d, uint64_t v)
{ for (int i = 0; i < 8; i++) d[i] = (uint8_t)(v >> (i*8)); }

static uint64_t le64_get(const uint8_t *s)
{ uint64_t v=0; for (int i=0;i<8;i++) v|=(uint64_t)s[i]<<(i*8); return v; }

/* ── deterministic inode number from filename ───────────────────── */

static uint64_t name_to_ino(const char *n)
{ uint64_t h=14695981039346656037ULL; while(*n) { h^=*n++; h*=1099511628211ULL; } return h; }

/* ── crypto primitives (identical to kernel scheme) ─────────────── */

static int derive_nonce(const uint8_t *fek, uint64_t ino,
                        uint64_t ext, uint8_t *nonce)
{
    uint8_t d[16], h[32]; unsigned hl=32;
    le64_put(d, ino); le64_put(d+8, ext);
    if (!HMAC(EVP_sha256(), fek, KEY_SZ, d, 16, h, &hl)) return -1;
    memcpy(nonce, h, NONCE_SZ);
    return 0;
}

static int enc_ext(const uint8_t *k, const uint8_t *n,
                   const uint8_t *pt, uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int len, r=-1;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),0,0,0)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,NONCE_SZ,0)!=1) goto e;
    if (EVP_EncryptInit_ex(c,0,0,k,n)!=1) goto e;
    if (EVP_EncryptUpdate(c,ct,&len,pt,EXT_SZ)!=1) goto e;
    if (EVP_EncryptFinal_ex(c,ct+len,&len)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,TAG_SZ,tag)!=1) goto e;
    r=0;
e:  EVP_CIPHER_CTX_free(c); return r;
}

static int dec_ext(const uint8_t *k, const uint8_t *n,
                   const uint8_t *ct, const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int len, r=-1;
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),0,0,0)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,NONCE_SZ,0)!=1) goto e;
    if (EVP_DecryptInit_ex(c,0,0,k,n)!=1) goto e;
    if (EVP_DecryptUpdate(c,pt,&len,ct,EXT_SZ)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,TAG_SZ,(void*)tag)!=1) goto e;
    if (EVP_DecryptFinal_ex(c,pt+len,&len)!=1) goto e;
    r=0;
e:  EVP_CIPHER_CTX_free(c); return r;
}

static int wrap_key(const uint8_t *mk, const uint8_t *n,
                    const uint8_t *pt, uint8_t *ct, uint8_t *tag)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int len, r=-1;
    if (!c) return -1;
    if (EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),0,0,0)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,NONCE_SZ,0)!=1) goto e;
    if (EVP_EncryptInit_ex(c,0,0,mk,n)!=1) goto e;
    if (EVP_EncryptUpdate(c,ct,&len,pt,KEY_SZ)!=1) goto e;
    if (EVP_EncryptFinal_ex(c,ct+len,&len)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,TAG_SZ,tag)!=1) goto e;
    r=0;
e:  EVP_CIPHER_CTX_free(c); return r;
}

static int unwrap_key(const uint8_t *mk, const uint8_t *n,
                      const uint8_t *ct, const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int len, r=-1;
    if (!c) return -1;
    if (EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),0,0,0)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,NONCE_SZ,0)!=1) goto e;
    if (EVP_DecryptInit_ex(c,0,0,mk,n)!=1) goto e;
    if (EVP_DecryptUpdate(c,pt,&len,ct,KEY_SZ)!=1) goto e;
    if (EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,TAG_SZ,(void*)tag)!=1) goto e;
    if (EVP_DecryptFinal_ex(c,pt+len,&len)!=1) goto e;
    r=0;
e:  EVP_CIPHER_CTX_free(c); return r;
}

/* ── hex snippet for display ─────────────────────────────────────── */

static void hex_line(const uint8_t *d, size_t n, char *out, size_t cap)
{
    size_t show = zmin(n, 16);
    int pos = 0;
    for (size_t i = 0; i < show && pos+3 < (int)cap; i++)
        pos += snprintf(out+pos, cap-pos, "%02x ", d[i]);
    if (n > 16 && pos+4 < (int)cap)
        pos += snprintf(out+pos, cap-pos, "...");
    /* ascii */
    if (pos+4 < (int)cap) pos += snprintf(out+pos, cap-pos, "  ");
    for (size_t i = 0; i < show && pos+2 < (int)cap; i++)
        out[pos++] = (d[i] >= 0x20 && d[i] < 0x7f) ? d[i] : '.';
    out[pos] = '\0';
}

/* ── path helpers ────────────────────────────────────────────────── */

static void enc_path(char *buf, size_t cap, const char *name)
{ snprintf(buf, cap, "%s/%s", g_enc, name); }

static void pt_path(char *buf, size_t cap, const char *name)
{ snprintf(buf, cap, "%s/%s", g_pt, name); }

/* ================================================================ */
/*  CryptoFS file operations — userspace replica of the kernel I/O  */
/* ================================================================ */

/*
 * Create a new encrypted file and its plaintext twin.
 * Returns the FEK (32 bytes) on success for later random-access use.
 */
static int cf_create(const char *name, const uint8_t *data, size_t len,
                     uint8_t *fek_out)
{
    char ep[512], pp[512];
    enc_path(ep, sizeof ep, name);
    pt_path(pp, sizeof pp, name);
    uint64_t ino = name_to_ino(name);

    /* ── Write plaintext twin ── */
    FILE *fp = fopen(pp, "wb");
    if (!fp) return -1;
    fwrite(data, 1, len, fp);
    fclose(fp);

    /* ── Generate per-file key ── */
    uint8_t fek[KEY_SZ];
    RAND_bytes(fek, KEY_SZ);
    if (fek_out) memcpy(fek_out, fek, KEY_SZ);

    /* ── Build header ── */
    struct hdr h;
    memset(&h, 0, sizeof h);
    le64_put((uint8_t*)&h.magic, MAGIC);
    h.version = VERSION; h.flags = FL_ENC;
    le64_put((uint8_t*)&h.file_size, (uint64_t)len);
    RAND_bytes(h.fek_nonce, NONCE_SZ);

    uint8_t wtag[TAG_SZ];
    if (wrap_key(g_master, h.fek_nonce, fek, h.wrapped_fek, wtag))
        return -1;
    memcpy(h.wrapped_fek + KEY_SZ, wtag, TAG_SZ);

    /* ── Write encrypted file ── */
    fp = fopen(ep, "wb");
    if (!fp) return -1;
    fwrite(&h, 1, HDR_SZ, fp);

    size_t off = 0;
    uint64_t ext = 0;
    while (off < len) {
        uint8_t pbuf[EXT_SZ], cbuf[EXT_SZ], tag[TAG_SZ], nonce[NONCE_SZ];
        memset(pbuf, 0, EXT_SZ);
        size_t chunk = zmin(EXT_SZ, len - off);
        memcpy(pbuf, data + off, chunk);

        if (derive_nonce(fek, ino, ext, nonce)) { fclose(fp); return -1; }
        if (enc_ext(fek, nonce, pbuf, cbuf, tag)) { fclose(fp); return -1; }

        fwrite(cbuf, 1, EXT_SZ, fp);
        fwrite(tag, 1, TAG_SZ, fp);
        off += chunk; ext++;
    }
    fclose(fp);
    return 0;
}

/*
 * Read an encrypted file, decrypt it, return malloc'd plaintext.
 * Caller must free(*out).
 */
static int cf_read(const char *name, uint8_t **out, size_t *out_len)
{
    char ep[512]; enc_path(ep, sizeof ep, name);
    uint64_t ino = name_to_ino(name);

    FILE *fp = fopen(ep, "rb");
    if (!fp) return -1;

    struct hdr h;
    if (fread(&h, 1, HDR_SZ, fp) != HDR_SZ) { fclose(fp); return -1; }
    if (le64_get((uint8_t*)&h.magic) != MAGIC) { fclose(fp); return -1; }

    uint8_t fek[KEY_SZ];
    if (unwrap_key(g_master, h.fek_nonce, h.wrapped_fek,
                   h.wrapped_fek + KEY_SZ, fek)) { fclose(fp); return -1; }

    uint64_t fsize = le64_get((uint8_t*)&h.file_size);
    uint8_t *buf = calloc(1, fsize ? fsize : 1);
    if (!buf) { fclose(fp); return -1; }

    size_t off = 0; uint64_t ext = 0;
    while (off < fsize) {
        uint8_t disk[EXT_DISK], pbuf[EXT_SZ], nonce[NONCE_SZ];
        if (fread(disk, 1, EXT_DISK, fp) != EXT_DISK) { free(buf); fclose(fp); return -1; }
        if (derive_nonce(fek, ino, ext, nonce)) { free(buf); fclose(fp); return -1; }
        if (dec_ext(fek, nonce, disk, disk + EXT_SZ, pbuf)) {
            free(buf); fclose(fp); return -1;
        }
        size_t chunk = zmin(EXT_SZ, fsize - off);
        memcpy(buf + off, pbuf, chunk);
        off += chunk; ext++;
    }
    fclose(fp);
    *out = buf; *out_len = fsize;
    return 0;
}

/*
 * Random-access write: write `len` bytes of `data` at `offset` inside
 * an existing encrypted file.  Implements the read-decrypt-modify-
 * reencrypt cycle for each affected extent, exactly as the kernel does.
 * Also patches the plaintext twin.
 */
static int cf_write_at(const char *name, size_t offset,
                       const uint8_t *data, size_t len)
{
    char ep[512], pp[512];
    enc_path(ep, sizeof ep, name);
    pt_path(pp, sizeof pp, name);
    uint64_t ino = name_to_ino(name);

    FILE *fp = fopen(ep, "r+b");
    if (!fp) return -1;

    /* Read header, unwrap FEK */
    struct hdr h;
    if (fread(&h, 1, HDR_SZ, fp) != HDR_SZ) { fclose(fp); return -1; }
    uint8_t fek[KEY_SZ];
    if (unwrap_key(g_master, h.fek_nonce, h.wrapped_fek,
                   h.wrapped_fek + KEY_SZ, fek)) { fclose(fp); return -1; }

    uint64_t fsize = le64_get((uint8_t*)&h.file_size);
    size_t pos = offset;
    const uint8_t *src = data;
    size_t rem = len;

    while (rem > 0) {
        uint64_t ei = pos / EXT_SZ;
        size_t   eo = pos % EXT_SZ;
        size_t   n  = zmin(EXT_SZ - eo, rem);

        /* Read existing extent (if any) and decrypt */
        uint8_t pbuf[EXT_SZ];
        memset(pbuf, 0, EXT_SZ);
        long disk_off = (long)(HDR_SZ + ei * EXT_DISK);
        fseek(fp, disk_off, SEEK_SET);
        uint8_t disk[EXT_DISK];
        if (fread(disk, 1, EXT_DISK, fp) == EXT_DISK) {
            uint8_t nonce[NONCE_SZ];
            derive_nonce(fek, ino, ei, nonce);
            dec_ext(fek, nonce, disk, disk + EXT_SZ, pbuf);
        }

        /* Patch plaintext */
        memcpy(pbuf + eo, src, n);

        /* Re-encrypt */
        uint8_t cbuf[EXT_SZ], tag[TAG_SZ], nonce[NONCE_SZ];
        derive_nonce(fek, ino, ei, nonce);
        enc_ext(fek, nonce, pbuf, cbuf, tag);

        /* Write back */
        fseek(fp, disk_off, SEEK_SET);
        fwrite(cbuf, 1, EXT_SZ, fp);
        fwrite(tag, 1, TAG_SZ, fp);

        pos += n; src += n; rem -= n;
    }

    /* Update size if extended */
    if (offset + len > fsize) {
        le64_put((uint8_t*)&h.file_size, (uint64_t)(offset + len));
        fseek(fp, 0, SEEK_SET);
        fwrite(&h, 1, HDR_SZ, fp);
    }
    fclose(fp);

    /* Patch plaintext twin */
    fp = fopen(pp, "r+b");
    if (!fp) fp = fopen(pp, "wb");
    if (fp) { fseek(fp, (long)offset, SEEK_SET); fwrite(data, 1, len, fp); fclose(fp); }
    return 0;
}

/*
 * Random-access read: read `len` bytes at `offset` from an encrypted
 * file into `buf`.  Decrypts only the needed extents.
 */
static int cf_read_at(const char *name, size_t offset,
                      uint8_t *buf, size_t len)
{
    char ep[512]; enc_path(ep, sizeof ep, name);
    uint64_t ino = name_to_ino(name);

    FILE *fp = fopen(ep, "rb");
    if (!fp) return -1;

    struct hdr h;
    if (fread(&h, 1, HDR_SZ, fp) != HDR_SZ) { fclose(fp); return -1; }
    uint8_t fek[KEY_SZ];
    if (unwrap_key(g_master, h.fek_nonce, h.wrapped_fek,
                   h.wrapped_fek + KEY_SZ, fek)) { fclose(fp); return -1; }

    size_t pos = offset, dst = 0, rem = len;

    while (rem > 0) {
        uint64_t ei = pos / EXT_SZ;
        size_t   eo = pos % EXT_SZ;
        size_t   n  = zmin(EXT_SZ - eo, rem);

        fseek(fp, (long)(HDR_SZ + ei * EXT_DISK), SEEK_SET);
        uint8_t disk[EXT_DISK];
        if (fread(disk, 1, EXT_DISK, fp) != EXT_DISK) { fclose(fp); return -1; }

        uint8_t pbuf[EXT_SZ], nonce[NONCE_SZ];
        derive_nonce(fek, ino, ei, nonce);
        if (dec_ext(fek, nonce, disk, disk + EXT_SZ, pbuf)) { fclose(fp); return -1; }

        memcpy(buf + dst, pbuf + eo, n);
        pos += n; dst += n; rem -= n;
    }
    fclose(fp);
    return 0;
}

/*
 * Append: extend an encrypted file.
 * Handles partial last extent (read-decrypt-modify-reencrypt).
 */
static int cf_append(const char *name, const uint8_t *data, size_t len)
{
    char ep[512]; enc_path(ep, sizeof ep, name);
    uint64_t ino = name_to_ino(name);

    FILE *fp = fopen(ep, "r+b");
    if (!fp) return -1;

    struct hdr h;
    if (fread(&h, 1, HDR_SZ, fp) != HDR_SZ) { fclose(fp); return -1; }
    uint8_t fek[KEY_SZ];
    if (unwrap_key(g_master, h.fek_nonce, h.wrapped_fek,
                   h.wrapped_fek + KEY_SZ, fek)) { fclose(fp); return -1; }

    uint64_t fsize = le64_get((uint8_t*)&h.file_size);
    size_t pos = (size_t)fsize;
    const uint8_t *src = data;
    size_t rem = len;

    while (rem > 0) {
        uint64_t ei = pos / EXT_SZ;
        size_t   eo = pos % EXT_SZ;
        size_t   n  = zmin(EXT_SZ - eo, rem);

        uint8_t pbuf[EXT_SZ];
        memset(pbuf, 0, EXT_SZ);

        /* If appending into a partial last extent, read-decrypt it first */
        if (eo > 0) {
            long disk_off = (long)(HDR_SZ + ei * EXT_DISK);
            fseek(fp, disk_off, SEEK_SET);
            uint8_t disk[EXT_DISK];
            if (fread(disk, 1, EXT_DISK, fp) == EXT_DISK) {
                uint8_t nn[NONCE_SZ];
                derive_nonce(fek, ino, ei, nn);
                dec_ext(fek, nn, disk, disk + EXT_SZ, pbuf);
            }
        }

        memcpy(pbuf + eo, src, n);

        uint8_t cbuf[EXT_SZ], tag[TAG_SZ], nonce[NONCE_SZ];
        derive_nonce(fek, ino, ei, nonce);
        enc_ext(fek, nonce, pbuf, cbuf, tag);

        fseek(fp, (long)(HDR_SZ + ei * EXT_DISK), SEEK_SET);
        fwrite(cbuf, 1, EXT_SZ, fp);
        fwrite(tag, 1, TAG_SZ, fp);

        pos += n; src += n; rem -= n;
    }

    fsize += len;
    le64_put((uint8_t*)&h.file_size, fsize);
    fseek(fp, 0, SEEK_SET);
    fwrite(&h, 1, HDR_SZ, fp);
    fclose(fp);

    /* Patch plaintext twin */
    char pp[512]; pt_path(pp, sizeof pp, name);
    fp = fopen(pp, "ab");
    if (fp) { fwrite(data, 1, len, fp); fclose(fp); }
    return 0;
}

/* ================================================================ */
/*                         T E S T S                                */
/* ================================================================ */

static void banner(const char *s)
{ printf("\n  ─────────────────────────────────────────────────────────\n  %s\n  ─────────────────────────────────────────────────────────\n", s); }

static void show_file(const char *label, const char *path)
{
    struct stat st;
    if (stat(path, &st)) { printf("        %-12s (not found)\n", label); return; }
    FILE *fp = fopen(path, "rb");
    if (!fp) return;
    uint8_t peek[32]; size_t n = fread(peek, 1, sizeof peek, fp); fclose(fp);
    char hex[128]; hex_line(peek, n, hex, sizeof hex);
    printf("        %-12s %6ld bytes   %s\n", label, (long)st.st_size, hex);
}

/* helper: create file and display summary */
static int create_and_show(const char *name, const uint8_t *data, size_t len,
                           uint8_t *fek_out)
{
    if (cf_create(name, data, len, fek_out)) return -1;
    char ep[512], pp[512];
    enc_path(ep, sizeof ep, name); pt_path(pp, sizeof pp, name);
    show_file("Plaintext:", pp);
    show_file("Encrypted:", ep);
    return 0;
}

/* helper: full-file decrypt and verify against plaintext */
static int verify_file(const char *name)
{
    char pp[512]; pt_path(pp, sizeof pp, name);
    FILE *fp = fopen(pp, "rb"); if (!fp) return -1;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    uint8_t *expected = malloc(sz); fread(expected, 1, sz, fp); fclose(fp);

    uint8_t *got = NULL; size_t got_len = 0;
    int rc = cf_read(name, &got, &got_len);
    if (rc || got_len != (size_t)sz || memcmp(expected, got, sz)) {
        free(expected); free(got); return -1;
    }
    free(expected); free(got);
    return 0;
}

/* ── Phase 1: Create files ────────────────────────────────────────── */

static void phase1_create(void)
{
    banner("Phase 1 — Create Files");

    /* T01 Small text */
    {
        const char *txt = "Hello, CryptoFS! This text is encrypted at rest.\n";
        printf("\n  [T01] Small text file (%zu bytes)\n", strlen(txt));
        int ok = (create_and_show("hello.txt", (const uint8_t*)txt, strlen(txt), NULL) == 0);
        CHECK("T01 create small text", ok);
    }

    /* T02 Exact extent boundary */
    {
        uint8_t buf[EXT_SZ]; memset(buf, 0xAA, EXT_SZ);
        printf("\n  [T02] Exact extent boundary (%d bytes)\n", EXT_SZ);
        int ok = (create_and_show("exact_4k.bin", buf, EXT_SZ, NULL) == 0);
        CHECK("T02 create exact-extent file", ok);
    }

    /* T03 Multi-extent */
    {
        size_t sz = 3 * EXT_SZ;  /* 12288 bytes = 3 extents */
        uint8_t *buf = malloc(sz);
        for (size_t i = 0; i < sz; i++) buf[i] = (uint8_t)(i & 0xFF);
        printf("\n  [T03] Multi-extent file (%zu bytes, 3 extents)\n", sz);
        int ok = (create_and_show("multi.bin", buf, sz, NULL) == 0);
        CHECK("T03 create multi-extent file", ok);
        free(buf);
    }

    /* T04 Large file */
    {
        size_t sz = 256 * 1024;  /* 256 KB = 64 extents */
        uint8_t *buf = malloc(sz);
        RAND_bytes(buf, sz);
        printf("\n  [T04] Large file (%zu KB, 64 extents)\n", sz/1024);
        int ok = (create_and_show("large.bin", buf, sz, NULL) == 0);
        CHECK("T04 create large file", ok);
        free(buf);
    }

    /* T05 Binary patterns */
    {
        printf("\n  [T05] Binary pattern files\n");
        uint8_t buf[EXT_SZ];
        const char *names[] = {"pat_zeros.bin","pat_ones.bin","pat_alt.bin","pat_seq.bin"};
        uint8_t fills[] = {0x00, 0xFF, 0xAA, 0};
        int all_ok = 1;
        for (int i = 0; i < 4; i++) {
            if (i == 3) for (int j=0;j<EXT_SZ;j++) buf[j]=(uint8_t)(j&0xFF);
            else memset(buf, fills[i], EXT_SZ);
            if (create_and_show(names[i], buf, EXT_SZ, NULL)) all_ok = 0;
        }
        CHECK("T05 create pattern files", all_ok);
    }

    /* T06 Many small files */
    {
        printf("\n  [T06] Batch: 20 small files\n");
        int all_ok = 1;
        for (int i = 0; i < 20; i++) {
            char fname[64];
            snprintf(fname, sizeof fname, "batch_%02d.txt", i);
            char content[128];
            int n = snprintf(content, sizeof content,
                             "File %d — CryptoFS batch test content #%d\n", i, i);
            if (cf_create(fname, (const uint8_t*)content, n, NULL)) all_ok = 0;
        }
        printf("        Created 20 files in both directories\n");
        CHECK("T06 create 20 small files", all_ok);
    }
}

/* ── Phase 2: Verify all files decrypt correctly ──────────────────── */

static void phase2_verify(void)
{
    banner("Phase 2 — Decrypt & Verify All Files");

    const char *files[] = {
        "hello.txt","exact_4k.bin","multi.bin","large.bin",
        "pat_zeros.bin","pat_ones.bin","pat_alt.bin","pat_seq.bin",
        NULL
    };
    for (int i = 0; files[i]; i++) {
        char label[128];
        snprintf(label, sizeof label, "Verify %-20s", files[i]);
        CHECK(label, verify_file(files[i]) == 0);
    }
    /* Verify batch files */
    int batch_ok = 1;
    for (int i = 0; i < 20; i++) {
        char fname[64];
        snprintf(fname, sizeof fname, "batch_%02d.txt", i);
        if (verify_file(fname)) batch_ok = 0;
    }
    CHECK("Verify all 20 batch files", batch_ok);
}

/* ── Phase 3: Random access ───────────────────────────────────────── */

static void phase3_random_access(void)
{
    banner("Phase 3 — Random Access");

    /* Create a test file: 8 extents (32768 bytes) of zeros */
    size_t sz = 8 * EXT_SZ;
    uint8_t *zeros = calloc(1, sz);
    uint8_t fek[KEY_SZ];
    cf_create("rand_access.bin", zeros, sz, fek);
    free(zeros);

    /* T07 Write at offset 1000 (within extent 0) */
    {
        printf("\n  [T07] Random write at offset 1000 (50 bytes, within extent 0)\n");
        uint8_t patch[50]; memset(patch, 0xDE, 50);
        cf_write_at("rand_access.bin", 1000, patch, 50);

        uint8_t rb[50];
        cf_read_at("rand_access.bin", 1000, rb, 50);
        char hex[128]; hex_line(rb, 50, hex, sizeof hex);
        printf("        Read-back: %s\n", hex);
        CHECK("T07 random write within extent", memcmp(patch, rb, 50) == 0);
    }

    /* T08 Write at offset 4090 (crosses extent 0→1 boundary) */
    {
        printf("\n  [T08] Cross-extent write at offset 4090 (20 bytes, spans extents 0-1)\n");
        uint8_t patch[20];
        for (int i = 0; i < 20; i++) patch[i] = (uint8_t)(0xA0 + i);
        cf_write_at("rand_access.bin", 4090, patch, 20);

        uint8_t rb[20];
        cf_read_at("rand_access.bin", 4090, rb, 20);
        char hex[128]; hex_line(rb, 20, hex, sizeof hex);
        printf("        Read-back: %s\n", hex);
        CHECK("T08 cross-extent write", memcmp(patch, rb, 20) == 0);
    }

    /* T09 Write deep into file (extent 5, offset 22000) */
    {
        printf("\n  [T09] Random write at offset 22000 (100 bytes, extent 5)\n");
        uint8_t patch[100]; RAND_bytes(patch, 100);
        cf_write_at("rand_access.bin", 22000, patch, 100);

        uint8_t rb[100];
        cf_read_at("rand_access.bin", 22000, rb, 100);
        CHECK("T09 deep random write", memcmp(patch, rb, 100) == 0);
    }

    /* T10 Verify untouched regions are still zero */
    {
        printf("\n  [T10] Verify untouched region (offset 2000, 100 bytes) is still zero\n");
        uint8_t rb[100], expected[100];
        memset(expected, 0, 100);
        cf_read_at("rand_access.bin", 2000, rb, 100);
        CHECK("T10 untouched region intact", memcmp(rb, expected, 100) == 0);
    }

    /* T11 Large random-access scatter */
    {
        printf("\n  [T11] Scatter: 50 random writes + reads across 32KB file\n");
        int ok = 1;
        for (int i = 0; i < 50; i++) {
            uint8_t off_bytes[2]; RAND_bytes(off_bytes, 2);
            size_t off = ((size_t)off_bytes[0] << 8 | off_bytes[1]) % (sz - 64);
            uint8_t wr[32]; RAND_bytes(wr, 32);
            cf_write_at("rand_access.bin", off, wr, 32);
            uint8_t rd[32];
            cf_read_at("rand_access.bin", off, rd, 32);
            if (memcmp(wr, rd, 32)) { ok = 0; break; }
        }
        CHECK("T11 scatter 50 random writes+reads", ok);
    }

    /* T12 Full-file decrypt still works after all the random access */
    {
        printf("\n  [T12] Full-file verify after random access\n");
        CHECK("T12 full verify after random ops", verify_file("rand_access.bin") == 0);
    }
}

/* ── Phase 4: Append ──────────────────────────────────────────────── */

static void phase4_append(void)
{
    banner("Phase 4 — Append Operations");

    /* Create initial file */
    const char *init = "Line 1: initial content\n";
    cf_create("append.txt", (const uint8_t*)init, strlen(init), NULL);

    const char *lines[] = {
        "Line 2: first append\n",
        "Line 3: second append\n",
        "Line 4: third append — now past 100 bytes\n",
        "Line 5: keeps going...\n",
    };

    int ok = 1;
    for (int i = 0; i < 4; i++) {
        cf_append("append.txt", (const uint8_t*)lines[i], strlen(lines[i]));
    }

    /* Verify full content */
    uint8_t *dec = NULL; size_t dl = 0;
    if (cf_read("append.txt", &dec, &dl)) ok = 0;
    else {
        /* Build expected */
        char expected[1024]; int pos = 0;
        pos += snprintf(expected+pos, sizeof(expected)-pos, "%s", init);
        for (int i = 0; i < 4; i++)
            pos += snprintf(expected+pos, sizeof(expected)-pos, "%s", lines[i]);
        if (dl != (size_t)pos || memcmp(dec, expected, dl)) ok = 0;
        free(dec);
    }
    CHECK("T13 append 4 times + verify", ok);

    /* T14 Large append crossing extent boundary */
    {
        printf("\n  [T14] Large append: push file past extent boundary\n");
        size_t big = EXT_SZ;  /* 4KB append to push well past first extent */
        uint8_t *buf = malloc(big);
        memset(buf, 'X', big);
        cf_append("append.txt", buf, big);
        free(buf);
        CHECK("T14 large append + verify", verify_file("append.txt") == 0);
    }
}

/* ── Phase 5: Overwrite ───────────────────────────────────────────── */

static void phase5_overwrite(void)
{
    banner("Phase 5 — Overwrite In-Place");

    /* Create 3-extent file with known content */
    size_t sz = 3 * EXT_SZ;
    uint8_t *orig = malloc(sz);
    for (size_t i = 0; i < sz; i++) orig[i] = (uint8_t)(i & 0xFF);
    cf_create("overwrite.bin", orig, sz, NULL);

    /* Overwrite the middle extent (offset 4096, 4096 bytes of 0xBB) */
    uint8_t *patch = malloc(EXT_SZ);
    memset(patch, 0xBB, EXT_SZ);
    cf_write_at("overwrite.bin", EXT_SZ, patch, EXT_SZ);

    /* Build expected: extent 0 original, extent 1 = 0xBB, extent 2 original */
    memcpy(orig + EXT_SZ, patch, EXT_SZ);

    /* Verify */
    uint8_t *dec = NULL; size_t dl = 0;
    int ok = (cf_read("overwrite.bin", &dec, &dl) == 0 &&
              dl == sz && memcmp(orig, dec, sz) == 0);
    CHECK("T15 overwrite middle extent + verify", ok);

    free(orig); free(patch); free(dec);
}

/* ── Phase 6: Tamper detection ─────────────────────────────────────── */

static void phase6_tamper(void)
{
    banner("Phase 6 — Tamper Detection");

    /* Create a file */
    uint8_t data[EXT_SZ]; RAND_bytes(data, EXT_SZ);
    cf_create("tamper.bin", data, EXT_SZ, NULL);

    /* Read the encrypted file, flip a byte in the ciphertext, try to decrypt */
    {
        char ep[512]; enc_path(ep, sizeof ep, "tamper.bin");
        FILE *fp = fopen(ep, "r+b");
        /* flip byte at offset HDR_SZ + 100 (inside ciphertext) */
        fseek(fp, HDR_SZ + 100, SEEK_SET);
        uint8_t b; fread(&b, 1, 1, fp);
        b ^= 0x01;
        fseek(fp, HDR_SZ + 100, SEEK_SET);
        fwrite(&b, 1, 1, fp);
        fclose(fp);
    }

    uint8_t *dec = NULL; size_t dl = 0;
    int tamper_detected = (cf_read("tamper.bin", &dec, &dl) != 0);
    free(dec);
    CHECK("T16 tamper detection: flipped ciphertext bit", tamper_detected);

    /* Restore and flip tag instead */
    cf_create("tamper.bin", data, EXT_SZ, NULL);
    {
        char ep[512]; enc_path(ep, sizeof ep, "tamper.bin");
        FILE *fp = fopen(ep, "r+b");
        /* flip byte in the tag (offset HDR_SZ + EXT_SZ + 5) */
        fseek(fp, HDR_SZ + EXT_SZ + 5, SEEK_SET);
        uint8_t b; fread(&b, 1, 1, fp);
        b ^= 0x01;
        fseek(fp, HDR_SZ + EXT_SZ + 5, SEEK_SET);
        fwrite(&b, 1, 1, fp);
        fclose(fp);
    }

    dec = NULL; dl = 0;
    tamper_detected = (cf_read("tamper.bin", &dec, &dl) != 0);
    free(dec);
    CHECK("T17 tamper detection: flipped auth tag bit", tamper_detected);
}

/* ── Phase 7: Summary ─────────────────────────────────────────────── */

static void phase7_summary(void)
{
    /* File size comparison */
    banner("File Size Comparison (encryption overhead)");
    printf("  %-22s  %10s  %10s  %s\n", "File", "Plaintext", "Encrypted", "Overhead");
    printf("  %-22s  %10s  %10s  %s\n", "────", "─────────", "─────────", "────────");

    const char *files[] = {
        "hello.txt","exact_4k.bin","multi.bin","large.bin",
        "rand_access.bin","append.txt","overwrite.bin", NULL
    };
    for (int i = 0; files[i]; i++) {
        char ep[512], pp[512]; struct stat se, sp;
        enc_path(ep, sizeof ep, files[i]); pt_path(pp, sizeof pp, files[i]);
        if (stat(ep, &se) || stat(pp, &sp)) continue;
        printf("  %-22s  %10ld  %10ld  +%ld bytes\n",
               files[i], (long)sp.st_size, (long)se.st_size,
               (long)(se.st_size - sp.st_size));
    }

    /* Show side-by-side hex for the text file */
    banner("Side-by-Side: hello.txt");
    {
        char pp[512]; pt_path(pp, sizeof pp, "hello.txt");
        printf("  Plaintext (cat hello.txt):\n");
        FILE *fp = fopen(pp, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof line, fp)) printf("    %s", line);
            if (line[strlen(line)-1] != '\n') printf("\n");
            fclose(fp);
        }

        char ep[512]; enc_path(ep, sizeof ep, "hello.txt");
        printf("\n  Encrypted (hexdump hello.txt):\n");
        fp = fopen(ep, "rb");
        if (fp) {
            uint8_t buf[256]; size_t n = fread(buf, 1, sizeof buf, fp); fclose(fp);
            for (size_t off = 0; off < n; off += 16) {
                printf("    %04zx  ", off);
                for (int j = 0; j < 16 && off+j < n; j++)
                    printf("%02x ", buf[off+j]);
                printf("\n");
            }
        }
    }
}

/* ================================================================ */

int main(int argc, char **argv)
{
    g_enc = getenv("ENC_DIR");  if (!g_enc) g_enc = "/data/encrypted";
    g_pt  = getenv("PT_DIR");   if (!g_pt)  g_pt  = "/data/plaintext";

    mkdir(g_enc, 0755); mkdir(g_pt, 0755);

    printf("════════════════════════════════════════════════════════════\n");
    printf("  CryptoFS — Encryption Demo & Proof\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("  Plaintext dir:  %s\n", g_pt);
    printf("  Encrypted dir:  %s\n", g_enc);

    /* Generate master key */
    RAND_bytes(g_master, KEY_SZ);
    {
        char kp[512]; snprintf(kp, sizeof kp, "%s/.master_key", g_enc);
        FILE *fp = fopen(kp, "wb");
        if (fp) { fwrite(g_master, 1, KEY_SZ, fp); fclose(fp); }
    }
    printf("  Master key:     saved to %s/.master_key\n", g_enc);

    phase1_create();
    phase2_verify();
    phase3_random_access();
    phase4_append();
    phase5_overwrite();
    phase6_tamper();
    phase7_summary();

    printf("\n════════════════════════════════════════════════════════════\n");
    printf("  Results:  %d passed,  %d failed\n", g_pass, g_fail);
    printf("════════════════════════════════════════════════════════════\n\n");

    if (g_fail == 0) {
        printf("  ✓  ALL TESTS PASSED\n\n");
        printf("  Inspect from your Mac:\n");
        printf("    cat  <plaintext-dir>/hello.txt\n");
        printf("    hexdump -C <encrypted-dir>/hello.txt | head -20\n");
        printf("    diff <(xxd <plaintext-dir>/multi.bin) "
               "<(xxd <decrypted-from-encrypted>)\n");
        printf("    ls -la <plaintext-dir>/  <encrypted-dir>/\n\n");
    }

    return g_fail > 0 ? 1 : 0;
}
