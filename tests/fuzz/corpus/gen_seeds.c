/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Standalone seed generator for tests/fuzz/corpus/fuzz_parse_file/.
 * Not part of the fuzz build (gcc, not clang; no libFuzzer entry point) --
 * run it once and commit its output.
 *
 * cryptofs_parse_and_decrypt_file() GCM-authenticates the wrapped FEK, so a
 * purely random 128-byte header will essentially never pass that check and
 * libFuzzer's mutations would never reach the file_size / extent-count
 * arithmetic this harness actually targets. These seeds plant a
 * validly-wrapped FEK under the fuzz harness's FIXED_MASTER_KEY (see
 * fuzz_parse_file.c) so mutation starts from a file that already clears
 * the auth check.
 *
 * Build: gcc -O2 -std=c11 -I../../crypto_verify gen_seeds.c -o gen_seeds -lssl -lcrypto
 * Run:   ./gen_seeds <output-dir>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "cryptofs_crypto.h"

/* Must match FIXED_MASTER_KEY in fuzz_parse_file.c. */
static const uint8_t FIXED_MASTER_KEY[CRYPTOFS_KEY_SIZE] = { 0 };

static void write_seed(const char *dir, const char *name,
                        const uint8_t *buf, size_t len)
{
    char path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    fwrite(buf, 1, len, f);
    fclose(f);
    printf("wrote %s (%zu bytes)\n", path, len);
}

/* Build a header with a validly-wrapped FEK and the given file_size. */
static void build_header(struct cryptofs_file_header *hdr,
                          const uint8_t *fek, uint64_t file_size)
{
    uint8_t wrap_nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t wrap_tag[CRYPTOFS_TAG_SIZE];
    uint8_t wrapped_fek[CRYPTOFS_KEY_SIZE];

    memset(hdr, 0, sizeof(*hdr));
    put_le64((uint8_t *)&hdr->magic, CRYPTOFS_FILE_MAGIC);
    hdr->version = CRYPTOFS_VERSION;
    hdr->flags = CRYPTOFS_FLAG_ENCRYPTED;
    put_le64((uint8_t *)&hdr->file_size, file_size);

    RAND_bytes(wrap_nonce, sizeof(wrap_nonce));
    if (gcm_wrap(FIXED_MASTER_KEY, wrap_nonce, fek, CRYPTOFS_KEY_SIZE,
                 wrapped_fek, wrap_tag) != 0) {
        fprintf(stderr, "gcm_wrap failed\n");
        exit(1);
    }
    memcpy(hdr->encrypted_fek, wrapped_fek, CRYPTOFS_KEY_SIZE);
    memcpy(hdr->encrypted_fek + CRYPTOFS_KEY_SIZE, wrap_tag, CRYPTOFS_TAG_SIZE);
    memcpy(hdr->fek_nonce, wrap_nonce, CRYPTOFS_NONCE_SIZE);
}

/*
 * A fully-valid, fully-decryptable file for a small file_size: header plus
 * ceil(file_size / EXTENT_SIZE) properly encrypted extents.
 */
static void gen_valid_file(const char *dir, const char *name, uint64_t file_size)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    struct cryptofs_file_header hdr;
    uint64_t num_extents = file_size == 0 ? 0 : (file_size - 1) / CRYPTOFS_EXTENT_SIZE + 1;
    size_t total = CRYPTOFS_HEADER_SIZE + (size_t)num_extents * CRYPTOFS_EXTENT_DISK_SIZE;
    uint8_t *buf = calloc(1, total ? total : 1);

    if (!buf) { perror("calloc"); exit(1); }

    RAND_bytes(fek, sizeof(fek));
    build_header(&hdr, fek, file_size);
    memcpy(buf, &hdr, CRYPTOFS_HEADER_SIZE);

    for (uint64_t i = 0; i < num_extents; i++) {
        uint8_t pt[CRYPTOFS_EXTENT_SIZE], nonce[CRYPTOFS_NONCE_SIZE], tag[CRYPTOFS_TAG_SIZE];
        uint8_t *dst = buf + CRYPTOFS_HEADER_SIZE + (size_t)i * CRYPTOFS_EXTENT_DISK_SIZE;

        RAND_bytes(pt, sizeof(pt));
        /* inode_no fixed at 0: matches cryptofs_parse_and_decrypt_file(),
         * which has no inode context. */
        if (derive_nonce(fek, 0, i, nonce) != 0) {
            fprintf(stderr, "derive_nonce failed\n");
            exit(1);
        }
        if (encrypt_extent(fek, nonce, pt, dst, tag) != 0) {
            fprintf(stderr, "encrypt_extent failed\n");
            exit(1);
        }
        memcpy(dst + CRYPTOFS_EXTENT_SIZE, tag, CRYPTOFS_TAG_SIZE);
    }

    write_seed(dir, name, buf, total);
    free(buf);
}

/*
 * Header-only seed with a large file_size and no extent data: exercises the
 * required_len > buf_len (truncated) and arithmetic-overflow-rejection
 * paths in cryptofs_parse_and_decrypt_file() without needing to materialize
 * an impossibly large file on disk.
 */
static void gen_header_only(const char *dir, const char *name, uint64_t file_size)
{
    uint8_t fek[CRYPTOFS_KEY_SIZE];
    struct cryptofs_file_header hdr;

    RAND_bytes(fek, sizeof(fek));
    build_header(&hdr, fek, file_size);
    write_seed(dir, name, (const uint8_t *)&hdr, CRYPTOFS_HEADER_SIZE);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";

    gen_valid_file(dir, "valid_empty",           0);
    gen_valid_file(dir, "valid_one_byte",        1);
    gen_valid_file(dir, "valid_extent_minus_one", (uint64_t)CRYPTOFS_EXTENT_SIZE - 1);
    gen_valid_file(dir, "valid_extent_exact",     (uint64_t)CRYPTOFS_EXTENT_SIZE);
    gen_valid_file(dir, "valid_extent_plus_one",  (uint64_t)CRYPTOFS_EXTENT_SIZE + 1);
    gen_valid_file(dir, "valid_three_extents",    (uint64_t)CRYPTOFS_EXTENT_SIZE * 3 - 7);

    gen_header_only(dir, "header_only_size_uint32max", 0xFFFFFFFFULL);
    gen_header_only(dir, "header_only_size_uint64max", 0xFFFFFFFFFFFFFFFFULL);

    printf("done\n");
    return 0;
}
