/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libFuzzer harness for the raw AES-256-GCM extent/FEK primitives in
 * tests/crypto_verify/cryptofs_crypto.h (decrypt_extent, encrypt_extent,
 * gcm_wrap, gcm_unwrap).
 *
 * Fuzzer-controlled key/nonce/tag/ciphertext are fed straight into
 * decrypt_extent: it must never crash regardless of whether the GCM tag
 * authenticates. A second pass round-trips encrypt_extent -> decrypt_extent
 * and asserts the plaintext comes back unchanged. A third pass exercises
 * gcm_wrap/gcm_unwrap at lengths below, at, and above CRYPTOFS_KEY_SIZE,
 * since that is the boundary the kernel's FEK wrap/unwrap path relies on.
 *
 * Build: see tests/fuzz/Makefile (clang -fsanitize=fuzzer,address,undefined).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cryptofs_crypto.h"

static size_t carve(const uint8_t *data, size_t size, size_t pos,
                     uint8_t *out, size_t out_len)
{
    size_t avail = pos < size ? size - pos : 0;
    size_t take = avail < out_len ? avail : out_len;

    if (take > 0)
        memcpy(out, data + pos, take);
    if (take < out_len)
        memset(out + take, 0, out_len - take);
    return pos + take;
}

static void check_wrap_unwrap(const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *data, int len)
{
    uint8_t ct[256], tag[CRYPTOFS_TAG_SIZE], pt[256];

    if (len < 0 || (size_t)len > sizeof(ct))
        return;

    if (gcm_wrap(key, nonce, data, len, ct, tag) != 0)
        abort(); /* wrap of well-formed input must never fail */
    if (gcm_unwrap(key, nonce, ct, len, tag, pt) != 0)
        abort(); /* unwrap of our own freshly-wrapped output must succeed */
    if (len > 0 && memcmp(data, pt, (size_t)len) != 0)
        abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t key[CRYPTOFS_KEY_SIZE];
    uint8_t nonce[CRYPTOFS_NONCE_SIZE];
    uint8_t tag[CRYPTOFS_TAG_SIZE];
    uint8_t ciphertext[CRYPTOFS_EXTENT_SIZE];
    uint8_t plaintext[CRYPTOFS_EXTENT_SIZE];
    size_t pos = 0;

    pos = carve(data, size, pos, key, sizeof(key));
    pos = carve(data, size, pos, nonce, sizeof(nonce));
    pos = carve(data, size, pos, tag, sizeof(tag));
    pos = carve(data, size, pos, ciphertext, sizeof(ciphertext));

    /* Fully adversarial decrypt: must return cleanly (0 or -1), never crash. */
    decrypt_extent(key, nonce, ciphertext, tag, plaintext);

    /* Round-trip: encrypt the fuzzer's "ciphertext" bytes as plaintext, then
     * decrypt what we just produced. Must always succeed and match. */
    {
        uint8_t ct2[CRYPTOFS_EXTENT_SIZE];
        uint8_t tag2[CRYPTOFS_TAG_SIZE];
        uint8_t dec2[CRYPTOFS_EXTENT_SIZE];

        if (encrypt_extent(key, nonce, ciphertext, ct2, tag2) != 0)
            abort(); /* encrypt of well-formed input must never fail */
        if (decrypt_extent(key, nonce, ct2, tag2, dec2) != 0)
            abort();
        if (memcmp(ciphertext, dec2, CRYPTOFS_EXTENT_SIZE) != 0)
            abort();
    }

    /* gcm_wrap/gcm_unwrap across lengths spanning below/at/above
     * CRYPTOFS_KEY_SIZE: the FEK wrap path always uses CRYPTOFS_KEY_SIZE,
     * but the primitive itself must behave at any length. */
    {
        uint8_t remaining[256];

        pos = carve(data, size, pos, remaining, sizeof(remaining));

        check_wrap_unwrap(key, nonce, remaining, CRYPTOFS_KEY_SIZE - 1);
        check_wrap_unwrap(key, nonce, remaining, CRYPTOFS_KEY_SIZE);
        check_wrap_unwrap(key, nonce, remaining, CRYPTOFS_KEY_SIZE + 1);

        if (size > pos) {
            int fuzzed_len = (int)(data[pos % size] % (sizeof(remaining) + 1));
            check_wrap_unwrap(key, nonce, remaining, fuzzed_len);
        }
    }

    return 0;
}
