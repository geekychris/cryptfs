/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libFuzzer harness for cryptofs_parse_and_decrypt_file() in
 * tests/crypto_verify/cryptofs_crypto.h, which mirrors the kernel VFS read
 * path's header-parse -> FEK-unwrap -> extent-count-from-file_size ->
 * per-extent-decrypt sequence (kernel/file.c cryptofs_read_iter,
 * kernel/inode.c num_extents computation).
 *
 * The whole fuzzer input is treated as an adversarial lower-file byte
 * buffer. A random 128-byte prefix will almost never pass the GCM auth tag
 * on the wrapped FEK, so without a seed corpus mutation could never get
 * past the header -- see tests/fuzz/corpus/fuzz_parse_file/ and
 * tests/fuzz/corpus/gen_seeds.c, which plant a validly-wrapped FEK under
 * FIXED_MASTER_KEY so coverage-guided mutation reaches the file_size /
 * extent-count arithmetic instead of dying at the auth check every time.
 *
 * FIXED_MASTER_KEY is a harness-only constant with no relation to any real
 * key: cryptofs_parse_and_decrypt_file() takes the master key as a plain
 * argument (unlike the kernel, which resolves it from an in-kernel key
 * table), so the harness must supply one.
 *
 * Build: see tests/fuzz/Makefile (clang -fsanitize=fuzzer,address,undefined).
 */

#include <stdint.h>
#include <stdlib.h>

#include "cryptofs_crypto.h"

static const uint8_t FIXED_MASTER_KEY[CRYPTOFS_KEY_SIZE] = { 0 };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;

    cryptofs_parse_and_decrypt_file(data, size, FIXED_MASTER_KEY,
                                     &plaintext, &plaintext_len);
    free(plaintext);

    return 0;
}
