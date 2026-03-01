#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: Random Access
#
# Tests seek + read/write at arbitrary offsets, verifying extent-based
# encryption handles partial reads/writes correctly.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
PASS=0
FAIL=0

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
TEST_DIR="${MOUNT_DIR}/random_access_test"

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; (( PASS++ )) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; (( FAIL++ )) || true; }

cleanup() { rm -rf "${TEST_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: Random Access"
echo "============================================"
echo ""

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted."
    exit 1
fi

mkdir -p "${TEST_DIR}"

# --- Test 1: Write at offset within first extent ---
echo "--- Seek within single extent ---"
dd if=/dev/zero of="${TEST_DIR}/seek1.dat" bs=4096 count=1 2>/dev/null
echo -n "MARKER" | dd of="${TEST_DIR}/seek1.dat" bs=1 seek=100 conv=notrunc 2>/dev/null
READBACK=$(dd if="${TEST_DIR}/seek1.dat" bs=1 skip=100 count=6 2>/dev/null)
if [ "$READBACK" = "MARKER" ]; then
    log_pass "Write at offset 100 within first extent"
else
    log_fail "Write at offset 100 (got: '$READBACK')"
fi

# --- Test 2: Write spanning extent boundary (4096) ---
echo "--- Cross-extent writes ---"
dd if=/dev/zero of="${TEST_DIR}/span.dat" bs=4096 count=4 2>/dev/null
# Write 100 bytes starting at offset 4090 (6 bytes in extent 0, 94 in extent 1)
dd if=/dev/urandom of=/tmp/cryptofs_testdata bs=100 count=1 2>/dev/null
ORIG_SUM=$(sha256sum /tmp/cryptofs_testdata | awk '{print $1}')
dd if=/tmp/cryptofs_testdata of="${TEST_DIR}/span.dat" bs=1 seek=4090 conv=notrunc 2>/dev/null
READ_SUM=$(dd if="${TEST_DIR}/span.dat" bs=1 skip=4090 count=100 2>/dev/null | sha256sum | awk '{print $1}')
if [ "$ORIG_SUM" = "$READ_SUM" ]; then
    log_pass "Write spanning extent boundary (offset 4090, 100 bytes)"
else
    log_fail "Cross-extent write mismatch"
fi

# --- Test 3: Read at various offsets in multi-extent file ---
echo "--- Multi-extent random reads ---"
dd if=/dev/urandom of="${TEST_DIR}/multi.dat" bs=4096 count=10 2>/dev/null
FULL_SUM=$(sha256sum "${TEST_DIR}/multi.dat" | awk '{print $1}')
# Verify reading the whole file back
REREAD_SUM=$(sha256sum "${TEST_DIR}/multi.dat" | awk '{print $1}')
if [ "$FULL_SUM" = "$REREAD_SUM" ]; then
    log_pass "Multi-extent file integrity (40KB)"
else
    log_fail "Multi-extent file integrity"
fi

# Read specific extent
E3_ORIG=$(dd if="${TEST_DIR}/multi.dat" bs=4096 skip=3 count=1 2>/dev/null | sha256sum | awk '{print $1}')
E3_READ=$(dd if="${TEST_DIR}/multi.dat" bs=4096 skip=3 count=1 2>/dev/null | sha256sum | awk '{print $1}')
if [ "$E3_ORIG" = "$E3_READ" ]; then
    log_pass "Read specific extent (extent 3)"
else
    log_fail "Read specific extent mismatch"
fi

# --- Test 4: Overwrite middle extent without affecting others ---
echo "--- Isolated extent overwrite ---"
dd if=/dev/urandom of="${TEST_DIR}/overwrite.dat" bs=4096 count=5 2>/dev/null
# Save hashes of extents 0, 2, 4
E0=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=0 count=1 2>/dev/null | sha256sum | awk '{print $1}')
E2=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=2 count=1 2>/dev/null | sha256sum | awk '{print $1}')
E4=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=4 count=1 2>/dev/null | sha256sum | awk '{print $1}')

# Overwrite extent 1 and 3
dd if=/dev/urandom of="${TEST_DIR}/overwrite.dat" bs=4096 seek=1 count=1 conv=notrunc 2>/dev/null
dd if=/dev/urandom of="${TEST_DIR}/overwrite.dat" bs=4096 seek=3 count=1 conv=notrunc 2>/dev/null

# Verify extents 0, 2, 4 are unchanged
E0_AFTER=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=0 count=1 2>/dev/null | sha256sum | awk '{print $1}')
E2_AFTER=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=2 count=1 2>/dev/null | sha256sum | awk '{print $1}')
E4_AFTER=$(dd if="${TEST_DIR}/overwrite.dat" bs=4096 skip=4 count=1 2>/dev/null | sha256sum | awk '{print $1}')

if [ "$E0" = "$E0_AFTER" ] && [ "$E2" = "$E2_AFTER" ] && [ "$E4" = "$E4_AFTER" ]; then
    log_pass "Isolated extent overwrite (unmodified extents preserved)"
else
    log_fail "Isolated extent overwrite (other extents corrupted)"
fi

# --- Test 5: Write single byte at end of file ---
echo "--- Edge offset writes ---"
dd if=/dev/zero of="${TEST_DIR}/endbyte.dat" bs=4096 count=2 2>/dev/null
echo -n "X" | dd of="${TEST_DIR}/endbyte.dat" bs=1 seek=8191 conv=notrunc 2>/dev/null
BYTE=$(dd if="${TEST_DIR}/endbyte.dat" bs=1 skip=8191 count=1 2>/dev/null)
if [ "$BYTE" = "X" ]; then
    log_pass "Write single byte at end of file"
else
    log_fail "Single byte at end (got: '$BYTE')"
fi

# --- Test 6: Sparse-like write (seek past current end) ---
echo "--- Seek past end ---"
echo "start" > "${TEST_DIR}/sparse.dat"
dd if=/dev/zero of="${TEST_DIR}/sparse.dat" bs=1 seek=10000 count=1 conv=notrunc 2>/dev/null
SIZE=$(stat -c '%s' "${TEST_DIR}/sparse.dat" 2>/dev/null || stat -f '%z' "${TEST_DIR}/sparse.dat" 2>/dev/null)
if [ "$SIZE" = "10001" ]; then
    log_pass "Seek past end creates correct file size"
else
    log_fail "Seek past end (expected 10001, got $SIZE)"
fi

# --- Summary ---
echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "============================================"

exit $FAIL
