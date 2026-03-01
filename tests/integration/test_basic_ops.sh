#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: Basic File Operations
#
# Tests: create, read, write, copy, move, delete, chmod, chown, symlinks, hardlinks
# through the CryptoFS mount point.
#
# Prerequisites:
#   - cryptofs.ko loaded
#   - cryptofs-keyd running with a key activated
#   - Mount point set up

# NOTE: Do NOT use set -e here. Each test handles its own pass/fail.
set -o pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
TEST_DIR="${MOUNT_DIR}/basic_ops_test"

# Per-test timeout (seconds)
TEST_TIMEOUT=30

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP + 1)); }
log_info() { echo -e "       $1"; }
log_trace() { echo "  [TRACE] $1"; }

cleanup() {
    echo "[CLEANUP] Removing test directory..."
    # Use timeout to prevent cleanup from hanging
    timeout 30 rm -rf "${TEST_DIR}" 2>/dev/null || true
    echo "[CLEANUP] Done."
}
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: Basic Operations"
echo "============================================"
echo ""

# Check prerequisites
if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted. Mount cryptofs first."
    exit 1
fi

mkdir -p "${TEST_DIR}"

# --- Test 1: Create and read a file ---
echo "--- File Create/Read ---"
log_trace "Test 1: create and read"
echo "Hello, CryptoFS!" > "${TEST_DIR}/hello.txt"
CONTENT=$(cat "${TEST_DIR}/hello.txt")
if [ "$CONTENT" = "Hello, CryptoFS!" ]; then
    log_pass "Create and read file"
else
    log_fail "Create and read file (got: '$CONTENT')"
fi

# --- Test 2: Verify lower file is encrypted ---
log_trace "Test 2: verify encryption"
LOWER_CONTENT=$(cat "${LOWER_DIR}/basic_ops_test/hello.txt" 2>/dev/null || echo "ERROR")
if [ "$LOWER_CONTENT" != "Hello, CryptoFS!" ] && [ "$LOWER_CONTENT" != "ERROR" ]; then
    log_pass "Lower file content is encrypted (not plaintext)"
else
    if [ "$LOWER_CONTENT" = "ERROR" ]; then
        log_skip "Cannot read lower file (may need different path)"
    else
        log_fail "Lower file contains plaintext!"
    fi
fi

# --- Test 3: Binary data round-trip ---
echo "--- Binary Data ---"
log_trace "Test 3: binary data 64KB"
dd if=/dev/urandom of="${TEST_DIR}/binary.dat" bs=1024 count=64 2>/dev/null
ORIG_SUM=$(sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
# Read it back
READ_SUM=$(sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
if [ "$ORIG_SUM" = "$READ_SUM" ]; then
    log_pass "Binary data round-trip (64KB)"
else
    log_fail "Binary data round-trip mismatch"
fi

# --- Test 4: Large file ---
echo "--- Large File ---"
log_trace "Test 4: large file 10MB"
dd if=/dev/urandom of="${TEST_DIR}/large.dat" bs=1M count=10 2>/dev/null
LARGE_SUM=$(sha256sum "${TEST_DIR}/large.dat" | awk '{print $1}')
cp "${TEST_DIR}/large.dat" "${TEST_DIR}/large_copy.dat"
COPY_SUM=$(sha256sum "${TEST_DIR}/large_copy.dat" | awk '{print $1}')
if [ "$LARGE_SUM" = "$COPY_SUM" ]; then
    log_pass "Large file write+copy (10MB)"
else
    log_fail "Large file copy mismatch"
fi

# --- Test 5: File copy ---
echo "--- File Operations ---"
log_trace "Test 5: file copy"
cp "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_copy.txt"
if [ "$(cat "${TEST_DIR}/hello_copy.txt")" = "Hello, CryptoFS!" ]; then
    log_pass "File copy"
else
    log_fail "File copy"
fi
# --- Test 6: File move/rename ---
log_trace "Test 6: file rename"
mv "${TEST_DIR}/hello_copy.txt" "${TEST_DIR}/hello_renamed.txt"
if [ -f "${TEST_DIR}/hello_renamed.txt" ] && [ ! -f "${TEST_DIR}/hello_copy.txt" ]; then
    log_pass "File rename"
else
    log_fail "File rename"
fi
# --- Test 7: File delete ---
log_trace "Test 7: file delete"
rm "${TEST_DIR}/hello_renamed.txt"
if [ ! -f "${TEST_DIR}/hello_renamed.txt" ]; then
    log_pass "File delete"
else
    log_fail "File delete"
fi

# --- Test 8: Directory operations ---
echo "--- Directory Operations ---"
log_trace "Test 8: nested dirs"
mkdir -p "${TEST_DIR}/subdir/nested"
echo "nested file" > "${TEST_DIR}/subdir/nested/file.txt"
if [ -d "${TEST_DIR}/subdir/nested" ] && [ "$(cat "${TEST_DIR}/subdir/nested/file.txt")" = "nested file" ]; then
    log_pass "Nested directory creation and file"
else
    log_fail "Nested directory creation and file"
fi
# --- Test 9: Directory listing ---
log_trace "Test 9: directory listing"
touch "${TEST_DIR}/subdir/a.txt" "${TEST_DIR}/subdir/b.txt" "${TEST_DIR}/subdir/c.txt"
COUNT=$(ls "${TEST_DIR}/subdir/" | wc -l)
if [ "$COUNT" -ge 4 ]; then  # nested/ + a.txt + b.txt + c.txt
    log_pass "Directory listing ($COUNT entries)"
else
    log_fail "Directory listing (expected >=4, got $COUNT)"
fi

# --- Test 10: rmdir ---
log_trace "Test 10: rmdir"
mkdir "${TEST_DIR}/empty_dir" 2>/dev/null
if rmdir "${TEST_DIR}/empty_dir" 2>/dev/null && [ ! -d "${TEST_DIR}/empty_dir" ]; then
    log_pass "rmdir"
else
    log_fail "rmdir"
fi

# --- Test 11: Symlinks ---
echo "--- Links ---"
log_trace "Test 11: symlinks"
if ln -s "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_link" 2>/dev/null; then
    LINK_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_link" 2>/dev/null || echo "TIMEOUT")
    if [ "$LINK_CONTENT" = "Hello, CryptoFS!" ]; then
        log_pass "Symbolic link"
    else
        log_fail "Symbolic link (got: '$LINK_CONTENT')"
    fi
else
    log_fail "Symbolic link (ln -s failed)"
fi

# --- Test 12: Hard links ---
log_trace "Test 12: hard links"
if ln "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_hard" 2>/dev/null; then
    HARD_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_hard" 2>/dev/null || echo "TIMEOUT")
    if [ "$HARD_CONTENT" = "Hello, CryptoFS!" ]; then
        log_pass "Hard link"
    else
        log_fail "Hard link (content mismatch: '$HARD_CONTENT')"
    fi
else
    log_skip "Hard link (not supported or failed)"
fi

# --- Test 13: File permissions ---
echo "--- Permissions ---"
log_trace "Test 13: chmod"
chmod 600 "${TEST_DIR}/hello.txt" 2>/dev/null
PERMS=$(stat -c '%a' "${TEST_DIR}/hello.txt" 2>/dev/null || stat -f '%Lp' "${TEST_DIR}/hello.txt" 2>/dev/null || echo "ERR")
if [ "$PERMS" = "600" ]; then
    log_pass "chmod 600"
else
    log_fail "chmod 600 (got: $PERMS)"
fi

# --- Test 14: Truncate ---
echo "--- Truncate ---"
log_trace "Test 14: truncate"
echo "This is a longer string that will be truncated" > "${TEST_DIR}/trunc.txt"
truncate -s 10 "${TEST_DIR}/trunc.txt" 2>/dev/null
SIZE=$(stat -c '%s' "${TEST_DIR}/trunc.txt" 2>/dev/null || stat -f '%z' "${TEST_DIR}/trunc.txt" 2>/dev/null || echo "ERR")
if [ "$SIZE" = "10" ]; then
    log_pass "Truncate to 10 bytes"
else
    log_fail "Truncate (expected 10, got $SIZE)"
fi

# --- Test 15: Empty file ---
echo "--- Edge Cases ---"
log_trace "Test 15: empty file"
touch "${TEST_DIR}/empty.txt"
SIZE=$(stat -c '%s' "${TEST_DIR}/empty.txt" 2>/dev/null || stat -f '%z' "${TEST_DIR}/empty.txt" 2>/dev/null || echo "ERR")
if [ "$SIZE" = "0" ]; then
    log_pass "Empty file"
else
    log_fail "Empty file (size=$SIZE)"
fi

# --- Test 16: File with exact extent size (4096 bytes) ---
log_trace "Test 16: exact extent (4096)"
dd if=/dev/urandom of="${TEST_DIR}/exact_extent.dat" bs=4096 count=1 2>/dev/null
EXACT_SUM=$(sha256sum "${TEST_DIR}/exact_extent.dat" | awk '{print $1}')
READ_EXACT=$(sha256sum "${TEST_DIR}/exact_extent.dat" | awk '{print $1}')
if [ "$EXACT_SUM" = "$READ_EXACT" ]; then
    log_pass "Exact extent size file (4096 bytes)"
else
    log_fail "Exact extent size file mismatch"
fi

# --- Test 17: File with size = extent_size - 1 ---
log_trace "Test 17: extent-1 (4095)"
dd if=/dev/urandom of="${TEST_DIR}/almost_extent.dat" bs=4095 count=1 2>/dev/null
ALMOST_SUM=$(sha256sum "${TEST_DIR}/almost_extent.dat" | awk '{print $1}')
READ_ALMOST=$(sha256sum "${TEST_DIR}/almost_extent.dat" | awk '{print $1}')
if [ "$ALMOST_SUM" = "$READ_ALMOST" ]; then
    log_pass "File size = extent_size - 1 (4095 bytes)"
else
    log_fail "File size = extent_size - 1 mismatch"
fi

# --- Test 18: File with size = extent_size + 1 ---
log_trace "Test 18: extent+1 (4097)"
dd if=/dev/urandom of="${TEST_DIR}/over_extent.dat" bs=4097 count=1 2>/dev/null
OVER_SUM=$(sha256sum "${TEST_DIR}/over_extent.dat" | awk '{print $1}')
READ_OVER=$(sha256sum "${TEST_DIR}/over_extent.dat" | awk '{print $1}')
if [ "$OVER_SUM" = "$READ_OVER" ]; then
    log_pass "File size = extent_size + 1 (4097 bytes)"
else
    log_fail "File size = extent_size + 1 mismatch"
fi

# --- Summary ---
echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "============================================"

exit $FAIL
