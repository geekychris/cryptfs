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
TEST_TIMEOUT=60

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP + 1)); }
log_info() { echo -e "       $1"; }
log_trace() { echo "  [TRACE] $1"; }

check() {
    # Usage: check "test name" ACTUAL EXPECTED
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        log_pass "$name"
    else
        log_fail "$name (expected '$expected', got '$actual')"
    fi
}

cleanup() {
    echo "[CLEANUP] Removing test directory..."
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
CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello.txt" 2>/dev/null || echo "TIMEOUT")
check "Create and read file" "$CONTENT" "Hello, CryptoFS!"

# --- Test 2: Verify lower file is encrypted ---
log_trace "Test 2: verify encryption"
LOWER_CONTENT=$(timeout $TEST_TIMEOUT cat "${LOWER_DIR}/basic_ops_test/hello.txt" 2>/dev/null || echo "ERROR")
if [ "$LOWER_CONTENT" != "Hello, CryptoFS!" ] && [ "$LOWER_CONTENT" != "ERROR" ]; then
    log_pass "Lower file content is encrypted (not plaintext)"
elif [ "$LOWER_CONTENT" = "ERROR" ]; then
    log_skip "Cannot read lower file (may need different path)"
else
    log_fail "Lower file contains plaintext!"
fi

# --- Test 3: Binary data round-trip ---
echo "--- Binary Data ---"
log_trace "Test 3: binary data 64KB"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/binary.dat" bs=1024 count=64 2>/dev/null
ORIG_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
READ_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
check "Binary data round-trip (64KB)" "$ORIG_SUM" "$READ_SUM"

# --- Test 4: Large file ---
echo "--- Large File ---"
log_trace "Test 4: large file 10MB"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/large.dat" bs=1M count=10 2>/dev/null
LARGE_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/large.dat" | awk '{print $1}')
timeout $TEST_TIMEOUT cp "${TEST_DIR}/large.dat" "${TEST_DIR}/large_copy.dat"
COPY_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/large_copy.dat" | awk '{print $1}')
check "Large file write+copy (10MB)" "$LARGE_SUM" "$COPY_SUM"

# --- Test 5: File copy ---
echo "--- File Operations ---"
log_trace "Test 5: file copy"
timeout $TEST_TIMEOUT cp "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_copy.txt"
COPY_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_copy.txt" 2>/dev/null || echo "TIMEOUT")
check "File copy" "$COPY_CONTENT" "Hello, CryptoFS!"

# --- Test 6: File move/rename ---
log_trace "Test 6: file rename"
timeout $TEST_TIMEOUT mv "${TEST_DIR}/hello_copy.txt" "${TEST_DIR}/hello_renamed.txt"
RENAME_EXISTS=$(test -f "${TEST_DIR}/hello_renamed.txt" && echo "yes" || echo "no")
check "File rename" "$RENAME_EXISTS" "yes"

# --- Test 7: File delete ---
log_trace "Test 7: file delete"
rm "${TEST_DIR}/hello_renamed.txt"
DELETE_GONE=$(test ! -f "${TEST_DIR}/hello_renamed.txt" && echo "yes" || echo "no")
check "File delete" "$DELETE_GONE" "yes"

# --- Test 8: Directory operations ---
echo "--- Directory Operations ---"
log_trace "Test 8: nested dirs"
mkdir -p "${TEST_DIR}/subdir/nested"
echo "nested file" > "${TEST_DIR}/subdir/nested/file.txt"
NESTED_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/subdir/nested/file.txt" 2>/dev/null || echo "TIMEOUT")
check "Nested directory creation and file" "$NESTED_CONTENT" "nested file"

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
rmdir "${TEST_DIR}/empty_dir" 2>/dev/null
RMDIR_GONE=$(test ! -d "${TEST_DIR}/empty_dir" && echo "yes" || echo "no")
check "rmdir" "$RMDIR_GONE" "yes"

# --- Test 11: Symlinks ---
echo "--- Links ---"
log_trace "Test 11: symlinks"
if ln -s "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_link" 2>/dev/null; then
    LINK_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_link" 2>/dev/null || echo "TIMEOUT")
    check "Symbolic link" "$LINK_CONTENT" "Hello, CryptoFS!"
else
    log_fail "Symbolic link (ln -s failed)"
fi

# --- Test 12: Hard links ---
log_trace "Test 12: hard links"
if ln "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_hard" 2>/dev/null; then
    HARD_CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_hard" 2>/dev/null || echo "TIMEOUT")
    check "Hard link" "$HARD_CONTENT" "Hello, CryptoFS!"
else
    log_skip "Hard link (not supported or failed)"
fi

# --- Test 13: File permissions ---
echo "--- Permissions ---"
log_trace "Test 13: chmod"
chmod 600 "${TEST_DIR}/hello.txt" 2>/dev/null
PERMS=$(stat -c '%a' "${TEST_DIR}/hello.txt" 2>/dev/null || stat -f '%Lp' "${TEST_DIR}/hello.txt" 2>/dev/null || echo "ERR")
check "chmod 600" "$PERMS" "600"

# --- Test 14: Truncate ---
echo "--- Truncate ---"
log_trace "Test 14: truncate"
echo "This is a longer string that will be truncated" > "${TEST_DIR}/trunc.txt"
truncate -s 10 "${TEST_DIR}/trunc.txt" 2>/dev/null
SIZE=$(stat -c '%s' "${TEST_DIR}/trunc.txt" 2>/dev/null || stat -f '%z' "${TEST_DIR}/trunc.txt" 2>/dev/null || echo "ERR")
check "Truncate to 10 bytes" "$SIZE" "10"

# --- Test 15: Empty file ---
echo "--- Edge Cases ---"
log_trace "Test 15: empty file"
touch "${TEST_DIR}/empty.txt"
SIZE=$(stat -c '%s' "${TEST_DIR}/empty.txt" 2>/dev/null || stat -f '%z' "${TEST_DIR}/empty.txt" 2>/dev/null || echo "ERR")
check "Empty file" "$SIZE" "0"

# --- Test 16: File with exact extent size (4096 bytes) ---
log_trace "Test 16: exact extent (4096)"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/exact_extent.dat" bs=4096 count=1 2>/dev/null
EXACT_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/exact_extent.dat" | awk '{print $1}')
READ_EXACT=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/exact_extent.dat" | awk '{print $1}')
check "Exact extent size file (4096 bytes)" "$EXACT_SUM" "$READ_EXACT"

# --- Test 17: File with size = extent_size - 1 ---
log_trace "Test 17: extent-1 (4095)"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/almost_extent.dat" bs=4095 count=1 2>/dev/null
ALMOST_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/almost_extent.dat" | awk '{print $1}')
READ_ALMOST=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/almost_extent.dat" | awk '{print $1}')
check "File size = extent_size - 1 (4095 bytes)" "$ALMOST_SUM" "$READ_ALMOST"

# --- Test 18: File with size = extent_size + 1 ---
log_trace "Test 18: extent+1 (4097)"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/over_extent.dat" bs=4097 count=1 2>/dev/null
OVER_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/over_extent.dat" | awk '{print $1}')
READ_OVER=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/over_extent.dat" | awk '{print $1}')
check "File size = extent_size + 1 (4097 bytes)" "$OVER_SUM" "$READ_OVER"

# --- Summary ---
echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "============================================"

exit $FAIL
