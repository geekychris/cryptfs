#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: Append Operations

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
PASS=0
FAIL=0

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
TEST_DIR="${MOUNT_DIR}/append_test"

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; (( PASS++ )) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; (( FAIL++ )) || true; }

cleanup() { rm -rf "${TEST_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: Append"
echo "============================================"
echo ""

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted."
    exit 1
fi

mkdir -p "${TEST_DIR}"

# --- Test 1: Simple text append ---
echo "line1" > "${TEST_DIR}/append.txt"
echo "line2" >> "${TEST_DIR}/append.txt"
echo "line3" >> "${TEST_DIR}/append.txt"
LINES=$(wc -l < "${TEST_DIR}/append.txt")
if [ "$LINES" = "3" ]; then
    log_pass "Simple text append (3 lines)"
else
    log_fail "Simple text append (expected 3 lines, got $LINES)"
fi

# --- Test 2: Append crossing extent boundary ---
# Create file just under 4096
dd if=/dev/zero of="${TEST_DIR}/cross.dat" bs=4090 count=1 2>/dev/null
PRE_SUM=$(sha256sum "${TEST_DIR}/cross.dat" | awk '{print $1}')
# Append 100 bytes (crosses into extent 1)
dd if=/dev/urandom of=/tmp/cryptofs_append_data bs=100 count=1 2>/dev/null
cat /tmp/cryptofs_append_data >> "${TEST_DIR}/cross.dat"
SIZE=$(stat -c '%s' "${TEST_DIR}/cross.dat" 2>/dev/null || stat -f '%z' "${TEST_DIR}/cross.dat" 2>/dev/null)
if [ "$SIZE" = "4190" ]; then
    log_pass "Append crossing extent boundary (4090 + 100 = 4190)"
else
    log_fail "Append crossing extent (expected 4190, got $SIZE)"
fi

# --- Test 3: Many small appends ---
> "${TEST_DIR}/many.dat"
for i in $(seq 1 100); do
    echo "append_$i" >> "${TEST_DIR}/many.dat"
done
COUNT=$(wc -l < "${TEST_DIR}/many.dat")
if [ "$COUNT" = "100" ]; then
    log_pass "100 small appends"
else
    log_fail "100 appends (expected 100 lines, got $COUNT)"
fi

# --- Test 4: Large append ---
dd if=/dev/urandom of="${TEST_DIR}/large_base.dat" bs=1M count=1 2>/dev/null
BASE_SUM=$(sha256sum "${TEST_DIR}/large_base.dat" | awk '{print $1}')
dd if=/dev/urandom of=/tmp/cryptofs_large_append bs=1M count=1 2>/dev/null
cat /tmp/cryptofs_large_append >> "${TEST_DIR}/large_base.dat"
SIZE=$(stat -c '%s' "${TEST_DIR}/large_base.dat" 2>/dev/null || stat -f '%z' "${TEST_DIR}/large_base.dat" 2>/dev/null)
if [ "$SIZE" = "2097152" ]; then
    log_pass "Large append (1MB + 1MB)"
else
    log_fail "Large append (expected 2097152, got $SIZE)"
fi

# --- Test 5: Verify original data intact after append ---
HEAD_SUM=$(dd if="${TEST_DIR}/large_base.dat" bs=1M count=1 2>/dev/null | sha256sum | awk '{print $1}')
if [ "$HEAD_SUM" = "$BASE_SUM" ]; then
    log_pass "Original data preserved after append"
else
    log_fail "Original data corrupted after append"
fi

echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "============================================"

exit $FAIL
