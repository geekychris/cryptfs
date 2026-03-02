#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: Concurrent Access
#
# Tests multiple processes reading/writing simultaneously.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
PASS=0
FAIL=0

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
TEST_DIR="${MOUNT_DIR}/concurrent_test"
NUM_WORKERS=${NUM_WORKERS:-8}

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; (( PASS++ )) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; (( FAIL++ )) || true; }

cleanup() { rm -rf "${TEST_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: Concurrent Access"
echo "============================================"
echo ""

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted."
    exit 1
fi

mkdir -p "${TEST_DIR}"

# --- Test 1: Concurrent writes to different files ---
echo "--- Concurrent writes to separate files ($NUM_WORKERS workers) ---"
for i in $(seq 1 $NUM_WORKERS); do
    (
        dd if=/dev/urandom of="${TEST_DIR}/worker_${i}.dat" bs=4096 count=100 2>/dev/null
        sha256sum "${TEST_DIR}/worker_${i}.dat" > "${TEST_DIR}/worker_${i}.sum"
    ) &
done
wait

# Verify all files
ALL_OK=true
for i in $(seq 1 $NUM_WORKERS); do
    EXPECTED=$(cat "${TEST_DIR}/worker_${i}.sum" | awk '{print $1}')
    ACTUAL=$(sha256sum "${TEST_DIR}/worker_${i}.dat" | awk '{print $1}')
    if [ "$EXPECTED" != "$ACTUAL" ]; then
        ALL_OK=false
        break
    fi
done

if $ALL_OK; then
    log_pass "Concurrent writes to $NUM_WORKERS separate files"
else
    log_fail "Concurrent write corruption detected"
fi

# --- Test 2: Concurrent reads of same file ---
echo "--- Concurrent reads of same file ---"
dd if=/dev/urandom of="${TEST_DIR}/shared_read.dat" bs=4096 count=256 2>/dev/null
EXPECTED_SUM=$(sha256sum "${TEST_DIR}/shared_read.dat" | awk '{print $1}')

READ_OK=true
for i in $(seq 1 $NUM_WORKERS); do
    (
        SUM=$(sha256sum "${TEST_DIR}/shared_read.dat" | awk '{print $1}')
        echo "$SUM" > "${TEST_DIR}/read_check_${i}.txt"
    ) &
done
wait

for i in $(seq 1 $NUM_WORKERS); do
    ACTUAL=$(cat "${TEST_DIR}/read_check_${i}.txt")
    if [ "$ACTUAL" != "$EXPECTED_SUM" ]; then
        READ_OK=false
        break
    fi
done

if $READ_OK; then
    log_pass "Concurrent reads of same file ($NUM_WORKERS readers)"
else
    log_fail "Concurrent read produced inconsistent data"
fi

# --- Test 3: Mixed read/write to different files ---
echo "--- Mixed concurrent read/write ---"
# Pre-create some files
for i in $(seq 1 4); do
    dd if=/dev/urandom of="${TEST_DIR}/mixed_${i}.dat" bs=4096 count=50 2>/dev/null
done

# Readers and writers simultaneously
for i in $(seq 1 4); do
    (sha256sum "${TEST_DIR}/mixed_${i}.dat" > /dev/null 2>&1) &
done
for i in $(seq 5 8); do
    (dd if=/dev/urandom of="${TEST_DIR}/mixed_${i}.dat" bs=4096 count=50 2>/dev/null) &
done
wait

# Verify newly written files
MIXED_OK=true
for i in $(seq 5 8); do
    if [ ! -f "${TEST_DIR}/mixed_${i}.dat" ]; then
        MIXED_OK=false
        break
    fi
    SIZE=$(stat -c '%s' "${TEST_DIR}/mixed_${i}.dat" 2>/dev/null || stat -f '%z' "${TEST_DIR}/mixed_${i}.dat" 2>/dev/null)
    if [ "$SIZE" -ne 204800 ]; then
        MIXED_OK=false
        break
    fi
done

if $MIXED_OK; then
    log_pass "Mixed concurrent read/write operations"
else
    log_fail "Mixed concurrent operations failed"
fi

# --- Test 4: Rapid create/delete cycle ---
echo "--- Rapid create/delete ---"
RAPID_OK=true
for i in $(seq 1 $NUM_WORKERS); do
    (
        for j in $(seq 1 50); do
            echo "data_${i}_${j}" > "${TEST_DIR}/rapid_${i}_${j}.tmp"
            rm -f "${TEST_DIR}/rapid_${i}_${j}.tmp"
        done
    ) &
done
wait

# Verify all temp files cleaned up
REMAINING=$(find "${TEST_DIR}" -maxdepth 1 -name 'rapid_*.tmp' -type f 2>/dev/null | wc -l)
if [ "$REMAINING" -eq 0 ]; then
    log_pass "Rapid create/delete cycle ($((NUM_WORKERS * 50)) ops)"
else
    log_fail "Rapid create/delete left $REMAINING files"
fi

echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "============================================"

exit $FAIL
