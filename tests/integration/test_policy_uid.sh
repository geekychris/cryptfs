#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: UID-Based Policy
#
# Tests that authorized UIDs get plaintext and unauthorized get ciphertext/EACCES.
# Requires root to switch UIDs.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0
SKIP=0

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
TEST_DIR="${MOUNT_DIR}/policy_uid_test"

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; (( PASS++ )) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; (( FAIL++ )) || true; }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; (( SKIP++ )) || true; }

cleanup() { rm -rf "${TEST_DIR}" 2>/dev/null || true; }
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: UID Policy"
echo "============================================"
echo ""

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Warning: Running as non-root. Some tests will be skipped."
fi

mkdir -p "${TEST_DIR}"

# Create test data as current user
AUTHORIZED_UID=$(id -u)
TEST_DATA="CryptoFS policy test data: $(date)"
echo "$TEST_DATA" > "${TEST_DIR}/policy_test.txt"

# --- Test 1: Authorized user reads plaintext ---
CONTENT=$(cat "${TEST_DIR}/policy_test.txt")
if [ "$CONTENT" = "$TEST_DATA" ]; then
    log_pass "Authorized user (UID=$AUTHORIZED_UID) reads plaintext"
else
    log_fail "Authorized user cannot read plaintext"
fi

# --- Test 2: Unauthorized user reads ciphertext ---
if [ "$(id -u)" -eq 0 ]; then
    # Create a test user
    UNAUTH_UID=65534  # nobody
    UNAUTH_CONTENT=$(su -s /bin/sh nobody -c "cat '${TEST_DIR}/policy_test.txt' 2>&1" || true)
    if [ "$UNAUTH_CONTENT" != "$TEST_DATA" ]; then
        log_pass "Unauthorized user (UID=$UNAUTH_UID) cannot read plaintext"
    else
        log_fail "Unauthorized user read plaintext!"
    fi
else
    log_skip "Unauthorized user read test (requires root)"
fi

# --- Test 3: Unauthorized user write blocked ---
if [ "$(id -u)" -eq 0 ]; then
    WRITE_RESULT=$(su -s /bin/sh nobody -c "echo 'hack' > '${TEST_DIR}/policy_test.txt'" 2>&1 || true)
    # Check original content is preserved
    CONTENT=$(cat "${TEST_DIR}/policy_test.txt")
    if [ "$CONTENT" = "$TEST_DATA" ]; then
        log_pass "Unauthorized write blocked (original data preserved)"
    else
        log_fail "Unauthorized write succeeded!"
    fi
else
    log_skip "Unauthorized write test (requires root)"
fi

# --- Test 4: Add policy via CLI, verify effect ---
# This would use: cryptofs-admin policy add --dir /path --type uid --value $UID --perm allow
log_skip "Dynamic policy add (requires cryptofs-admin integration)"

echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "============================================"

exit $FAIL
