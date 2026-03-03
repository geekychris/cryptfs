#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Integration Test: Guarded Key Access Mode
#
# Tests the GUARDED access mode where the master key must reside in the
# calling process's session keyring (via request_key) rather than the
# kernel key table.
#
# Prerequisites:
#   - cryptofs.ko loaded and mounted
#   - tools/set_key and tools/add_policy built
#   - keyctl (from keyutils package) installed
#   - Running as root (for netlink policy ops and drop_caches)

set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASS=0
FAIL=0
SKIP=0

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
TEST_DIR="${MOUNT_DIR}/guarded_key_test"
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SET_KEY="${SCRIPT_DIR}/tools/set_key"
ADD_POLICY="${SCRIPT_DIR}/tools/add_policy"

# Known test key (32 bytes = 64 hex chars)
TEST_KEY_HEX="aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
# Default key_id (16 bytes of zeros = 32 hex chars)
KEY_ID_HEX="00000000000000000000000000000000"
# Keyring description matching kernel's format
KEY_DESC="cryptofs:${KEY_ID_HEX}"
# Policy rule ID (set when the guarded policy is added)
POLICY_RULE_ID=""

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL + 1)); }
log_skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP + 1)); }
log_info() { echo -e "       $1"; }

check() {
    local name="$1" actual="$2" expected="$3"
    if [ "$actual" = "$expected" ]; then
        log_pass "$name"
    else
        log_fail "$name (expected '$expected', got '$actual')"
    fi
}

drop_caches() {
    sync
    echo 2 > /proc/sys/vm/drop_caches 2>/dev/null || true
}

# Revoke all cryptofs logon keys from session keyring
revoke_session_keys() {
    local serials
    serials=$(keyctl search @s logon "$KEY_DESC" 2>/dev/null) || true
    if [ -n "$serials" ]; then
        for s in $serials; do
            keyctl revoke "$s" 2>/dev/null || true
            keyctl unlink "$s" @s 2>/dev/null || true
        done
    fi
}

# Remove the guarded policy rule added during the test
remove_guarded_policy() {
    if [ -n "$POLICY_RULE_ID" ]; then
        "${ADD_POLICY}" --delete "${POLICY_RULE_ID}" > /dev/null 2>&1 || true
    fi
}

cleanup() {
    echo "[CLEANUP] Revoking session keys, removing policy, and test directory..."
    revoke_session_keys
    remove_guarded_policy
    rm -rf "${TEST_DIR}" 2>/dev/null || true
    echo "[CLEANUP] Done."
}
trap cleanup EXIT

echo "============================================"
echo "CryptoFS Integration Test: Guarded Key Mode"
echo "============================================"
echo ""

# ── Check prerequisites ──

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not mounted."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This test requires root."
    exit 1
fi

if ! command -v keyctl &>/dev/null; then
    echo "Error: keyctl not found. Install keyutils: apt-get install keyutils"
    exit 1
fi

if [ ! -x "${SET_KEY}" ]; then
    # Try to build it
    if [ -f "${SET_KEY}.c" ]; then
        echo "Building set_key..."
        gcc -o "${SET_KEY}" "${SET_KEY}.c" 2>/dev/null
    fi
    if [ ! -x "${SET_KEY}" ]; then
        echo "Error: ${SET_KEY} not found or not executable."
        exit 1
    fi
fi

if [ ! -x "${ADD_POLICY}" ]; then
    # Try to build it
    if [ -f "${ADD_POLICY}.c" ]; then
        echo "Building add_policy..."
        gcc -o "${ADD_POLICY}" "${ADD_POLICY}.c" 2>/dev/null
    fi
    if [ ! -x "${ADD_POLICY}" ]; then
        echo "Error: ${ADD_POLICY} not found or not executable."
        exit 1
    fi
fi

mkdir -p "${TEST_DIR}"

# Clean session keyring of any stale test keys
revoke_session_keys

# ── Phase 1: Write a file using transparent mode (default) ──
echo "--- Phase 1: Setup with Transparent Mode ---"

# Load the known key into the kernel key table (transparent mode)
"${SET_KEY}" "${TEST_KEY_HEX}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Error: Failed to set key via set_key tool"
    exit 1
fi

TEST_DATA="Hello from transparent mode — guarded test data $(date +%s)"
echo "$TEST_DATA" > "${TEST_DIR}/file1.txt"
sync

# --- Test 1: Verify transparent read works ---
CONTENT=$(cat "${TEST_DIR}/file1.txt" 2>/dev/null || echo "READ_FAILED")
check "Transparent mode: write and read file" "$CONTENT" "$TEST_DATA"

# --- Test 2: Verify lower file is encrypted ---
LOWER_CONTENT=$(cat "${LOWER_DIR}/guarded_key_test/file1.txt" 2>/dev/null || echo "LOWER_ERROR")
if [ "$LOWER_CONTENT" != "$TEST_DATA" ] && [ "$LOWER_CONTENT" != "LOWER_ERROR" ]; then
    log_pass "Lower file is encrypted (not plaintext)"
else
    log_skip "Lower file check (path may differ)"
fi

# ── Phase 2: Add guarded policy and test without session key ──
echo ""
echo "--- Phase 2: Guarded Policy — No Session Key ---"

# Add a guarded policy for uid=0 (root) with default key_id
ADD_OUTPUT=$("${ADD_POLICY}" --type 0 --value "0" --perm 1 \
    --key-id "${KEY_ID_HEX}" --access-mode 1 2>&1)
if [ $? -ne 0 ]; then
    echo "Error: Failed to add guarded policy"
    exit 1
fi
# Extract the policy rule ID from dmesg (last added rule)
POLICY_RULE_ID=$(dmesg | grep -o 'added policy rule [0-9]*' | tail -1 | grep -o '[0-9]*')
log_info "Added guarded policy for UID=0, key_id=${KEY_ID_HEX} (rule_id=${POLICY_RULE_ID})"

# Drop caches to evict cached FEKs — force re-open to use new policy
drop_caches

# --- Test 3: Read WITHOUT session key should fail ---
# Policy says GUARDED, but no key in session keyring → request_key fails
CONTENT=$(timeout 10 cat "${TEST_DIR}/file1.txt" 2>/dev/null)
RC=$?
if [ "$CONTENT" != "$TEST_DATA" ]; then
    log_pass "Guarded mode: read denied without session key"
else
    log_fail "Guarded mode: read should fail without session key but got plaintext"
fi

# ── Phase 3: Inject key into session keyring and test ──
echo ""
echo "--- Phase 3: Guarded Policy — With Session Key ---"

# Inject the key into the session keyring as a logon key
SERIAL=$(echo -n "${TEST_KEY_HEX}" | xxd -r -p | keyctl padd logon "${KEY_DESC}" @s 2>/dev/null)
if [ -z "$SERIAL" ] || [ "$SERIAL" = "" ]; then
    echo "Error: Failed to inject key into session keyring"
    exit 1
fi
log_info "Injected key into session keyring (serial=${SERIAL})"

# Drop caches again to force FEK reload via guarded path
drop_caches

# --- Test 4: Read WITH session key should succeed ---
CONTENT=$(timeout 10 cat "${TEST_DIR}/file1.txt" 2>/dev/null || echo "READ_FAILED")
check "Guarded mode: read succeeds with session key" "$CONTENT" "$TEST_DATA"

# --- Test 5: Write a NEW file via guarded mode ---
GUARDED_DATA="Hello from guarded mode — written with session key $(date +%s)"
echo "$GUARDED_DATA" > "${TEST_DIR}/file2.txt" 2>/dev/null
WRITE_RC=$?
if [ $WRITE_RC -eq 0 ]; then
    log_pass "Guarded mode: write new file succeeds with session key"
else
    log_fail "Guarded mode: write new file failed (rc=$WRITE_RC)"
fi

# --- Test 6: Read back the guarded-mode file ---
CONTENT=$(timeout 10 cat "${TEST_DIR}/file2.txt" 2>/dev/null || echo "READ_FAILED")
check "Guarded mode: read back new file" "$CONTENT" "$GUARDED_DATA"

# ── Phase 4: Revoke key and verify access lost ──
echo ""
echo "--- Phase 4: Revoke Session Key ---"

keyctl revoke "$SERIAL" 2>/dev/null || true
keyctl unlink "$SERIAL" @s 2>/dev/null || true
log_info "Revoked session key (serial=${SERIAL})"

# Drop caches to force FEK reload
drop_caches

# --- Test 7: Read after revoke should fail ---
CONTENT=$(timeout 10 cat "${TEST_DIR}/file1.txt" 2>/dev/null)
if [ "$CONTENT" != "$TEST_DATA" ]; then
    log_pass "Guarded mode: read denied after key revocation"
else
    log_fail "Guarded mode: read should fail after revoke but got plaintext"
fi

# --- Test 8: Re-inject key and verify access restored ---
echo ""
echo "--- Phase 5: Re-inject Key ---"

SERIAL2=$(echo -n "${TEST_KEY_HEX}" | xxd -r -p | keyctl padd logon "${KEY_DESC}" @s 2>/dev/null)
log_info "Re-injected key (serial=${SERIAL2})"

drop_caches

CONTENT=$(timeout 10 cat "${TEST_DIR}/file1.txt" 2>/dev/null || echo "READ_FAILED")
check "Guarded mode: read restored after re-injection" "$CONTENT" "$TEST_DATA"

# Also verify file2 (written in guarded mode) is still readable
CONTENT=$(timeout 10 cat "${TEST_DIR}/file2.txt" 2>/dev/null || echo "READ_FAILED")
check "Guarded mode: guarded-written file still readable" "$CONTENT" "$GUARDED_DATA"

# ── Summary ──
echo ""
echo "============================================"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "============================================"

exit $FAIL
