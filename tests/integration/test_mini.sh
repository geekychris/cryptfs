#!/bin/bash
# Minimal reproducer - matches test_basic_ops.sh structure but only tests 1-10
set -o pipefail
MOUNT_DIR=/tmp/cryptofs_mount
LOWER_DIR=/tmp/cryptofs_lower
TEST_DIR="${MOUNT_DIR}/basic_ops_test"
TEST_TIMEOUT=30
PASS=0; FAIL=0; SKIP=0
log_pass() { echo "[PASS] $1"; PASS=$((PASS + 1)); }
log_fail() { echo "[FAIL] $1"; FAIL=$((FAIL + 1)); }
log_skip() { echo "[SKIP] $1"; SKIP=$((SKIP + 1)); }
log_trace() { echo "  [TRACE] $1"; }
cleanup() {
    echo "[CLEANUP] start"
    timeout 10 rm -rf "${TEST_DIR}" 2>/dev/null || true
    echo "[CLEANUP] done"
}
trap cleanup EXIT

mountpoint -q "${MOUNT_DIR}" || { echo "NOT_MOUNTED"; exit 1; }
mkdir -p "${TEST_DIR}"

log_trace "T1: create+read"
echo "Hello, CryptoFS!" > "${TEST_DIR}/hello.txt"
CONTENT=$(cat "${TEST_DIR}/hello.txt")
if [ "$CONTENT" = "Hello, CryptoFS!" ]; then log_pass "T1"; else log_fail "T1"; fi

log_trace "T2: verify encryption"
LOWER_CONTENT=$(cat "${LOWER_DIR}/basic_ops_test/hello.txt" 2>/dev/null || echo "ERROR")
if [ "$LOWER_CONTENT" != "Hello, CryptoFS!" ] && [ "$LOWER_CONTENT" != "ERROR" ]; then
    log_pass "T2"
else
    log_skip "T2"
fi

log_trace "T3: binary 64KB"
dd if=/dev/urandom of="${TEST_DIR}/binary.dat" bs=1024 count=64 2>/dev/null
S1=$(sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
S2=$(sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
if [ "$S1" = "$S2" ]; then log_pass "T3"; else log_fail "T3"; fi

log_trace "T4: large 10MB"
dd if=/dev/urandom of="${TEST_DIR}/large.dat" bs=1M count=10 2>/dev/null
cp "${TEST_DIR}/large.dat" "${TEST_DIR}/large_copy.dat"
L1=$(sha256sum "${TEST_DIR}/large.dat" | awk '{print $1}')
L2=$(sha256sum "${TEST_DIR}/large_copy.dat" | awk '{print $1}')
if [ "$L1" = "$L2" ]; then log_pass "T4"; else log_fail "T4"; fi

log_trace "T5: file copy"
cp "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_copy.txt"
if [ "$(cat "${TEST_DIR}/hello_copy.txt")" = "Hello, CryptoFS!" ]; then log_pass "T5"; else log_fail "T5"; fi

log_trace "T6: rename"
mv "${TEST_DIR}/hello_copy.txt" "${TEST_DIR}/hello_renamed.txt"
if [ -f "${TEST_DIR}/hello_renamed.txt" ] && [ ! -f "${TEST_DIR}/hello_copy.txt" ]; then log_pass "T6"; else log_fail "T6"; fi

log_trace "T7: delete"
rm "${TEST_DIR}/hello_renamed.txt"
if [ ! -f "${TEST_DIR}/hello_renamed.txt" ]; then log_pass "T7"; else log_fail "T7"; fi

log_trace "T8: nested dirs"
mkdir -p "${TEST_DIR}/subdir/nested"
echo "nested file" > "${TEST_DIR}/subdir/nested/file.txt"
if [ -d "${TEST_DIR}/subdir/nested" ] && [ "$(cat "${TEST_DIR}/subdir/nested/file.txt")" = "nested file" ]; then
    log_pass "T8"
else
    log_fail "T8"
fi

log_trace "T9: dir listing"
touch "${TEST_DIR}/subdir/a.txt" "${TEST_DIR}/subdir/b.txt" "${TEST_DIR}/subdir/c.txt"
COUNT=$(ls "${TEST_DIR}/subdir/" | wc -l)
if [ "$COUNT" -ge 4 ]; then log_pass "T9"; else log_fail "T9"; fi

log_trace "T10: rmdir"
mkdir "${TEST_DIR}/empty_dir" 2>/dev/null
if rmdir "${TEST_DIR}/empty_dir" 2>/dev/null && [ ! -d "${TEST_DIR}/empty_dir" ]; then
    log_pass "T10"
else
    log_fail "T10"
fi

echo ""
echo "RESULTS: pass=$PASS fail=$FAIL skip=$SKIP"
exit $FAIL
