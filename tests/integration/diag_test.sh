#!/bin/bash
# Diagnostic test: mirrors test_basic_ops.sh flow with dmesg captures
# Goal: identify exactly where the kernel hangs

set -o pipefail
trap 'echo "[CLEANUP]"; timeout 10 rm -rf "${TEST_DIR}" 2>/dev/null; echo "[CLEANUP DONE]"' EXIT

MOUNT_DIR="/tmp/cryptofs_mount"
LOWER_DIR="/tmp/cryptofs_lower"
TEST_DIR="${MOUNT_DIR}/basic_ops_test"
TEST_TIMEOUT=30

echo "=== DIAG START ==="
sudo dmesg -C
mkdir -p "${TEST_DIR}"

# --- Test 1 ---
echo ">>> TEST 1: create+read"
echo "Hello, CryptoFS!" > "${TEST_DIR}/hello.txt"
CONTENT=$(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello.txt" 2>/dev/null || echo "TIMEOUT")
echo "  result: '$CONTENT'"

# --- Test 2 ---
echo ">>> TEST 2: verify encryption"
LOWER_CONTENT=$(timeout $TEST_TIMEOUT cat "${LOWER_DIR}/basic_ops_test/hello.txt" 2>/dev/null || echo "ERROR")
echo "  lower != plain: $([ "$LOWER_CONTENT" != "Hello, CryptoFS!" ] && echo YES || echo NO)"

# --- Test 3 ---
echo ">>> TEST 3: binary 64KB"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/binary.dat" bs=1024 count=64 2>/dev/null
ORIG_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
READ_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/binary.dat" | awk '{print $1}')
echo "  match: $([ "$ORIG_SUM" = "$READ_SUM" ] && echo YES || echo NO)"

# --- Test 4: LARGE FILE ---
echo ">>> TEST 4: large file 10MB"
timeout $TEST_TIMEOUT dd if=/dev/urandom of="${TEST_DIR}/large.dat" bs=1M count=10 2>/dev/null
echo "  dd done, exit=$?"
LARGE_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/large.dat" | awk '{print $1}')
echo "  sha256sum done"
timeout $TEST_TIMEOUT cp "${TEST_DIR}/large.dat" "${TEST_DIR}/large_copy.dat"
echo "  cp done"
COPY_SUM=$(timeout $TEST_TIMEOUT sha256sum "${TEST_DIR}/large_copy.dat" | awk '{print $1}')
echo "  match: $([ "$LARGE_SUM" = "$COPY_SUM" ] && echo YES || echo NO)"

# --- Test 5 ---
echo ">>> TEST 5: file copy"
timeout $TEST_TIMEOUT cp "${TEST_DIR}/hello.txt" "${TEST_DIR}/hello_copy.txt"
echo "  copy content: $(timeout $TEST_TIMEOUT cat "${TEST_DIR}/hello_copy.txt" 2>/dev/null)"

# --- Test 6 ---
echo ">>> TEST 6: rename"
timeout $TEST_TIMEOUT mv "${TEST_DIR}/hello_copy.txt" "${TEST_DIR}/hello_renamed.txt"
echo "  done: $([ -f "${TEST_DIR}/hello_renamed.txt" ] && echo OK || echo FAIL)"

# --- Test 7 ---
echo ">>> TEST 7: delete"
rm "${TEST_DIR}/hello_renamed.txt"
echo "  done: $([ ! -f "${TEST_DIR}/hello_renamed.txt" ] && echo OK || echo FAIL)"

# --- Test 8 ---
echo ">>> TEST 8: nested dirs"
mkdir -p "${TEST_DIR}/subdir/nested"
echo "nested file" > "${TEST_DIR}/subdir/nested/file.txt"
echo "  content: $(timeout $TEST_TIMEOUT cat "${TEST_DIR}/subdir/nested/file.txt" 2>/dev/null)"

# --- Test 9 ---
echo ">>> TEST 9: dir listing"
touch "${TEST_DIR}/subdir/a.txt" "${TEST_DIR}/subdir/b.txt" "${TEST_DIR}/subdir/c.txt"
COUNT=$(ls "${TEST_DIR}/subdir/" | wc -l)
echo "  count=$COUNT"

# --- DIAGNOSTICS before test 10 ---
echo ""
echo "=== PRE-TEST-10 DIAGNOSTICS ==="
echo "--- dmesg (last 30 lines) ---"
sudo dmesg | tail -30
echo "--- D-state procs ---"
ps aux | awk '$8 ~ /D/' || echo "(none)"
echo "--- meminfo ---"
grep -E "MemFree|MemAvailable|Dirty|Writeback|Slab" /proc/meminfo
echo "--- open files on mount ---"
sudo lsof +D "${MOUNT_DIR}" 2>/dev/null | head -20 || echo "(none or lsof not available)"
echo "=== END DIAGNOSTICS ==="
echo ""

# --- Test 10 ---
echo ">>> TEST 10: mkdir"
echo "  about to mkdir..."
mkdir "${TEST_DIR}/empty_dir"
echo "  mkdir done!"
echo "  about to rmdir..."
rmdir "${TEST_DIR}/empty_dir"
echo "  rmdir done!"

echo ""
echo "=== ALL TESTS COMPLETED ==="
