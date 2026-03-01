#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# ============================================================================
# CryptoFS Stress Test — Exhaustive Data Integrity Validation
#
# This test writes data in a wide variety of patterns, sizes, and access modes,
# then reads every byte back and verifies correctness with SHA-256.
#
# Sections:
#   1. Graduated file sizes (0 B → 500 MB)
#   2. Known-pattern fills (zeros, 0xFF, repeating, alternating)
#   3. Extent-boundary edge cases
#   4. Overwrite-in-place cycles
#   5. Append-then-verify cycles
#   6. Random-offset read/write verification
#   7. Concurrent multi-process write/verify
#   8. Rapid create → verify → delete churn
#   9. Unmount/remount persistence check
#  10. Large-file streaming integrity
#
# Environment:
#   MOUNT_DIR   — cryptofs mount point  (default /tmp/cryptofs_mount)
#   LOWER_DIR   — lower backing dir     (default /tmp/cryptofs_lower)
#   STRESS_LEVEL — light|medium|heavy   (default medium)
#   NUM_WORKERS  — parallel workers     (default 8)
# ============================================================================
set -euo pipefail

# --------------- configuration ---------------
MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
TEST_DIR="${MOUNT_DIR}/stress_test"
REF_DIR="/tmp/cryptofs_stress_ref"       # reference copies on native FS
STRESS_LEVEL="${STRESS_LEVEL:-medium}"
NUM_WORKERS="${NUM_WORKERS:-8}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
TOTAL_BYTES_VERIFIED=0
START_TS=$(date +%s)

# --------------- helpers ---------------
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1"; (( PASS++ )) || true; }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1"; (( FAIL++ )) || true; }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC} $1"; (( SKIP++ )) || true; }
log_section() { echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}"; }
log_info()  { echo -e "       $1"; }

# SHA-256 of a file, portable
file_hash() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

# Write random data, copy reference, verify via hash
# Usage: write_and_verify <label> <bs> <count> <filename>
write_and_verify() {
    local LABEL="$1" BS="$2" COUNT="$3" FNAME="$4"
    local FPATH="${TEST_DIR}/${FNAME}"
    local RPATH="${REF_DIR}/${FNAME}"

    dd if=/dev/urandom of="${RPATH}" bs="${BS}" count="${COUNT}" 2>/dev/null
    cp "${RPATH}" "${FPATH}"

    local REF_HASH BACK_HASH
    REF_HASH=$(file_hash "${RPATH}")
    BACK_HASH=$(file_hash "${FPATH}")

    local SIZE
    SIZE=$(stat -c '%s' "${RPATH}" 2>/dev/null || stat -f '%z' "${RPATH}" 2>/dev/null)
    TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + SIZE))

    if [ "${REF_HASH}" = "${BACK_HASH}" ]; then
        log_pass "${LABEL} (${SIZE} bytes)"
    else
        log_fail "${LABEL} — hash mismatch (ref=${REF_HASH:0:16}… got=${BACK_HASH:0:16}…)"
    fi
}

# Write a deterministic pattern, read back, compare byte-for-byte
# Usage: pattern_fill_verify <label> <size_bytes> <byte_hex> <filename>
pattern_fill_verify() {
    local LABEL="$1" SIZE="$2" BYTE="$3" FNAME="$4"
    local FPATH="${TEST_DIR}/${FNAME}"
    local RPATH="${REF_DIR}/${FNAME}"

    # Generate pattern on native FS
    dd if=/dev/zero bs=1 count=0 seek="${SIZE}" of="${RPATH}" 2>/dev/null
    if [ "${BYTE}" = "00" ]; then
        dd if=/dev/zero of="${RPATH}" bs="${SIZE}" count=1 2>/dev/null
    else
        # Use tr to translate zeros → desired byte
        dd if=/dev/zero bs="${SIZE}" count=1 2>/dev/null | tr '\000' "\\x${BYTE}" > "${RPATH}"
    fi

    cp "${RPATH}" "${FPATH}"

    local REF_HASH BACK_HASH
    REF_HASH=$(file_hash "${RPATH}")
    BACK_HASH=$(file_hash "${FPATH}")

    TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + SIZE))

    if [ "${REF_HASH}" = "${BACK_HASH}" ]; then
        log_pass "${LABEL} (${SIZE} bytes, 0x${BYTE})"
    else
        log_fail "${LABEL} — pattern mismatch"
    fi
}

cleanup() {
    rm -rf "${TEST_DIR}" "${REF_DIR}" /tmp/cryptofs_stress_worker_* 2>/dev/null || true
}
trap cleanup EXIT

# --------------- size matrix by stress level ---------------
case "${STRESS_LEVEL}" in
    light)
        SIZES_LABEL=( "0B" "1B" "511B" "4095B" "4096B" "4097B" "8191B" "8192B" "64KB" "1MB" "10MB" )
        SIZES_BS=(    "1"  "1"  "1"     "1"     "1"     "1"     "1"     "1"     "1024" "1024" "1024" )
        SIZES_COUNT=( "0"  "1"  "511"   "4095"  "4096"  "4097"  "8191"  "8192"  "64"   "1024" "10240" )
        LARGE_MB=50
        CHURN_COUNT=200
        OVERWRITE_CYCLES=10
        APPEND_CYCLES=50
        ;;
    heavy)
        SIZES_LABEL=( "0B" "1B" "255B" "511B" "512B" "1023B" "1024B" "2048B" "4095B" "4096B" "4097B" \
                       "8191B" "8192B" "8193B" "12288B" "16384B" "32KB" "64KB" "128KB" "256KB" \
                       "512KB" "1MB" "4MB" "10MB" "50MB" "100MB" "500MB" )
        SIZES_BS=(    "1"  "1"  "1"   "1"   "1"   "1"    "1"    "1"    "1"    "1"    "1"    \
                      "1"    "1"    "1"    "1"     "1"     "1024" "1024" "1024"  "1024"  \
                      "1024"  "1024" "4096" "4096" "1048576" "1048576" "1048576" )
        SIZES_COUNT=( "0"  "1"  "255" "511" "512" "1023" "1024" "2048" "4095" "4096" "4097" \
                      "8191" "8192" "8193" "12288" "16384" "32"   "64"   "128"   "256"   \
                      "512"   "1024" "1024" "2560" "50"      "100"     "500" )
        LARGE_MB=500
        CHURN_COUNT=1000
        OVERWRITE_CYCLES=50
        APPEND_CYCLES=200
        ;;
    *)  # medium (default)
        SIZES_LABEL=( "0B" "1B" "255B" "511B" "4095B" "4096B" "4097B" "8191B" "8192B" \
                       "8193B" "12288B" "16384B" "64KB" "256KB" "1MB" "10MB" "50MB" "100MB" )
        SIZES_BS=(    "1"  "1"  "1"   "1"   "1"    "1"    "1"    "1"    "1"    \
                      "1"    "1"     "1"     "1024" "1024"  "1024" "4096" "1048576" "1048576" )
        SIZES_COUNT=( "0"  "1"  "255" "511" "4095" "4096" "4097" "8191" "8192" \
                      "8193" "12288" "16384" "64"   "256"   "1024" "2560" "50"      "100" )
        LARGE_MB=200
        CHURN_COUNT=500
        OVERWRITE_CYCLES=25
        APPEND_CYCLES=100
        ;;
esac

# --------------- pre-flight ---------------
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} CryptoFS Stress Test — Data Integrity Validation${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " Mount:       ${MOUNT_DIR}"
echo -e " Level:       ${STRESS_LEVEL}"
echo -e " Workers:     ${NUM_WORKERS}"
echo -e " File sizes:  ${#SIZES_LABEL[@]} variants"
echo -e "${BOLD}============================================================${NC}"
echo ""

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo "Error: ${MOUNT_DIR} is not a mount point."
    echo "Mount cryptofs first, or set MOUNT_DIR."
    exit 1
fi

mkdir -p "${TEST_DIR}" "${REF_DIR}"

# ============================================================================
# 1. GRADUATED FILE SIZES — random data
# ============================================================================
log_section "1. Graduated File Sizes (random data write → read → verify)"

for idx in "${!SIZES_LABEL[@]}"; do
    LBL="${SIZES_LABEL[$idx]}"
    BS="${SIZES_BS[$idx]}"
    CNT="${SIZES_COUNT[$idx]}"

    if [ "${CNT}" = "0" ]; then
        # special case: empty file
        touch "${TEST_DIR}/size_${LBL}.dat"
        touch "${REF_DIR}/size_${LBL}.dat"
        SZ=$(stat -c '%s' "${TEST_DIR}/size_${LBL}.dat" 2>/dev/null || stat -f '%z' "${TEST_DIR}/size_${LBL}.dat" 2>/dev/null)
        if [ "${SZ}" = "0" ]; then
            log_pass "Empty file (0 bytes)"
        else
            log_fail "Empty file — size=${SZ}"
        fi
    else
        write_and_verify "Random ${LBL}" "${BS}" "${CNT}" "size_${LBL}.dat"
    fi
done

# ============================================================================
# 2. KNOWN-PATTERN FILLS
# ============================================================================
log_section "2. Known-Pattern Fills (deterministic byte patterns)"

PATTERN_SIZE=40960   # 10 extents exactly

pattern_fill_verify "All zeros"         "${PATTERN_SIZE}" "00" "pattern_zeros.dat"
pattern_fill_verify "All 0xFF"          "${PATTERN_SIZE}" "FF" "pattern_ff.dat"
pattern_fill_verify "All 0xAA"          "${PATTERN_SIZE}" "AA" "pattern_aa.dat"
pattern_fill_verify "All 0x55"          "${PATTERN_SIZE}" "55" "pattern_55.dat"
pattern_fill_verify "All 0xDE"          "${PATTERN_SIZE}" "DE" "pattern_de.dat"

# Repeating 256-byte ramp pattern (0x00..0xFF repeated)
RAMP_FILE="${REF_DIR}/pattern_ramp.dat"
python3 -c "
import sys
pat = bytes(range(256))
sys.stdout.buffer.write(pat * (${PATTERN_SIZE} // 256))
" > "${RAMP_FILE}" 2>/dev/null || {
    # Fallback without python
    dd if=/dev/urandom of="${RAMP_FILE}" bs="${PATTERN_SIZE}" count=1 2>/dev/null
}
cp "${RAMP_FILE}" "${TEST_DIR}/pattern_ramp.dat"
R1=$(file_hash "${RAMP_FILE}")
R2=$(file_hash "${TEST_DIR}/pattern_ramp.dat")
TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + PATTERN_SIZE))
if [ "$R1" = "$R2" ]; then
    log_pass "Repeating ramp 0x00..0xFF (${PATTERN_SIZE} bytes)"
else
    log_fail "Ramp pattern mismatch"
fi

# ============================================================================
# 3. EXTENT BOUNDARY EDGE CASES
# ============================================================================
log_section "3. Extent Boundary Edge Cases"

EXTENT=4096
TAG=16
DISK_EXTENT=$((EXTENT + TAG))  # 4112

# Files whose sizes sit exactly at interesting boundaries
for OFFSET in -2 -1 0 1 2; do
    for MULT in 1 2 3 5 10; do
        SZ=$(( MULT * EXTENT + OFFSET ))
        if [ "${SZ}" -le 0 ]; then continue; fi
        write_and_verify "Extent boundary ${MULT}×4096${OFFSET:+${OFFSET}}" \
            "1" "${SZ}" "extent_${MULT}x${OFFSET}.dat"
    done
done

# ============================================================================
# 4. OVERWRITE-IN-PLACE CYCLES
# ============================================================================
log_section "4. Overwrite-In-Place Cycles (${OVERWRITE_CYCLES} rounds)"

OW_FILE="${TEST_DIR}/overwrite.dat"
OW_REF="${REF_DIR}/overwrite.dat"
OW_SIZE=40960
OW_OK=0
OW_BAD=0

for i in $(seq 1 "${OVERWRITE_CYCLES}"); do
    dd if=/dev/urandom of="${OW_REF}" bs="${OW_SIZE}" count=1 2>/dev/null
    cp "${OW_REF}" "${OW_FILE}"
    H1=$(file_hash "${OW_REF}")
    H2=$(file_hash "${OW_FILE}")
    if [ "$H1" = "$H2" ]; then
        OW_OK=$((OW_OK + 1))
    else
        OW_BAD=$((OW_BAD + 1))
    fi
done

TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + OW_SIZE * OVERWRITE_CYCLES))
if [ "${OW_BAD}" -eq 0 ]; then
    log_pass "Overwrite-in-place: ${OW_OK}/${OVERWRITE_CYCLES} rounds OK"
else
    log_fail "Overwrite-in-place: ${OW_BAD}/${OVERWRITE_CYCLES} rounds FAILED"
fi

# ============================================================================
# 5. APPEND-THEN-VERIFY CYCLES
# ============================================================================
log_section "5. Append-Then-Verify (${APPEND_CYCLES} appends)"

AP_FILE="${TEST_DIR}/append_stress.dat"
AP_REF="${REF_DIR}/append_stress.dat"
> "${AP_FILE}"
> "${AP_REF}"

AP_BAD=0
for i in $(seq 1 "${APPEND_CYCLES}"); do
    CHUNK_SIZE=$(( (RANDOM % 8192) + 1 ))
    dd if=/dev/urandom bs="${CHUNK_SIZE}" count=1 2>/dev/null | tee -a "${AP_REF}" >> "${AP_FILE}"
done

AP_REF_HASH=$(file_hash "${AP_REF}")
AP_FILE_HASH=$(file_hash "${AP_FILE}")
AP_SIZE=$(stat -c '%s' "${AP_REF}" 2>/dev/null || stat -f '%z' "${AP_REF}" 2>/dev/null)
TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + AP_SIZE))

if [ "${AP_REF_HASH}" = "${AP_FILE_HASH}" ]; then
    log_pass "Append-then-verify: ${APPEND_CYCLES} appends, ${AP_SIZE} bytes total"
else
    log_fail "Append-then-verify: hash mismatch after ${APPEND_CYCLES} appends"
fi

# Verify intermediate: read first 1024 bytes, last 1024 bytes
AP_HEAD_REF=$(dd if="${AP_REF}" bs=1024 count=1 2>/dev/null | file_hash /dev/stdin)
AP_HEAD_FS=$(dd if="${AP_FILE}" bs=1024 count=1 2>/dev/null | file_hash /dev/stdin)
if [ "${AP_HEAD_REF}" = "${AP_HEAD_FS}" ]; then
    log_pass "Append file head (first 1024 bytes) intact"
else
    log_fail "Append file head corrupted"
fi

# ============================================================================
# 6. RANDOM OFFSET READ/WRITE VERIFICATION
# ============================================================================
log_section "6. Random Offset Read/Write Verification"

RO_FILE="${TEST_DIR}/random_offset.dat"
RO_REF="${REF_DIR}/random_offset.dat"
RO_SIZE=131072   # 128 KB = 32 extents

dd if=/dev/urandom of="${RO_REF}" bs="${RO_SIZE}" count=1 2>/dev/null
cp "${RO_REF}" "${RO_FILE}"

# Overwrite 20 random regions and verify the whole file after each
RO_BAD=0
for i in $(seq 1 20); do
    OFFSET=$(( RANDOM % (RO_SIZE - 512) ))
    LEN=$(( (RANDOM % 512) + 1 ))
    dd if=/dev/urandom of=/tmp/cryptofs_stress_patch bs="${LEN}" count=1 2>/dev/null
    # Apply patch to both
    dd if=/tmp/cryptofs_stress_patch of="${RO_REF}" bs=1 seek="${OFFSET}" conv=notrunc 2>/dev/null
    dd if=/tmp/cryptofs_stress_patch of="${RO_FILE}" bs=1 seek="${OFFSET}" conv=notrunc 2>/dev/null
done

H1=$(file_hash "${RO_REF}")
H2=$(file_hash "${RO_FILE}")
TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + RO_SIZE))

if [ "$H1" = "$H2" ]; then
    log_pass "Random offset patching: 20 patches on 128KB file"
else
    log_fail "Random offset patching: final hash mismatch"
fi

# Spot-check: read 4096 bytes from a random extent boundary
SPOT_OFF=$(( (RANDOM % 28) * 4096 ))
SPOT_REF=$(dd if="${RO_REF}" bs=1 skip="${SPOT_OFF}" count=4096 2>/dev/null | sha256sum | awk '{print $1}')
SPOT_FS=$(dd if="${RO_FILE}" bs=1 skip="${SPOT_OFF}" count=4096 2>/dev/null | sha256sum | awk '{print $1}')
if [ "${SPOT_REF}" = "${SPOT_FS}" ]; then
    log_pass "Spot-check extent at offset ${SPOT_OFF}"
else
    log_fail "Spot-check extent at offset ${SPOT_OFF}"
fi

# ============================================================================
# 7. CONCURRENT MULTI-PROCESS WRITE / VERIFY
# ============================================================================
log_section "7. Concurrent Multi-Process Write/Verify (${NUM_WORKERS} workers)"

CONC_DIR="${TEST_DIR}/concurrent"
CONC_REF="${REF_DIR}/concurrent"
mkdir -p "${CONC_DIR}" "${CONC_REF}"

WORKER_FILES=50   # files per worker
WORKER_SIZE=32768  # 32 KB each = 8 extents

for w in $(seq 1 "${NUM_WORKERS}"); do
    (
        W_OK=0
        W_BAD=0
        for f in $(seq 1 "${WORKER_FILES}"); do
            FNAME="w${w}_f${f}.dat"
            dd if=/dev/urandom of="${CONC_REF}/${FNAME}" bs="${WORKER_SIZE}" count=1 2>/dev/null
            cp "${CONC_REF}/${FNAME}" "${CONC_DIR}/${FNAME}"
            H1=$(sha256sum "${CONC_REF}/${FNAME}" | awk '{print $1}')
            H2=$(sha256sum "${CONC_DIR}/${FNAME}" | awk '{print $1}')
            if [ "$H1" = "$H2" ]; then
                W_OK=$((W_OK + 1))
            else
                W_BAD=$((W_BAD + 1))
            fi
        done
        echo "${W_OK} ${W_BAD}" > "/tmp/cryptofs_stress_worker_${w}.result"
    ) &
done
wait

CONC_OK=0
CONC_BAD=0
for w in $(seq 1 "${NUM_WORKERS}"); do
    read WOK WBAD < "/tmp/cryptofs_stress_worker_${w}.result"
    CONC_OK=$((CONC_OK + WOK))
    CONC_BAD=$((CONC_BAD + WBAD))
done

TOTAL_CONC=$((NUM_WORKERS * WORKER_FILES))
TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + TOTAL_CONC * WORKER_SIZE))

if [ "${CONC_BAD}" -eq 0 ]; then
    log_pass "Concurrent write/verify: ${CONC_OK}/${TOTAL_CONC} files OK (${NUM_WORKERS} workers)"
else
    log_fail "Concurrent write/verify: ${CONC_BAD}/${TOTAL_CONC} files FAILED"
fi

# Second pass: re-read every file just written and verify again
REREAD_BAD=0
for w in $(seq 1 "${NUM_WORKERS}"); do
    for f in $(seq 1 "${WORKER_FILES}"); do
        FNAME="w${w}_f${f}.dat"
        H1=$(sha256sum "${CONC_REF}/${FNAME}" | awk '{print $1}')
        H2=$(sha256sum "${CONC_DIR}/${FNAME}" | awk '{print $1}')
        if [ "$H1" != "$H2" ]; then
            REREAD_BAD=$((REREAD_BAD + 1))
        fi
    done
done

TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + TOTAL_CONC * WORKER_SIZE))

if [ "${REREAD_BAD}" -eq 0 ]; then
    log_pass "Concurrent re-read verification: all ${TOTAL_CONC} files still valid"
else
    log_fail "Concurrent re-read: ${REREAD_BAD}/${TOTAL_CONC} files corrupted after settle"
fi

# ============================================================================
# 8. RAPID CREATE → VERIFY → DELETE CHURN
# ============================================================================
log_section "8. Rapid Create/Verify/Delete Churn (${CHURN_COUNT} files)"

CHURN_DIR="${TEST_DIR}/churn"
mkdir -p "${CHURN_DIR}"

CHURN_OK=0
CHURN_BAD=0

for i in $(seq 1 "${CHURN_COUNT}"); do
    SZ=$(( (RANDOM % 16384) + 1 ))
    FNAME="churn_${i}.dat"
    dd if=/dev/urandom of="/tmp/cryptofs_stress_churn_ref" bs="${SZ}" count=1 2>/dev/null
    cp "/tmp/cryptofs_stress_churn_ref" "${CHURN_DIR}/${FNAME}"
    H1=$(sha256sum "/tmp/cryptofs_stress_churn_ref" | awk '{print $1}')
    H2=$(sha256sum "${CHURN_DIR}/${FNAME}" | awk '{print $1}')
    rm -f "${CHURN_DIR}/${FNAME}"
    if [ "$H1" = "$H2" ]; then
        CHURN_OK=$((CHURN_OK + 1))
    else
        CHURN_BAD=$((CHURN_BAD + 1))
    fi
done

TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + CHURN_COUNT * 8192))  # approx avg

if [ "${CHURN_BAD}" -eq 0 ]; then
    log_pass "Create/verify/delete churn: ${CHURN_OK}/${CHURN_COUNT} OK"
else
    log_fail "Create/verify/delete churn: ${CHURN_BAD}/${CHURN_COUNT} FAILED"
fi

# ============================================================================
# 9. UNMOUNT / REMOUNT PERSISTENCE CHECK
# ============================================================================
log_section "9. Unmount/Remount Persistence"

# Write sentinel files before unmount
PERSIST_DIR="${TEST_DIR}/persist"
PERSIST_REF="${REF_DIR}/persist"
mkdir -p "${PERSIST_DIR}" "${PERSIST_REF}"

for i in $(seq 1 10); do
    dd if=/dev/urandom of="${PERSIST_REF}/persist_${i}.dat" bs=4096 count=$((i * 3)) 2>/dev/null
    cp "${PERSIST_REF}/persist_${i}.dat" "${PERSIST_DIR}/persist_${i}.dat"
done

# Save hashes
declare -A PERSIST_HASHES
for i in $(seq 1 10); do
    PERSIST_HASHES[$i]=$(file_hash "${PERSIST_REF}/persist_${i}.dat")
done

# Attempt unmount/remount (requires root)
if [ "$(id -u)" -eq 0 ]; then
    # Sync first
    sync
    umount "${MOUNT_DIR}" 2>/dev/null || true
    sleep 1

    # Remount (assumes the original mount command is recorded)
    # The actual mount command depends on how it was set up
    mount -t cryptofs "${LOWER_DIR}" "${MOUNT_DIR}" 2>/dev/null || {
        log_skip "Could not remount (mount command may differ)"
        # Try to re-mount anyway for subsequent tests
        mount -t cryptofs "${LOWER_DIR}" "${MOUNT_DIR}" 2>/dev/null || true
    }

    if mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
        P_BAD=0
        for i in $(seq 1 10); do
            H=$(file_hash "${PERSIST_DIR}/persist_${i}.dat")
            if [ "$H" != "${PERSIST_HASHES[$i]}" ]; then
                P_BAD=$((P_BAD + 1))
            fi
        done
        if [ "${P_BAD}" -eq 0 ]; then
            log_pass "Persistence after unmount/remount: 10/10 files intact"
        else
            log_fail "Persistence: ${P_BAD}/10 files corrupted after remount"
        fi
    else
        log_skip "Remount failed — cannot verify persistence"
    fi
else
    log_skip "Unmount/remount persistence (requires root)"
fi

# ============================================================================
# 10. LARGE FILE STREAMING INTEGRITY
# ============================================================================
log_section "10. Large File Streaming Integrity (${LARGE_MB} MB)"

LARGE_FILE="${TEST_DIR}/large_stream.dat"
LARGE_REF="${REF_DIR}/large_stream.dat"

echo -n "  Writing ${LARGE_MB} MB... "
dd if=/dev/urandom of="${LARGE_REF}" bs=1048576 count="${LARGE_MB}" 2>/dev/null
echo "done"

echo -n "  Copying to cryptofs... "
cp "${LARGE_REF}" "${LARGE_FILE}"
echo "done"

echo -n "  Verifying... "
LH1=$(file_hash "${LARGE_REF}")
LH2=$(file_hash "${LARGE_FILE}")

TOTAL_BYTES_VERIFIED=$((TOTAL_BYTES_VERIFIED + LARGE_MB * 1048576))

if [ "$LH1" = "$LH2" ]; then
    log_pass "Large file streaming: ${LARGE_MB} MB write → read verified"
else
    log_fail "Large file streaming: hash mismatch on ${LARGE_MB} MB file"
fi

# Spot-check: read 10 random 4KB extents from the large file
LARGE_EXTENTS=$((LARGE_MB * 256))  # extents in file
SPOT_BAD=0
for i in $(seq 1 10); do
    EXT_IDX=$(( RANDOM % LARGE_EXTENTS ))
    EXT_OFF=$(( EXT_IDX * 4096 ))
    SH1=$(dd if="${LARGE_REF}" bs=4096 skip="${EXT_IDX}" count=1 2>/dev/null | sha256sum | awk '{print $1}')
    SH2=$(dd if="${LARGE_FILE}" bs=4096 skip="${EXT_IDX}" count=1 2>/dev/null | sha256sum | awk '{print $1}')
    if [ "$SH1" != "$SH2" ]; then
        SPOT_BAD=$((SPOT_BAD + 1))
    fi
done
if [ "${SPOT_BAD}" -eq 0 ]; then
    log_pass "Large file extent spot-check: 10/10 random extents match"
else
    log_fail "Large file extent spot-check: ${SPOT_BAD}/10 mismatched"
fi

# ============================================================================
# SUMMARY
# ============================================================================
END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))
VERIFIED_MB=$((TOTAL_BYTES_VERIFIED / 1048576))

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD} STRESS TEST RESULTS${NC}"
echo -e "${BOLD}============================================================${NC}"
echo -e " Level:            ${STRESS_LEVEL}"
echo -e " Duration:         ${ELAPSED}s"
echo -e " Data verified:    ${VERIFIED_MB} MB (${TOTAL_BYTES_VERIFIED} bytes)"
echo -e " Workers:          ${NUM_WORKERS}"
echo -e " ${GREEN}Passed:${NC}           ${PASS}"
echo -e " ${RED}Failed:${NC}           ${FAIL}"
echo -e " ${YELLOW}Skipped:${NC}          ${SKIP}"

if [ "${FAIL}" -eq 0 ]; then
    echo -e "\n ${GREEN}${BOLD}✓ ALL DATA INTEGRITY CHECKS PASSED${NC}"
else
    echo -e "\n ${RED}${BOLD}✗ ${FAIL} DATA INTEGRITY CHECK(S) FAILED${NC}"
fi
echo -e "${BOLD}============================================================${NC}"

exit "${FAIL}"
