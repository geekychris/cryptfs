#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# CryptoFS Performance Benchmark using fio
#
# Runs fio benchmarks on both CryptoFS and a baseline (native) filesystem,
# then outputs a comparison summary.
#
# Usage: ./run_fio.sh [--cryptofs-dir DIR] [--baseline-dir DIR] [--runtime SECS]

set -euo pipefail

CRYPTOFS_DIR="${CRYPTOFS_DIR:-/tmp/cryptofs_mount/bench}"
BASELINE_DIR="${BASELINE_DIR:-/tmp/cryptofs_baseline/bench}"
RESULTS_DIR="${RESULTS_DIR:-/tmp/cryptofs_results}"
RUNTIME="${RUNTIME:-30}"
FILE_SIZE="${FILE_SIZE:-256M}"

mkdir -p "${CRYPTOFS_DIR}" "${BASELINE_DIR}" "${RESULTS_DIR}"

echo "============================================"
echo "CryptoFS Performance Benchmarks"
echo "============================================"
echo "CryptoFS dir:  ${CRYPTOFS_DIR}"
echo "Baseline dir:  ${BASELINE_DIR}"
echo "Runtime:       ${RUNTIME}s per test"
echo "File size:     ${FILE_SIZE}"
echo "============================================"
echo ""

run_fio_test() {
    local NAME="$1"
    local DIR="$2"
    local RW="$3"
    local BS="$4"
    local JOBS="$5"
    local OUTPUT="$6"

    echo -n "  Running ${NAME}... "
    fio --name="${NAME}" \
        --directory="${DIR}" \
        --rw="${RW}" \
        --bs="${BS}" \
        --size="${FILE_SIZE}" \
        --numjobs="${JOBS}" \
        --time_based \
        --runtime="${RUNTIME}" \
        --group_reporting \
        --output-format=json \
        --output="${OUTPUT}" \
        2>/dev/null

    # Extract key metrics
    if [ "${RW}" = "read" ] || [ "${RW}" = "randread" ]; then
        BW=$(jq -r '.jobs[0].read.bw_bytes' "${OUTPUT}" 2>/dev/null || echo 0)
        IOPS=$(jq -r '.jobs[0].read.iops' "${OUTPUT}" 2>/dev/null || echo 0)
        LAT=$(jq -r '.jobs[0].read.lat_ns.mean' "${OUTPUT}" 2>/dev/null || echo 0)
    elif [ "${RW}" = "write" ] || [ "${RW}" = "randwrite" ]; then
        BW=$(jq -r '.jobs[0].write.bw_bytes' "${OUTPUT}" 2>/dev/null || echo 0)
        IOPS=$(jq -r '.jobs[0].write.iops' "${OUTPUT}" 2>/dev/null || echo 0)
        LAT=$(jq -r '.jobs[0].write.lat_ns.mean' "${OUTPUT}" 2>/dev/null || echo 0)
    else
        # mixed workload
        RBW=$(jq -r '.jobs[0].read.bw_bytes' "${OUTPUT}" 2>/dev/null || echo 0)
        WBW=$(jq -r '.jobs[0].write.bw_bytes' "${OUTPUT}" 2>/dev/null || echo 0)
        BW=$((RBW + WBW))
        RIOPS=$(jq -r '.jobs[0].read.iops' "${OUTPUT}" 2>/dev/null || echo 0)
        WIOPS=$(jq -r '.jobs[0].write.iops' "${OUTPUT}" 2>/dev/null || echo 0)
        IOPS=$(echo "$RIOPS + $WIOPS" | bc 2>/dev/null || echo 0)
        LAT=$(jq -r '.jobs[0].read.lat_ns.mean' "${OUTPUT}" 2>/dev/null || echo 0)
    fi

    BW_MB=$(echo "scale=2; ${BW} / 1048576" | bc 2>/dev/null || echo "?")
    LAT_US=$(echo "scale=2; ${LAT} / 1000" | bc 2>/dev/null || echo "?")

    echo "${BW_MB} MB/s, ${IOPS} IOPS, ${LAT_US} µs avg lat"
}

echo "=== Baseline (native filesystem) ==="
run_fio_test "seq_write_4k"    "${BASELINE_DIR}" "write"    "4k"  1 "${RESULTS_DIR}/baseline_seq_write_4k.json"
run_fio_test "seq_read_4k"     "${BASELINE_DIR}" "read"     "4k"  1 "${RESULTS_DIR}/baseline_seq_read_4k.json"
run_fio_test "seq_write_1m"    "${BASELINE_DIR}" "write"    "1m"  1 "${RESULTS_DIR}/baseline_seq_write_1m.json"
run_fio_test "seq_read_1m"     "${BASELINE_DIR}" "read"     "1m"  1 "${RESULTS_DIR}/baseline_seq_read_1m.json"
run_fio_test "rand_read_4k"    "${BASELINE_DIR}" "randread" "4k"  4 "${RESULTS_DIR}/baseline_rand_read_4k.json"
run_fio_test "rand_write_4k"   "${BASELINE_DIR}" "randwrite" "4k"  4 "${RESULTS_DIR}/baseline_rand_write_4k.json"
run_fio_test "rand_rw_4k"      "${BASELINE_DIR}" "randrw"   "4k"  4 "${RESULTS_DIR}/baseline_rand_rw_4k.json"
echo ""

echo "=== CryptoFS (encrypted) ==="
run_fio_test "seq_write_4k"    "${CRYPTOFS_DIR}" "write"    "4k"  1 "${RESULTS_DIR}/cryptofs_seq_write_4k.json"
run_fio_test "seq_read_4k"     "${CRYPTOFS_DIR}" "read"     "4k"  1 "${RESULTS_DIR}/cryptofs_seq_read_4k.json"
run_fio_test "seq_write_1m"    "${CRYPTOFS_DIR}" "write"    "1m"  1 "${RESULTS_DIR}/cryptofs_seq_write_1m.json"
run_fio_test "seq_read_1m"     "${CRYPTOFS_DIR}" "read"     "1m"  1 "${RESULTS_DIR}/cryptofs_seq_read_1m.json"
run_fio_test "rand_read_4k"    "${CRYPTOFS_DIR}" "randread" "4k"  4 "${RESULTS_DIR}/cryptofs_rand_read_4k.json"
run_fio_test "rand_write_4k"   "${CRYPTOFS_DIR}" "randwrite" "4k"  4 "${RESULTS_DIR}/cryptofs_rand_write_4k.json"
run_fio_test "rand_rw_4k"      "${CRYPTOFS_DIR}" "randrw"   "4k"  4 "${RESULTS_DIR}/cryptofs_rand_rw_4k.json"
echo ""

echo "=== Results saved to ${RESULTS_DIR} ==="
echo "Use tests/bench/compare_results.py to generate comparison report."

# Cleanup benchmark files
rm -f "${BASELINE_DIR}"/seq_* "${BASELINE_DIR}"/rand_*
rm -f "${CRYPTOFS_DIR}"/seq_* "${CRYPTOFS_DIR}"/rand_*
