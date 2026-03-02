#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# ============================================================================
# CryptoFS — Build Everything & Run All Tests
#
# This script:
#   1. Builds the kernel module (if on Linux)
#   2. Builds the Rust daemon and CLI
#   3. Runs daemon unit tests
#   4. Sets up the cryptofs mount (load module, start daemon, mount)
#   5. Runs all integration test suites
#   6. Runs the exhaustive data-integrity stress test
#   7. Optionally runs Docker tests and fio benchmarks
#   8. Tears down the mount and prints a full report
#
# Usage:
#   ./build_and_test.sh                  # build + all tests (medium stress)
#   ./build_and_test.sh --stress heavy   # heavy stress level
#   ./build_and_test.sh --skip-build     # tests only (assumes already built)
#   ./build_and_test.sh --include-bench  # also run fio benchmarks
#   ./build_and_test.sh --include-docker # also run Docker tests
#   ./build_and_test.sh --help
#
# Environment overrides:
#   LOWER_DIR      backing directory     (default /tmp/cryptofs_lower)
#   MOUNT_DIR      mount point           (default /tmp/cryptofs_mount)
#   STRESS_LEVEL   light|medium|heavy    (default medium)
#   NUM_WORKERS    parallel workers      (default 8)
#   KDIR           kernel build dir      (default auto-detect)
# ============================================================================
set -uo pipefail   # no -e: we track failures ourselves

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- defaults ----
LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
STRESS_LEVEL="${STRESS_LEVEL:-medium}"
NUM_WORKERS="${NUM_WORKERS:-8}"
SUITE_TIMEOUT=120
SKIP_BUILD=false
INCLUDE_BENCH=false
INCLUDE_DOCKER=false
BUILD_ONLY=false

# ---- colours ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---- result tracking ----
declare -a SUITE_NAMES=()
declare -a SUITE_RESULTS=()   # "pass" or "FAIL"
declare -a SUITE_DETAILS=()
OVERALL_RC=0
START_TS=$(date +%s)

# ---- argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stress)       STRESS_LEVEL="$2"; shift 2 ;;
        --skip-build)   SKIP_BUILD=true; shift ;;
        --build-only)   BUILD_ONLY=true; shift ;;
        --include-bench)  INCLUDE_BENCH=true; shift ;;
        --include-docker) INCLUDE_DOCKER=true; shift ;;
        --workers)      NUM_WORKERS="$2"; shift 2 ;;
        --lower-dir)    LOWER_DIR="$2"; shift 2 ;;
        --mount-dir)    MOUNT_DIR="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,/^# ====/{ /^#/s/^# \?//p }' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
}

step() { echo -e "\n${BOLD}▸ $1${NC}"; }

record_suite() {
    local NAME="$1" RC="$2" DETAIL="${3:-}"
    SUITE_NAMES+=("$NAME")
    if [ "$RC" -eq 0 ]; then
        SUITE_RESULTS+=("pass")
        echo -e "  ${GREEN}✓ ${NAME}${NC}"
    else
        SUITE_RESULTS+=("FAIL")
        OVERALL_RC=1
        echo -e "  ${RED}✗ ${NAME}${NC}"
    fi
    SUITE_DETAILS+=("$DETAIL")
}

is_linux() { [ "$(uname -s)" = "Linux" ]; }

# ============================================================================
banner "CryptoFS — Build & Test"
# ============================================================================
echo -e " Date:          $(date)"
echo -e " Host:          $(uname -srm)"
echo -e " Stress level:  ${STRESS_LEVEL}"
echo -e " Workers:       ${NUM_WORKERS}"
echo -e " Lower dir:     ${LOWER_DIR}"
echo -e " Mount dir:     ${MOUNT_DIR}"
echo -e " Script dir:    ${SCRIPT_DIR}"

# ============================================================================
# PHASE 1 — BUILD
# ============================================================================
if [ "${SKIP_BUILD}" = false ]; then
    banner "Phase 1: Build"

    # ---- 1a. Kernel module ----
    if is_linux; then
        step "Building kernel module"
        if make -C "${SCRIPT_DIR}/kernel" 2>&1; then
            record_suite "Kernel module build" 0
        else
            record_suite "Kernel module build" 1
        fi
    else
        echo -e "  ${YELLOW}Skipping kernel build (not Linux)${NC}"
        record_suite "Kernel module build" 0 "skipped — not Linux"
    fi

    # ---- 1b. Rust daemon ----
    step "Building daemon (cryptofs-keyd)"
    if cargo build --manifest-path "${SCRIPT_DIR}/daemon/Cargo.toml" --release 2>&1; then
        record_suite "Daemon build" 0
    else
        record_suite "Daemon build" 1
    fi

    # ---- 1c. Rust CLI ----
    step "Building CLI (cryptofs-admin)"
    if cargo build --manifest-path "${SCRIPT_DIR}/cli/Cargo.toml" --release 2>&1; then
        record_suite "CLI build" 0
    else
        record_suite "CLI build" 1
    fi
else
    echo -e "  ${YELLOW}Skipping build (--skip-build)${NC}"
fi

if [ "${BUILD_ONLY}" = true ]; then
    echo -e "\n${BOLD}Build-only mode — stopping here.${NC}"
    exit "${OVERALL_RC}"
fi

# ============================================================================
# PHASE 2 — UNIT TESTS
# ============================================================================
banner "Phase 2: Unit Tests"

step "Daemon unit tests (cargo test)"
CARGO_OUTPUT=$(cargo test --manifest-path "${SCRIPT_DIR}/daemon/Cargo.toml" 2>&1) || true
if echo "$CARGO_OUTPUT" | grep -q "test result: ok"; then
    DAEMON_TESTS=$(echo "$CARGO_OUTPUT" | grep "test result:" | head -1)
    record_suite "Daemon unit tests" 0 "$DAEMON_TESTS"
else
    record_suite "Daemon unit tests" 1 "$(echo "$CARGO_OUTPUT" | tail -5)"
fi

# ============================================================================
# PHASE 3 — SETUP CRYPTOFS MOUNT
# ============================================================================
banner "Phase 3: Setup CryptoFS Mount"

TEARDOWN_NEEDED=false

if is_linux; then
    mkdir -p "${LOWER_DIR}" "${MOUNT_DIR}"

    # Load kernel module if not already loaded
    if ! grep -q cryptofs /proc/filesystems 2>/dev/null; then
        step "Loading kernel module"
        if [ -f "${SCRIPT_DIR}/kernel/cryptofs.ko" ]; then
            if sudo insmod "${SCRIPT_DIR}/kernel/cryptofs.ko" 2>&1; then
                record_suite "Load kernel module" 0
            else
                record_suite "Load kernel module" 1
            fi
        else
            record_suite "Load kernel module" 1 "cryptofs.ko not found"
        fi
    else
        echo "  Kernel module already loaded"
        record_suite "Load kernel module" 0 "already loaded"
    fi

    # Start daemon if not running
    if ! pgrep -x cryptofs-keyd >/dev/null 2>&1; then
        step "Starting daemon"
        KEYD="${SCRIPT_DIR}/daemon/target/release/cryptofs-keyd"
        if [ -f "${KEYD}" ]; then
            sudo "${KEYD}" --foreground \
                --key-dir /tmp/cryptofs_test_keys \
                --socket /tmp/cryptofs_test.sock \
                --audit-log /tmp/cryptofs_test_audit.log \
                --pid-file /tmp/cryptofs_test.pid \
                &
            DAEMON_PID=$!
            # Poll for daemon readiness (wait for socket to appear)
            READY=false
            for _i in $(seq 1 10); do
                sleep 1
                if [ -S /tmp/cryptofs_test.sock ] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
                    READY=true
                    break
                fi
            done
            if ${READY}; then
                record_suite "Start daemon" 0
                TEARDOWN_NEEDED=true
            else
                record_suite "Start daemon" 1
            fi
        else
            record_suite "Start daemon" 1 "binary not found"
        fi
    else
        echo "  Daemon already running"
        record_suite "Start daemon" 0 "already running"
    fi

    # Mount if not mounted
    if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
        step "Mounting cryptofs"
        if sudo mount -t cryptofs "${LOWER_DIR}" "${MOUNT_DIR}" 2>&1; then
            record_suite "Mount cryptofs" 0
            TEARDOWN_NEEDED=true
        else
            record_suite "Mount cryptofs" 1
            echo -e "  ${RED}Cannot mount — integration tests will fail${NC}"
        fi
    else
        echo "  Already mounted at ${MOUNT_DIR}"
        record_suite "Mount cryptofs" 0 "already mounted"
    fi
else
    echo -e "  ${YELLOW}Not Linux — cannot set up real cryptofs mount.${NC}"
    echo -e "  ${YELLOW}Integration tests require a Linux environment (use the Vagrant VM).${NC}"
    record_suite "Setup cryptofs mount" 0 "skipped — not Linux"
fi

# ============================================================================
# PHASE 4 — INTEGRATION TESTS
# ============================================================================
banner "Phase 4: Integration Tests"

export MOUNT_DIR LOWER_DIR

run_test_script() {
    local NAME="$1" SCRIPT="$2"
    step "${NAME}"
    if [ ! -f "${SCRIPT}" ]; then
        record_suite "${NAME}" 1 "script not found: ${SCRIPT}"
        return
    fi
    if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null && is_linux; then
        record_suite "${NAME}" 1 "mount not available"
        return
    fi
    if ! is_linux; then
        record_suite "${NAME}" 0 "skipped — not Linux"
        return
    fi

    local OUTPUT RC
    OUTPUT=$(timeout ${SUITE_TIMEOUT} bash "${SCRIPT}" 2>&1)
    RC=$?

    # Extract pass/fail counts from output
    local SUMMARY
    if [ "${RC}" -eq 124 ]; then
        SUMMARY="TIMED OUT after ${SUITE_TIMEOUT}s"
    else
        SUMMARY=$(echo "${OUTPUT}" | grep -i "Results:" | tail -1)
    fi

    if [ "${RC}" -eq 0 ]; then
        record_suite "${NAME}" 0 "${SUMMARY}"
    else
        record_suite "${NAME}" 1 "${SUMMARY}"
    fi
}

TESTS_DIR="${SCRIPT_DIR}/tests/integration"

run_test_script "Basic file operations"    "${TESTS_DIR}/test_basic_ops.sh"
run_test_script "Random access"            "${TESTS_DIR}/test_random_access.sh"
run_test_script "Append operations"        "${TESTS_DIR}/test_append.sh"
run_test_script "Concurrent access"        "${TESTS_DIR}/test_concurrent.sh"
run_test_script "UID policy"               "${TESTS_DIR}/test_policy_uid.sh"

# ============================================================================
# PHASE 5 — STRESS TEST
# ============================================================================
banner "Phase 5: Data Integrity Stress Test (level: ${STRESS_LEVEL})"

if is_linux && mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    step "Running stress test (${STRESS_LEVEL})"

    export STRESS_LEVEL NUM_WORKERS
    STRESS_OUTPUT=$(bash "${TESTS_DIR}/test_stress.sh" 2>&1) || true
    STRESS_RC=$?

    # Show the last summary block
    echo "${STRESS_OUTPUT}" | tail -15

    STRESS_SUMMARY=$(echo "${STRESS_OUTPUT}" | grep -E "Passed:|Failed:|Data verified:" | tr '\n' ' ')

    if [ "${STRESS_RC}" -eq 0 ]; then
        record_suite "Stress test (${STRESS_LEVEL})" 0 "${STRESS_SUMMARY}"
    else
        record_suite "Stress test (${STRESS_LEVEL})" 1 "${STRESS_SUMMARY}"
    fi
else
    if ! is_linux; then
        record_suite "Stress test" 0 "skipped — not Linux"
    else
        record_suite "Stress test" 1 "mount not available"
    fi
fi

# ============================================================================
# PHASE 6 — DOCKER TESTS (optional)
# ============================================================================
if [ "${INCLUDE_DOCKER}" = true ]; then
    banner "Phase 6: Docker Tests"
    if command -v docker &>/dev/null && is_linux; then
        step "Docker container tests"
        DOCKER_OUTPUT=$(bash "${TESTS_DIR}/test_docker.sh" 2>&1) || true
        DOCKER_RC=$?
        DOCKER_SUMMARY=$(echo "${DOCKER_OUTPUT}" | grep "Results:" | tail -1)
        record_suite "Docker tests" "${DOCKER_RC}" "${DOCKER_SUMMARY}"
    else
        record_suite "Docker tests" 0 "skipped — Docker not available or not Linux"
    fi
fi

# ============================================================================
# PHASE 7 — BENCHMARKS (optional)
# ============================================================================
if [ "${INCLUDE_BENCH}" = true ]; then
    banner "Phase 7: Performance Benchmarks"
    if is_linux && mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
        step "Running fio benchmarks"
        export CRYPTOFS_DIR="${MOUNT_DIR}/bench"
        export BASELINE_DIR="/tmp/cryptofs_baseline/bench"
        mkdir -p "${CRYPTOFS_DIR}" "${BASELINE_DIR}"

        BENCH_OUTPUT=$(bash "${SCRIPT_DIR}/tests/bench/run_fio.sh" 2>&1) || true
        BENCH_RC=$?
        record_suite "fio benchmarks" "${BENCH_RC}"

        step "Generating comparison report"
        python3 "${SCRIPT_DIR}/tests/bench/compare_results.py" 2>&1 || true
    else
        record_suite "fio benchmarks" 0 "skipped — mount not available"
    fi
fi

# ============================================================================
# TEARDOWN
# ============================================================================
banner "Teardown"

if [ "${TEARDOWN_NEEDED}" = true ] && is_linux; then
    step "Unmounting and cleaning up"
    sync 2>/dev/null || true
    sudo umount "${MOUNT_DIR}" 2>/dev/null || true
    sudo rmmod cryptofs 2>/dev/null || true

    if [ -n "${DAEMON_PID:-}" ]; then
        sudo kill "${DAEMON_PID}" 2>/dev/null || true
    fi

    rm -f /tmp/cryptofs_test.sock /tmp/cryptofs_test.pid /tmp/cryptofs_test_audit.log
    rm -rf /tmp/cryptofs_test_keys /tmp/cryptofs_stress_ref /tmp/cryptofs_stress_worker_*
    echo "  Cleanup complete"
else
    echo "  Nothing to tear down"
fi

# ============================================================================
# FINAL REPORT
# ============================================================================
END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

banner "Final Report"

TOTAL=${#SUITE_NAMES[@]}
PASSED=0
FAILED=0

for i in "${!SUITE_NAMES[@]}"; do
    NAME="${SUITE_NAMES[$i]}"
    RESULT="${SUITE_RESULTS[$i]}"
    DETAIL="${SUITE_DETAILS[$i]}"

    if [ "${RESULT}" = "pass" ]; then
        ICON="${GREEN}✓${NC}"
        ((PASSED++))
    else
        ICON="${RED}✗${NC}"
        ((FAILED++))
    fi

    if [ -n "${DETAIL}" ]; then
        printf "  ${ICON}  %-40s %s\n" "${NAME}" "${DETAIL}"
    else
        printf "  ${ICON}  %s\n" "${NAME}"
    fi
done

echo ""
echo -e " Total suites:    ${TOTAL}"
echo -e " ${GREEN}Passed:${NC}          ${PASSED}"
echo -e " ${RED}Failed:${NC}          ${FAILED}"
echo -e " Duration:        ${ELAPSED}s"
echo ""

if [ "${OVERALL_RC}" -eq 0 ]; then
    echo -e " ${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
    echo -e " ${GREEN}${BOLD}  ✓  ALL SUITES PASSED${NC}"
    echo -e " ${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
else
    echo -e " ${RED}${BOLD}═══════════════════════════════════════════${NC}"
    echo -e " ${RED}${BOLD}  ✗  ${FAILED} SUITE(S) FAILED${NC}"
    echo -e " ${RED}${BOLD}═══════════════════════════════════════════${NC}"
fi

exit "${OVERALL_RC}"
