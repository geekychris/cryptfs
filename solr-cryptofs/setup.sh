#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# ============================================================================
# Solr on CryptoFS — Setup
#
# Runs INSIDE the Vagrant VM. Sets up CryptoFS and starts Solr with its
# index stored on the encrypted mount.
#
# Usage:
#   ./solr-cryptofs/setup.sh              # full setup (build + mount + solr)
#   ./solr-cryptofs/setup.sh --skip-build # skip CryptoFS build
#
# Prerequisites:
#   - Running inside the Vagrant VM (vagrant ssh)
#   - Project synced to /home/vagrant/cryptofs
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Paths — aligned with the existing test infrastructure
LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
SOLR_HOME="${MOUNT_DIR}/solr-home"
SOLR_CONTAINER="solr-cryptofs"

SKIP_BUILD=false

# ---- colours ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${NC}"
}
step() { echo -e "\n${BOLD}▸ $1${NC}"; }
ok()   { echo -e "  ${GREEN}✓ $1${NC}"; }
fail() { echo -e "  ${RED}✗ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠ $1${NC}"; }

# ---- argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=true; shift ;;
        --help|-h)
            sed -n '2,/^# ====/{ /^#/s/^# \?//p }' "$0"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---- sanity checks ----
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}Error: This script must run inside the Vagrant VM (Linux).${NC}"
    echo "  From your Mac:  cd vagrant && vagrant ssh"
    echo "  Then:           cd cryptofs && ./solr-cryptofs/setup.sh"
    exit 1
fi

banner "Solr on CryptoFS — Setup"

# ============================================================================
# PHASE 1 — BUILD CRYPTOFS
# ============================================================================
if [ "${SKIP_BUILD}" = false ]; then
    banner "Phase 1: Build CryptoFS"

    step "Building kernel module"
    if make -C "${PROJECT_DIR}/kernel" 2>&1; then
        ok "cryptofs.ko built"
    else
        fail "Kernel module build failed"
        exit 1
    fi

    step "Building set_key tool"
    if gcc -o "${PROJECT_DIR}/tools/set_key" "${PROJECT_DIR}/tools/set_key.c" 2>&1; then
        ok "set_key compiled"
    else
        fail "set_key build failed"
        exit 1
    fi
else
    echo -e "  ${YELLOW}Skipping build (--skip-build)${NC}"
fi

# ============================================================================
# PHASE 2 — LOAD MODULE + START DAEMON + KEY + MOUNT
# ============================================================================
banner "Phase 2: CryptoFS Setup"

SET_KEY_TOOL="${PROJECT_DIR}/tools/set_key"

mkdir -p "${LOWER_DIR}" "${MOUNT_DIR}"

# Load kernel module
step "Loading kernel module"
if grep -q cryptofs /proc/filesystems 2>/dev/null; then
    ok "Already loaded"
else
    if sudo insmod "${PROJECT_DIR}/kernel/cryptofs.ko" 2>&1; then
        ok "cryptofs.ko loaded"
    else
        fail "Could not load cryptofs.ko"
        exit 1
    fi
fi

# Build the set_key netlink tool if not present
step "Preparing set_key tool"
if [ ! -x "${SET_KEY_TOOL}" ]; then
    if gcc -o "${SET_KEY_TOOL}" "${PROJECT_DIR}/tools/set_key.c" 2>&1; then
        ok "set_key compiled"
    else
        fail "Could not compile set_key"
        exit 1
    fi
else
    ok "set_key already built"
fi

# Mount CryptoFS
step "Mounting CryptoFS"
if mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    ok "Already mounted at ${MOUNT_DIR}"
else
    if sudo mount -t cryptofs "${LOWER_DIR}" "${MOUNT_DIR}" 2>&1; then
        ok "Mounted: ${LOWER_DIR} → ${MOUNT_DIR}"
    else
        fail "Could not mount CryptoFS"
        exit 1
    fi
fi

# Inject master key into the kernel module's internal key table.
# Must happen AFTER mount — the key table is per-superblock, created fresh
# at mount time. With no policies, CryptoFS uses TRANSPARENT mode with a
# default all-zeros key_id. The set_key netlink command populates this table
# directly — distinct from the kernel keyring used by GUARDED mode.
step "Injecting encryption key via netlink"
if sudo "${SET_KEY_TOOL}" 2>&1; then
    ok "Key injected into kernel module"
else
    fail "Could not inject key"
    exit 1
fi

echo ""
echo -e "  Lower (encrypted):  ${LOWER_DIR}"
echo -e "  Mount (decrypted):  ${MOUNT_DIR}"

# ============================================================================
# PHASE 3 — START SOLR ON CRYPTOFS
# ============================================================================
banner "Phase 3: Start Solr"

# Pull Solr image if not present
step "Pulling Solr Docker image"
if docker image inspect solr:9 >/dev/null 2>&1; then
    ok "solr:9 already available"
else
    docker pull solr:9
    ok "solr:9 pulled"
fi

# Stop existing Solr container if present
if docker ps -a --format '{{.Names}}' | grep -q "^${SOLR_CONTAINER}$"; then
    step "Removing previous Solr container"
    docker rm -f "${SOLR_CONTAINER}" >/dev/null 2>&1
    ok "Removed"
fi

# Prepare Solr home on the CryptoFS mount
step "Preparing Solr home on CryptoFS mount"
sudo mkdir -p "${SOLR_HOME}"

if [ ! -f "${SOLR_HOME}/solr.xml" ]; then
    # Extract Solr config from Docker image to a temp dir, then copy into
    # CryptoFS mount via the host — Docker processes don't have access to
    # the CryptoFS kernel keyring, so they can't write to the encrypted mount.
    TMPCONF="/tmp/solr-config-staging"
    sudo rm -rf "${TMPCONF}"
    mkdir -p "${TMPCONF}"
    docker run --rm --user root -v "${TMPCONF}:/out" solr:9 bash -c \
        'cp /opt/solr/server/solr/solr.xml /out/ && cp -r /opt/solr/server/solr/configsets /out/'
    sudo cp -r "${TMPCONF}/"* "${SOLR_HOME}/"
    sudo rm -rf "${TMPCONF}"
    ok "Solr config copied to encrypted mount"
fi

# Set ownership to Solr user (uid 8983)
sudo chown -R 8983:8983 "${SOLR_HOME}"
ok "Solr home ready at ${SOLR_HOME}"

# Start Solr container — bind-mounted to the CryptoFS mount
step "Starting Solr container"
docker run -d \
    --name "${SOLR_CONTAINER}" \
    -p 8983:8983 \
    -v "${SOLR_HOME}:/var/solr/data" \
    solr:9 \
    solr-foreground -s /var/solr/data >/dev/null

# Wait for Solr to be ready
echo -n "  Waiting for Solr..."
for i in $(seq 1 60); do
    if curl -sf http://localhost:8983/solr/admin/info/system >/dev/null 2>&1; then
        echo ""
        ok "Solr is running on http://localhost:8983"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo ""
        fail "Solr did not start within 60 seconds"
        echo "  Check: docker logs ${SOLR_CONTAINER}"
        exit 1
    fi
    echo -n "."
    sleep 2
done

# ============================================================================
# DONE
# ============================================================================
banner "Setup Complete"
echo ""
echo "  CryptoFS mount:  ${MOUNT_DIR}"
echo "  Solr home:       ${SOLR_HOME}  (on encrypted mount)"
echo "  Lower dir:       ${LOWER_DIR}  (ciphertext on disk)"
echo "  Solr URL:        http://localhost:8983/solr/"
echo "  Solr container:  ${SOLR_CONTAINER}"
echo ""
echo "  Next: run the demo to index and search:"
echo "    ./solr-cryptofs/demo.sh"
echo ""
