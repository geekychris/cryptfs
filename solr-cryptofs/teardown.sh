#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# ============================================================================
# Solr on CryptoFS — Teardown
#
# Stops Solr, unmounts CryptoFS, stops daemon, unloads kernel module.
# ============================================================================
set -uo pipefail

MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
SOLR_CONTAINER="solr-cryptofs"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BOLD}▸ $1${NC}"; }
ok()   { echo -e "  ${GREEN}✓ $1${NC}"; }

echo -e "\n${BOLD}Solr on CryptoFS — Teardown${NC}\n"

# Stop Solr container
step "Stopping Solr container"
if docker ps --format '{{.Names}}' | grep -q "^${SOLR_CONTAINER}$"; then
    docker rm -f "${SOLR_CONTAINER}" >/dev/null 2>&1
    ok "Container stopped and removed"
else
    ok "Not running"
fi

# Unmount CryptoFS
step "Unmounting CryptoFS"
if mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    sudo umount "${MOUNT_DIR}" 2>&1
    ok "Unmounted ${MOUNT_DIR}"
else
    ok "Not mounted"
fi

# Stop daemon
step "Stopping daemon"
if pgrep -x cryptofs-keyd >/dev/null 2>&1; then
    sudo pkill -x cryptofs-keyd 2>/dev/null
    sleep 1
    ok "Daemon stopped"
else
    ok "Not running"
fi

# Unload kernel module
step "Unloading kernel module"
if lsmod 2>/dev/null | grep -q cryptofs; then
    sudo rmmod cryptofs 2>&1
    ok "Module unloaded"
else
    ok "Not loaded"
fi

echo ""
echo -e "${GREEN}Teardown complete.${NC}"
echo "  Encrypted data remains at /tmp/cryptofs_lower/"
echo "  To wipe: rm -rf /tmp/cryptofs_lower /tmp/cryptofs_mount /tmp/cryptofs_solr_keys"
echo ""
