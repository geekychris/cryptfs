#!/bin/bash
# Entrypoint for Solr with encrypted index
# 1. Initialize gocryptfs on first run
# 2. Mount decrypted view of encrypted volume
# 3. Prepare Solr home in decrypted space
# 4. Start Solr as the solr user
set -e

ENCRYPTED_DIR="/data/encrypted"
DECRYPTED_DIR="/data/decrypted"
SOLR_DATA="${DECRYPTED_DIR}/solr"
PASSWORD="${ENCRYPTION_PASSWORD:-solr-encrypted-demo}"

echo "=== Solr Encrypted Index Container ==="

# ── Step 1: Initialize gocryptfs if needed ──
if [ ! -f "${ENCRYPTED_DIR}/gocryptfs.conf" ]; then
    echo "[init] Initializing encrypted filesystem in ${ENCRYPTED_DIR}..."
    echo "${PASSWORD}" | gocryptfs -init -q "${ENCRYPTED_DIR}"
    echo "[init] Encryption initialized (AES-256-GCM)."
else
    echo "[init] Encrypted filesystem already initialized."
fi

# ── Step 2: Mount decrypted view via FUSE ──
# force_owner makes files appear owned by solr (uid 8983) so Solr can write
echo "[mount] Mounting decrypted view at ${DECRYPTED_DIR}..."
echo "${PASSWORD}" | gocryptfs -q -allow_other -force_owner 8983:8983 "${ENCRYPTED_DIR}" "${DECRYPTED_DIR}"
echo "[mount] Decrypted FUSE mount active."

# Ensure cleanup on exit
cleanup() {
    echo "[shutdown] Unmounting encrypted filesystem..."
    fusermount -u "${DECRYPTED_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 3: Prepare Solr home ──
mkdir -p "${SOLR_DATA}"

if [ ! -f "${SOLR_DATA}/solr.xml" ]; then
    echo "[solr] Setting up Solr home in encrypted space..."
    cp /opt/solr/server/solr/solr.xml "${SOLR_DATA}/"
    # Copy configsets so CREATE core works
    cp -r /opt/solr/server/solr/configsets "${SOLR_DATA}/"
fi

chown -R solr:solr "${DECRYPTED_DIR}"

# ── Step 4: Start Solr ──
echo "[solr] Starting Solr (data is encrypted at rest)..."
echo "[solr] Admin UI: http://localhost:8983/solr/"
echo ""

exec gosu solr solr-foreground -s "${SOLR_DATA}"
