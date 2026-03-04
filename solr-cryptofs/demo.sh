#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# ============================================================================
# Solr on CryptoFS — Demo
#
# Runs INSIDE the Vagrant VM after setup.sh.
# Indexes sample documents, runs searches, then compares the encrypted
# lower directory with the decrypted mount to prove CryptoFS is working.
# ============================================================================
set -eo pipefail

LOWER_DIR="${LOWER_DIR:-/tmp/cryptofs_lower}"
MOUNT_DIR="${MOUNT_DIR:-/tmp/cryptofs_mount}"
SOLR_HOME="${MOUNT_DIR}/solr-home"
SOLR_URL="http://localhost:8983/solr"
CORE="demo"

# ---- colours ----
RED='\033[0;31m'
GREEN='\033[0;32m'
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

# ---- sanity checks ----
if ! curl -sf "${SOLR_URL}/admin/info/system" >/dev/null 2>&1; then
    echo -e "${RED}Error: Solr is not running. Run setup.sh first.${NC}"
    exit 1
fi

if ! mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
    echo -e "${RED}Error: CryptoFS is not mounted at ${MOUNT_DIR}.${NC}"
    exit 1
fi

banner "Solr on CryptoFS — Demo"

# ============================================================================
# 1. CREATE CORE
# ============================================================================
step "Creating Solr core '${CORE}'"
CORE_EXISTS=$(curl -sf "${SOLR_URL}/admin/cores?action=STATUS&core=${CORE}" \
    | grep -c '"instanceDir"' || true)
if [ "$CORE_EXISTS" -gt 0 ]; then
    ok "Core '${CORE}' already exists"
else
    curl -sf "${SOLR_URL}/admin/cores?action=CREATE&name=${CORE}&configSet=_default" >/dev/null
    ok "Core '${CORE}' created"
fi

# ============================================================================
# 2. INDEX DOCUMENTS
# ============================================================================
step "Indexing sample documents"
curl -sf -X POST "${SOLR_URL}/${CORE}/update?commit=true" \
    -H 'Content-Type: application/json' \
    -d '[
  {
    "id": "1",
    "title": "Introduction to Cryptography",
    "author": "Alice Johnson",
    "category": "security",
    "content": "Cryptography is the practice of securing communication through encryption. Modern encryption uses mathematical algorithms like AES and RSA to protect data at rest and in transit."
  },
  {
    "id": "2",
    "title": "Building Search Engines with Apache Solr",
    "author": "Bob Smith",
    "category": "search",
    "content": "Apache Solr is a powerful open-source search platform built on Apache Lucene. It provides full-text search, faceted search, and real-time indexing capabilities."
  },
  {
    "id": "3",
    "title": "Kernel-Level Filesystem Encryption",
    "author": "Carol Williams",
    "category": "security",
    "content": "VFS-layer encrypted filesystems like CryptoFS provide transparent encryption at the kernel level. Unlike FUSE-based solutions, they operate entirely in kernel space with no userspace round-trips, resulting in lower latency and higher throughput."
  },
  {
    "id": "4",
    "title": "Docker Security Best Practices",
    "author": "Dave Brown",
    "category": "devops",
    "content": "Container security involves multiple layers including image scanning, runtime protection, and encrypted storage. Docker supports bind-mounting host directories, which can leverage kernel-level encryption transparently."
  },
  {
    "id": "5",
    "title": "Data at Rest Encryption Strategies",
    "author": "Eve Davis",
    "category": "security",
    "content": "Encrypting data at rest protects sensitive information from unauthorized access when storage media is compromised. Stacked filesystems encrypt at the VFS layer, requiring no changes to applications or underlying storage."
  }
]' >/dev/null
ok "5 documents indexed"

# ============================================================================
# 3. SEARCH QUERIES
# ============================================================================
step "Running search queries"

echo ""
echo "--- Query: 'encryption' (full-text across title + content) ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=encryption&defType=edismax&qf=title+content&fl=id,title,score&rows=5" \
    | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=encryption&defType=edismax&qf=title+content&fl=id,title,score&rows=5"
echo ""

echo "--- Query: 'kernel VFS' ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=kernel+VFS&defType=edismax&qf=title+content&fl=id,title,score&rows=5" \
    | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=kernel+VFS&defType=edismax&qf=title+content&fl=id,title,score&rows=5"
echo ""

echo "--- Query: category:security ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=category:security&fl=id,title,author&rows=5" \
    | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=category:security&fl=id,title,author&rows=5"
echo ""

# ============================================================================
# 4. VERIFY ENCRYPTION — COMPARE LOWER VS MOUNT
# ============================================================================
banner "Encryption Verification"

SOLR_LOWER="${LOWER_DIR}/solr-home"

# --- Decrypted view (through CryptoFS mount) ---
step "Decrypted view (CryptoFS mount: ${SOLR_HOME})"
echo ""
echo "  Solr home directory:"
ls -la "${SOLR_HOME}/" 2>/dev/null | sed 's/^/    /'
echo ""
echo "  Index files (standard Lucene segments):"
INDEX_DIR="${SOLR_HOME}/demo/data/index"
if [ -d "${INDEX_DIR}" ]; then
    ls -la "${INDEX_DIR}/" 2>/dev/null | sed 's/^/    /'
else
    echo "    (index directory not yet created)"
fi

# --- Encrypted view (lower directory — raw on-disk) ---
step "Encrypted view (lower dir: ${SOLR_LOWER})"
echo ""
echo "  Lower directory (same path structure, encrypted contents):"
ls -la "${SOLR_LOWER}/" 2>/dev/null | sed 's/^/    /'

LOWER_INDEX="${SOLR_LOWER}/demo/data/index"
if [ -d "${LOWER_INDEX}" ]; then
    echo ""
    echo "  Index files on disk (same filenames — CryptoFS preserves names):"
    ls -la "${LOWER_INDEX}/" 2>/dev/null | sed 's/^/    /'
fi

# --- Content comparison ---
step "Content comparison: same file, two views"
echo ""

# Find a Lucene index file to compare
SAMPLE_FILE=""
if [ -d "${INDEX_DIR}" ]; then
    SAMPLE_FILE=$(find "${INDEX_DIR}" -type f -name "*.fdt" -o -name "*.si" | head -1)
fi

if [ -n "${SAMPLE_FILE}" ] && [ -f "${SAMPLE_FILE}" ]; then
    BASENAME=$(basename "${SAMPLE_FILE}")
    LOWER_FILE="${LOWER_INDEX}/${BASENAME}"

    echo "  File: ${BASENAME}"
    echo ""

    echo "  Through CryptoFS mount (decrypted — normal Lucene data):"
    hexdump -C "${SAMPLE_FILE}" 2>/dev/null | head -6 | sed 's/^/    /'
    echo ""

    if [ -f "${LOWER_FILE}" ]; then
        echo "  Lower directory (encrypted — CryptoFS header + AES-256-GCM ciphertext):"
        hexdump -C "${LOWER_FILE}" 2>/dev/null | head -8 | sed 's/^/    /'
        echo ""

        # Check for CRYPTOFS magic header
        MAGIC=$(head -c 8 "${LOWER_FILE}" 2>/dev/null | cat -v)
        if echo "${MAGIC}" | grep -q "CRYPTOFS"; then
            ok "CRYPTOFS magic header present in lower file"
        else
            echo "  (Header bytes: ${MAGIC})"
        fi
    else
        echo "  (lower file not found at ${LOWER_FILE})"
    fi
else
    echo "  (no index files found yet — try running a search to trigger segment creation)"
fi

# --- File size comparison ---
step "File size comparison (encrypted overhead)"
if [ -d "${INDEX_DIR}" ] && [ -d "${LOWER_INDEX}" ]; then
    MOUNT_SIZE=$(du -sb "${INDEX_DIR}" 2>/dev/null | awk '{print $1}')
    LOWER_SIZE=$(du -sb "${LOWER_INDEX}" 2>/dev/null | awk '{print $1}')
    echo ""
    echo "  Decrypted index size:  ${MOUNT_SIZE} bytes"
    echo "  Encrypted index size:  ${LOWER_SIZE} bytes"
    if [ -n "${MOUNT_SIZE}" ] && [ -n "${LOWER_SIZE}" ] && [ "${MOUNT_SIZE}" -gt 0 ]; then
        OVERHEAD=$(( (LOWER_SIZE - MOUNT_SIZE) * 100 / MOUNT_SIZE ))
        echo "  Encryption overhead:   ~${OVERHEAD}%  (128B header + 16B auth tag per 4KB extent)"
    fi
fi

# ============================================================================
# SUMMARY
# ============================================================================
banner "Demo Complete"
echo ""
echo "  Key observations:"
echo "    - Solr indexes and searches work normally — zero application changes"
echo "    - CryptoFS encrypts at the kernel VFS layer (no FUSE, no userspace overhead)"
echo "    - File NAMES are preserved (stacked filesystem model)"
echo "    - File CONTENTS are encrypted: 128-byte header + AES-256-GCM ciphertext"
echo "    - Docker containers access encrypted data transparently via bind mount"
echo ""
echo "  Try it yourself:"
echo "    curl '${SOLR_URL}/${CORE}/select?q=YOUR_QUERY&defType=edismax&qf=title+content'"
echo ""
echo "  Compare any file:"
echo "    hexdump -C ${MOUNT_DIR}/solr-home/demo/data/index/segments_2 | head"
echo "    hexdump -C ${LOWER_DIR}/solr-home/demo/data/index/segments_2 | head"
echo ""
