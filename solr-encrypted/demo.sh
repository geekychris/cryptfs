#!/bin/bash
# Demo: Index documents into Solr and search, then verify encryption on host
set -e

SOLR_URL="http://localhost:8983/solr"
CORE="demo"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "============================================"
echo "  Solr Encrypted Index Demo"
echo "============================================"
echo ""

# ── Wait for Solr to be ready ──
echo "[1/5] Waiting for Solr to be ready..."
for i in $(seq 1 60); do
    if curl -sf "${SOLR_URL}/admin/info/system" > /dev/null 2>&1; then
        echo "       Solr is up."
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "ERROR: Solr did not start within 60 seconds."
        exit 1
    fi
    sleep 2
done

# ── Create a core ──
echo ""
echo "[2/5] Creating Solr core '${CORE}'..."
CORE_EXISTS=$(curl -sf "${SOLR_URL}/admin/cores?action=STATUS&core=${CORE}" | grep -c '"instanceDir"' || true)
if [ "$CORE_EXISTS" -gt 0 ]; then
    echo "       Core '${CORE}' already exists, skipping."
else
    curl -sf "${SOLR_URL}/admin/cores?action=CREATE&name=${CORE}&configSet=_default" > /dev/null
    echo "       Core '${CORE}' created."
fi

# ── Index sample documents ──
echo ""
echo "[3/5] Indexing sample documents..."
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
    "title": "Filesystem Encryption with FUSE",
    "author": "Carol Williams",
    "category": "security",
    "content": "FUSE-based encrypted filesystems like gocryptfs provide transparent encryption at the filesystem level. Files are encrypted individually using AES-256-GCM, and the encrypted ciphertext is stored on the underlying filesystem."
  },
  {
    "id": "4",
    "title": "Docker Security Best Practices",
    "author": "Dave Brown",
    "category": "devops",
    "content": "Container security involves multiple layers including image scanning, runtime protection, and encrypted storage. Docker supports various security mechanisms such as seccomp profiles, AppArmor, and capability restrictions."
  },
  {
    "id": "5",
    "title": "Data at Rest Encryption Strategies",
    "author": "Eve Davis",
    "category": "security",
    "content": "Encrypting data at rest protects sensitive information from unauthorized access when storage media is compromised. Common approaches include full-disk encryption, filesystem-level encryption, and application-level encryption."
  }
]'
echo ""
echo "       5 documents indexed."

# ── Run search queries ──
echo ""
echo "[4/5] Running search queries..."
echo ""

echo "--- Query: 'encryption' (full-text across title + content) ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=encryption&defType=edismax&qf=title+content&fl=id,title,score&rows=5" | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=encryption&defType=edismax&qf=title+content&fl=id,title,score&rows=5"
echo ""

echo "--- Query: 'docker security' (full-text across title + content) ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=docker+security&defType=edismax&qf=title+content&fl=id,title,score&rows=5" | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=docker+security&defType=edismax&qf=title+content&fl=id,title,score&rows=5"
echo ""

echo "--- Query: category:security (field-specific) ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=category:security&fl=id,title,author&rows=5" | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=category:security&fl=id,title,author&rows=5"
echo ""

echo "--- Faceted query: facet by category ---"
curl -sf "${SOLR_URL}/${CORE}/select?q=*:*&facet=true&facet.field=category&rows=0" | python3 -m json.tool 2>/dev/null || \
    curl -sf "${SOLR_URL}/${CORE}/select?q=*:*&facet=true&facet.field=category&rows=0"
echo ""

# ── Verify encryption on host ──
echo ""
echo "[5/5] Verifying encrypted data on host..."
echo ""
ENCRYPTED_DIR="${SCRIPT_DIR}/encrypted_data"

if [ -d "${ENCRYPTED_DIR}" ]; then
    echo "Host-mounted encrypted directory contents:"
    echo "-------------------------------------------"
    ls -la "${ENCRYPTED_DIR}/" 2>/dev/null | head -20
    echo ""
    echo "File count in encrypted dir (recursive):"
    find "${ENCRYPTED_DIR}" -type f 2>/dev/null | wc -l
    echo ""
    echo "Sample encrypted filename (ciphertext):"
    find "${ENCRYPTED_DIR}" -type f -not -name "gocryptfs.*" 2>/dev/null | head -5
    echo ""
    echo "Attempting to read an encrypted file (should be binary gibberish):"
    SAMPLE_FILE=$(find "${ENCRYPTED_DIR}" -type f -not -name "gocryptfs.*" 2>/dev/null | head -1)
    if [ -n "${SAMPLE_FILE}" ]; then
        echo "File: ${SAMPLE_FILE}"
        xxd "${SAMPLE_FILE}" 2>/dev/null | head -8 || hexdump -C "${SAMPLE_FILE}" 2>/dev/null | head -8
    else
        echo "(No encrypted data files found yet — index may be too small)"
    fi
else
    echo "WARNING: encrypted_data directory not found at ${ENCRYPTED_DIR}"
fi

echo ""
echo "============================================"
echo "  Demo Complete"
echo "============================================"
echo ""
echo "Key observations:"
echo "  - Solr indexes and searches work normally"
echo "  - The host volume (./encrypted_data) contains only ciphertext"
echo "  - Filenames and content are encrypted with AES-256-GCM"
echo "  - Plaintext index is only accessible inside the running container"
echo ""
echo "Try it yourself:"
echo "  curl '${SOLR_URL}/${CORE}/select?q=YOUR_QUERY'"
echo ""
