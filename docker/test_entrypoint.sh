#!/bin/bash
# CryptoFS Docker test entrypoint
set -euo pipefail

MODE="${1:-all}"

run_basic_test() {
    echo "=== Basic File Operations Test ==="
    echo "test data" > /data/test_file.txt
    CONTENT=$(cat /data/test_file.txt)
    if [ "$CONTENT" = "test data" ]; then
        echo "PASS: read/write"
    else
        echo "FAIL: read/write"
    fi

    dd if=/dev/urandom of=/data/binary_test.dat bs=4096 count=100 2>/dev/null
    SUM=$(sha256sum /data/binary_test.dat | awk '{print $1}')
    REREAD=$(sha256sum /data/binary_test.dat | awk '{print $1}')
    if [ "$SUM" = "$REREAD" ]; then
        echo "PASS: binary integrity (400KB)"
    else
        echo "FAIL: binary integrity"
    fi
    rm -f /data/test_file.txt /data/binary_test.dat
}

run_benchmark() {
    echo "=== FIO Benchmark ==="
    echo "--- Sequential Write ---"
    fio --name=seq_write --directory=/data --rw=write --bs=4k --size=64M \
        --numjobs=1 --time_based --runtime=30 --output-format=json \
        --output=/results/seq_write.json 2>/dev/null
    echo "Result saved to /results/seq_write.json"

    echo "--- Sequential Read ---"
    fio --name=seq_read --directory=/data --rw=read --bs=4k --size=64M \
        --numjobs=1 --time_based --runtime=30 --output-format=json \
        --output=/results/seq_read.json 2>/dev/null
    echo "Result saved to /results/seq_read.json"

    echo "--- Random Read/Write (4K) ---"
    fio --name=rand_rw --directory=/data --rw=randrw --bs=4k --size=64M \
        --numjobs=4 --time_based --runtime=30 --output-format=json \
        --output=/results/rand_rw.json 2>/dev/null
    echo "Result saved to /results/rand_rw.json"

    echo "--- Random Read/Write (64K) ---"
    fio --name=rand_rw_64k --directory=/data --rw=randrw --bs=64k --size=64M \
        --numjobs=4 --time_based --runtime=30 --output-format=json \
        --output=/results/rand_rw_64k.json 2>/dev/null
    echo "Result saved to /results/rand_rw_64k.json"

    rm -f /data/seq_write.* /data/seq_read.* /data/rand_rw.* /data/rand_rw_64k.*
}

case "$MODE" in
    basic) run_basic_test ;;
    bench) run_benchmark ;;
    all)   run_basic_test; run_benchmark ;;
    *)     echo "Usage: $0 {basic|bench|all}"; exit 1 ;;
esac
