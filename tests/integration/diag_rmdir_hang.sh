#!/bin/bash
# Diagnostic: stat-after-rmdir hang
# Captures kernel stack traces to identify the exact deadlock location
set -o pipefail

MOUNT_DIR="/tmp/cryptofs_mount"
DIAG_DIR="/tmp/diag_results"
mkdir -p "$DIAG_DIR"

echo "=== Diagnostic: stat-after-rmdir ==="

# Enable sysrq
echo 1 | sudo tee /proc/sys/kernel/sysrq > /dev/null

# Clear dmesg
sudo dmesg -C

# Step 1: mkdir + rmdir
echo "[1] mkdir + rmdir"
sudo mkdir "$MOUNT_DIR/diagtest"
sudo rmdir "$MOUNT_DIR/diagtest"
echo "[1] done"

# Step 2: Start stat in background (no strace - it adds too much delay)
echo "[2] Starting stat in background..."
sudo stat "$MOUNT_DIR/diagtest" 2>/dev/null &
STAT_PID=$!
echo "[2] stat PID=$STAT_PID"

# Step 3: Wait and collect diagnostics
for i in 2 5 10; do
    sleep $i
    echo "[3] After ${i}s: checking if stat is still running..."
    if kill -0 $STAT_PID 2>/dev/null; then
        echo "[3] stat still running — collecting diagnostics"
        # Try to get the kernel stack
        sudo cat /proc/$STAT_PID/stack 2>/dev/null > "$DIAG_DIR/stack_${i}s.txt" || echo "(could not read stack)"
        sudo cat /proc/$STAT_PID/wchan 2>/dev/null > "$DIAG_DIR/wchan_${i}s.txt" || echo "(could not read wchan)"
        # Dump to dmesg
        echo w | sudo tee /proc/sysrq-trigger > /dev/null 2>&1 || true
    else
        echo "[3] stat completed (exited)"
        wait $STAT_PID 2>/dev/null
        echo "[3] stat exit code: $?"
        break
    fi
done

# Step 4: Collect results
echo "=== Results ==="
echo "--- dmesg (cryptofs + lockup + Call) ---"
sudo dmesg | grep -E "cryptofs|lockup|stuck|Call Trace|RCU|d_lookup|walk_comp" | head -60
echo ""
echo "--- strace ---"
cat /tmp/diag_strace.txt 2>/dev/null | head -20
echo ""
echo "--- Kernel stacks ---"
for f in "$DIAG_DIR"/stack_*.txt; do
    echo "--- $f ---"
    cat "$f" 2>/dev/null
done
echo ""
echo "--- wchan ---"
for f in "$DIAG_DIR"/wchan_*.txt; do
    echo "--- $f ---"
    cat "$f" 2>/dev/null
done

# Cleanup
sudo kill -9 $STAT_PID 2>/dev/null
echo "=== Diagnostic complete ==="
