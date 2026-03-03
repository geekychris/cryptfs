#!/bin/bash
# Traced test runner: saves dmesg to persistent storage every 2 seconds
# so we can read the kernel log even after a VM hang + restart.

LOG=/root/trace_log.txt
DMESG_DUMP=/root/dmesg_last.txt

echo "=== TRACED TEST START $(date) ===" | sudo tee "$LOG"

# Background watchdog: dump dmesg to disk every 2 seconds
(
  while true; do
    sudo dmesg > "$DMESG_DUMP" 2>/dev/null
    sync
    sleep 2
  done
) &
WATCHDOG_PID=$!

# Cleanup previous test state
sudo rm -rf /tmp/cryptofs_lower/basic_ops_test 2>/dev/null
sync
sleep 1

echo "Running test_basic_ops.sh ..." | sudo tee -a "$LOG"
sudo bash /home/vagrant/cryptofs/tests/integration/test_basic_ops.sh 2>&1 | sudo tee -a "$LOG"
TEST_EXIT=$?

echo "=== TEST EXIT CODE: $TEST_EXIT ===" | sudo tee -a "$LOG"

# Final dmesg dump
sudo dmesg > "$DMESG_DUMP"
sync

# Kill watchdog
kill $WATCHDOG_PID 2>/dev/null

echo "=== TRACED TEST DONE ==="
