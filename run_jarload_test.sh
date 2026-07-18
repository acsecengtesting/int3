#!/bin/bash
# Test: load class from external jar, capture source path and bytecode hash
set -e
cd /root/jclass_monitor

echo "Starting JarLoadTest..."
java JarLoadTest &
JPID=$!
echo "Java PID: $JPID"

sleep 1

echo "Attaching classloader monitor..."
/root/jclass_monitor/jclass_monitor -v -n -p $JPID > /tmp/jarload_out.log 2>&1 &
BPID=$!

wait $JPID 2>/dev/null || true
sleep 1
kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true

echo ""
echo "=== CLASSLOADER MONITOR OUTPUT ==="
cat /tmp/jarload_out.log
