#!/bin/bash
set -e
cd /root/jclass_monitor

echo "=== Building ==="
make clean && make 2>&1 | tail -5

echo ""
echo "=== Running JarLoadTest with native lib detection ==="
javac JarLoadTest.java

java JarLoadTest &
JPID=$!
echo "Java PID: $JPID"
sleep 1

/root/jclass_monitor/jclass_monitor -v -p $JPID -n > /tmp/jclass_out.log 2>&1 &
BPID=$!

wait $JPID 2>/dev/null || true
sleep 1
kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true

echo ""
echo "=== OUTPUT ==="
cat /tmp/jclass_out.log
