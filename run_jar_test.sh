#!/bin/bash
# Test: start Java app loading from jars, capture class load events with source info
set -e

cd /root/jclass_monitor
javac JarTest.java

echo "Starting Java test app..."
java JarTest &
JPID=$!
echo "Java PID: $JPID"

sleep 1

echo "Attaching classloader monitor (showing all events including source)..."
/root/jclass_monitor/jclass_monitor -v -p $JPID > /tmp/jclass_out.log 2>&1 &
BPID=$!

# Wait for Java to finish
wait $JPID 2>/dev/null || true
sleep 1

kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true

echo ""
echo "=== CLASSLOADER MONITOR OUTPUT ==="
cat /tmp/jclass_out.log
