#!/bin/bash
# Test script: starts Java app, attaches classloader monitor, captures output
set -e

cd /root/jclass_monitor
javac TestApp.java

echo "Starting Java test app..."
java TestApp &
JPID=$!
echo "Java PID: $JPID"

sleep 2

echo "Attaching classloader monitor..."
./jclass_monitor -v -p $JPID -n > /tmp/jclass_out.log 2>&1 &
BPID=$!

# Wait for Java to finish
wait $JPID 2>/dev/null || true
sleep 1

kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true

echo ""
echo "=== CLASSLOADER MONITOR OUTPUT ==="
cat /tmp/jclass_out.log
