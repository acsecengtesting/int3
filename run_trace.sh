#!/bin/bash
# Trace JVM class loading paths using bpftrace
cd /root/jclass_monitor

java JarTest > /dev/null 2>&1 &
JPID=$!
echo "Java PID: $JPID"
sleep 1

timeout 12 bpftrace -p $JPID /root/jclass_monitor/trace_classload.bt 2>&1

wait $JPID 2>/dev/null
