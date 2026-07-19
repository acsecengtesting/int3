#!/bin/bash
set -e
cd /root/jclass_monitor

echo "=== Building native lib ==="
docker exec testjava javac /tmp/NativeNet.java -d /tmp/ -h /tmp/ 2>&1
docker exec testjava gcc -shared -fPIC -o /tmp/libnativenet.so /tmp/native_connect.c \
    -I/opt/java/openjdk/include -I/opt/java/openjdk/include/linux 2>&1
echo "Build OK"

echo "=== Starting detector ==="
./jni_net > /tmp/jni_net_out.log 2>&1 &
DPID=$!
sleep 2

echo "=== Running NativeNet (direct connect from JNI .so) ==="
docker exec testjava java -cp /tmp NativeNet

sleep 3
kill $DPID 2>/dev/null || true
wait $DPID 2>/dev/null || true

echo ""
echo "=== OUTPUT ==="
cat /tmp/jni_net_out.log
