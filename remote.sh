#!/bin/bash
set -e
cd /root/jclass_monitor

echo "=== Building overlay detector ==="
if [ ! -f vmlinux.h ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
    -c ovl_detect.bpf.c -o ovl_detect.bpf.o 2>&1
gcc -O2 -g -Wall -o ovl_detect ovl_detect.c -lbpf -lelf -lz 2>&1

echo ""
echo "=== Setting up test container ==="
docker rm -f testjava 2>/dev/null || true
docker run -d --name testjava eclipse-temurin:21-jdk-noble sleep 3600
sleep 2

echo "=== Starting detector ==="
./ovl_detect > /tmp/ovl_out.log 2>&1 &
DPID=$!
sleep 2

echo "=== Test 1: .so from writable layer ==="
docker exec testjava sh -c "cp /opt/java/openjdk/lib/libverify.so /tmp/evil.so"
docker exec testjava sh -c "cat /tmp/evil.so > /dev/null"

echo "=== Test 2: .class from writable layer ==="
docker exec testjava sh -c "echo 'cafebabe' > /tmp/Evil.class"
docker exec testjava sh -c "cat /tmp/Evil.class > /dev/null"

echo "=== Test 3: .jar from writable layer ==="
docker exec testjava sh -c "cp /opt/java/openjdk/lib/jrt-fs.jar /tmp/evil.jar"
docker exec testjava sh -c "cat /tmp/evil.jar > /dev/null"

echo "=== Test 4: .so from image layer (should NOT alert) ==="
docker exec testjava sh -c "cat /opt/java/openjdk/lib/libjava.so > /dev/null"

echo "=== Test 5: .class loaded by Java from writable layer ==="
docker exec testjava sh -c 'cat > /tmp/Pwned.java << "JAVA"
public class Pwned {
    public static void main(String[] args) {
        System.out.println("You have been pwned!");
    }
}
JAVA
javac /tmp/Pwned.java -d /tmp/'
docker exec testjava java -cp /tmp Pwned

sleep 3
kill $DPID 2>/dev/null || true
wait $DPID 2>/dev/null || true

echo ""
echo "=== DETECTOR OUTPUT ==="
cat /tmp/ovl_out.log
