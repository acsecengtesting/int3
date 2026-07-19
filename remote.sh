#!/bin/bash
set -e
cd /root/jclass_monitor

# Use JDK image (has javac)
docker rm -f testjava 2>/dev/null || true
docker run -d --name testjava eclipse-temurin:21-jdk-noble sleep 3600
sleep 2

# Write test into the container
docker exec testjava sh -c 'cat > /tmp/JniLoadTest.java << "JAVA"
public class JniLoadTest {
    public static void main(String[] args) throws Exception {
        System.out.println("PID: " + ProcessHandle.current().pid());
        
        // Copy a real .so to the writable layer (simulating attacker dropping a lib)
        Runtime.getRuntime().exec(new String[]{"cp", "/opt/java/openjdk/lib/libverify.so", "/tmp/libmalicious.so"}).waitFor();
        Thread.sleep(1000);
        
        System.out.println("Attempting to load /tmp/libmalicious.so via System.load()...");
        try {
            System.load("/tmp/libmalicious.so");
            System.out.println("Loaded successfully!");
        } catch (UnsatisfiedLinkError e) {
            System.out.println("Load attempted: " + e.getMessage());
        }
        
        // Also load a legit library from the image layer for comparison
        System.out.println("Loading legit library from image layer...");
        try {
            System.loadLibrary("zip");
            System.out.println("libzip loaded from image layer");
        } catch (UnsatisfiedLinkError e) {
            System.out.println("zip: " + e.getMessage());
        }
        
        Thread.sleep(1000);
        System.out.println("Done.");
    }
}
JAVA
'

docker exec testjava javac /tmp/JniLoadTest.java -d /tmp/

echo "=== Starting overlay detector ==="
./ovl_detect > /tmp/ovl_out.log 2>&1 &
DPID=$!
sleep 2

echo "=== Running Java JNI load test inside container ==="
docker exec testjava java -cp /tmp JniLoadTest

sleep 2
kill $DPID 2>/dev/null || true
wait $DPID 2>/dev/null || true

echo ""
echo "=== DETECTOR OUTPUT ==="
cat /tmp/ovl_out.log
